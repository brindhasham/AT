#!/usr/bin/env python3


import os
import re
import hashlib
import sys
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from email.message import EmailMessage
from email.utils import parseaddr
from urllib.parse import urlparse

import gspread
from google.oauth2.service_account import Credentials
import yara


@dataclass(frozen=True)
class Config:
    SCOPES: Tuple[str, ...] = (
        "https://www.googleapis.com/auth/spreadsheets",
        "https://www.googleapis.com/auth/drive",
    )
    SHEET_NAME: str = "Phishing_Triage"
    CREDENTIALS_FILE: str = "credentials.json"
    SAMPLES_DIR: str = "samples"
    YARA_RULES_DIR: str = "yara_rules"
    YARA_INDEX: str = "index.yar"

    WEIGHTS: Dict[str, int] = None

    def __post_init__(self):
        
        if self.WEIGHTS is None:
            object.__setattr__(self, 'WEIGHTS', {
                'spf_fail': 2,
                'dkim_fail': 2,
                'dmarc_fail': 3,
                'domain_mismatch': 3,
                'base64_body': 1,
                'has_urls': 1,
                'url_shortener': 2,
                'yara_match': 3,
                'suspicious_attachment': 2,
                'executable_attachment': 4,
            })


CONFIG = Config()

SHORTENERS: Set[str] = {
    'bit.ly', 't.co', 'tinyurl.com', 'goo.gl', 'ow.ly',
    'rebrand.ly', 'short.link', 'is.gd', 'buff.ly',
    'tiny.cc', 't.ly', 'rb.gy', 'shorturl.at', 'zpr.io',
}

SUSPICIOUS_EXTS: Set[str] = {
    '.exe', '.dll', '.scr', '.bat', '.cmd', '.sh',
    '.js', '.jse', '.vbs', '.vbe', '.wsf', '.hta',
    '.ps1', '.psm1', '.jar', '.msi', '.msp',
    '.docm', '.xlsm', '.pptm', '.dotm', '.xltm',
}


AUTH_NORMALIZER = {
    'pass': 'PASS',
    'pass+': 'PASS',
    'fail': 'FAIL',
    'softfail': 'FAIL',
    'neutral': 'NEUTRAL',
    'none': 'NONE',
    'unknown': 'UNKNOWN',
    'error': 'ERROR',
    'temperror': 'ERROR',
    'permerror': 'ERROR',
}


def normalize_auth(result: str) -> str:
    if not result:
        return "UNKNOWN"
    return AUTH_NORMALIZER.get(result.lower().strip(), result.upper())



class EmailExtractor:

    @staticmethod
    def get_text_body(msg: EmailMessage) -> str:
       
        plain_parts: List[str] = []
        html_parts: List[str] = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                if content_type == "text/plain":
                    plain_parts.append(payload.decode(errors="ignore"))
                elif content_type == "text/html":
                    html = payload.decode(errors="ignore")
                    html_parts.append(re.sub(r'<[^>]+>', ' ', html))
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                plain_parts.append(payload.decode(errors="ignore"))

        parts = plain_parts if plain_parts else html_parts
        return "\n".join(parts) if parts else ""

    @staticmethod
    def extract_urls(text: str) -> List[str]:
        pattern = r'https?://[^\s"<>()\[\]{}]+'
        urls = re.findall(pattern, text, re.IGNORECASE)
        
        return [re.sub(r'[.,:;!?\']+$', '', url) for url in urls]

    @staticmethod
    def defang_url(url: str) -> str:
        
        try:
            parsed = urlparse(url)
            scheme = parsed.scheme.replace("http", "hxxp")
            netloc = parsed.netloc.replace(".", "[.]")
            result = f"{scheme}://{netloc}"
            if parsed.path:
                result += parsed.path
            if parsed.params:
                result += ";" + parsed.params
            if parsed.query:
                result += "?" + parsed.query
            if parsed.fragment:
                result += "#" + parsed.fragment
            return result
        except Exception:
            
            return url.replace("http", "hxxp").replace(".", "[.]")

    @staticmethod
    def parse_address(header: str) -> Tuple[str, str]:
        """Parse email header into (email_address, domain)."""
        if not header:
            return ("", "")
        display, email = parseaddr(header)
       
        if "@" in display and not email:
            email = display
        if "@" not in email:
            return (email or "", "")
        domain = email.split("@")[-1].lower().strip()
        return (email.lower().strip(), domain)

    @staticmethod
    def extract_origin_ip(msg: EmailMessage) -> str:
        """
        Extract originating sender IP from Received headers.
        Tries multiple patterns to match different MTA formats.
        """
        received_headers = msg.get_all("Received", [])

        
        patterns = [
            r'from\s+[^\n]*?\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\s+by',
            r'from\s+\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]',
            r'\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)',
            r'client\s+IP=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        ]

        
        for header in reversed(received_headers):
            header_str = str(header)
            for pattern in patterns:
                match = re.search(pattern, header_str, re.IGNORECASE)
                if match:
                    ip = match.group(1)
                    octets = ip.split('.')
                    if all(o.isdigit() and 0 <= int(o) <= 255 for o in octets):
                        if not EmailExtractor._is_private_ip(ip):
                            return ip
        return ""

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        
        """Check if IP is private/reserved."""
        parts = [int(p) for p in ip.split('.')]
        
        if parts[0] == 0:
            return True
        
        if parts[0] == 10:
            return True
        
        if parts[0] == 100 and 64 <= parts[1] <= 127:
            return True
        
        if parts[0] == 127:
            return True
        
        if parts[0] == 169 and parts[1] == 254:
            return True
       
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        
        if parts[0] == 192 and parts[1] == 168:
            return True
        
        if parts[0] >= 224:
            return True
        return False

    @staticmethod
    def check_base64_encoding(msg: EmailMessage) -> bool:
        cte = str(msg.get("Content-Transfer-Encoding", "")).lower()
        if "base64" in cte:
            return True

        if msg.is_multipart():
            for part in msg.walk():
                part_cte = str(part.get("Content-Transfer-Encoding", "")).lower()
                if "base64" in part_cte:
                    return True
        return False


@dataclass
class AttachmentInfo:
    filename: str
    content_type: str
    size: int
    sha256: str
    is_executable: bool
    is_suspicious: bool
    yara_matches: List[str]


class AttachmentAnalyzer:
    def __init__(self, yara_rules: yara.Rules):
        self.yara_rules = yara_rules

    def analyze(self, msg: EmailMessage) -> List[AttachmentInfo]:
        attachments = []

        for part in msg.walk():
            filename = part.get_filename()
            if not filename:
                continue

            payload = part.get_payload(decode=True)
            if not payload:
                continue

            sha256 = hashlib.sha256(payload).hexdigest()

            try:
                matches = self.yara_rules.match(data=payload)
                yara_hits = [m.rule for m in matches] if matches else []
            except Exception:
                yara_hits = []

            ext = Path(filename).suffix.lower()
            is_executable = ext in SUSPICIOUS_EXTS
            is_suspicious = is_executable or bool(yara_hits)

            attachments.append(AttachmentInfo(
                filename=filename,
                content_type=part.get_content_type() or "application/octet-stream",
                size=len(payload),
                sha256=sha256,
                is_executable=is_executable,
                is_suspicious=is_suspicious,
                yara_matches=yara_hits,
            ))

        return attachments



@dataclass
class AuthResults:
    spf: str
    dkim: str
    dmarc: str
    spf_normalized: str
    dkim_normalized: str
    dmarc_normalized: str

    @classmethod
    def parse(cls, msg: EmailMessage) -> "AuthResults":
        auth_header = str(msg.get("Authentication-Results", ""))

        spf = cls._extract(auth_header, r'spf=(\w+)') or "unknown"
        dkim = cls._extract(auth_header, r'dkim=(\w+)') or "unknown"
        dmarc = cls._extract(auth_header, r'dmarc=(\w+)') or "unknown"

        return cls(
            spf=spf,
            dkim=dkim,
            dmarc=dmarc,
            spf_normalized=normalize_auth(spf),
            dkim_normalized=normalize_auth(dkim),
            dmarc_normalized=normalize_auth(dmarc),
        )

    @staticmethod
    def _extract(header: str, pattern: str) -> Optional[str]:
        match = re.search(pattern, header, re.IGNORECASE)
        return match.group(1).lower() if match else None


@dataclass
class RiskAssessment:
    score: int
    verdict: str
    reasons: List[str]
    mitre_techniques: List[str]

    CLEAN_THRESHOLD = 2
    SUSPICIOUS_THRESHOLD = 5

    @classmethod
    def calculate(
        cls,
        auth: AuthResults,
        domain_mismatch: bool,
        base64: bool,
        urls: List[str],
        shortener_used: bool,
        yara_body_hits: List[str],
        attachments: List[AttachmentInfo],
        config: Config = CONFIG,
    ) -> "RiskAssessment":
        score = 0
        reasons = []
        mitre = []

        if auth.spf in ("fail", "softfail"):
            score += config.WEIGHTS['spf_fail']
            reasons.append(f"SPF {auth.spf_normalized}")
            mitre.append("T1566.002")

        if auth.dkim in ("fail", "none"):
            score += config.WEIGHTS['dkim_fail']
            reasons.append(f"DKIM {auth.dkim_normalized}")
            mitre.append("T1566.002")

        if auth.dmarc == "fail":
            score += config.WEIGHTS['dmarc_fail']
            reasons.append(f"DMARC {auth.dmarc_normalized}")
            mitre.append("T1566.002")

        if domain_mismatch:
            score += config.WEIGHTS['domain_mismatch']
            reasons.append("Reply-To domain mismatch")
            mitre.append("T1566.002")

        if base64:
            score += config.WEIGHTS['base64_body']
            reasons.append("Base64 encoded content")
            mitre.append("T1027.001")

        if urls:
            score += config.WEIGHTS['has_urls']
            reasons.append(f"Contains {len(urls)} URL(s)")

        if shortener_used:
            score += config.WEIGHTS['url_shortener']
            reasons.append("URL shortener detected")
            mitre.append("T1566.002")

        if yara_body_hits:
            score += config.WEIGHTS['yara_match']
            reasons.append(f"YARA match: {', '.join(yara_body_hits[:3])}")

        for att in attachments:
            if att.is_executable:
                score += config.WEIGHTS['executable_attachment']
                reasons.append(f"Executable attachment: {att.filename}")
                mitre.append("T1566.001")
            elif att.is_suspicious:
                score += config.WEIGHTS['suspicious_attachment']
                reasons.append(f"Suspicious attachment: {att.filename}")
                mitre.append("T1566.001")

            if att.yara_matches:
                score += config.WEIGHTS['yara_match']
                reasons.append(f"Attachment YARA: {', '.join(att.yara_matches[:2])}")

        if score >= cls.SUSPICIOUS_THRESHOLD:
            verdict = "Likely Phishing"
        elif score >= cls.CLEAN_THRESHOLD:
            verdict = "Suspicious"
        else:
            verdict = "Clean"

        mitre = list(dict.fromkeys(mitre))

        return cls(
            score=score,
            verdict=verdict,
            reasons=reasons,
            mitre_techniques=mitre,
        )


class SheetManager:
    COLUMN_ORDER = [
        "Case_ID", "File_Name", "Subject", "Sender", "Sender_Domain",
        "Reply_To", "Reply_Domain", "Domain_Mismatch", "Sender_IP",
        "URL_Count", "URLs", "Defanged_URLs", "URL_Shortener_Used",
        "Has_Attachment", "Attachment_Count", "Attachment_Names",
        "Executable_Attachment", "Attachment_SHA256s",
        "Base64_Detected", "SPF_Result", "DKIM_Result", "DMARC_Result",
        "SPF_Normalized", "DKIM_Normalized", "DMARC_Normalized",
        "YARA_Body_Matches", "YARA_Attachment_Matches",
        "Risk_Score", "Risk_Reasons", "MITRE_Techniques", "Verdict",
    ]

    
    def __init__(self, credentials_path: str):
        self.credentials_path = credentials_path
        self.sheet = None
        self._connect()

    def _connect(self):
        try:
            creds = Credentials.from_service_account_file(
                self.credentials_path,
                scopes=CONFIG.SCOPES,
            )
            client = gspread.authorize(creds)
            spreadsheet = client.open(CONFIG.SHEET_NAME)
            self.sheet = spreadsheet.sheet1
            self._ensure_headers()

        except Exception as e:
            print(f"[!] Failed to connect to Google Sheets: {e}")
            sys.exit(1)

    def _ensure_headers(self):
        try:
            try:
                current = self.sheet.row_values(1)
            except Exception:
                current = []

            if not current or current != self.COLUMN_ORDER:
                print("[*] Writing/correcting headers")
                if current:
                    self.sheet.delete_rows(1)
                self.sheet.insert_row(self.COLUMN_ORDER, 1)

        except Exception as e:
            print(f"[!] Header check failed: {e}")
            raise

    def clear_data(self):
        try:
            values = self.sheet.get_all_values()
            if len(values) > 1:
                self.sheet.delete_rows(2, len(values))
                print(f"[+] Cleared {len(values) - 1} existing rows")
        except Exception as e:
            print(f"[!] Failed to clear sheet: {e}")

    def append_result(self, result: Dict) -> bool:
        try:
            row = []
            for col in self.COLUMN_ORDER:
                val = result.get(col, "")
                if isinstance(val, bool):
                    val = str(val)
                elif isinstance(val, list):
                    val = ",".join(str(v) for v in val)
                else:
                    val = str(val) if val is not None else ""
                row.append(val)

            self.sheet.append_row(row, value_input_option="RAW")
            return True

        except Exception as e:
            print(f"[!] Failed to append row: {e}")
            return False



class PhishingAnalyzer:
    
    def __init__(
        self,
        credentials_path: str = CONFIG.CREDENTIALS_FILE,
        verbose: bool = False,
    ):
        self.verbose = verbose
        self.yara_rules = self._load_yara_rules()
        self.sheet = SheetManager(credentials_path)
        self.extractor = EmailExtractor()
        self.attachment_analyzer = AttachmentAnalyzer(self.yara_rules)

    def _load_yara_rules(self) -> yara.Rules:
        
        script_dir = Path(__file__).parent.absolute()
        rules_path = script_dir / CONFIG.YARA_RULES_DIR / CONFIG.YARA_INDEX

        try:
            rules = yara.compile(filepath=str(rules_path))
            print(f"[+] Loaded YARA rules from {rules_path}")
            return rules
        except Exception as e:
            print(f"[!] Failed to compile YARA rules: {e}")
            print("[*] Continuing with empty rules")
            return yara.compile(source='rule dummy { condition: false }')

    def _debug(self, message: str):
        
        if self.verbose:
            print(message)

    def analyze_file(self, filepath: Path, case_id: str) -> Optional[Dict]:
        print(f"[*] Analyzing: {filepath.name} ({case_id})")

        try:
            with open(filepath, "rb") as f:
                msg = BytesParser(policy=policy.default).parse(f)
        except Exception as e:
            print(f"[!] Failed to parse {filepath}: {e}")
            return None

        
        from_header_raw = msg.get("from")
        reply_header_raw = msg.get("reply-to")
        received_headers = msg.get_all("Received", [])

        
        self._debug(f"    DEBUG From raw: {repr(from_header_raw)}")
        self._debug(f"    DEBUG Reply-To raw: {repr(reply_header_raw)}")
        if received_headers:
            self._debug(f"    DEBUG Received headers: {len(received_headers)}")
            oldest = str(received_headers[-1])[:200] if received_headers else "None"
            self._debug(f"    DEBUG Oldest Received: {oldest}...")

        
        from_header = from_header_raw or ""
        reply_header = reply_header_raw or ""

        sender_email, sender_domain = self.extractor.parse_address(from_header)
        reply_email, reply_domain = self.extractor.parse_address(reply_header)

        
        if not sender_email:
            return_path = msg.get("Return-Path", "")
            sender_email, sender_domain = self.extractor.parse_address(return_path)
            self._debug(f"    DEBUG Fallback to Return-Path: {sender_email}")

        
        if not sender_email:
            sender_header = msg.get("Sender", "")
            sender_email, sender_domain = self.extractor.parse_address(sender_header)
            self._debug(f"    DEBUG Fallback to Sender: {sender_email}")

        domain_mismatch = bool(
            reply_domain and sender_domain and sender_domain != reply_domain
        )

        
        body = self.extractor.get_text_body(msg)
        urls = self.extractor.extract_urls(body)
        defanged = [self.extractor.defang_url(u) for u in urls]

    
        shortener_used = False
        for url in urls:
            try:
                netloc = urlparse(url).netloc.lower().replace("www.", "")
                if netloc in SHORTENERS:
                    shortener_used = True
                    break
            except Exception:
                continue

     
        yara_body_hits = []
        try:
            body_bytes = body.encode(errors="ignore")
            if body_bytes:
                matches = self.yara_rules.match(data=body_bytes)
                yara_body_hits = [m.rule for m in matches] if matches else []
        except Exception as e:
            self._debug(f"    DEBUG YARA body scan error: {e}")

    
        auth = AuthResults.parse(msg)

        
        sender_ip = self.extractor.extract_origin_ip(msg)
        self._debug(f"    DEBUG Extracted IP: {sender_ip or '(none)'}")

    
        base64_detected = self.extractor.check_base64_encoding(msg)

     
        attachments = self.attachment_analyzer.analyze(msg)

        
        risk = RiskAssessment.calculate(
            auth=auth,
            domain_mismatch=domain_mismatch,
            base64=base64_detected,
            urls=urls,
            shortener_used=shortener_used,
            yara_body_hits=yara_body_hits,
            attachments=attachments,
        )

      
        result = {
            "Case_ID": case_id,
            "File_Name": filepath.name,
            "Subject": (msg.get("subject") or "")[:500],
            "Sender": sender_email,
            "Sender_Domain": sender_domain,
            "Reply_To": reply_email,
            "Reply_Domain": reply_domain,
            "Domain_Mismatch": domain_mismatch,
            "Sender_IP": sender_ip,
            "URL_Count": len(urls),
            "URLs": ",".join(urls[:20]),
            "Defanged_URLs": ",".join(defanged[:20]),
            "URL_Shortener_Used": shortener_used,
            "Has_Attachment": len(attachments) > 0,
            "Attachment_Count": len(attachments),
            "Attachment_Names": "; ".join(a.filename for a in attachments),
            "Executable_Attachment": any(a.is_executable for a in attachments),
            "Attachment_SHA256s": "; ".join(a.sha256 for a in attachments),
            "Base64_Detected": base64_detected,
            "SPF_Result": auth.spf,
            "DKIM_Result": auth.dkim,
            "DMARC_Result": auth.dmarc,
            "SPF_Normalized": auth.spf_normalized,
            "DKIM_Normalized": auth.dkim_normalized,
            "DMARC_Normalized": auth.dmarc_normalized,
            "YARA_Body_Matches": ",".join(yara_body_hits),
            "YARA_Attachment_Matches": "; ".join(
                f"{a.filename}:{','.join(a.yara_matches)}"
                for a in attachments if a.yara_matches
            ),
            "Risk_Score": risk.score,
            "Risk_Reasons": "; ".join(risk.reasons),
            "MITRE_Techniques": ",".join(risk.mitre_techniques),
            "Verdict": risk.verdict,
        }

        print(
            f"    Score: {risk.score} | Verdict: {risk.verdict} "
            f"| YARA: {len(yara_body_hits)} hits"
        )
        return result

    def run(self, samples_dir: str = CONFIG.SAMPLES_DIR, clear_sheet: bool = True):
        samples_path = Path(samples_dir)

        if not samples_path.exists():
            print(f"[!] Samples directory not found: {samples_dir}")
            return

        eml_files = sorted(samples_path.glob("*.eml"))
        if not eml_files:
            print(f"[!] No .eml files found in {samples_dir}")
            return

        print(f"[+] Found {len(eml_files)} email(s) to analyze")

        if clear_sheet:
            self.sheet.clear_data()

        success = 0
        for idx, filepath in enumerate(eml_files, 1):
            case_id = f"PH-{idx:03d}"
            result = self.analyze_file(filepath, case_id)

            if result and self.sheet.append_result(result):
                success += 1

        print(
            f"\n[+] Complete: {success}/{len(eml_files)} emails "
            f"processed successfully"
        )

def main():
    parser = argparse.ArgumentParser(description="Phishing Email Analyzer")
    parser.add_argument(
        "--samples", "-s",
        default=CONFIG.SAMPLES_DIR,
        help=f"Directory containing .eml files (default: {CONFIG.SAMPLES_DIR})",
    )
    parser.add_argument(
        "--no-clear", "-n",
        action="store_true",
        help="Don't clear existing sheet data",
    )
    parser.add_argument(
        "--credentials", "-c",
        default=CONFIG.CREDENTIALS_FILE,
        help="Path to Google service account credentials",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose debug output",
    )

    args = parser.parse_args()


    analyzer = PhishingAnalyzer(
        credentials_path=args.credentials,
        verbose=args.verbose,
    )
    analyzer.run(args.samples, clear_sheet=not args.no_clear)


if __name__ == "__main__":
    main()
