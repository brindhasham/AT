#!/usr/bin/env python3
import os
import re
import time
import json
import html
import uuid
import queue
import threading
import base64
import logging
import ipaddress
import platform
import hashlib
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple, Any, TypedDict
from functools import lru_cache

import requests
import streamlit as st

try:
    from streamlit.runtime.scriptrunner import add_script_run_ctx
except ImportError:
    def add_script_run_ctx(thread):
        pass

from dateutil import parser as date_parser

class Config:
    MAX_FILE_SIZE = 10 * 1024 * 1024 * 1024
    CORRELATION_WINDOW_MINUTES = 10
    BRUTE_FORCE_THRESHOLD = 5
    BRUTE_FORCE_CRITICAL = 20
    BRUTE_FORCE_HIGH = 10
    MAX_IOC_LENGTH = 2048
    MAX_QUEUE_SIZE = 1000
    MAX_TIMELINE_EVENTS = 1000
    MAX_STORED_ALERTS = 10000
    MAX_UNIQUE_IPS = 10000
    CACHE_TTL = 300
    RATE_LIMITS = {
        "virustotal": 4,
        "abuseipdb": 5,
        "otx": 60,
        "urlhaus": 10
    }
    ALLOWED_LOG_DIRS = [
        os.path.expanduser("~/logs"),
        "/var/log/app",
        "/opt/logsentinel",
    ]

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("LogSentinel")

class ThreatIntelSource(TypedDict, total=False):
    source: str
    success: bool
    score: int
    error: Optional[str]
    country: Optional[str]
    isp: Optional[str]
    total_reports: Optional[int]
    malicious: Optional[int]
    suspicious: Optional[int]
    total_engines: Optional[int]
    pulse_count: Optional[int]
    status: Optional[str]
    threat: Optional[str]

class EnrichmentResult(TypedDict):
    ioc: str
    type: str
    timestamp: str
    sources: Dict[str, ThreatIntelSource]
    overall_score: int
    max_severity: str

class SecurityAlert(TypedDict):
    id: str
    timestamp: datetime
    type: str
    severity: str
    source_ip: Optional[str]
    username: Optional[str]
    details: str
    mitre: str
    raw: str
    iocs: Dict[str, Any]

class RateLimiter:
    def __init__(self):
        self.next_available: Dict[str, float] = {}
        self.min_intervals = {k: 60.0 / v for k, v in Config.RATE_LIMITS.items()}
        self._lock = threading.Lock()

    def wait_if_needed(self, source: str):
        with self._lock:
            now = time.time()
            next_time = self.next_available.get(source, 0.0)
            sleep_time = max(0.0, next_time - now)
            interval = self.min_intervals.get(source, 1.0)
            self.next_available[source] = now + sleep_time + interval

        if sleep_time > 0:
            time.sleep(sleep_time)

rate_limiter = RateLimiter()

@lru_cache(maxsize=1024)
def detect_ioc_type(ioc: str) -> Tuple[str, str]:
    if len(ioc) > Config.MAX_IOC_LENGTH:
        return 'unknown', ioc[:Config.MAX_IOC_LENGTH]

    ioc = ioc.strip()
    ioc_lower = ioc.lower()

    try:
        ip_obj = ipaddress.ip_address(ioc_lower)
        if isinstance(ip_obj, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            return 'ip', ioc_lower
    except ValueError:
        pass

    if ioc_lower.startswith(('http://', 'https://')):
        return 'url', ioc.rstrip('/')

    if re.match(r"^[a-f0-9]{32}$", ioc_lower):
        return 'md5', ioc_lower
    if re.match(r"^[a-f0-9]{40}$", ioc_lower):
        return 'sha1', ioc_lower
    if re.match(r"^[a-f0-9]{64}$", ioc_lower):
        return 'sha256', ioc_lower

    if '.' in ioc and ' ' not in ioc and '/' not in ioc:
        if re.match(
            r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?"
            r"(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$",
            ioc_lower
        ):
            parts = ioc_lower.split('.')
            if len(parts[-1]) >= 2:
                return 'domain', ioc_lower

    return 'unknown', ioc

class ThreatIntelClient:
    def __init__(self):
        self.cache: Dict[str, Tuple[Dict, float]] = {}
        self._cache_lock = threading.Lock()
        self._stats_lock = threading.Lock()
        self.api_stats = {
            'requests': Counter(),
            'errors': Counter(),
            'cache_hits': 0
        }

    def _cache_key(self, source: str, ioc: str, ioc_type: str) -> str:
        return f"{source}:{ioc_type}:{ioc}"

    def _get_cache(self, key: str) -> Optional[Dict]:
        with self._cache_lock:
            if key in self.cache:
                result, ts = self.cache[key]
                if time.time() - ts < Config.CACHE_TTL:
                    with self._stats_lock:
                        self.api_stats['cache_hits'] += 1
                    return result
                del self.cache[key]
        return None

    def _set_cache(self, key: str, result: Dict):
        with self._cache_lock:
            self.cache[key] = (result, time.time())

    def query_abuseipdb(self, ip: str) -> ThreatIntelSource:
        if not CONFIG['abuseipdb_key']:
            return {"source": "abuseipdb", "success": False, "error": "No API key"}

        key = self._cache_key("abuse", ip, "ip")
        cached = self._get_cache(key)
        if cached:
            return cached

        rate_limiter.wait_if_needed("abuseipdb")
        with self._stats_lock:
            self.api_stats['requests']['abuseipdb'] += 1

        try:
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": CONFIG['abuseipdb_key']},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=10
            )
            r.raise_for_status()
            data = r.json()

            result: ThreatIntelSource = {
                "source": "abuseipdb",
                "success": True,
                "score": data.get("data", {}).get("abuseConfidenceScore", 0),
                "country": data.get("data", {}).get("countryCode", "Unknown"),
                "isp": data.get("data", {}).get("isp", "Unknown"),
                "total_reports": data.get("data", {}).get("totalReports", 0),
            }
            self._set_cache(key, result)
            return result
        except requests.exceptions.RequestException as e:
            with self._stats_lock:
                self.api_stats['errors']['abuseipdb'] += 1
            return {"source": "abuseipdb", "success": False, "error": f"Network: {str(e)}"}
        except json.JSONDecodeError as e:
            with self._stats_lock:
                self.api_stats['errors']['abuseipdb'] += 1
            return {"source": "abuseipdb", "success": False, "error": f"Invalid JSON: {str(e)}"}

    def query_virustotal(self, ioc: str, ioc_type: str) -> ThreatIntelSource:
        if not CONFIG['vt_api_key']:
            return {"source": "virustotal", "success": False, "error": "No API key"}

        key = self._cache_key("vt", ioc, ioc_type)
        cached = self._get_cache(key)
        if cached:
            return cached

        rate_limiter.wait_if_needed("virustotal")
        with self._stats_lock:
            self.api_stats['requests']['virustotal'] += 1

        endpoints = {
            'ip': f"ip_addresses/{ioc}",
            'domain': f"domains/{ioc}",
            'url': f"urls/{base64.urlsafe_b64encode(ioc.encode()).decode().strip('=')}",
            'md5': f"files/{ioc}",
            'sha1': f"files/{ioc}",
            'sha256': f"files/{ioc}",
        }

        endpoint = endpoints.get(ioc_type)
        if not endpoint:
            return {"source": "virustotal", "success": False, "error": f"Unsupported: {ioc_type}"}

        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/{endpoint}",
                headers={"x-apikey": CONFIG['vt_api_key']},
                timeout=10
            )
            r.raise_for_status()
            data = r.json()

            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) if stats else 0

            score = min((malicious + suspicious) * 10, 100) if total > 0 else 0

            result: ThreatIntelSource = {
                "source": "virustotal",
                "success": True,
                "score": score,
                "malicious": malicious,
                "suspicious": suspicious,
                "total_engines": total,
            }
            self._set_cache(key, result)
            return result
        except requests.exceptions.HTTPError as e:
            with self._stats_lock:
                self.api_stats['errors']['virustotal'] += 1
            status_code = e.response.status_code if getattr(e, "response", None) is not None else "unknown"
            if status_code == 404:
                return {"source": "virustotal", "success": True, "score": 0, "error": "Not found"}
            return {"source": "virustotal", "success": False, "error": f"HTTP {status_code}: {str(e)}"}
        except requests.exceptions.RequestException as e:
            with self._stats_lock:
                self.api_stats['errors']['virustotal'] += 1
            return {"source": "virustotal", "success": False, "error": f"Network: {str(e)}"}
        except (KeyError, ValueError) as e:
            with self._stats_lock:
                self.api_stats['errors']['virustotal'] += 1
            return {"source": "virustotal", "success": False, "error": f"Parse error: {str(e)}"}

    def query_urlhaus(self, url: str) -> ThreatIntelSource:
        key = self._cache_key("haus", url, "url")
        cached = self._get_cache(key)
        if cached:
            return cached

        rate_limiter.wait_if_needed("urlhaus")
        with self._stats_lock:
            self.api_stats['requests']['urlhaus'] += 1

        headers = {}
        if CONFIG['urlhaus_key']:
            headers['Auth-Key'] = CONFIG['urlhaus_key']

        try:
            r = requests.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                headers=headers,
                data={"url": url},
                timeout=10
            )
            r.raise_for_status()
            data = r.json()

            status = data.get("query_status", "unknown")
            if status == "ok":
                result: ThreatIntelSource = {
                    "source": "urlhaus",
                    "success": True,
                    "score": 100,
                    "threat": data.get("threat", "Unknown"),
                    "status": "Malicious",
                }
            elif status == "no_results":
                result = {"source": "urlhaus", "success": True, "score": 0, "status": "Clean"}
            else:
                result = {"source": "urlhaus", "success": False, "error": f"Status: {status}"}

            self._set_cache(key, result)
            return result
        except requests.exceptions.RequestException as e:
            with self._stats_lock:
                self.api_stats['errors']['urlhaus'] += 1
            return {"source": "urlhaus", "success": False, "error": f"Network: {str(e)}"}
        except json.JSONDecodeError as e:
            with self._stats_lock:
                self.api_stats['errors']['urlhaus'] += 1
            return {"source": "urlhaus", "success": False, "error": f"Invalid JSON: {str(e)}"}

    def query_otx(self, ioc: str, ioc_type: str) -> ThreatIntelSource:
        if not CONFIG['otx_key']:
            return {"source": "otx", "success": False, "error": "No API key"}

        key = self._cache_key("otx", ioc, ioc_type)
        cached = self._get_cache(key)
        if cached:
            return cached

        rate_limiter.wait_if_needed("otx")
        with self._stats_lock:
            self.api_stats['requests']['otx'] += 1

        type_map = {
            'ip': f"IPv4/{ioc}",
            'domain': f"domain/{ioc}",
            'md5': f"file/{ioc}",
            'sha1': f"file/{ioc}",
            'sha256': f"file/{ioc}",
        }
        endpoint = type_map.get(ioc_type)
        if not endpoint:
            return {"source": "otx", "success": False, "error": f"Unsupported: {ioc_type}"}

        try:
            r = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/{endpoint}/general",
                headers={"X-OTX-API-KEY": CONFIG['otx_key']},
                timeout=10
            )
            r.raise_for_status()
            data = r.json()

            pulses = data.get("pulse_info", {})
            count = pulses.get("count", 0)

            result: ThreatIntelSource = {
                "source": "otx",
                "success": True,
                "score": min(count * 5, 100),
                "pulse_count": count,
            }
            self._set_cache(key, result)
            return result
        except requests.exceptions.RequestException as e:
            with self._stats_lock:
                self.api_stats['errors']['otx'] += 1
            return {"source": "otx", "success": False, "error": f"Network: {str(e)}"}
        except (KeyError, ValueError) as e:
            with self._stats_lock:
                self.api_stats['errors']['otx'] += 1
            return {"source": "otx", "success": False, "error": f"Parse error: {str(e)}"}

    def enrich(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        result: EnrichmentResult = {
            "ioc": ioc,
            "type": ioc_type,
            "timestamp": datetime.now().isoformat(),
            "sources": {},
            "overall_score": 0,
            "max_severity": "clean",
        }

        scores: List[Any] = []

        if ioc_type == 'ip':
            result["sources"]["abuseipdb"] = self.query_abuseipdb(ioc)
            result["sources"]["virustotal"] = self.query_virustotal(ioc, 'ip')
            result["sources"]["otx"] = self.query_otx(ioc, 'ip')
            scores = [
                result["sources"]["abuseipdb"].get("score", 0),
                result["sources"]["virustotal"].get("score", 0),
                result["sources"]["otx"].get("score", 0),
            ]
        elif ioc_type in ('md5', 'sha1', 'sha256'):
            result["sources"]["virustotal"] = self.query_virustotal(ioc, ioc_type)
            result["sources"]["otx"] = self.query_otx(ioc, ioc_type)
            scores = [
                result["sources"]["virustotal"].get("score", 0),
                result["sources"]["otx"].get("score", 0),
            ]
        elif ioc_type == 'domain':
            result["sources"]["virustotal"] = self.query_virustotal(ioc, 'domain')
            result["sources"]["otx"] = self.query_otx(ioc, 'domain')
            scores = [
                result["sources"]["virustotal"].get("score", 0),
                result["sources"]["otx"].get("score", 0),
            ]
        elif ioc_type == 'url':
            result["sources"]["virustotal"] = self.query_virustotal(ioc, 'url')
            result["sources"]["urlhaus"] = self.query_urlhaus(ioc)
            if result["sources"]["urlhaus"].get("success"):
                scores.append(result["sources"]["urlhaus"].get("score", 0))
            scores.append(result["sources"]["virustotal"].get("score", 0))

        numeric_scores = [s for s in scores if isinstance(s, (int, float))]
        result["overall_score"] = int(max(numeric_scores)) if numeric_scores else 0

        if result["overall_score"] >= 80:
            result["max_severity"] = "critical"
        elif result["overall_score"] >= 50:
            result["max_severity"] = "high"
        elif result["overall_score"] >= 20:
            result["max_severity"] = "medium"
        else:
            result["max_severity"] = "clean"

        return result

class CorrelationEngine:
    def __init__(self):
        self.events: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.time_window = timedelta(minutes=Config.CORRELATION_WINDOW_MINUTES)
        self._lock = threading.Lock()

    def add_event(self, parsed: Dict, alert: Optional[SecurityAlert] = None) -> Optional[SecurityAlert]:
        with self._lock:
            username = parsed.get('username')
            if not username:
                return None

            now = datetime.now()

            event_type = self._classify_event(parsed, alert)
            if not event_type:
                return None

            self.events[username].append({
                'timestamp': now,
                'type': event_type,
                'ip': parsed.get('source_ip'),
                'alert_type': alert.get('type') if alert else None
            })

            while self.events[username] and now - self.events[username][0]['timestamp'] > self.time_window:
                self.events[username].popleft()

            return self._check_pattern_optimized(username, now)

    def _classify_event(self, parsed: Dict, alert: Optional[SecurityAlert]) -> Optional[str]:
        event_type = parsed.get('event_type', '')
        message = str(parsed.get('message', '')).lower()

        if event_type in ['failed_login', 'failed_auth']:
            return 'failed_login'
        if event_type in ['successful_login', 'success']:
            return 'successful_login'
        if 'sudo' in message or event_type in ['privilege_escalation']:
            return 'sudo'
        return None

    def _check_pattern_optimized(self, username: str, now: datetime) -> Optional[SecurityAlert]:
        events = list(self.events.get(username, []))
        if len(events) < 3:
            return None

        sudo_indices = [i for i, e in enumerate(events) if e['type'] == 'sudo']
        for sudo_idx in reversed(sudo_indices):
            sudo_time = events[sudo_idx]['timestamp']
            sudo_ip = events[sudo_idx]['ip']

            for j in range(sudo_idx - 1, -1, -1):
                if events[j]['type'] == 'successful_login':
                    success_ip = events[j]['ip']

                    failed_count = 0
                    first_fail_time = None

                    for k in range(j - 1, -1, -1):
                        if events[k]['type'] == 'failed_login':
                            failed_count += 1
                            if first_fail_time is None:
                                first_fail_time = events[k]['timestamp']
                        else:
                            break

                    if failed_count >= Config.BRUTE_FORCE_THRESHOLD:
                        if first_fail_time and (sudo_time - first_fail_time) <= self.time_window:
                            if sudo_ip == success_ip:
                                return {
                                    'id': str(uuid.uuid4()),
                                    'timestamp': now,
                                    'type': 'Suspicious Account Compromise Chain Detected',
                                    'severity': 'CRITICAL',
                                    'source_ip': success_ip,
                                    'username': username,
                                    'details': f'Pattern detected: {failed_count} failed logins → successful login → sudo from IP {success_ip}',
                                    'mitre': 'T1078',
                                    'raw': f'Correlation alert for user {username}'
                                }
        return None

def _is_path_allowed(resolved_path: str) -> bool:
    for allowed in Config.ALLOWED_LOG_DIRS:
        allowed_resolved = os.path.realpath(os.path.expanduser(allowed))
        if resolved_path == allowed_resolved or resolved_path.startswith(allowed_resolved + os.sep):
            return True
    return False

def _secure_open_file(filepath: str):
    try:
        is_linux = platform.system() == 'Linux'
        has_procfs = os.path.exists('/proc/self/fd')

        if not is_linux or not has_procfs:
            real_path = os.path.realpath(os.path.expanduser(filepath))

            blocked_prefixes = (
                '/etc', '/proc', '/sys', '/dev', '/root',
                '/boot', '/sbin', '/bin', '/usr/sbin',
            )
            for prefix in blocked_prefixes:
                if real_path == prefix or real_path.startswith(prefix + os.sep):
                    return None, f"Access denied to system path: {real_path}"

            if not _is_path_allowed(real_path):
                return None, f"Path '{real_path}' is outside allowed directories"

            if os.path.isdir(real_path):
                return None, f"Is a directory: {real_path}"
            if not os.path.exists(real_path):
                return None, f"File not found: {real_path}"
            if not os.path.isfile(real_path):
                return None, f"Not a regular file: {real_path}"

            try:
                size = os.path.getsize(real_path)
                if size > Config.MAX_FILE_SIZE:
                    return None, "File too large (>10 GB)"
            except OSError as e:
                return None, f"Cannot stat file: {str(e)}"

            return open(real_path, 'r', encoding='utf-8', errors='ignore'), None

        fd = os.open(filepath, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            real_path = os.path.realpath(f"/proc/self/fd/{fd}")
        except (OSError, ValueError):
            os.close(fd)
            return None, "Cannot resolve file descriptor"

        blocked_prefixes = (
            '/etc', '/proc', '/sys', '/dev', '/root',
            '/boot', '/sbin', '/bin', '/usr/sbin',
        )
        for prefix in blocked_prefixes:
            if real_path == prefix or real_path.startswith(prefix + os.sep):
                os.close(fd)
                return None, f"Access denied to system path: {real_path}"

        if not _is_path_allowed(real_path):
            os.close(fd)
            return None, f"Path outside allowed directories: {real_path}"

        return os.fdopen(fd, 'r', encoding='utf-8', errors='ignore'), None

    except OSError as e:
        return None, f"Cannot open file: {str(e)}"

def _resolve_and_validate_path(filepath: str) -> Tuple[bool, str, str]:
    filepath = os.path.expanduser(filepath)

    blocked_prefixes = (
        '/etc', '/proc', '/sys', '/dev', '/root',
        '/boot', '/sbin', '/bin', '/usr/sbin',
    )

    resolved = os.path.realpath(filepath)
    for prefix in blocked_prefixes:
        if resolved == prefix or resolved.startswith(prefix + os.sep):
            return False, resolved, f"Access denied to system path: {resolved}"

    if not _is_path_allowed(resolved):
        return (
            False, resolved,
            f"Path '{resolved}' is outside the allowed directories: "
            f"{', '.join(Config.ALLOWED_LOG_DIRS)}"
        )

    if os.path.isdir(resolved):
        return False, resolved, f"Is a directory: {resolved}"
    if not os.path.exists(resolved):
        return False, resolved, f"File not found: {resolved}"
    if not os.path.isfile(resolved):
        return False, resolved, f"Not a regular file: {resolved}"

    try:
        size = os.path.getsize(resolved)
        if size > Config.MAX_FILE_SIZE:
            return False, resolved, "File too large (>10 GB)"
    except OSError as e:
        return False, resolved, f"Cannot stat file: {str(e)}"

    return True, resolved, ""

class UniversalLogParser:
    def __init__(self):
        self.patterns = self._compile_patterns()
        self.windows: Dict[str, list] = defaultdict(list)
        self.user_failures: Dict[str, list] = defaultdict(list)
        self.format_stats: Dict[str, int] = defaultdict(int)
        self._last_cleanup = datetime.now()
        self.correlation_engine = CorrelationEngine()

        self.known_events = {
            "login_failed",
            "login_success",
            "privilege_escalation",
            "service_created",
            "file_download",
            "execution",
            "outbound_connection",
            "file_access",
            "query",
            "high_cpu",
            "lateral_movement",
            "encoded_command",
            "ransomware_detected",
        }

        self.known_event_types = {
            "failed_login",
            "failed_auth",
            "successful_login",
            "success",
            "error",
            "threat",
            "system_event",
            "web_access",
            "security_alert",
            "structured",
            "privilege_escalation",
            "unknown",
        }

    def reset(self) -> None:
        self.windows.clear()
        self.user_failures.clear()
        self.format_stats.clear()
        self._last_cleanup = datetime.now()
        self.correlation_engine = CorrelationEngine()

    def _compile_patterns(self) -> List[Dict]:
        return [
            {
                'name': 'syslog_rfc3164',
                'regex': re.compile(
                    r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
                    r'(?P<host>\S+)\s+'
                    r'(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s*'
                    r'(?P<message>.*)$'
                ),
                'type': 'syslog'
            },
            {
                'name': 'syslog_rfc5424',
                'regex': re.compile(
                    r'^<(?P<priority>\d+)>\d*\s*'
                    r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'
                    r'(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+'
                    r'(?P<host>\S+)\s+'
                    r'(?P<process>\S+)\s+'
                    r'(?P<procid>\S+)\s+'
                    r'(?P<msgid>\S+)\s+'
                    r'(?:-\s+(?P<message>.*)|.*)$'
                ),
                'type': 'syslog'
            },
            {
                'name': 'apache_combined',
                'regex': re.compile(
                    r'^(?P<source_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+'
                    r'\S+\s+'
                    r'(?P<auth_user>\S+)\s+'
                    r'\[(?P<timestamp>[^\]]+)\]\s+'
                    r'"(?P<method>\S+)\s+(?P<path>[^"]*)\s+HTTP[/\s][\d.]+"\s+'
                    r'(?P<status>\d+)\s+'
                    r'(?P<bytes>\d+)\s+'
                    r'"(?P<referer>[^"]*)"\s+'
                    r'"(?P<user_agent>[^"]*)"'
                ),
                'type': 'web'
            },
            {
                'name': 'iis_w3c',
                'regex': re.compile(
                    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
                    r'(?P<source_ip>\S+)\s+'
                    r'(?P<method>\S+)\s+'
                    r'(?P<path>\S+)\s+'
                    r'(?P<query>\S+)\s+'
                    r'(?P<port>\d+)\s+'
                    r'(?P<username>\S+)\s+'
                    r'(?P<client_ip>\S+)\s+'
                    r'(?P<user_agent>.*?)\s+'
                    r'(?P<referer>.*?)\s+'
                    r'(?P<status>\d+)\s+'
                    r'(?P<substatus>\d+)\s+'
                    r'(?P<win32_status>\d+).*?$'
                ),
                'type': 'web'
            },
            {
                'name': 'windows_event',
                'regex': re.compile(
                    r'^(?P<timestamp>\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}'
                    r'\s+[AP]M)\s+'
                    r'(?P<level>\w+)\s+'
                    r'(?P<source>\S+)\s+'
                    r'(?P<event_id>\d+)\s+'
                    r'(?P<category>\S+)\s+'
                    r'(?P<username>\S+)\s+'
                    r'(?P<message>.*)$'
                ),
                'type': 'windows'
            },
            {
                'name': 'cisco_asa',
                'regex': re.compile(
                    r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2})\s+'
                    r'(?P<host>[\w\-]+)\s+:\s+%(?P<facility>\w+)-'
                    r'(?P<severity>\d+)-(?P<msg_id>\d+):\s*'
                    r'(?P<message>.*)$'
                ),
                'type': 'firewall'
            },
        ]

    def _extract_ips(self, line: str) -> List[str]:
        ips = []
        ipv4_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        ips.extend(ipv4_pattern.findall(line))

        tokens = re.split(r'[,\s\[\]()<>]+', line)
        for token in tokens:
            token = token.strip()
            if not token:
                continue
            try:
                addr = ipaddress.ip_address(token)
                if isinstance(addr, ipaddress.IPv6Address):
                    ips.append(str(addr))
            except ValueError:
                continue

        return ips

    def _extract_timestamp_heuristic(self, line: str) -> Optional[datetime]:
        patterns = [
            r'\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}'
            r'(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b',
            r'\b(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})\b',
            r'\b(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})\b',
            r'\b(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b',
            r'\b(\d{2}-\d{2}-\d{4}\s+\d{2}:\d{2}:\d{2})\b',
        ]
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                try:
                    return date_parser.parse(match.group(1), dayfirst=True)
                except Exception:
                    continue
        return None

    def _extract_user_heuristic(self, line: str) -> Optional[str]:
        patterns = [
            r'user[:\s=]+([a-zA-Z0-9_\-\.]+)',
            r'username[:\s=]+([a-zA-Z0-9_\-\.]+)',
            r'for\s+([a-zA-Z0-9_\-\.]+)',
            r'uid[:\s=]+(\d+|[a-zA-Z0-9_\-\.]+)',
        ]
        for pattern in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def _is_json_line(self, line: str) -> bool:
        line = line.strip()
        return line.startswith('{') and line.endswith('}') and ':' in line

    def _normalize_json(self, data: Dict, raw_line: str) -> Dict:
        field_mappings = {
            'timestamp': ['timestamp', 'time', 'ts', 'date', '@timestamp', 'created', 'eventTime'],
            'source_ip': ['src_ip', 'source_ip', 'client_ip', 'remote_addr', 'ip', 'sourceAddress'],
            'username': ['user', 'username', 'user_name', 'userId', 'actor', 'principal'],
            'message': ['message', 'msg', 'log', 'event', 'description', 'reason'],
            'status': ['status', 'status_code', 'response_code', 'severity', 'level', 'priority'],
        }

        result: Dict[str, Any] = {
            'timestamp': datetime.now(),
            'source_ip': None,
            'username': None,
            'message': '',
            'status_code': None,
            'event_type': 'structured',
            'format': 'json',
            'raw': raw_line,
            'original': data
        }

        lower_data = {k.lower(): v for k, v in data.items()}

        for std_field, possible_names in field_mappings.items():
            for name in possible_names:
                value = lower_data.get(name.lower())
                if value is None:
                    continue
                if std_field == 'timestamp' and isinstance(value, str):
                    try:
                        result['timestamp'] = date_parser.parse(value, dayfirst=True)
                    except Exception:
                        result['timestamp'] = value
                elif std_field == 'status':
                    result['status_code'] = value
                else:
                    result[std_field] = value
                break

        msg_str = str(result.get('message', '')).lower()
        status = result.get('status_code')
        if status in [401, 403, 500] or 'fail' in msg_str:
            result['event_type'] = 'failed_auth'
        elif status == 200 or 'success' in msg_str:
            result['event_type'] = 'success'

        return result

    def _parse_keyvalue_pairs(self, line: str) -> Optional[Dict]:
        if '=' not in line:
            return None

        pattern = re.compile(r'([a-zA-Z0-9_]+)=(".*?"|[^\s]+)')
        matches = pattern.findall(line)
        if not matches:
            return None

        pairs: Dict[str, str] = {}
        for k, v in matches:
            if v.startswith('"') and v.endswith('"'):
                v = v[1:-1]
            pairs[k] = v

        if not any(k in pairs for k in ("time", "timestamp", "event", "sourcetype", "source")):
            return None

        timestamp_str = pairs.get('time') or pairs.get('timestamp') or ""
        ts = datetime.now()
        if timestamp_str:
            try:
                ts = date_parser.parse(timestamp_str, dayfirst=True)
            except Exception:
                pass

        alert_type = pairs.get('alert')
        event_value = (pairs.get('event') or "").lower()

        event_type = 'unknown'
        if alert_type:
            event_type = 'security_alert'
        elif 'login' in event_value and ('fail' in event_value or 'failed' in event_value):
            event_type = 'failed_login'
        elif 'login' in event_value and 'success' in event_value:
            event_type = 'successful_login'
        elif 'privilege' in event_value or 'sudo' in (pairs.get('source') or '').lower():
            event_type = 'privilege_escalation'

        source_ip = pairs.get('src_ip') or pairs.get('source_ip') or pairs.get('ip') or None
        username = pairs.get('user') or pairs.get('username') or None

        msg = ' '.join([f"{k}={v}" for k, v in pairs.items() if k not in ('time', 'timestamp')])
        if alert_type:
            msg = f"{msg} [ALERT: {alert_type}]"

        return {
            'timestamp': ts,
            'source_ip': source_ip,
            'username': username,
            'message': msg[:2000],
            'event_type': event_type,
            'format': 'keyvalue',
            'raw': line,
            'parsed_pairs': pairs
        }

    def _heuristic_parse(self, line: str) -> Dict:
        ips = self._extract_ips(line)
        timestamp = self._extract_timestamp_heuristic(line)
        user = self._extract_user_heuristic(line)

        line_lower = line.lower()
        event_type = 'unknown'
        if any(x in line_lower for x in ['fail', 'denied', 'rejected', 'unauthorized', '401', '403']):
            event_type = 'failed_auth'
        elif any(x in line_lower for x in ['success', 'accepted', 'granted', '200']):
            event_type = 'success'
        elif any(x in line_lower for x in ['error', 'exception', 'critical', 'alert']):
            event_type = 'error'
        elif any(x in line_lower for x in ['attack', 'injection', 'malicious', 'threat']):
            event_type = 'threat'

        return {
            'timestamp': timestamp or datetime.now(),
            'source_ip': ips[0] if ips else None,
            'username': user,
            'message': line[:2000],
            'event_type': event_type,
            'format': 'heuristic',
            'raw': line
        }

    def parse_line(self, line: str) -> Optional[Dict]:
        line = line.strip()
        if not line or line.startswith('#'):
            return None

        kv = self._parse_keyvalue_pairs(line)
        if kv:
            self.format_stats['keyvalue_log'] += 1
            return kv

        for pattern_def in self.patterns:
            match = pattern_def['regex'].match(line)
            if match:
                self.format_stats[pattern_def['name']] += 1
                return self._normalize_regex(match, pattern_def, line)

        if self._is_json_line(line):
            try:
                data = json.loads(line)
                self.format_stats['json_log'] += 1
                return self._normalize_json(data, line)
            except json.JSONDecodeError:
                pass

        return self._heuristic_parse(line)

    def _normalize_regex(self, match: re.Match, pattern_def: Dict, raw_line: str) -> Dict:
        groups = match.groupdict()
        result: Dict[str, Any] = {
            'timestamp': datetime.now(),
            'source_ip': None,
            'username': None,
            'message': '',
            'event_type': 'unknown',
            'format': pattern_def['name'],
            'raw': raw_line
        }

        field_map = {
            'source_ip': ['source_ip', 'client_ip', 'remote_addr', 'src_ip'],
            'username': ['username', 'auth_user', 'user', 'uid'],
            'message': ['message', 'msg', 'path'],
            'host': ['host', 'hostname', 'server'],
            'process': ['process', 'source', 'facility']
        }

        for std_field, possible in field_map.items():
            for name in possible:
                if name in groups and groups[name]:
                    result[std_field] = groups[name]
                    break

        if 'timestamp' in groups and groups['timestamp']:
            try:
                result['timestamp'] = date_parser.parse(groups['timestamp'], dayfirst=True)
            except Exception:
                pass

        if 'status' in groups:
            try:
                result['status_code'] = int(groups['status'])
            except (ValueError, TypeError):
                result['status_code'] = groups['status']

        if not result.get('source_ip'):
            ips = self._extract_ips(raw_line)
            if ips:
                result['source_ip'] = ips[0]
        
        if not result.get('username'):
            result['username'] = self._extract_user_heuristic(raw_line)

        msg = str(result.get('message', ''))
        msg_lower = msg.lower()

        alert_match = re.search(r'\[ALERT:\s*([A-Z_]+)\s*\]', msg)
        if alert_match:
            result['alert_type'] = alert_match.group(1)
            result['event_type'] = 'security_alert'
            result['iocs'] = self._extract_iocs_from_alert(msg, result['alert_type'])
        elif pattern_def['type'] == 'syslog':
            if any(kw in msg_lower for kw in ['fail', 'denied', 'failed', 'invalid', 'error']):
                result['event_type'] = 'failed_login'
            elif any(kw in msg_lower for kw in ['accept', 'success', 'accepted', 'opened']):
                result['event_type'] = 'successful_login'
            else:
                result['event_type'] = 'system_event'
        elif pattern_def['type'] == 'web':
            result['event_type'] = 'web_access'

        return result

    def _extract_iocs_from_alert(self, message: str, alert_type: str) -> Dict:
        iocs: Dict[str, Any] = {}

        ip_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        ips = ip_pattern.findall(message)

        if ips:
            iocs['all_ips'] = list(set(ips))
            iocs['ip'] = ips[0]

        user_match = re.search(r'\buser(?:name)?[:\s=]+([a-zA-Z0-9_\-\.]+)', message, re.IGNORECASE)
        if user_match:
            iocs['username'] = user_match.group(1)

        url_match = re.search(r'(https?://[^\s\[\]]+)', message)
        if url_match:
            iocs['url'] = url_match.group(1)

        domain_match = re.search(r'\bdomain[:\s=]+([a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,})', message, re.IGNORECASE)
        if domain_match:
            iocs['domain'] = domain_match.group(1)

        return iocs

    def analyze(self, parsed: Dict) -> List[SecurityAlert]:
        alerts: List[SecurityAlert] = []
        if not parsed:
            return alerts

        now = datetime.now()
        raw = parsed.get('raw', '')
        event_type = parsed.get('event_type', 'unknown')
        ip = parsed.get('source_ip')
        username = parsed.get('username')

        if (now - self._last_cleanup) > timedelta(minutes=10):
            cutoff = now - timedelta(minutes=10)
            for key in list(self.windows.keys()):
                self.windows[key] = [e for e in self.windows[key] if e.get('time', now) > cutoff]
                if not self.windows[key]:
                    del self.windows[key]
            for user in list(self.user_failures.keys()):
                self.user_failures[user] = [e for e in self.user_failures[user] if e.get('time', now) > cutoff]
                if not self.user_failures[user]:
                    del self.user_failures[user]
            self._last_cleanup = now

        parsed_pairs = parsed.get('parsed_pairs') or {}
        kv_event = (parsed_pairs.get('event') or '').strip()
        kv_event_lower = kv_event.lower() if kv_event else ""

        alert_type = None
        if parsed_pairs.get('alert'):
            alert_type = parsed_pairs.get('alert')
        else:
            msg = str(parsed.get('message', ''))
            m = re.search(r'\[ALERT:\s*([A-Z_]+)\s*\]', msg)
            if m:
                alert_type = m.group(1)

        severity_map = {
            'BRUTE_FORCE_ATTEMPT': 'HIGH',
            'MULTIPLE_LOGIN_FAILURES': 'MEDIUM',
            'REVERSE_SHELL': 'CRITICAL',
            'MALICIOUS_IP_COMMUNICATION': 'HIGH',
            'PRIV_ESCALATION': 'CRITICAL',
            'MALWARE_DOWNLOAD': 'CRITICAL',
            'SQL_INJECTION': 'CRITICAL',
            'MALWARE_DETECTED': 'HIGH',
            'PROCESS_ANOMALY': 'MEDIUM',
            'SUSPICIOUS_LOGIN_SUCCESS': 'HIGH',
            'SUDO_PRIVILEGE_USED': 'HIGH',
            'PERSISTENCE_MECHANISM': 'CRITICAL',
            'SUSPICIOUS_SERVICE_CREATION': 'CRITICAL',
            'SUSPICIOUS_DOWNLOAD': 'CRITICAL',
            'EXECUTION_OF_UNKNOWN_BINARY': 'CRITICAL',
            'C2_CONNECTION': 'CRITICAL',
            'PRIVILEGE_PERSISTENCE': 'CRITICAL',
            'DATA_EXFILTRATION_ATTEMPT': 'CRITICAL',
            'CRYPTO_MINING_ACTIVITY': 'CRITICAL',
            'CREDENTIAL_ACCESS': 'CRITICAL',
            'LATERAL_MOVEMENT': 'CRITICAL',
            'OBFUSCATED_COMMAND': 'CRITICAL',
            'RANSOMWARE_ACTIVITY': 'CRITICAL',
            'POSSIBLE_DATA_STAGING': 'HIGH',
            'UNKNOWN_EVENT_DETECTED': 'LOW',
        }

        mitre_map = {
            'BRUTE_FORCE_ATTEMPT': 'T1110',
            'MULTIPLE_LOGIN_FAILURES': 'T1110',
            'REVERSE_SHELL': 'T1059',
            'MALICIOUS_IP_COMMUNICATION': 'T1071',
            'PRIV_ESCALATION': 'T1068',
            'MALWARE_DOWNLOAD': 'T1105',
            'SQL_INJECTION': 'T1190',
            'MALWARE_DETECTED': 'T1204',
            'PROCESS_ANOMALY': 'T1055',
            'SUSPICIOUS_LOGIN_SUCCESS': 'T1078',
            'SUDO_PRIVILEGE_USED': 'T1548',
            'PERSISTENCE_MECHANISM': 'T1053',
            'SUSPICIOUS_SERVICE_CREATION': 'T1543',
            'SUSPICIOUS_DOWNLOAD': 'T1105',
            'EXECUTION_OF_UNKNOWN_BINARY': 'T1204',
            'C2_CONNECTION': 'T1071',
            'PRIVILEGE_PERSISTENCE': 'T1548',
            'DATA_EXFILTRATION_ATTEMPT': 'T1041',
            'CRYPTO_MINING_ACTIVITY': 'T1496',
            'CREDENTIAL_ACCESS': 'T1003',
            'LATERAL_MOVEMENT': 'T1021',
            'OBFUSCATED_COMMAND': 'T1027',
            'RANSOMWARE_ACTIVITY': 'T1486',
            'POSSIBLE_DATA_STAGING': 'T1074',
            'UNKNOWN_EVENT_DETECTED': 'T1204',
        }

        if alert_type:
            iocs = parsed.get('iocs', {}) or self._extract_iocs_from_alert(raw, alert_type) or {}

            if parsed_pairs:
                if parsed_pairs.get('src_ip'):
                    iocs['ip'] = parsed_pairs['src_ip']
                    ip = parsed_pairs['src_ip']
                if parsed_pairs.get('dest_ip'):
                    iocs['dst_ip'] = parsed_pairs['dest_ip']
                if parsed_pairs.get('user'):
                    iocs['username'] = parsed_pairs['user']
                    username = parsed_pairs['user']
                if parsed_pairs.get('domain'):
                    iocs['domain'] = parsed_pairs['domain']
                if parsed_pairs.get('url'):
                    iocs['url'] = parsed_pairs['url']
                if parsed_pairs.get('path'):
                    iocs['file_path'] = parsed_pairs['path']
                if parsed_pairs.get('file'):
                    iocs['file_path'] = parsed_pairs['file']
                if parsed_pairs.get('service'):
                    iocs['service_name'] = parsed_pairs['service']
                if parsed_pairs.get('command'):
                    iocs['command'] = parsed_pairs['command']

            if parsed_pairs:
                details = " | ".join([f"{k}={v}" for k, v in parsed_pairs.items() if k not in ('time', 'timestamp')])
            else:
                details = re.sub(r'\s*\[ALERT:\s*[A-Z_]+\s*\]$', '', str(parsed.get('message', '')))

            alert: SecurityAlert = {
                'id': str(uuid.uuid4()),
                'timestamp': parsed.get('timestamp', now),
                'type': alert_type.replace('_', ' '),
                'severity': severity_map.get(alert_type, 'CRITICAL'),
                'source_ip': ip,
                'username': username,
                'details': details[:2000],
                'mitre': mitre_map.get(alert_type, 'T1000'),
                'raw': raw,
                'iocs': iocs
            }
            alerts.append(alert)

            correlation_alert = self.correlation_engine.add_event(parsed, alert)
            if correlation_alert:
                alerts.append(correlation_alert)

        unknown_reasons = []

        if event_type == "unknown":
            unknown_reasons.append("parser_event_type=unknown")

        if parsed_pairs and kv_event:
            if kv_event_lower not in self.known_events:
                unknown_reasons.append(f"unknown_kv_event={kv_event}")

        if event_type and event_type not in self.known_event_types:
            unknown_reasons.append(f"unrecognized_event_type_label={event_type}")

        if unknown_reasons:
            detail_bits = []
            if parsed_pairs:
                for k in ("host", "source", "sourcetype", "event", "severity"):
                    if k in parsed_pairs:
                        detail_bits.append(f"{k}={parsed_pairs[k]}")
            if ip:
                detail_bits.append(f"src_ip={ip}")
            if username:
                detail_bits.append(f"user={username}")
            detail_bits.append("reason=" + ",".join(unknown_reasons))

            alerts.append({
                'id': str(uuid.uuid4()),
                "timestamp": parsed.get("timestamp", now),
                "type": "UNKNOWN EVENT TYPE DETECTED",
                "severity": "LOW",
                "source_ip": ip,
                "username": username,
                "details": " | ".join(detail_bits)[:2000],
                "mitre": mitre_map.get("UNKNOWN_EVENT_DETECTED", "T1000"),
                "raw": raw,
                "iocs": {
                    "ip": ip,
                    "username": username,
                    "event": kv_event or None,
                    "reasons": unknown_reasons,
                }
            })

        if event_type in ['failed_login', 'failed_auth'] and ip:
            key = f"{ip}:{event_type}"
            self.windows[key].append({'time': now, 'user': username, 'data': parsed})

            cutoff = now - timedelta(minutes=5)
            self.windows[key] = [e for e in self.windows[key] if e['time'] > cutoff]

            attempts = len(self.windows[key])
            if attempts >= Config.BRUTE_FORCE_THRESHOLD:
                severity = (
                    "CRITICAL" if attempts >= Config.BRUTE_FORCE_CRITICAL
                    else "HIGH" if attempts >= Config.BRUTE_FORCE_HIGH
                    else "MEDIUM"
                )
                alert = {
                    'id': str(uuid.uuid4()),
                    'timestamp': now,
                    'type': f'Brute Force ({parsed.get("format", "unknown")})',
                    'severity': severity,
                    'source_ip': ip,
                    'username': username,
                    'details': f"{attempts} failed attempts detected",
                    'mitre': 'T1110',
                    'raw': raw
                }
                alerts.append(alert)

                correlation_alert = self.correlation_engine.add_event(parsed, alert)
                if correlation_alert:
                    alerts.append(correlation_alert)

            if username:
                self.user_failures[username].append({'time': now, 'ip': ip})

        elif event_type in ['successful_login', 'success'] and (ip or username):
            alert = None
            if username and username in self.user_failures:
                failures = self.user_failures[username]
                failure_count = len(failures)
                failure_ips = list(set(f['ip'] for f in failures if f['ip']))

                current_ip = ip or 'unknown'

                if current_ip in failure_ips and failure_count >= 3:
                    alert = {
                        'id': str(uuid.uuid4()),
                        'timestamp': now,
                        'type': 'ACCOUNT COMPROMISE (Lockout Bypass)',
                        'severity': 'CRITICAL',
                        'source_ip': current_ip,
                        'username': username,
                        'details': f"SUCCESS after {failure_count} failures from same IP",
                        'mitre': 'T1078',
                        'raw': raw
                    }
                elif current_ip not in failure_ips:
                    alert = {
                        'id': str(uuid.uuid4()),
                        'timestamp': now,
                        'type': 'CONFIRMED ACCOUNT COMPROMISE (Cross-IP)',
                        'severity': 'CRITICAL',
                        'source_ip': current_ip,
                        'username': username,
                        'details': (
                            f"SUCCESS from {current_ip} after {failure_count} failures "
                            f"from {failure_ips[0] if failure_ips else 'other IPs'}"
                        ),
                        'mitre': 'T1078',
                        'raw': raw
                    }

                del self.user_failures[username]

            elif ip:
                for key in list(self.windows.keys()):
                    if key.startswith(f"{ip}:") and len(self.windows[key]) >= 3:
                        alert = {
                            'id': str(uuid.uuid4()),
                            'timestamp': now,
                            'type': 'Login After Failed Attempts',
                            'severity': 'HIGH',
                            'source_ip': ip,
                            'username': username,
                            'details': f"Success after {len(self.windows[key])} failures",
                            'mitre': 'T1078',
                            'raw': raw
                        }
                        del self.windows[key]
                        break

            if alert:
                alerts.append(alert)
                correlation_alert = self.correlation_engine.add_event(parsed, alert)
                if correlation_alert:
                    alerts.append(correlation_alert)

        elif event_type == 'web_access':
            status = parsed.get('status_code', 0)
            path = f"{parsed.get('path', '')} {parsed.get('message', '')}".upper()
            ua = str(parsed.get('user_agent', '')).lower()

            if any(x in path for x in ['SELECT+', 'UNION+', '<SCRIPT', 'NULL', 'UNDEFINED', '../../']):
                alert = {
                    'id': str(uuid.uuid4()),
                    'timestamp': now,
                    'type': 'Web Attack (Injection)',
                    'severity': 'CRITICAL',
                    'source_ip': ip,
                    'details': f"Malicious pattern: {path[:60]}",
                    'mitre': 'T1059',
                    'raw': raw
                }
                alerts.append(alert)
                correlation_alert = self.correlation_engine.add_event(parsed, alert)
                if correlation_alert:
                    alerts.append(correlation_alert)

            if 'googlebot' in ua and ip and not str(ip).startswith('66.249.'):
                alert = {
                    'id': str(uuid.uuid4()),
                    'timestamp': now,
                    'type': 'Fake Crawler',
                    'severity': 'MEDIUM',
                    'source_ip': ip,
                    'details': f"IP {ip} claims Googlebot",
                    'mitre': 'T1071',
                    'raw': raw
                }
                alerts.append(alert)
                correlation_alert = self.correlation_engine.add_event(parsed, alert)
                if correlation_alert:
                    alerts.append(correlation_alert)

            if status in [401, 403] and ip:
                self.windows[ip].append({'time': now, 'type': 'web_auth_fail'})
                recent = [
                    e for e in self.windows[ip]
                    if e['time'] > now - timedelta(minutes=5) and e.get('type') == 'web_auth_fail'
                ]
                if len(recent) == 20:
                    alert = {
                        'id': str(uuid.uuid4()),
                        'timestamp': now,
                        'type': 'Web Auth Brute Force',
                        'severity': 'HIGH',
                        'source_ip': ip,
                        'details': "20 auth failures in 5 minutes",
                        'mitre': 'T1110',
                        'raw': raw
                    }
                    alerts.append(alert)
                    correlation_alert = self.correlation_engine.add_event(parsed, alert)
                    if correlation_alert:
                        alerts.append(correlation_alert)

        return alerts

    def get_stats(self) -> Dict:
        return dict(self.format_stats)

LogParser = UniversalLogParser

class RealTimeLogStreamer:
    def __init__(self):
        self.active = False
        self.line_queue: queue.Queue = queue.Queue(maxsize=Config.MAX_QUEUE_SIZE)
        self.alert_queue: queue.Queue = queue.Queue(maxsize=Config.MAX_QUEUE_SIZE)
        self.raw_log_queue: queue.Queue = queue.Queue(maxsize=Config.MAX_QUEUE_SIZE)
        self.threads: List[threading.Thread] = []
        self._parser = UniversalLogParser()
        self._stop_event = threading.Event()
        self._file_path = None

        self.health_stats = {
            'lines_dropped': 0,
            'alerts_dropped': 0,
            'lines_processed': 0,
            'start_time': None,
            'last_error': None
        }
        self._stats_lock = threading.Lock()

    def validate_and_start(self, filepath: str) -> bool:
        ok, resolved, error = _resolve_and_validate_path(filepath)
        if not ok:
            st.error(f"[ERROR] {error}")
            return False

        self._file_path = resolved
        self._stop_event.clear()
        self.health_stats['start_time'] = datetime.now()
        self._start_file_tail()
        self._start_processor()
        self.active = True
        logger.info(f"Started streaming: {resolved}")
        return True

    def _start_file_tail(self):
        def tail():
            last_inode = None
            last_pos = 0

            while not self._stop_event.is_set():
                try:
                    if not os.path.exists(self._file_path):
                        logger.warning(f"File not found: {self._file_path}")
                        time.sleep(1)
                        continue

                    stat = os.stat(self._file_path)
                    current_inode = stat.st_ino
                    if last_inode is not None and current_inode != last_inode:
                        logger.info(f"File rotated: {self._file_path}")
                        last_pos = 0
                    last_inode = current_inode

                    f, error = _secure_open_file(self._file_path)
                    if error:
                        logger.error(f"Cannot open file: {error}")
                        time.sleep(1)
                        continue

                    with f:
                        try:
                            fd_stat = os.fstat(f.fileno())
                            if fd_stat.st_ino != current_inode:
                                logger.warning("File rotated between stat and open — restarting tail")
                                f.close()
                                continue
                        except OSError:
                            logger.warning("Failed to fstat — continuing anyway")
                            pass

                        f.seek(last_pos)
                        while not self._stop_event.is_set():
                            line = f.readline()
                            if not line:
                                break

                            try:
                                self.line_queue.put(line.strip(), block=False)
                                last_pos = f.tell()
                            except queue.Full:
                                try:
                                    self.line_queue.get_nowait()
                                    self.line_queue.put(line.strip(), block=False)
                                    last_pos = f.tell()
                                    with self._stats_lock:
                                        self.health_stats['lines_dropped'] += 1
                                except queue.Empty:
                                    pass

                    time.sleep(0.5)

                except Exception as e:
                    logger.error(f"Tail error: {e}")
                    with self._stats_lock:
                        self.health_stats['last_error'] = str(e)
                    time.sleep(1)

        t = threading.Thread(target=tail, daemon=True, name="LogTail")
        add_script_run_ctx(t)
        t.start()
        self.threads.append(t)

    def _start_processor(self):
        def process():
            while not self._stop_event.is_set():
                try:
                    line = self.line_queue.get(timeout=1)
                    parsed = self._parser.parse_line(line)
                    if parsed:
                        alerts = self._parser.analyze(parsed)
                        for alert in alerts:
                            try:
                                self.alert_queue.put(alert, block=False)
                            except queue.Full:
                                with self._stats_lock:
                                    self.health_stats['alerts_dropped'] += 1

                        try:
                            self.raw_log_queue.put({'type': 'parsed', 'data': parsed, 'alerts': len(alerts)}, block=False)
                        except queue.Full:
                            pass

                        with self._stats_lock:
                            self.health_stats['lines_processed'] += 1

                except queue.Empty:
                    continue
                except Exception as e:
                    logger.error(f"Processor error: {e}")
                    with self._stats_lock:
                        self.health_stats['last_error'] = str(e)

        t = threading.Thread(target=process, daemon=True, name="LogProcessor")
        add_script_run_ctx(t)
        t.start()
        self.threads.append(t)

    def get_pending_items(self) -> Tuple[List[SecurityAlert], List[Dict]]:
        alerts: List[SecurityAlert] = []
        logs: List[Dict] = []

        while True:
            try:
                alerts.append(self.alert_queue.get_nowait())
            except queue.Empty:
                break

        count = 0
        while count < 100:
            try:
                logs.append(self.raw_log_queue.get_nowait())
                count += 1
            except queue.Empty:
                break

        return alerts, logs

    def get_health(self) -> Dict:
        with self._stats_lock:
            stats = self.health_stats.copy()

        stats['queue_depth_lines'] = self.line_queue.qsize()
        stats['queue_depth_alerts'] = self.alert_queue.qsize()
        stats['is_active'] = self.active

        if stats['start_time']:
            runtime = datetime.now() - stats['start_time']
            stats['runtime_seconds'] = runtime.total_seconds()
            stats['lines_per_second'] = (
                stats['lines_processed'] / runtime.total_seconds()
                if runtime.total_seconds() > 0 else 0.0
            )
        else:
            stats['runtime_seconds'] = 0.0
            stats['lines_per_second'] = 0.0

        return stats

    def stop(self):
        self._stop_event.set()
        self.active = False
        logger.info("Stopping stream...")

        for t in self.threads:
            t.join(timeout=3)

        self.threads.clear()
        self._parser.reset()

def render_ioc_card(ioc: str, ioc_type: str, result: EnrichmentResult):
    ioc_esc = html.escape(ioc)
    ioc_type_esc = html.escape(ioc_type)
    score = int(result.get("overall_score", 0))
    severity_raw = str(result.get("max_severity", "clean"))
    severity = html.escape(severity_raw)

    colors = {
        "critical": ("#dc2626", "#fef2f2", "[BLOCK] Immediate Action Required"),
        "high": ("#ea580c", "#fff7ed", "[INVESTIGATE] Review Recommended"),
        "medium": ("#ca8a04", "#fefce8", "[MONITOR] Track Activity"),
        "clean": ("#16a34a", "#f0fdf4", "[BENIGN] No Action Needed"),
    }
    color, bg, action = colors.get(severity_raw, colors["clean"])

    st.markdown(f"""
    <div style="background: linear-gradient(135deg, {bg} 0%, #fff 100%);
         border: 2px solid {color}; border-radius: 12px; padding: 24px;
         margin: 16px 0;">
        <div style="display: flex; justify-content: space-between;
             align-items: center;">
            <div>
                <div style="font-size: 0.875rem; color: #6b7280;
                     text-transform: uppercase;
                     font-weight: 600;">{ioc_type_esc.upper()}</div>
                <div style="font-size: 1.5rem; font-weight: 700;
                     font-family: monospace; margin-top: 4px;
                     word-break: break-all;">{ioc_esc}</div>
            </div>
            <div style="text-align: right;">
                <div style="background: {color}; color: white;
                     padding: 8px 16px; border-radius: 20px;
                     font-weight: 600; font-size: 0.875rem;
                     text-transform: uppercase;
                     letter-spacing: 0.5px;">{severity.upper()}</div>
                <div style="font-size: 2.5rem; font-weight: 800;
                     color: {color};">{score}</div>
                <div style="font-size: 0.875rem; color: #6b7280;
                     font-weight: 500;">Risk Score</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown(
        f'<div style="background: {bg}; border-left: 4px solid {color}; '
        f'padding: 16px; margin: 16px 0; border-radius: 0 8px 8px 0; '
        f'font-weight: 500;"><b style="color: {color};">'
        f'RECOMMENDED ACTION:</b> {html.escape(action)}</div>',
        unsafe_allow_html=True
    )

    st.subheader("Threat Intelligence Sources")
    sources = result.get("sources", {}) or {}
    if not sources:
        st.warning("No threat intelligence data available. Check API key configuration.")
        return

    cols = st.columns(min(len(sources), 4))
    for idx, (name, data) in enumerate(sources.items()):
        with cols[idx % len(cols)]:
            name_esc = html.escape(str(name))
            if not data.get("success"):
                err = html.escape(str(data.get("error", "Connection failed"))[:80])
                st.error(f"[FAILED] {name_esc}: {err}")
                continue

            if name == 'abuseipdb':
                val = f"{data.get('score', 0)}%"
                title = "Confidence"
                detail = f"{html.escape(str(data.get('country', '??')))} | {data.get('total_reports', 0)} reports"
            elif name == 'virustotal':
                val = f"{data.get('malicious', 0) + data.get('suspicious', 0)}"
                title = f"of {data.get('total_engines', 0)} engines"
                detail = f"{data.get('malicious', 0)} malicious | {data.get('suspicious', 0)} suspicious"
            elif name == 'urlhaus':
                val = html.escape(str(data.get('status', 'Unknown')))
                title = "Status"
                detail = html.escape(str(data.get('threat', 'N/A'))) if data.get('status') == 'Malicious' else "Not in database"
            elif name == 'otx':
                val = str(data.get('pulse_count', 0))
                title = "Pulses"
                detail = "Community threat intel"
            else:
                val = str(data.get('score', 0))
                title = "Score"
                detail = "See raw data"

            score_val = data.get('score', 0)
            if isinstance(score_val, str):
                card_color = "#6b7280"
            else:
                card_color = (
                    "#dc2626" if score_val >= 80
                    else "#ea580c" if score_val >= 50
                    else "#ca8a04" if score_val >= 20
                    else "#16a34a"
                )

            st.markdown(f"""
            <div style="background: white; border: 1px solid #e5e7eb;
                 border-radius: 8px; padding: 16px; text-align: center;
                 box-shadow: 0 1px 2px rgba(0,0,0,0.05);">
                <div style="font-size: 0.75rem; color: #6b7280;
                     text-transform: uppercase; margin-bottom: 8px;
                     font-weight: 600; letter-spacing: 0.5px;">{name_esc.upper()}</div>
                <div style="font-size: 2rem; font-weight: 700;
                     color: {card_color};">{html.escape(str(val))}</div>
                <div style="font-size: 0.875rem; color: #6b7280;
                     font-weight: 500;">{html.escape(str(title))}</div>
                <div style="font-size: 0.75rem; color: #9ca3af;
                     margin-top: 8px;">{html.escape(str(detail))}</div>
            </div>
            """, unsafe_allow_html=True)

    st.subheader("Response Actions")
    c1, c2, c3, c4, c5 = st.columns(5)

    with c1:
        st.download_button("Copy IOC", ioc, file_name=f"ioc_{ioc[:20]}.txt", use_container_width=True)

    with c2:
        if ioc_type == 'ip':
            st.link_button("VirusTotal", f"https://www.virustotal.com/gui/ip-address/{ioc}", use_container_width=True)
        elif ioc_type in ('md5', 'sha1', 'sha256'):
            st.link_button("VirusTotal", f"https://www.virustotal.com/gui/file/{ioc}", use_container_width=True)
        elif ioc_type == 'domain':
            st.link_button("VirusTotal", f"https://www.virustotal.com/gui/domain/{ioc}", use_container_width=True)
        else:
            st.button("VirusTotal", disabled=True, use_container_width=True)

    with c3:
        if ioc_type == 'ip':
            st.link_button("AbuseIPDB", f"https://www.abuseipdb.com/check/{ioc}", use_container_width=True)
        else:
            st.button("AbuseIPDB", disabled=True, use_container_width=True)

    with c4:
        if ioc_type == 'url':
            st.link_button("URLhaus", f"https://urlhaus.abuse.ch/browse.php?search={ioc}", use_container_width=True)
        else:
            st.button("URLhaus", disabled=True, use_container_width=True)

    with c5:
        misp = {
            "Event": {
                "info": f"IOC: {ioc}",
                "threat_level_id": ("1" if score > 80 else "2" if score > 50 else "3"),
                "Attribute": [{
                    "type": {"ip": "ip-dst", "domain": "domain", "url": "url", "md5": "md5", "sha1": "sha1", "sha256": "sha256"}.get(ioc_type, "text"),
                    "value": ioc,
                    "to_ids": score > 50
                }]
            }
        }
        st.download_button(
            "Export MISP",
            json.dumps(misp, indent=2),
            file_name=f"misp_{ioc[:20]}.json",
            mime="application/json",
            use_container_width=True
        )

    with st.expander("View Raw Data"):
        st.json(result)

def render_alert_card(alert: SecurityAlert):
    colors = {
        "CRITICAL": "#dc2626",
        "HIGH": "#ea580c",
        "MEDIUM": "#ca8a04",
        "LOW": "#16a34a"
    }
    color = colors.get(str(alert.get('severity', 'LOW')).upper(), "#6b7280")
    timestamp = alert.get('timestamp')
    ts_str = timestamp.strftime('%H:%M:%S') if isinstance(timestamp, datetime) else html.escape(str(timestamp))

    alert_type = html.escape(str(alert.get('type', '')))
    severity = html.escape(str(alert.get('severity', '')))
    source_ip = html.escape(str(alert.get('source_ip', 'N/A')))
    mitre = html.escape(str(alert.get('mitre', '')))
    details = html.escape(str(alert.get('details', '')))

    st.markdown(f"""
    <div style="border-left: 4px solid {color};
         background: linear-gradient(90deg, {color}08 0%, #ffffff 100%);
         padding: 16px; margin: 12px 0; border-radius: 0 8px 8px 0;
         box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
        <div style="display: inline-block; background: {color};
             color: white; padding: 4px 12px; border-radius: 12px;
             font-size: 0.75rem; font-weight: 600;
             text-transform: uppercase; letter-spacing: 0.5px;">{severity}</div>
        <div style="font-size: 1.1rem; font-weight: 600; margin-top: 8px;
             color: #1f2937; letter-spacing: -0.2px;">{alert_type}</div>
        <div style="font-size: 0.875rem; color: #6b7280; margin-top: 4px;
             font-family: monospace;">{ts_str} | {source_ip} | MITRE {mitre}</div>
        <div style="font-size: 0.875rem; color: #4b5563; margin-top: 8px;
             line-height: 1.5;">{details}</div>
    </div>
    """, unsafe_allow_html=True)

    iocs = alert.get('iocs', {}) or {}
    if iocs:
        with st.expander("Related IoCs"):
            cols = st.columns(min(len(iocs), 4))
            for idx, (ioc_type, ioc_value) in enumerate(iocs.items()):
                if not ioc_value:
                    continue
                with cols[idx % len(cols)]:
                    st.code(f"{html.escape(str(ioc_type))}: {html.escape(str(ioc_value))}", language='text')
                    if ioc_type in ['ip', 'domain', 'url']:
                        unique_id = alert.get('id', str(id(alert)))
                        safe_ioc = hashlib.md5(str(ioc_value).encode()).hexdigest()[:8]
                        btn_key = f"enrich_{unique_id}_{ioc_type}_{safe_ioc}"
                        
                        if st.button(f"Enrich {ioc_type}", key=btn_key):
                            st.session_state['enrich_ioc'] = {'ioc': str(ioc_value), 'type': str(ioc_type)}
                            st.rerun()

    if alert.get('raw'):
        with st.expander("View Raw Log Entry"):
            st.code(str(alert['raw']), language='text')

def init_state():
    defaults = {
        'events': [],
        'timeline': [],
        'streamer': None,
        'parser': None,
        'last_ioc': None,
        'stats': {
            'total_logs': 0,
            'unique_ips': set(),
            'alerts_by_severity': Counter()
        }
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

def add_timeline(msg: str):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    st.session_state.timeline.append(f"[{ts}] {msg}")
    if len(st.session_state.timeline) > Config.MAX_TIMELINE_EVENTS:
        st.session_state.timeline = st.session_state.timeline[-Config.MAX_TIMELINE_EVENTS:]

@st.cache_resource
def get_config():
    return {
        "vt_api_key": st.secrets.get("VT_KEY", ""),
        "abuseipdb_key": st.secrets.get("ABUSE_KEY", ""),
        "otx_key": st.secrets.get("OTX_KEY", ""),
        "urlhaus_key": st.secrets.get("URLHAUS_KEY", ""),
    }

CONFIG = get_config()

ti_client = ThreatIntelClient()

def main():
    st.set_page_config(page_title="LogSentinel Professional", page_icon=":shield:", layout="wide")
    init_state()

    st.title("LogSentinel Professional Dashboard")
    st.caption("SOC Log Detection & Threat Intelligence Platform")
    st.divider()

    if st.session_state.parser is None:
        st.session_state.parser = UniversalLogParser()

    if 'enrich_ioc' in st.session_state:
        ioc_data = st.session_state.pop('enrich_ioc')
        st.info(f"Enriching {ioc_data['type']}: {ioc_data['ioc']}")
        st.session_state.last_ioc = {
            'ioc': ioc_data['ioc'],
            'type': ioc_data['type'],
            'data': ti_client.enrich(ioc_data['ioc'], ioc_data['type'])
        }
        st.rerun()

    with st.sidebar:
        st.header("Control Panel")

        mode = st.radio(
            "Operation Mode",
            ["Batch Analysis", "Real-time Stream", "IOC Lookup"],
            key="mode_selector"
        )

        if mode == "IOC Lookup":
            st.subheader("IOC Enrichment")
            ioc_input = st.text_input("Indicator (IP/Domain/URL/Hash)", placeholder="e.g., 8.8.8.8")

            if ioc_input:
                t, norm = detect_ioc_type(ioc_input)
                st.caption(f"Detected Type: **{t.upper()}**")

            c1, c2 = st.columns([2, 1])
            with c1:
                if st.button("Analyze", type="primary", use_container_width=True) and ioc_input:
                    t, norm = detect_ioc_type(ioc_input)
                    if t == 'unknown':
                        st.error("Unknown indicator type")
                    else:
                        with st.spinner("Querying threat intelligence..."):
                            result = ti_client.enrich(norm, t)
                            st.session_state.last_ioc = {'ioc': norm, 'type': t, 'data': result}
                        st.rerun()
            with c2:
                if st.button("Clear", use_container_width=True):
                    st.session_state.last_ioc = None
                    st.rerun()

            if st.session_state.last_ioc:
                st.divider()
                st.metric("Risk Score", f"{st.session_state.last_ioc['data'].get('overall_score', 0)}/100")

        elif mode == "Real-time Stream":
            st.subheader("Real-time Log Streaming")
            path = st.text_input(
                "Log file path",
                value="~/logs/test.log",
                help="Supports: Syslog, Apache, IIS, JSON, Windows Events, Cisco ASA, Key=Value"
            )

            is_active = (st.session_state.streamer is not None and st.session_state.streamer.active)

            if is_active:
                st.markdown(
                    '<div style="display: flex; align-items: center; gap: 8px;">'
                    '<div style="width: 10px; height: 10px; background-color: #22c55e; border-radius: 50%;"></div>'
                    '<span style="color: #22c55e; font-weight: 600;">Active</span></div>',
                    unsafe_allow_html=True
                )
                health = st.session_state.streamer.get_health()
                with st.expander("Stream Health"):
                    st.metric("Lines/sec", f"{health['lines_per_second']:.1f}")
                    st.metric("Queue Depth", health['queue_depth_lines'])
                    st.metric("Dropped Lines", health['lines_dropped'])
                    if health['last_error']:
                        st.error(f"Last Error: {health['last_error'][:100]}")
            else:
                st.markdown(
                    '<div style="display: flex; align-items: center; gap: 8px;">'
                    '<div style="width: 10px; height: 10px; background-color: #9ca3af; border-radius: 50%;"></div>'
                    '<span style="color: #9ca3af; font-weight: 600;">Stopped</span></div>',
                    unsafe_allow_html=True
                )

            c1, c2 = st.columns(2)
            with c1:
                if st.button("Start Stream", use_container_width=True) and not is_active:
                    st.session_state.events = []
                    st.session_state.stats = {'total_logs': 0, 'unique_ips': set(), 'alerts_by_severity': Counter()}
                    st.session_state.timeline = []

                    st.session_state.streamer = RealTimeLogStreamer()
                    if st.session_state.streamer.validate_and_start(path):
                        add_timeline("Stream started")
                        st.rerun()
                    else:
                        st.session_state.streamer = None

            with c2:
                if st.button("Stop Stream", use_container_width=True) and is_active:
                    if st.session_state.streamer:
                        st.session_state.streamer.stop()
                    st.session_state.streamer = None
                    add_timeline("Stream stopped")
                    st.rerun()

        else:
            st.subheader("Batch Log Analysis")
            st.info("Upload a log file using the file uploader in the main panel.")

        st.divider()

        col1, col2 = st.columns(2)
        with col1:
            st.metric("Total Logs Processed", st.session_state.stats['total_logs'])
            st.metric("Unique IP Addresses", len(st.session_state.stats['unique_ips']))
        with col2:
            st.metric("Total Alerts", len(st.session_state.events))
            severity_counts = dict(st.session_state.stats['alerts_by_severity'])
            if severity_counts:
                st.caption("Alert Distribution:")
                for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                    count = severity_counts.get(sev, 0)
                    if count > 0:
                        color = {
                            "CRITICAL": "#dc2626",
                            "HIGH": "#ea580c",
                            "MEDIUM": "#ca8a04",
                            "LOW": "#16a34a"
                        }.get(sev, "#6b7280")
                        st.markdown(
                            f'<div style="display: flex; justify-content: space-between; align-items: center; margin: 2px 0;">'
                            f'<span style="font-size: 0.8rem; color: {color}; font-weight: 600;">{sev}</span>'
                            f'<span style="font-size: 0.8rem; font-weight: 600;">{count}</span></div>',
                            unsafe_allow_html=True
                        )

        if st.session_state.timeline:
            with st.expander("Event Timeline"):
                for e in reversed(st.session_state.timeline[-10:]):
                    st.text(e)

    if mode == "IOC Lookup":
        if st.session_state.last_ioc:
            render_ioc_card(st.session_state.last_ioc['ioc'], st.session_state.last_ioc['type'], st.session_state.last_ioc['data'])
        else:
            st.info("Enter an IOC above to begin threat intelligence analysis.")

    elif mode == "Batch Analysis":
        uploaded = st.file_uploader(
            "Select log file (supports: syslog, apache, iis, json, csv, key=value, etc.)",
            type=["log", "txt", "csv", "json"]
        )

        if uploaded:
            st.session_state.events = []
            st.session_state.stats = {'total_logs': 0, 'unique_ips': set(), 'alerts_by_severity': Counter()}
            st.session_state.parser = UniversalLogParser()

            lines_total = 0
            for chunk in iter(lambda: uploaded.read(8192), b""):
                lines_total += chunk.count(b'\n')

            uploaded.seek(0)

            prog = st.progress(0)
            status = st.empty()

            line_num = 0
            for line_bytes in uploaded:
                line = line_bytes.decode("utf-8", errors="ignore").strip()
                if not line:
                    continue

                parsed = st.session_state.parser.parse_line(line)
                if parsed:
                    st.session_state.stats['total_logs'] += 1
                    ip = parsed.get('source_ip')
                    if ip:
                        st.session_state.stats['unique_ips'].add(ip)

                        if len(st.session_state.stats['unique_ips']) > Config.MAX_UNIQUE_IPS:
                            st.session_state.stats['unique_ips'] = set(
                                list(st.session_state.stats['unique_ips'])[-Config.MAX_UNIQUE_IPS//2:]
                            )

                    alerts = st.session_state.parser.analyze(parsed)
                    for a in alerts:
                        st.session_state.events.append(a)
                        st.session_state.stats['alerts_by_severity'][a['severity']] += 1

                        if len(st.session_state.events) > Config.MAX_STORED_ALERTS:
                            st.session_state.events = st.session_state.events[-Config.MAX_STORED_ALERTS:]

                line_num += 1
                if line_num % 100 == 0 or line_num == lines_total:
                    prog.progress(line_num / max(lines_total, 1))
                    status.text(f"Processing line {line_num}/{lines_total} | Alerts: {len(st.session_state.events)}")

            prog.empty()
            status.empty()

            st.success(f"Analysis complete. Processed ~{line_num} lines, detected {len(st.session_state.events)} security alerts.")

            if st.session_state.events:
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Total Alerts", len(st.session_state.events))
                c2.metric("Critical", st.session_state.stats['alerts_by_severity'].get('CRITICAL', 0))
                c3.metric("High", st.session_state.stats['alerts_by_severity'].get('HIGH', 0))
                c4.metric("Medium", st.session_state.stats['alerts_by_severity'].get('MEDIUM', 0))

                st.divider()

                severities = st.multiselect(
                    "Filter by Severity",
                    ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    default=["CRITICAL", "HIGH", "MEDIUM", "LOW"]
                )
                filtered = [a for a in st.session_state.events if a['severity'] in severities]

                st.subheader(f"Security Alerts ({len(filtered)} of {len(st.session_state.events)})")
                for alert in filtered:
                    render_alert_card(alert)

                export = [{
                    'id': a.get('id'),
                    'timestamp': (a['timestamp'].isoformat() if isinstance(a['timestamp'], datetime) else str(a['timestamp'])),
                    'severity': a.get('severity'),
                    'type': a.get('type'),
                    'source_ip': a.get('source_ip'),
                    'mitre': a.get('mitre'),
                    'details': a.get('details')
                } for a in st.session_state.events]

                st.download_button(
                    "Export to JSON",
                    json.dumps(export, indent=2),
                    f"alerts_{datetime.now():%Y%m%d_%H%M%S}.json"
                )
            else:
                st.info("No security alerts detected in the provided log file.")

    else:
        streamer = st.session_state.streamer

        if streamer and streamer.active:
            new_alerts, new_logs = streamer.get_pending_items()

            for alert in new_alerts:
                st.session_state.events.append(alert)
                st.session_state.stats['alerts_by_severity'][alert['severity']] += 1

            for log_item in new_logs:
                st.session_state.stats['total_logs'] += 1
                ip = log_item.get('data', {}).get('source_ip')
                if ip:
                    st.session_state.stats['unique_ips'].add(ip)

                    if len(st.session_state.stats['unique_ips']) > Config.MAX_UNIQUE_IPS:
                        st.session_state.stats['unique_ips'] = set(
                            list(st.session_state.stats['unique_ips'])[-Config.MAX_UNIQUE_IPS//2:]
                        )

            if len(st.session_state.events) > Config.MAX_STORED_ALERTS:
                st.session_state.events = st.session_state.events[-Config.MAX_STORED_ALERTS:]
                add_timeline(f"Alert buffer trimmed to {Config.MAX_STORED_ALERTS}")

        if st.session_state.events:
            st.subheader(f"Live Alert Feed ({len(st.session_state.events)} alerts)")

            severities = st.multiselect(
                "Filter by Severity",
                ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                default=["CRITICAL", "HIGH", "MEDIUM", "LOW"]
            )

            filtered = [a for a in st.session_state.events if a['severity'] in severities][-50:]
            for alert in reversed(filtered):
                render_alert_card(alert)
        else:
            st.info("Real-time stream is active. Alerts will appear here when detected.")
            st.caption("Monitoring for new log entries...")

        with st.expander("Event Timeline"):
            for e in reversed(st.session_state.timeline[-100:]):
                st.text(e)

        if streamer and streamer.active:
            time.sleep(1)
            st.rerun()

if __name__ == "__main__":
    main()
