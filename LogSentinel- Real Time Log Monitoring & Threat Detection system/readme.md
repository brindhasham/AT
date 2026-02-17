
#  LogSentinel Professional- Real Time Log Monitoring & Threat Detection system

**A comprehensive SOC Log Detection & Threat Intelligence Platform built with Python and Streamlit.**

**LogSentinel Professional combines universal log parsing, behavioral threat detection, and multi-source threat intelligence enrichment into a single deployable web application designed for security analysts, incident responders, and SOC teams.**

---

## **Universal Log Parsing**

- **Auto-detection of 7+ log formats with zero manual configuration**
- **Regex-based pattern matching with intelligent fallback to heuristic parsing**
- **Automatic field normalization (timestamps, IPs, usernames, messages) across all formats**
- **JSON structured log ingestion with flexible field mapping (30+ field name variants)**
- **Format statistics tracking for log source visibility**

---

## **Behavioral Threat Detection Engine**

- **Brute Force Detection — Sliding-window analysis tracking failed authentication attempts per IP with escalating severity thresholds (5/10/20 attempts → MEDIUM/HIGH/CRITICAL)**
- **Account Compromise Detection- Correlates successful logins following failed attempts, detecting bothsame-IP lockout bypass and cross-IP attack patterns**
- **Web Application Attack Detection — Identifies SQL injection, XSS, path traversal, and other injection patterns in HTTP request paths**
- **Fake Crawler Detection — Flags requests claiming to be Googlebot from non-Google IP ranges**
- **Web Auth Brute Force — Tracks HTTP 401/403 response floods per source IP**
- **MITRE ATT&CK Mapping — Every alert is tagged with the corresponding MITRE technique ID**

---

## **Multi-Source Threat Intelligence Enrichment**

- **VirusTotal — File hash, IP, domain, and URL reputation scoring across 70+ AV engines**
- **AbuseIPDB — IP abuse confidence scoring, geolocation, ISP identification, and report history**
- **OTX AlienVault — Community-driven pulse/threat feed correlation**
- **URLhaus (abuse.ch) — Malware URL database lookup for active threat identification**
- **Automatic IOC type detection (IPv4/IPv6, MD5, SHA1, SHA256, domain, URL)**
- **Unified risk scoring (0–100) with severity classification**
- **Result caching with configurable TTL to minimize API calls**

---

## **Three Operation Modes**

| **Mode** | **Description** |
|------|-------------|
| **Batch Analysis** | **Upload and analyze complete log files** (**up to 1M lines**) with **progress tracking** |
| **Real-time Stream** | **Tail live log files with** **continuous monitoring**, **threaded processing**, and **automatic alert generation** |
| **IOC Lookup** | **Instant threat intelligence enrichment** for any **indicator of compromise** |

---

## **Interactive Dashboard**

- **Real-time metrics (total logs, unique IPs, alert counts, severity distribution)**
- **Filterable alert feed with severity-based color coding**
- **Expandable raw log viewer for forensic investigation**
- **Event timeline with millisecond-precision timestamps**
- **One-click export to JSON and MISP format**
- **Direct pivot links to VirusTotal, AbuseIPDB, and URLhaus**
