
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

---

## **Built-in Security Controls**
- **Path traversal prevention — Resolves symlinks and validates against allowed directory whitelist**
- **System path blocking — Denies access to /etc, /proc, /sys, /dev, /root, /boot, /sbin, /bin**
- **File size limits — Rejects files exceeding 10 GB**
- **Rate limiting — Per-source API rate limiting with thread-safe locking**
- **Input validation — IOC type verification before API submission**
- **Queue overflow protection — Bounded queues with oldest-entry eviction**


## **Supported Log Formats**


| **Format** | **Example** |
|--------|---------|
| **Syslog RFC 3164** | **Jan 15 14:23:01 server sshd[1234]: Failed password for root from 192.168.1.100 port 22** |
| **Syslog RFC 5424** | **<34>1 2024-01-15T14:23:01.000Z server sshd 1234 - - Failed password for root** |
| **Apache Combined** | **192.168.1.1 - admin [15/Jan/2024:14:23:01 +0000] "GET /admin HTTP/1.1" 401 512 "-" "Mozilla/5.0"** |
| **IIS W3C** | **2024-01-15 14:23:01 192.168.1.1 GET /login - 443 admin 10.0.0.1 Mozilla/5.0 - 200 0 0** |
| **Windows Event** | **01/15/2024 02:23:01 PM Error Security 4625 Logon user1 An account failed to log on** |
| **Cisco ASA** | **Jan 15 2024 14:23:01 firewall-1 : %ASA-4-106023: Deny tcp src inside:10.0.0.1** |
| **JSON Structured** | **{"timestamp": "2024-01-15T14:23:01Z", "src_ip": "192.168.1.1", "message": "Failed login"}** |
| **Heuristic Fallback** | **Any text containing recognizable IPs, timestamps, or security keywords** |


**All parsed output is normalized into a consistent schema:**

```python
{
    'timestamp': datetime,       # Parsed or current time
    'source_ip': str | None,     # Extracted source IP address
    'username': str | None,      # Extracted username
    'message': str,              # Log message content
    'event_type': str,           # Classified event type
    'format': str,               # Detected log format name
    'status_code': int | None,   # HTTP status or severity level
    'raw': str                   # Original unmodified log line
}
```

## ** Detection Rules**

| **Rule** | **Trigger** | **Severity** | **MITRE ID** |
|----------|-------------|--------------|--------------|
| **Brute Force (Low)** | **≥5 failed auth from same IP in 5 min** | **MEDIUM** | **T1110** |
| **Brute Force (Med)** | **≥10 failed auth from same IP in 5 min** | **HIGH** | **T1110** |
| **Brute Force (High)** | **≥20 failed auth from same IP in 5 min** | **CRITICAL** | **T1110** |
| **Lockout Bypass** | **Successful login after ≥3 failures from same IP** | **CRITICAL** | **T1078** |
| **Cross-IP Compromise** | **Successful login from new IP after failures from different IP** | **CRITICAL** | **T1078** |
| **Post-Failure Login** | **Successful login from IP with ≥3 prior failures** | **HIGH** | **T1078** |
| **SQL Injection** | **SELECT+, UNION+ in HTTP path** | **CRITICAL** | **T1059** |
| **XSS Attack** | **<SCRIPT in HTTP path** | **CRITICAL** | **T1059** |
| **Path Traversal** | **../../ in HTTP path** | **CRITICAL** | **T1059** |
| **Fake Crawler** | **Googlebot UA from non-Google IP** | **MEDIUM** | **T1071** |
| **Web Auth Brute Force** | **20× HTTP 401/403 from same IP in 5 min** | **HIGH** | **T1110** |

| **Score Range** | **Severity** | **Recommended Action** |
|-----------------|--------------|------------------------|
| **80 – 100** | **🔴 CRITICAL** | **BLOCK — Immediate Action Required** |
| **50 – 79** | **🟠 HIGH** | **INVESTIGATE — Review Recommended** |
| **20 – 49** | **🟡 MEDIUM** | **MONITOR — Track Activity** |
| **0 – 19** | **🟢 CLEAN** | **BENIGN — No Action Needed** |

## Installation

### Prerequisites

- **Python 3.8 or higher**
- **pip package manager**

```

python -m venv venv
source venv/bin/activate        # Linux / macOS

# Install dependencies
pip install -r requirements.txt (streamlit, pandas, requests, python-dateutil)
```
**Obtain free API keys from:**

| **Service** | **Registration URL** |
|-------------|----------------------|
| **VirusTotal** | **https://www.virustotal.com/gui/join-us** |
| **AbuseIPDB** | **https://www.abuseipdb.com/register** |
| **AlienVault OTX** | **https://otx.alienvault.com/api** |
| **URLhaus** | **https://urlhaus.abuse.ch/api/** |


3. **To configure API keys**
   
- `mkdir -p .streamlit`

- `nano .streamlit/secrets.toml`

`VT_KEY = "virustotal_api_key"`
   
`ABUSE_KEY = "abuseipdb_api_key"`
   
`OTX_KEY = "alienvault_otx_api_key"`
    
`URLHAUS_KEY = "urlhaus_api_key"`

### Run the application
```streamlit run logsentinel.py```

## **Usage**

### **Mode 1: Batch Analysis**

- **Best for analyzing historical log files and incident investigation**
- **Upload file containing log in recommended format and analyze**
**Sample working:**

  <source src="https://raw.githubusercontent.com/brindhasham/l_analysis/main/LogSentinel-%20Real%20Time%20Log%20Monitoring%20%26%20Threat%20Detection%20system/screenshare/streamlit-log__pp-2026-02-17-14-28-17-ezgif.com-video-to-mp4-converter.mp4" type="video/mp4">
</video>



