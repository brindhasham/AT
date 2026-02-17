
#  LogSentinel Professional- Real Time Log Monitoring & Threat Detection system

**A comprehensive SOC Log Detection & Threat Intelligence Platform built with Python and Streamlit.**

**LogSentinel Professional combines universal log parsing, behavioral threat detection, and multi-source threat intelligence enrichment into a single deployable web application designed for security analysts, incident responders, and SOC teams.**

---

## **General features**

- **Auto-detection of 10+ log formats with zero manual configuration**
- **Real-time Detection: Identifies threats as they happen with streaming analysis**
- **Threat Intelligence: Enriches IOCs with data from VirusTotal, AbuseIPDB, OTX, and URLhaus**
- **Attack Correlation: Connects related events to detect sophisticated multi-stage attacks**
- **Zero Infrastructure: Runs entirely in browser—no database or backend required**

---

## **Security features**

| **Feature**                      | **Description**                                                                                     |
| -------------------------------- | --------------------------------------------------------------------------------------------------- |
| **Multi-Format Log Parsing**     | **Automatically detects and parses Syslog, Apache, IIS, JSON, Windows Events, Cisco ASA, and more** |
| **Real-Time Streaming**          | **Monitor log files continuously with live alert generation**                                       |
| **Brute Force Detection**        | **Identifies password guessing attacks with configurable thresholds**                               |
| **Account Compromise Detection** | **Detects successful logins following failed attempts**                                             |
| **Web Attack Detection**         | **Identifies SQL injection, XSS, directory traversal, and other web attacks**                       |
| **Correlation Engine**           | **Links related events to detect multi-stage attack chains**                                        |
| **MITRE ATT&CK Mapping**         | **All detections mapped to MITRE ATT&CK framework techniques**                                      |

---

## **Multi-Source Threat Intelligence Enrichment**

- **VirusTotal — File hash, IP, domain, and URL reputation scoring across 70+ AV engines**
- **AbuseIPDB — IP abuse confidence scoring, geolocation, ISP identification, and report history**
- **OTX AlienVault — Community-driven pulse/threat feed correlation**
- **URLhaus (abuse.ch) — Malware URL database lookup for active threat identification**

---

**Dashboard & Visualization**

**Interactive Dashboard: Real-time alert feeds**
**Severity-Based Filtering: Focus on critical, high, medium, or low severity alerts**
**Event Timeline: Chronological view of all security events**
**IOC Cards: Rich visualization of threat intelligence results**
**Export Capabilities: JSON, MISP format, and text exports**

---

## **Three Operation Modes**

| **Mode** | **Description** |
|------|-------------|
| **Batch Analysis** | **Upload and analyze complete log files** (**up to 1M lines**) with **progress tracking** |
| **Real-time Stream** | **Tail live log files with** **continuous monitoring**, **threaded processing**, and **automatic alert generation** |
| **IOC Lookup** | **Instant threat intelligence enrichment** for any **indicator of compromise** |

---

## **Supported Log Formats**

| **Format**          | **Example**                                                                                  |
| ------------------- | -------------------------------------------------------------------------------------------- |
| **Syslog RFC3164**  | **Jan 15 10:30:45 server sshd[1234]: message**                                               |
| **Syslog RFC5424**  | **<34>1 2024-01-15T10:30:45.123Z server app 1234 ID47 - message**                            |
| **Apache Combined** | **192.168.1.1 - user [15/Jan/2024:10:30:45 +0000] "GET /path HTTP/1.1" 200 1234 "ref" "ua"** |
| **IIS W3C**         | **2024-01-15 10:30:45 192.168.1.1 GET /path - 80 - 10.0.0.1 Mozilla/5.0 - 200 0 0**          |
| **Windows Event**   | **01/15/2024 10:30:45 AM Information Source 1234 Category User Message**                     |
| **Cisco ASA**       | **Jan 15 2024 10:30:45 firewall : %ASA-6-302013: message**                                   |
| **JSON Logs**       | **{"timestamp": "2024-01-15T10:30:45Z", "level": "error", "message": "..."}**                |
| **Heuristic**       | **Any text containing timestamps, IPs, or security keywords**                                |


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





