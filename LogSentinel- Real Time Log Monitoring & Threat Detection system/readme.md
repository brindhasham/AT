
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

**Mode 1: Batch Analysis**

**How to Use**

- **Select "Batch Analysis" from the sidebar**
- **Upload log file using the file uploader (supports .log, .txt, .csv, .json)**
- **Wait for processing - progress bar shows analysis status**
- **Review alerts - filter by severity (CRITICAL, HIGH, MEDIUM, LOW)**
- **Export results - download alerts as JSON**

**Mode 2: Real-time Monitoring**

**Monitor log files in real-time for live threat detection.**

**Directory Configuration**

**By default, monitoring is restricted to these directories:**

**~/logs**
**/var/log/app**
**/opt/logsentinel**

**How to Use**

- **Select "Real-time Stream" from the sidebar**
- **Enter log file path (e.g., ~/logs/auth.log)**
- **Click "Start Stream" to begin monitoring**
- **Watch live alerts appear as threats are detected**
- **Click "Stop Stream" when finished**

**Mode 3: IOC Enrichment Analyzer**

**Enrich Indicators of Compromise (IOCs) with threat intelligence from multiple sources.**

| **Type**         | **Format**          | **Example**                                                            |
| ---------------- | ------------------- | ---------------------------------------------------------------------- |
| **IPv4 Address** | **x.x.x.x**         | **`8.8.8.8`**                                                          |
| **IPv6 Address** | **Full/compressed** | **`2001:4860:4860::8888`**                                             |
| **Domain**       | **FQDN**            | **`zonetransfer.org`**                                                 |
| **URL**          | **Full URL**        | **`https://monolith.stone48tyranny.coupons/webclient`**                |
| **MD5 Hash**     | **32 hex chars**    | **`d41d8cd98f00b204e9800998ecf8427e`**                                 |
| **SHA1 Hash**    | **40 hex chars**    | **`da39a3ee5e6b4b0d3255bfef95601890afd80709`**                         |
| **SHA256 Hash**  | **64 hex chars**    | **`50e82acecc7e468cf9c9be676d01ae0c07bf9e2629078f0fdaaf7493befb6ba1`** |




