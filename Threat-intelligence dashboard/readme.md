#  Threat Intelligence Analyzer Dashboard

**A multi-source IOC (Indicator of Compromise) enrichment and risk assessment platform built with Streamlit. Aggregates intelligence from VirusTotal, AbuseIPDB, AlienVault OTX, URLhaus, and Feodo Tracker into a single unified interface.**

---

## Description

**This platform accepts various types of threat indicators and queries multiple threat intelligence APIs concurrently, producing a consolidated risk score and exportable MISP-format reports.**

### Supported IOC Types

| Type       | Example                                    |
|------------|--------------------------------------------|
| IPv4       | `8.8.8.8`                                  |
| IPv6       | `2001:4860:4860::8888`                     |
| Domain     | `zonetransfer.org`                              |
| URL        | `https://monolith.stone48tyranny.coupons/webclient`       |
| MD5 Hash   | `d41d8cd98f00b204e9800998ecf8427e`         |
| SHA1 Hash  | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| SHA256 Hash| `e3b0c44298fc1c149afbf4c8996fb92427ae41e...`|

### Intelligence Sources

| Source          | Covers                        | API Key Required |
|-----------------|-------------------------------|------------------|
| VirusTotal* | IPs, Domains, URLs, Hashes    |    Yes           |
| AbuseIPDB**   | IPv4, IPv6                    |    Yes           |
| AlienVault OTX| IPs, Domains, Hashes       |    Yes           |
| URLhaus    | URLs                          |    Yes           |
| Feodo Tracker | C2 Blocklist (sidebar feed) |    No            |

### Key Features

- **Auto-detection — Automatically identifies IOC type from input**
- **Concurrent enrichment** — Queries all relevant sources in parallel using `ThreadPoolExecutor` **
- **Risk scoring — Computes a composite risk score across all sources**
- **Severity classification — Critical / High / Medium / Low**
- **Bulk analysis — Process up to 5 IOCs simultaneously**
- **MISP export — Download results as MISP-compatible JSON events**
- **Rate limiting — Built-in per-source rate limiting to avoid API bans**
- **Response caching — 5-minute TTL cache to reduce redundant API calls**
- **Live threat feed — Feodo Tracker C2 blocklist displayed in the sidebar**

---

## Logic
### Risk Scoring Logic
**Score = AbuseIPDB Confidence Score (0-100)**
      **+ (VT Malicious + VT Suspicious detections) × 10**
      **+ OTX Pulse Count × 5**
      **+ URLhaus Match (50 if found)**

| Score range     | Severity                                   |
|------------|--------------------------------------------|
| > 100      | Critical                                |
| 51 – 100  | High      |
| 21 – 50  | Medium|
| 0 – 20| Low|    

**Rate Limits**

**Built-in rate limiting prevents API throttling:**

| Source      | Requests / Minute                                   |
|------------|--------------------------------------------|
| VirusTotal       | 4                                |
| AbuseIPDB       | 4                 |
| AlienVault OTX     | 60                              |
| URLhaus      | 10      |

##  Requirements

### System

- **Python 3.9+**

### Python Packages

- **Streamlit, pandas, requests**

### 
All other imports (`re`, `base64`, `json`, `time`, `logging`, `socket`,
`concurrent.futures`, `functools`) are part of the Python standard library.

### API Keys

Obtain free API keys from:

| Service      | Registration URL                                   |
|----------------|---------------------------------------------------------| 
|VirusTotal   | https://www.virustotal.com/gui/join-us           |
|AbuseIPDB    | https://www.abuseipdb.com/register                  |
| AlienVault OTX | https://otx.alienvault.com/api                 |
|URLhaus      | https://urlhaus.abuse.ch/api/                       |

---

##  Installation & Running

1. **Created virtual environment:**
`python -m venv venv`

  **Linux**
`source venv/bin/activate`

2. **To install dependencies, `pip install -r requirements.txt` (Streamlit, pandas, requests)**
3. **To configure API keys**
   
`mkdir -p .streamlit`

`nano .streamlit/secrets.toml`


`VT_KEY = "virustotal_api_key"`
   
`ABUSE_KEY = "abuseipdb_api_key"`
   
`OTX_KEY = "alienvault_otx_api_key"`
    
`URLHAUS_KEY = "urlhaus_api_key"`

4. **To run the application**

`streamlit run dashboard.py`

**The application opens at http://localhost:8501 by default**

 **Usage**
**Single IOC Analysis**

- **Ensure Bulk Mode toggle is OFF**
- **Enter an indicator in the input field (e.g., 8.8.8.8)**
- **Click Analyze**
- **Review the risk score, severity, and per-source results**
- **Expand Technical Details for raw API responses**
- **Click Export MISP to download the JSON report**

**Bulk Analysis**

- **Enable the Bulk Mode toggle**
- **Enter up to 5 indicators, one per line**
- **Click Analyze**
- **Each indicator is enriched and displayed as a separate card**

**Sample Working**




![](https://github.com/brindhasham/l_analysis/blob/main/Threat-intelligence%20dashboard/screenshare/Threat-intelligencedashboard_screenshare_streamlit-dashboardpy.gif)

