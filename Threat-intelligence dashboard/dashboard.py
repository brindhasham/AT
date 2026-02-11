# Import Streamlit for creating the web UI framework
import streamlit as st
# Import pandas for data manipulation and DataFrame handling
import pandas as pd
# Import requests for making HTTP API calls to threat intel sources
import requests
# Import re for regular expression pattern matching (IOC detection)
import re
# Import base64 for encoding URLs for VirusTotal API
import base64
# Import json for parsing API responses and creating MISP export format
import json
# Import time for rate limiting functionality
import time
# Import logging for error tracking and debugging
import logging
# Import socket for IPv6 address normalization
import socket
# Import ThreadPoolExecutor and as_completed for parallel API requests
from concurrent.futures import ThreadPoolExecutor, as_completed
# Import wraps for preserving function metadata in decorators
from functools import wraps

# CONFIGURATION SECTION

# Configure logging to show INFO level messages and above in console/output
logging.basicConfig(level=logging.INFO)
# Configure Streamlit page with title "ThreatFeed" and wide layout for more space
st.set_page_config(page_title="ThreatFeed", layout="wide")
# Define rate limits per minute for each API source (requests per minute)
RATES, LAST = {"vt": 4, "abuse": 5, "otx": 60, "haus": 10}, {}
# vt = VirusTotal (4/min), abuse = AbuseIPDB (5/min), otx = AlienVault OTX (60/min), haus = URLhaus (10/min)
# LAST dictionary will store timestamps of last API calls for rate limiting
# Create lambda function to retrieve API keys from Streamlit secrets manager
KEY = lambda k: st.secrets.get(k, "")
# Returns empty string if key not found, preventing crashes

# RATE LIMITING DECORATOR

def rate_lim(s):
    # Define decorator factory that takes source name 's' (e.g., "vt", "abuse")
    def d(f):
        # Inner decorator that takes the function to be wrapped 'f'
        @wraps(f)
        # Preserve original function name and docstring
        def w(*a, **k):
            # Wrapper function accepts any positional (*a) and keyword (**k) arguments
            n = 60 / RATES.get(s, 60)
            # Calculate minimum seconds between requests (60 seconds / rate limit)
            # Default to 60 if source not in RATES (1 request per minute)
            if s in LAST and time.time() - LAST[s] < n:
                # Check if we've called this source before AND time since last call is less than required interval
                time.sleep(n - (time.time() - LAST[s]))
                # Sleep for remaining time needed to respect rate limit
            LAST[s] = time.time()
            # Record current timestamp as last call time for this source
            return f(*a, **k)
            # Call and return result of original function with original arguments
        return w
        # Return the wrapper function
    return d
    # Return the decorator

# HTTP REQUEST HELPER

def req(url, h=None, d=None, m="GET", t=10, params=None):
    # Generic HTTP request function with error handling
    # url: endpoint URL, h: headers dict, d: data/body, m: HTTP method, t: timeout, params: URL parameters
    try:
        # Begin exception handling block
        r = requests.request(m, url, headers=h, data=d, params=params, timeout=t)
        # Execute HTTP request with all provided parameters
        r.raise_for_status()
        # Raise HTTPError if response status is 4xx or 5xx
        return {"ok": True, "data": r.json()}
        # Return success dict with parsed JSON response
    except Exception as e:
        # Catch any exception (network, parsing, HTTP errors)
        logging.error(f"{url}: {e}")
        # Log the error with URL for debugging
        return {"ok": False, "error": str(e)[:100]}
        # Return failure dict with truncated error message

# IOC TYPE DETECTION

@st.cache_data(ttl=300)
# Cache results for 5 minutes (300 seconds) to avoid re-detecting same IOCs
def detect(ioc):
    # Function to automatically identify type of Indicator of Compromise
    i = ioc.strip().lower()
    # Normalize input: remove whitespace, convert to lowercase for consistent matching
    # IPv4 DETECTION: Match standard dotted decimal format (0-255).(0-255).(0-255).(0-255)
    if re.match(r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$", i):
        # 25[0-5] = 250-255, 2[0-4]\d = 200-249, 1\d\d = 100-199, [1-9]?\d = 0-99
        return "ip4", i
        # Return type "ip4" and normalized value
    
    # IPv6 DETECTION: Multiple regex patterns for different compression formats
    # Full format: 8 groups of 4 hex digits separated by colons
    if re.match(r"^(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}$", i) or \
       # Double colon compression with prefix and suffix (:: in middle)
       re.match(r"^([0-9a-f]{1,4}:){0,7}::([0-9a-f]{1,4}:){0,7}[0-9a-f]{1,4}$", i) or \
       # Trailing double colon (ends with ::)
       re.match(r"^([0-9a-f]{1,4}:){1,7}:$", i) or \
       # Leading double colon (starts with ::)
       re.match(r"^::([0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}$", i) or \
       # 7 groups then single hex (one group compressed)
       re.match(r"^([0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}$", i) or \
       # 6 groups + 2 compressed groups
       re.match(r"^([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}$", i) or \
       # 5 groups + 3 compressed groups
       re.match(r"^([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}$", i) or \
       # 4 groups + 4 compressed groups
       re.match(r"^([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}$", i) or \
       # 3 groups + 5 compressed groups
       re.match(r"^([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}$", i) or \
       # 1 group + 6 compressed groups
       re.match(r"^[0-9a-f]{1,4}:(:[0-9a-f]{1,4}){1,6}$", i) or \
       # Pure compressed form with leading ::
       re.match(r"^::([0-9a-f]{1,4}:){0,5}[0-9a-f]{1,4}$", i):
        # If any IPv6 pattern matches, attempt to normalize using socket library
        try:
            normalized = socket.inet_ntop(socket.AF_INET6, socket.inet_pton(socket.AF_INET6, i))
            # inet_pton parses IPv6 string to binary, inet_ntop converts back to standard string format
            return "ip6", normalized.lower()
            # Return type "ip6" with normalized lowercase address
        except:
            # If normalization fails (invalid IPv6 that passed regex), return as-is
            return "ip6", i
    
    # HASH DETECTION: MD5, SHA1, SHA256 by exact length
    if re.match(r"^[a-f0-9]{32}$", i):
        # Exactly 32 hex characters = MD5 hash
        return "md5", i
    if re.match(r"^[a-f0-9]{40}$", i):
        # Exactly 40 hex characters = SHA1 hash
        return "sha1", i
    if re.match(r"^[a-f0-9]{64}$", i):
        # Exactly 64 hex characters = SHA256 hash
        return "sha256", i
    
    # URL DETECTION: Starts with http (covers http:// and https://)
    if i.startswith("http"):
        return "url", i.rstrip("/").lower()
        # Remove trailing slash for consistency, lowercase
    
    # DOMAIN DETECTION: Contains dot but no slash (simple heuristic)
    if "." in i and "/" not in i:
        return "domain", i
        # Could be domain or subdomain
    
    # Fallback for unrecognized formats
    return "unknown", i

# API QUERY FUNCTIONS (all decorated with rate limiting)

@rate_lim("abuse")
# Apply 5 requests/minute rate limit
def abuse_q(i):
    # Query AbuseIPDB for IP reputation data
    return req("https://api.abuseipdb.com/api/v2/check",
               {"Key": KEY("ABUSE_KEY")},  # API key header
               None,  # No request body
               "GET",
               params={"ipAddress": i, "maxAgeInDays": 90})  # Check reports from last 90 days

@rate_lim("otx")
# Apply 60 requests/minute rate limit
def otx_q(i, t):
    # Query AlienVault OTX for various IOC types
    ep = {"ip4": f"IPv4/{i}", "ip6": f"IPv6/{i}", "domain": f"domain/{i}",
          "md5": f"file/{i}", "sha1": f"file/{i}", "sha256": f"file/{i}"}
    # Map internal types to OTX API endpoint paths
    return req(f"https://otx.alienvault.com/api/v1/indicators/{ep.get(t)}/general",
               {"X-OTX-API-KEY": KEY("OTX_KEY")}) if ep.get(t) else {"ok": False, "error": "unsupported"}
    # Return error if IOC type not supported by OTX

@rate_lim("vt")
# Apply 4 requests/minute rate limit (most restrictive)
def vt_q(i, t):
    # Query VirusTotal for comprehensive malware/reputation data
    ep = {"ip4": f"ip_addresses/{i}", "ip6": f"ip_addresses/{i}",
          "domain": f"domains/{i}", "md5": f"files/{i}", "sha1": f"files/{i}",
          "sha256": f"files/{i}",
          "url": f"urls/{base64.urlsafe_b64encode(i.encode()).decode().strip('=')}"}
    # VirusTotal requires URL-safe base64 encoding for URL lookups, no padding
    return req(f"https://www.virustotal.com/api/v3/{ep.get(t)}",
               {"x-apikey": KEY("VT_KEY")})

@rate_lim("haus")
# Apply 10 requests/minute rate limit
def urlhaus_q(u):
    # Query URLhaus for malicious URL data
    return req("https://urlhaus-api.abuse.ch/v1/url/",
               {"Auth-Key": KEY("URLHAUS_KEY")},
               {"url": u},  # POST body with URL to check
               "POST")

# MAIN ENRICHMENT ORCHESTRATION

@st.cache_data(ttl=300)
# Cache enrichment results for 5 minutes
def enrich(ioc_raw):
    # Main function to gather threat intelligence from all relevant sources
    t, i, log, r = *detect(ioc_raw), [], {}
    # Unpack detection result (type, normalized_value), initialize log list and results dict
    
    if t == "unknown":
        # Early return if we can't identify the IOC type
        return t, i, {}, 0, log, [{"source": "error", "value": "Unknown IOC type", "ok": False}]
    
    with ThreadPoolExecutor(4) as e:
        # Create thread pool with 4 workers for parallel API calls
        f = {}
        # Dictionary to store future objects
        
        # Select appropriate APIs based on IOC type
        if t in ("ip4", "ip6"):
            # IPs: query AbuseIPDB, OTX, and VirusTotal
            f = {"abuse": e.submit(abuse_q, i), "otx": e.submit(otx_q, i, t), "vt": e.submit(vt_q, i, t)}
        elif t in ("md5", "sha1", "sha256"):
            # Hashes: OTX and VirusTotal (file reputation)
            f = {"otx": e.submit(otx_q, i, t), "vt": e.submit(vt_q, i, t)}
        elif t == "domain":
            # Domains: OTX and VirusTotal
            f = {"otx": e.submit(otx_q, i, t), "vt": e.submit(vt_q, i, t)}
        elif t == "url":
            # URLs: VirusTotal and URLhaus
            f = {"vt": e.submit(vt_q, i, t), "haus": e.submit(urlhaus_q, i)}
        
        # Collect results as they complete
        for k, fu in f.items():
            try:
                r[k] = fu.result(timeout=15)
                # Wait up to 15 seconds for each API call
                log.append(f"✓ {k}")
                # Record success
            except Exception as e:
                r[k] = {"ok": False, "error": str(e)}
                # Store error result
                log.append(f"✗ {k}: {e}")
                # Record failure
    
    # CALCULATE RISK SCORE (0-100+ scale)
    s = sum([
        # AbuseIPDB: abuse confidence score 0-100
        (r.get("abuse", {}).get("data", {}).get("data", {}).get("abuseConfidenceScore", 0) if r.get("abuse", {}).get("ok") else 0),
        # VirusTotal: (malicious + suspicious detections) * 10, capped effectively at ~70+
        ((r.get("vt", {}).get("data", {}).get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0) +
          r.get("vt", {}).get("data", {}).get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("suspicious", 0)) * 10 if r.get("vt", {}).get("ok") else 0),
        # OTX: pulse count * 5 (community threat intelligence mentions)
        (r.get("otx", {}).get("data", {}).get("pulse_info", {}).get("count", 0) * 5 if r.get("otx", {}).get("ok") else 0),
        # URLhaus: binary 50 points if known malicious
        (50 if r.get("haus", {}).get("data", {}).get("query_status") == "ok" else 0)
    ])
    
    # Helper to extract display-friendly value from each source result
    def get_value(k, v):
        if not v.get("ok"):
            return v.get("error", "failed")
        if k == "abuse":
            return v.get("data", {}).get("data", {}).get("abuseConfidenceScore", 0)
        elif k == "vt":
            return v.get("data", {}).get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
        elif k == "otx":
            return v.get("data", {}).get("pulse_info", {}).get("count", 0)
        elif k == "haus":
            qs = v.get("data", {}).get("query_status", "unknown")
            if qs == "ok":
                return "MALICIOUS"  # Known bad URL
            elif qs == "no_results":
                return "CLEAN"  # Not in database
            else:
                return qs  # Other status
        return "unknown"
    
    # Return: type, normalized value, raw results, score, log, formatted list for UI
    return t, i, r, int(s), log, [{"source": k, "value": get_value(k, v), "ok": v.get("ok")} for k, v in r.items()]

# MISP EXPORT FUNCTION

def misp_exp(ioc, t, s, r):
    # Generate MISP (Malware Information Sharing Platform) compatible JSON export
    lvl = "1" if s > 100 else "2" if s > 50 else "3" if s > 20 else "4"
    # Map score to MISP threat level: 1=high, 2=medium, 3=low, 4=undefined
    
    return json.dumps({
        "Event": {
            "info": f"TI: {ioc}",  # Event title
            "threat_level_id": lvl,  # Calculated threat level
            "Attribute": [
                # Primary IOC attribute
                {
                    "type": {"ip4": "ip-dst", "ip6": "ip-dst", "md5": "md5", "sha1": "sha1",
                            "sha256": "sha256", "domain": "domain", "url": "url"}.get(t, "text"),
                    "value": ioc,
                    "to_ids": s > 50,  # Generate IDS rules only for high-risk IOCs
                    "comment": f"Risk: {s}"
                }
            ] + [
                # Additional comment attributes for each source result
                {"type": "comment", "value": f"{k}: {v.get('data') if v.get('ok') else v.get('error', 'failed')}"}
                for k, v in r.items()
            ]
        }
    }, indent=2)

# UI COLOR HELPER

def card_col(v, o):
    # Determine background color for source result cards
    if not o:
        return "#6c757d"  # Gray for failed/offline sources
    try:
        n = float(v)
        # Numeric values: red (>50), orange (>20), yellow (>0), green (0)
        return "#dc3545" if n > 50 else "#fd7e14" if n > 20 else "#ffc107" if n > 0 else "#28a745"
    except:
        # String values: map semantic meanings
        v_str = str(v).lower()
        if v_str in ["malicious"]:
            return "#dc3545"  # Red
        elif v_str in ["clean", "no_results"]:
            return "#28a745"  # Green
        elif v_str in ["suspicious"]:
            return "#fd7e14"  # Orange
        else:
            return "#6c757d"  # Gray default

# STREAMLIT UI SECTION

st.title("🛡️ ThreatFeed Dashboard")
# Main application title with shield emoji
st.caption("Secure multi-source threat intelligence")
# Subtitle description

# Input widgets: text field and bulk mode toggle
ioc, bulk = st.text_input(
    "Drop any IOC (IP / domain / URL / hash)",
    placeholder="8.8.8.8 | example.com | https://evil.com | hash..."
), st.toggle("Bulk mode (one per line)")

if ioc:
    # Only process if user entered something
    for i in (ioc.split("\n") if bulk else [ioc])[:5]:
        # Split by newline if bulk mode, else single item; limit to 5 max
        i = i.strip()
        if not i:
            continue  # Skip empty lines
        
        with st.spinner(f"Analyzing {i[:40]}..."):
            # Show loading indicator while enriching
            t, norm, res, score, log, enrich_list = enrich(i)
        
        # Determine severity color and label based on score
        col = "#dc3545" if score > 100 else "#fd7e14" if score > 50 else "#ffc107" if score > 20 else "#28a745"
        sev = "CRITICAL" if score > 100 else "HIGH" if score > 50 else "MEDIUM" if score > 20 else "LOW"
        
        with st.container():
            # Create visual card with left border color
            st.markdown(f'<div style="border-left:4px solid {col};padding-left:1rem;margin:1rem 0">', unsafe_allow_html=True)
            
            # Four-column layout for header info
            c1, c2, c3, c4 = st.columns([2, 1, 1, 2])
            
            # Column 1: IOC value (truncated), type, and normalized form
            c1.markdown(f"**{i[:60]}{'...' if len(i) > 60 else ''}**<br>`{t.upper()}` | `{norm}`", unsafe_allow_html=True)
            
            # Column 2: Numeric risk score metric
            c2.metric("Risk", score)
            
            # Column 3: Severity label with color
            c3.markdown(f'<span style="color:{col};font-size:1.5rem;font-weight:bold">{sev}</span>', unsafe_allow_html=True)
            
            # Column 4: MISP export download button
            with c4:
                st.download_button("⬇ MISP", misp_exp(i, t, score, res), f"misp_{norm[:20]}.json", use_container_width=True)
            
            # Source result cards row
            if enrich_list:
                ec = st.columns(len(enrich_list))
                # Create equal columns for each source
                for idx, e in enumerate(enrich_list):
                    with ec[idx]:
                        bg = card_col(e["value"], e["ok"])
                        # Get appropriate background color
                        st.markdown(
                            f'<div style="background:{bg};color:white;padding:0.8rem;border-radius:0.5rem;text-align:center">'
                            f'<b>{e["source"].upper()}</b><br>'
                            f'<span style="font-size:1.3rem">{e["value"]}</span></div>',
                            unsafe_allow_html=True
                        )
            
            # Expandable section with raw JSON and processing log
            with st.expander("Details"):
                st.json(res)  # Pretty-printed API responses
                st.write("Timeline:", log)  # Success/failure sequence
            
            st.markdown('</div>', unsafe_allow_html=True)  # Close card div

# SIDEBAR: Live threat feed

st.sidebar.header("📡 Live C2 Feed (Feodo Tracker)")
try:
    # Attempt to fetch current Feodo Tracker botnet C2 list
    st.sidebar.dataframe(
        pd.DataFrame(
            requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json", timeout=10).json()
        ).head(10)  # Show top 10 entries
    )
except:
    st.sidebar.error("Feed unavailable")  # Graceful degradation if feed down
