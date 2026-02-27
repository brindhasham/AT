import streamlit as st, pandas as pd, requests, re, base64, json, time, logging, socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps

# Config
logging.basicConfig(level=logging.INFO)
st.set_page_config(page_title="Threat Intelligence Platform", layout="wide", initial_sidebar_state="expanded")
RATES, LAST = {"vt": 4, "abuse": 5, "otx": 60, "haus": 10}, {}
KEY = lambda k: st.secrets.get(k, "")

#Rate limiting
def rate_lim(s):
    def d(f):
        @wraps(f)
        def w(*a, **k):
            n = 60 / RATES.get(s, 60)
            if s in LAST and time.time() - LAST[s] < n: time.sleep(n - (time.time() - LAST[s]))
            LAST[s] = time.time()
            return f(*a, **k)
        return w
    return d

# Request Function
def req(url, h=None, d=None, m="GET", t=10, params=None):
    try: r = requests.request(m, url, headers=h, data=d, params=params, timeout=t); r.raise_for_status(); return {"ok": True, "data": r.json()}
    except Exception as e: logging.error(f"{url}: {e}"); return {"ok": False, "error": str(e)[:100]}

#Cached Detection Function: If same input is given within 5 minutes, return cached result instead of recalculating

@st.cache_data(ttl=300)
def detect(ioc):
    i = ioc.strip().lower()
    if re.match(r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$", i): return "ip4", i #ipv4
    if re.match(r"^(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}$", i) or \ #ipv6
       re.match(r"^([0-9a-f]{1,4}:){0,7}::([0-9a-f]{1,4}:){0,7}[0-9a-f]{1,4}$", i) or \
       re.match(r"^([0-9a-f]{1,4}:){1,7}:$", i) or \
       re.match(r"^::([0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}$", i) or \
       re.match(r"^([0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}$", i) or \
       re.match(r"^([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}$", i) or \
       re.match(r"^([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}$", i) or \
       re.match(r"^([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}$", i) or \
       re.match(r"^([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}$", i) or \
       re.match(r"^[0-9a-f]{1,4}:(:[0-9a-f]{1,4}){1,6}$", i) or \
       re.match(r"^::([0-9a-f]{1,4}:){0,5}[0-9a-f]{1,4}$", i):
        try:
            normalized = socket.inet_ntop(socket.AF_INET6, socket.inet_pton(socket.AF_INET6, i))
            return "ip6", normalized.lower()
        except:
            return "ip6", i
   #hash detection
    if re.match(r"^[a-f0-9]{32}$", i): return "md5", i
    if re.match(r"^[a-f0-9]{40}$", i): return "sha1", i
    if re.match(r"^[a-f0-9]{64}$", i): return "sha256", i
    #URL, Domain, Unknown Detection
    if i.startswith("http"): return "url", i.rstrip("/").lower()
    if "." in i and "/" not in i: return "domain", i
    return "unknown", i

# Threat intel requests (fn call req)
@rate_lim("abuse")
def abuse_q(i): return req("https://api.abuseipdb.com/api/v2/check", {"Key": KEY("ABUSE_KEY")}, None, "GET", params={"ipAddress": i, "maxAgeInDays": 90})

@rate_lim("otx")
def otx_q(i, t):
    ep = {"ip4": f"IPv4/{i}", "ip6": f"IPv6/{i}", "domain": f"domain/{i}", "md5": f"file/{i}", "sha1": f"file/{i}", "sha256": f"file/{i}"}
    return req(f"https://otx.alienvault.com/api/v1/indicators/{ep.get(t)}/general", {"X-OTX-API-KEY": KEY("OTX_KEY")}) if ep.get(t) else {"ok": False, "error": "unsupported"}

@rate_lim("vt")
def vt_q(i, t):
    ep = {"ip4": f"ip_addresses/{i}", "ip6": f"ip_addresses/{i}", "domain": f"domains/{i}", "md5": f"files/{i}", "sha1": f"files/{i}", "sha256": f"files/{i}", "url": f"urls/{base64.urlsafe_b64encode(i.encode()).decode().strip('=')}"}
    return req(f"https://www.virustotal.com/api/v3/{ep.get(t)}", {"x-apikey": KEY("VT_KEY")})

@rate_lim("haus")
def urlhaus_q(u):
    return req("https://urlhaus-api.abuse.ch/v1/url/", {"Auth-Key": KEY("URLHAUS_KEY")}, {"url": u}, "POST")

# Color coding
def card_color(value, is_ok):
    """Determine card background color based on value"""
    if not is_ok:
        return "#6b7280" # Gray - "We couldn't check"
    
    if isinstance(value, str):
        val_str = value.lower()
        if val_str == "malicious":
            return "#dc2626"  # Red - DANGER!
        elif val_str == "suspicious":
            return "#ea580c"  # Orange - Be careful
        elif val_str in ["clean", "no_results"]:
            return "#059669"  # Green - Safe
        else:
            return "#6b7280"   # Gray - "We couldn't check"
    
    try:
        n = float(value)
        if n > 50:
            return "#dc2626" # Red - DANGER!
        elif n > 20:
            return "#ea580c"  # Orange - Be careful
        elif n > 0:
            return "#d97706"  # Yellow - Slightly concerning
        else:
            return "#059669"  # Green - Safe
    except (ValueError, TypeError):
        return "#6b7280"     # Gray - "We couldn't check"

@st.cache_data(ttl=300)
def enrich(ioc_raw):
    t, i, log, r = *detect(ioc_raw), [], {}
    if t == "unknown": return t, i, {}, 0, log, [{"source": "error", "value": "Unknown IOC type", "ok": False}] # If I don't know what the input is, stop and report an error.
    with ThreadPoolExecutor(4) as e:
        f = {}
        if t in ("ip4", "ip6"): f = {"abuse": e.submit(abuse_q, i), "otx": e.submit(otx_q, i, t), "vt": e.submit(vt_q, i, t)} # IP addresses: Ask AbuseIPDB, OTX, and VirusTotal
        elif t in ("md5", "sha1", "sha256"): f = {"otx": e.submit(otx_q, i, t), "vt": e.submit(vt_q, i, t)} # File hashes: Ask OTX and VirusTotal
        elif t == "domain": f = {"otx": e.submit(otx_q, i, t), "vt": e.submit(vt_q, i, t)} # Domains: Ask OTX and VirusTotal
        elif t == "url": f = {"vt": e.submit(vt_q, i, t), "haus": e.submit(urlhaus_q, i)}  # URLs: Ask VirusTotal and URLhaus
        for k, fu in f.items():
            try: r[k] = fu.result(timeout=15); log.append(f"PASS: {k}")
            except Exception as e: r[k] = {"ok": False, "error": str(e)}; log.append(f"FAIL: {k}")
    s = sum([(r.get("abuse", {}).get("data", {}).get("data", {}).get("abuseConfidenceScore", 0) if r.get("abuse", {}).get("ok") else 0),
             ((r.get("vt", {}).get("data", {}).get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0) + r.get("vt", {}).get("data", {}).get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("suspicious", 0)) * 10 if r.get("vt", {}).get("ok") else 0),
             (r.get("otx", {}).get("data", {}).get("pulse_info", {}).get("count", 0) * 5 if r.get("otx", {}).get("ok") else 0),
             (50 if r.get("haus", {}).get("data", {}).get("query_status") == "ok" else 0)])
    
    def get_value(k, v):
        if not v.get("ok"): return v.get("error", "failed")
        if k == "abuse": return v.get("data", {}).get("data", {}).get("abuseConfidenceScore", 0)
        elif k == "vt": return v.get("data", {}).get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
        elif k == "otx": return v.get("data", {}).get("pulse_info", {}).get("count", 0)
        elif k == "haus":
            qs = v.get("data", {}).get("query_status", "unknown")
            if qs == "ok": return "MALICIOUS"
            elif qs == "no_results": return "CLEAN"
            else: return qs
        return "unknown"
    
    return t, i, r, int(s), log, [{"source": k, "value": get_value(k, v), "ok": v.get("ok")} for k, v in r.items()]

def misp_exp(ioc, t, s, r):
    lvl = "1" if s > 100 else "2" if s > 50 else "3" if s > 20 else "4"
    return json.dumps({"Event": {"info": f"TI: {ioc}", "threat_level_id": lvl, "Attribute": [{"type": {"ip4": "ip-dst", "ip6": "ip-dst", "md5": "md5", "sha1": "sha1", "sha256": "sha256", "domain": "domain", "url": "url"}.get(t, "text"), "value": ioc, "to_ids": s > 50, "comment": f"Risk: {s}"}] + [{"type": "comment", "value": f"{k}: {v.get('data') if v.get('ok') else v.get('error', 'failed')}"} for k, v in r.items()]}}, indent=2)

# UI
st.markdown("""
<style>
    .main-header {font-size: 1.75rem; font-weight: 600; color: #111827; margin-bottom: 0.25rem;}
    .sub-header {font-size: 0.9rem; color: #6b7280; margin-bottom: 2rem;}
    .ioc-card {background-color: #ffffff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1);}
    .severity-critical {color: #dc2626; font-weight: 700; font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.05em;}
    .severity-high {color: #ea580c; font-weight: 700; font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.05em;}
    .severity-medium {color: #d97706; font-weight: 700; font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.05em;}
    .severity-low {color: #059669; font-weight: 700; font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.05em;}
    .source-card {padding: 1rem; border-radius: 6px; text-align: center; color: white; font-weight: 600;}
    .source-header {font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem; opacity: 0.9;}
    .source-value {font-size: 1.25rem; font-weight: 700;}
    div[data-testid="stButton"] > button {font-weight: 600;}
</style>
""", unsafe_allow_html=True)

# Header
st.markdown('<div class="main-header">Threat Intelligence Analyzer</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Multi-source IOC enrichment and risk assessment platform</div>', unsafe_allow_html=True)

# Bulk Toggle
input_col, mode_col = st.columns([4, 1])
with input_col:
    if 'bulk_mode' not in st.session_state:
        st.session_state.bulk_mode = False
    
    if st.session_state.bulk_mode:
        ioc = st.text_area(
            "Indicators of Compromise",
            placeholder="8.8.8.8\nexample.com\nmalicious-domain.com",
            height=120,
            label_visibility="collapsed"
        )
    else:
        ioc = st.text_input(
            "Indicator of Compromise",
            placeholder="Enter IP address, domain, URL, or file hash...",
            label_visibility="collapsed"
        )

with mode_col:
    bulk = st.toggle("Bulk Mode", key="bulk_mode", help="Enable multi-line input for up to 5 IOCs")

# Analyze Button
analyze_col, _ = st.columns([1, 4])
with analyze_col:
    analyze_btn = st.button("Analyze", type="primary", use_container_width=True)

# Analysis Section - Only runs when button is clicked
if analyze_btn and ioc:
    indicators = ioc.split("\n") if bulk else [ioc]
    indicators = [i.strip() for i in indicators if i.strip()][:5]
    
    if len(indicators) > 1:
        st.info(f"Processing {len(indicators)} indicators...")
    
    for idx, indicator in enumerate(indicators):
        with st.spinner(f"Analyzing {indicator[:50]}..."):
            t, norm, res, score, log, enrich_list = enrich(indicator)
        
        if t == "unknown":
            st.error(f"Unable to identify indicator type: {indicator}")
            continue
            
        # Determine severity
        if score > 100:
            severity_class = "severity-critical"
            severity_text = "Critical"
            border_color = "#dc2626"
        elif score > 50:
            severity_class = "severity-high"
            severity_text = "High"
            border_color = "#ea580c"
        elif score > 20:
            severity_class = "severity-medium"
            severity_text = "Medium"
            border_color = "#d97706"
        else:
            severity_class = "severity-low"
            severity_text = "Low"
            border_color = "#059669"
        
        # Main Card
        with st.container():
            st.markdown(f'<div class="ioc-card" style="border-left: 4px solid {border_color};">', unsafe_allow_html=True)
            
            # Header Row
            header_col, type_col, score_col, sev_col, action_col = st.columns([3, 1, 1, 1, 1])
            
            with header_col:
                st.markdown(f"<b style='font-size: 1.1rem; color: #111827;'>{indicator[:80]}{'...' if len(indicator) > 80 else ''}</b>", unsafe_allow_html=True)
                st.markdown(f"<code style='color: #6b7280; font-size: 0.85rem;'>{norm}</code>", unsafe_allow_html=True)
            
            with type_col:
                st.markdown(f"<div style='text-align: center;'><span style='background-color: #f3f4f6; padding: 0.25rem 0.75rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; color: #374151; text-transform: uppercase;'>{t}</span></div>", unsafe_allow_html=True)
            
            with score_col:
                st.metric("Risk Score", score)
            
            with sev_col:
                st.markdown(f"<div style='text-align: center; padding-top: 0.5rem;'><div class='{severity_class}'>{severity_text}</div></div>", unsafe_allow_html=True)
            
            with action_col:
                st.download_button(
                    label="Export MISP",
                    data=misp_exp(indicator, t, score, res),
                    file_name=f"misp_{norm[:20]}.json",
                    mime="application/json",
                    use_container_width=True
                )
            
            st.markdown("<hr style='margin: 1rem 0; border: none; border-top: 1px solid #e5e7eb;'>", unsafe_allow_html=True)
            
            # Intelligence Sources with Color Coding
            st.markdown("<div style='font-size: 0.875rem; font-weight: 600; color: #374151; margin-bottom: 0.75rem;'>Intelligence Sources</div>", unsafe_allow_html=True)
            
            if enrich_list:
                cols = st.columns(len(enrich_list))
                for idx, e in enumerate(enrich_list):
                    with cols[idx]:
                        bg_color = card_color(e["value"], e["ok"])
                        display_val = e["value"]
                        
                        st.markdown(f"""
                        <div class="source-card" style="background-color: {bg_color};">
                            <div class="source-header">{e['source']}</div>
                            <div class="source-value">{display_val}</div>
                        </div>
                        """, unsafe_allow_html=True)
            
            # Details Expander
            with st.expander("Technical Details"):
                detail_col1, detail_col2 = st.columns([3, 1])
                with detail_col1:
                    st.json(res)
                with detail_col2:
                    st.markdown("<div style='font-size: 0.875rem; font-weight: 600; color: #374151; margin-bottom: 0.5rem;'>Processing Log</div>", unsafe_allow_html=True)
                    for entry in log:
                        if entry.startswith("PASS"):
                            st.markdown(f"<div style='font-size: 0.8rem; color: #059669; font-family: monospace;'>[OK] {entry[5:]}</div>", unsafe_allow_html=True)
                        else:
                            st.markdown(f"<div style='font-size: 0.8rem; color: #dc2626; font-family: monospace;'>[ER] {entry[5:]}</div>", unsafe_allow_html=True)
            
            st.markdown('</div>', unsafe_allow_html=True)

# Sidebar - Feodo Tracker with Status Column
st.sidebar.markdown("<div style='font-size: 1rem; font-weight: 600; color: #111827; margin-bottom: 1rem;'>Live Threat Feed</div>", unsafe_allow_html=True)
st.sidebar.markdown("<div style='font-size: 0.875rem; color: #6b7280; margin-bottom: 1rem;'>Feodo Tracker C2 Blocklist</div>", unsafe_allow_html=True)

try:
    feed_data = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json", timeout=10).json()
    if feed_data:
        df = pd.DataFrame(feed_data).head(10)
        st.sidebar.dataframe(df, hide_index=True, use_container_width=True)
    else:
        st.sidebar.info("No feed data available")
except Exception as e:
    st.sidebar.error("Feed unavailable")
