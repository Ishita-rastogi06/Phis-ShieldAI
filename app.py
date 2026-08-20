
import tempfile
import json
from datetime import datetime, timedelta, timezone
import html

import plotly.graph_objects as go
from plotly.subplots import make_subplots

import streamlit as st

# -- Startup diagnostic: API key presence check ------------------------------
# Runs once per process at import time (before any widget renders).  The
# result is stored in session_state so the sidebar banner can read it.
from intelligence.diagnostics import load_and_report_provider_configuration as _check_keys
if "provider_key_config" not in st.session_state:
    st.session_state["provider_key_config"] = _check_keys()
_PROVIDER_KEY_CONFIG: dict = st.session_state["provider_key_config"]
# ----------------------------------------------------------------------------

from ai_copilot import generate_ai_explanation
from email_ai_copilot import generate_email_intelligence

from ml.email_detector import analyze_email_content
from ml.url_detector import predict_url
from analysis.url_analysis_pipeline import analyze_url as run_complete_url_analysis
from analysis.input_routes import analyze_extracted_urls
from security.input_validation import validate_url
from feature_extractor import extract_features
from brand_detector import detect_brand
from threat_explainer import explain_threat
from website_analyzer import analyze_website
from email_url_scanner import extract_urls
from whois_checker import check_domain_age
from mitre_mapper import map_to_mitre

from history_manager import (
    save_scan,
    save_canonical_scan,
    load_history,
    clear_history
)

from report_generator import generate_report, generate_input_report, generate_canonical_report


# =====================================================
# PAGE CONFIG
# =====================================================

st.set_page_config(
    page_title="Phis-ShieldAI",
    page_icon="🛡️",
    layout="wide"
)
st.markdown("""
<style>
:root { --bg:#18181b; --surface:#27272a; --surface-soft:rgba(39,39,42,.78); --line:rgba(244,244,245,.12); --text:#f4f4f5; --muted:#a1a1aa; --crimson:#e11d48; --crimson-deep:#be123c; --danger:#fb7185; --warning:#fbbf24; --success:#86efac; }
* { scrollbar-color:#52525b var(--bg); }
.stApp,[data-testid="stAppViewContainer"], [data-testid="stHeader"] { background:var(--bg) !important; color:var(--text) !important; }
[data-testid="stHeader"] { border-bottom:1px solid var(--line); background:rgba(24,24,27,.94) !important; }
section[data-testid="stSidebar"] { background:#202024 !important; border-right:1px solid var(--line); }
section[data-testid="stSidebar"] * { color:var(--text) !important; }
section[data-testid="stSidebar"] label p { font-size:14px !important; font-weight:700; letter-spacing:.04em; }
section[data-testid="stSidebar"] [data-baseweb="radio"] > div:first-child { border-color:#71717a !important; }
section[data-testid="stSidebar"] [data-baseweb="radio"] [aria-checked="true"] > div:first-child { background:var(--crimson) !important; border-color:var(--crimson) !important; }
h1,h2,h3,p,label,.stMarkdown { color:var(--text) !important; letter-spacing:-.018em; }
h1 { font-size:2rem !important; font-weight:800 !important; } h2 { font-weight:750 !important; } h3 { color:#e4e4e7 !important; }
[data-testid="stMetric"], [data-testid="stExpander"] { background:linear-gradient(135deg,var(--surface-soft),rgba(39,39,42,.58)) !important; border:1px solid var(--line) !important; box-shadow:0 10px 28px rgba(0,0,0,.16); border-radius:10px; padding:14px; backdrop-filter:blur(10px); }
[data-testid="stMetricLabel"] { color:var(--muted) !important; text-transform:uppercase; font-size:.72rem !important; letter-spacing:.08em; } [data-testid="stMetricValue"] { color:var(--text) !important; font-weight:800 !important; }
.stButton>button, [data-testid="stDownloadButton"] button { background:var(--crimson) !important; color:#fff !important; border:1px solid #fb7185 !important; border-radius:7px; font-weight:800; letter-spacing:.025em; box-shadow:0 6px 18px rgba(225,29,72,.2); }
.stButton>button:hover, [data-testid="stDownloadButton"] button:hover { background:var(--crimson-deep) !important; border-color:#fda4af !important; }
.stTextInput input,.stTextArea textarea { background:#202024 !important; color:var(--text) !important; border:1px solid #52525b !important; border-radius:7px !important; }
.stTextInput input:focus,.stTextArea textarea:focus { border-color:var(--crimson) !important; box-shadow:0 0 0 1px var(--crimson) !important; }
[data-testid="stAlert"] { background:var(--surface) !important; border:1px solid var(--line) !important; color:var(--text) !important; border-radius:8px; }
[data-testid="stDataFrame"] { border:1px solid var(--line); border-radius:8px; overflow:hidden; }
[data-testid="stExpander"] summary { color:var(--text) !important; font-weight:700; }
hr { border-color:var(--line) !important; } .stCaption { color:var(--muted) !important; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Phis-ShieldAI")

st.subheader(
    "AI-Powered Phishing Detection & Threat Intelligence Platform"
)


st.markdown("""
<style>
:root { --bg:#0A0D12; --sidebar:#07090E; --surface:#121820; --glass:rgba(18,24,32,.84); --line:#1E293B; --text:#FFFFFF; --muted:#94A3B8; --emerald:#10B981; }
#MainMenu, header, footer, [data-testid="stToolbar"], [data-testid="stDecoration"], [data-testid="stDeployButton"] { display:none !important; }
.stApp,[data-testid="stAppViewContainer"] { background:radial-gradient(circle at 75% -25%,rgba(16,185,129,.07),transparent 35%),var(--bg) !important; color:var(--text) !important; }.block-container { padding-top:1.7rem !important; max-width:1440px !important; }
section[data-testid="stSidebar"] { background:var(--sidebar) !important; border-right:1px solid var(--line) !important; } section[data-testid="stSidebar"] > div { padding:1.25rem .7rem; } section[data-testid="stSidebar"] label p { color:var(--muted) !important; font-size:.76rem !important; font-weight:850; letter-spacing:.12em; }
section[data-testid="stSidebar"] [data-baseweb="radio"] > div { padding:.58rem .65rem; border:1px solid transparent; border-radius:9px; transition:all .16s ease; } section[data-testid="stSidebar"] [data-baseweb="radio"] > div:hover { background:#101722; border-color:#223144; } section[data-testid="stSidebar"] [data-baseweb="radio"] > div:has(input:checked) { background:rgba(16,185,129,.12); border-color:rgba(16,185,129,.42); box-shadow:inset 3px 0 0 var(--emerald); }
[data-testid="stMetric"], [data-testid="stExpander"] { background:var(--glass) !important; border:1px solid var(--line) !important; box-shadow:0 12px 30px rgba(0,0,0,.28); border-radius:12px; backdrop-filter:blur(10px); } [data-testid="stMetric"]:hover { border-color:rgba(16,185,129,.62) !important; box-shadow:0 0 0 1px rgba(16,185,129,.16),0 0 22px rgba(16,185,129,.1); } [data-testid="stMetricLabel"] { color:var(--muted) !important; font-size:.68rem !important; letter-spacing:.1em; }
.stButton>button,[data-testid="stDownloadButton"] button { background:var(--emerald) !important; color:#03140D !important; border:1px solid #34D399 !important; border-radius:8px; box-shadow:0 7px 20px rgba(16,185,129,.2); }.stButton>button:hover,[data-testid="stDownloadButton"] button:hover { background:#34D399 !important; box-shadow:0 0 25px rgba(16,185,129,.32); }.stTextInput input,.stTextArea textarea { background:#0E141C !important; border-color:#334155 !important; }.stTextInput input:focus,.stTextArea textarea:focus { border-color:var(--emerald) !important; box-shadow:0 0 0 1px var(--emerald),0 0 16px rgba(16,185,129,.14) !important; }
.soc-header { display:flex; align-items:center; gap:14px; margin:0 0 1.5rem; padding:16px 18px; background:var(--glass); border:1px solid var(--line); border-radius:12px; backdrop-filter:blur(10px); box-shadow:0 10px 30px rgba(0,0,0,.24); }.soc-icon { width:42px; height:42px; border-radius:10px; display:grid; place-items:center; background:rgba(16,185,129,.13); border:1px solid rgba(16,185,129,.5); color:#6EE7B7; font-size:1.25rem; }.soc-copy { flex:1; }.soc-title { font-size:1.25rem; font-weight:850; }.soc-subtitle { color:var(--muted); font-size:.78rem; margin-top:2px; }.soc-tag { color:#CBD5E1; background:#0B1017; border:1px solid #334155; padding:6px 9px; border-radius:5px; font-size:.65rem; font-weight:800; letter-spacing:.11em; }
</style><div class="soc-header"><div class="soc-icon">🛡</div><div class="soc-copy"><div class="soc-title">Phis-ShieldAI</div><div class="soc-subtitle">Threat Intelligence, Detection &amp; Response</div></div><div class="soc-tag">SECURITY OPERATIONS CENTER</div></div>
""", unsafe_allow_html=True)

st.markdown("""
<style>
/* Flat enterprise application override: intentionally no gradients, glow, or shadows. */
:root { --page:#F8FAFC; --card:#FFFFFF; --border:#E2E8F0; --sidebar:#1E293B; --ink:#0F172A; --muted:#64748B; --side-text:#94A3B8; --active:#334155; --emerald:#059669; --crimson:#DC2626; --amber:#D97706; }
html,body,[data-testid="stAppViewContainer"],.stApp { background:var(--page) !important; color:var(--ink) !important; font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif !important; }
.stApp { background:var(--page) !important; } .block-container { max-width:1380px !important; padding-top:1.5rem !important; }
section[data-testid="stSidebar"] { background:var(--sidebar) !important; border-right:0 !important; } section[data-testid="stSidebar"] > div { padding:1.25rem .75rem; } section[data-testid="stSidebar"] * { color:var(--side-text) !important; }
section[data-testid="stSidebar"] label p { color:var(--side-text) !important; font-size:.74rem !important; font-weight:750 !important; letter-spacing:.09em; }
section[data-testid="stSidebar"] [data-baseweb="radio"] > div { border-radius:6px !important; border:0 !important; padding:.62rem .7rem !important; } section[data-testid="stSidebar"] [data-baseweb="radio"] > div:hover { background:#27364a !important; } section[data-testid="stSidebar"] [data-baseweb="radio"] > div:has(input:checked) { background:var(--active) !important; box-shadow:none !important; } section[data-testid="stSidebar"] [data-baseweb="radio"] > div:has(input:checked) * { color:#FFFFFF !important; }
h1,h2,h3,h4,p,label,.stMarkdown { color:var(--ink) !important; font-family:Inter,system-ui,sans-serif !important; } h1 { font-size:1.75rem !important; font-weight:750 !important; } h2 { font-size:1.25rem !important; font-weight:700 !important; } h3 { font-size:1rem !important; font-weight:700 !important; }
.soc-header { background:var(--card) !important; border:1px solid var(--border) !important; border-radius:6px !important; box-shadow:none !important; backdrop-filter:none !important; margin-bottom:1.25rem !important; }.soc-icon { background:#ECFDF5 !important; border:1px solid #A7F3D0 !important; color:var(--emerald) !important; border-radius:6px !important; }.soc-title { color:var(--ink) !important; }.soc-subtitle { color:var(--muted) !important; }.soc-tag { background:#F1F5F9 !important; border:1px solid var(--border) !important; color:var(--muted) !important; }
[data-testid="stMetric"],[data-testid="stExpander"] { background:var(--card) !important; border:1px solid var(--border) !important; border-radius:6px !important; box-shadow:none !important; backdrop-filter:none !important; padding:14px !important; } [data-testid="stMetric"]:hover { border-color:var(--border) !important; box-shadow:none !important; } [data-testid="stMetricLabel"] { color:var(--muted) !important; font-size:.68rem !important; font-weight:750 !important; letter-spacing:.08em; } [data-testid="stMetricValue"] { color:var(--ink) !important; font-weight:800 !important; }
.stButton>button,[data-testid="stDownloadButton"] button { background:var(--emerald) !important; color:#FFFFFF !important; border:1px solid var(--emerald) !important; border-radius:5px !important; box-shadow:none !important; font-weight:700 !important; }.stButton>button:hover,[data-testid="stDownloadButton"] button:hover { background:#047857 !important; border-color:#047857 !important; box-shadow:none !important; }
.stTextInput input,.stTextArea textarea { background:#FFFFFF !important; color:var(--ink) !important; border:1px solid #CBD5E1 !important; border-radius:5px !important; }.stTextInput input:focus,.stTextArea textarea:focus { border-color:var(--emerald) !important; box-shadow:0 0 0 1px var(--emerald) !important; }
[data-testid="stAlert"] { background:#FFFFFF !important; border:1px solid var(--border) !important; border-radius:5px !important; color:var(--ink) !important; } [data-testid="stExpander"] summary { color:var(--ink) !important; } [data-testid="stDataFrame"] { border:1px solid var(--border) !important; border-radius:6px !important; } [data-testid="stDataFrame"] * { color:var(--ink) !important; } hr { border-color:var(--border) !important; } .stCaption { color:var(--muted) !important; }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<style>
/* Warm taupe/sand enterprise theme override. No Streamlit chrome or default radio visuals. */
:root { --sand:#C5B08A; --taupe:#4A2C24; --cream:#FDFBF7; --espresso:#2C221E; --muted-taupe:#5A4840; --border:#A89370; --chestnut:#F4A261; --peach-hover:#E98E73; }
#MainMenu,header,footer,[data-testid="stToolbar"],[data-testid="stDecoration"],[data-testid="stDeployButton"] { display:none !important; }
html,body,.stApp,[data-testid="stAppViewContainer"] { background:var(--sand) !important; color:var(--espresso) !important; }
.block-container { max-width:1380px !important; padding-top:1.5rem !important; }
section[data-testid="stSidebar"] { background:var(--taupe) !important; border-right:0 !important; } section[data-testid="stSidebar"] > div { padding:1.35rem .78rem; }
section[data-testid="stSidebar"] * { color:var(--cream) !important; } section[data-testid="stSidebar"] label p { color:var(--cream) !important; font-size:.76rem !important; font-weight:800 !important; letter-spacing:.09em; }
section[data-testid="stSidebar"] [data-baseweb="radio"] > div { width:100%; padding:.72rem .82rem; margin:.15rem 0; border:0 !important; border-radius:8px; transition:background .16s ease,transform .16s ease; } section[data-testid="stSidebar"] [data-baseweb="radio"] > div:hover { background:rgba(253,251,247,.17) !important; transform:translateX(1px); } section[data-testid="stSidebar"] [data-baseweb="radio"] > div:has(input:checked) { background:var(--cream) !important; box-shadow:0 4px 12px rgba(0,0,0,.08) !important; } section[data-testid="stSidebar"] [data-baseweb="radio"] > div:has(input:checked) * { color:var(--espresso) !important; } section[data-testid="stSidebar"] [data-baseweb="radio"] [role="radio"] > div:first-child { display:none !important; }
h1,h2,h3,h4,p,label,.stMarkdown { color:var(--espresso) !important; font-family:Inter,system-ui,-apple-system,"Segoe UI",sans-serif !important; } h1 { font-weight:800 !important; } .stCaption { color:var(--muted-taupe) !important; }
.soc-header { background:var(--cream) !important; border:1px solid var(--border) !important; border-radius:10px !important; box-shadow:none !important; backdrop-filter:none !important; }.soc-icon { background:#F4EDE4 !important; border:1px solid var(--border) !important; color:var(--chestnut) !important; border-radius:8px !important; }.soc-title { color:var(--espresso) !important; }.soc-subtitle { color:var(--muted-taupe) !important; }.soc-tag { background:#F4EDE4 !important; border:1px solid var(--border) !important; color:var(--muted-taupe) !important; }
[data-testid="stMetric"],[data-testid="stExpander"],[data-testid="stAlert"] { background:var(--cream) !important; border:1px solid var(--border) !important; border-radius:10px !important; box-shadow:none !important; backdrop-filter:none !important; } [data-testid="stMetric"]:hover { border-color:var(--border) !important; box-shadow:none !important; } [data-testid="stMetricLabel"] { color:var(--muted-taupe) !important; } [data-testid="stMetricValue"] { color:var(--espresso) !important; }
.stButton>button,[data-testid="stDownloadButton"] button { background:var(--chestnut) !important; color:var(--espresso) !important; border:1px solid #DD865F !important; border-radius:6px !important; box-shadow:none !important; font-weight:800 !important; }.stButton>button:hover,[data-testid="stDownloadButton"] button:hover { background:var(--peach-hover) !important; border-color:#D97B62 !important; box-shadow:none !important; }
.stTextInput input,.stTextArea textarea,[data-testid="stFileUploaderDropzone"] { background:var(--cream) !important; color:var(--espresso) !important; border:1px solid var(--border) !important; border-radius:8px !important; }.stTextInput input:focus,.stTextArea textarea:focus { border-color:var(--chestnut) !important; box-shadow:0 0 0 1px var(--chestnut) !important; }
[data-testid="stDataFrame"] { background:var(--cream) !important; border:1px solid var(--border) !important; border-radius:8px !important; } [data-testid="stDataFrame"] * { color:var(--espresso) !important; } [data-testid="stExpander"] summary { color:var(--espresso) !important; } hr { border-color:var(--border) !important; }
</style>
""", unsafe_allow_html=True)

# Global product theme.  Loaded last so it consistently overrides legacy
# inline presentation rules without changing any analysis functionality.
with open("custom.css", encoding="utf-8") as theme_file:
    st.markdown(f"<style>{theme_file.read()}</style>", unsafe_allow_html=True)

# Legacy render_url_evidence stub removed; the canonical version below handles all scan types.


UNAVAILABLE_STATUSES = {"UNAVAILABLE", "NOT_CONFIGURED", "TIMEOUT", "RATE_LIMITED", "ERROR"}

# Three precise states for any provider result:
#   NOT_QUERIED  — scan was blocked before the call was ever attempted
#   UNAVAILABLE  — call was attempted but provider returned an error / auth rejection
#   NO_MATCH     — call succeeded; provider simply has no record for this target
_STATE_LABELS = {
    "NOT_CONFIGURED": ("NOT QUERIED", "Provider key not configured — call was never sent."),
    "UNAVAILABLE":    ("UNAVAILABLE", "Provider call attempted but returned an error."),
    "ERROR":          ("ERROR",        "Provider returned an unexpected response."),
    "TIMEOUT":        ("TIMEOUT",      "Provider did not respond within the time limit."),
    "RATE_LIMITED":   ("RATE LIMITED", "Provider rate-limited this request (HTTP 429)."),
    "NO_MATCH":       ("NO MATCH",     "Provider queried successfully — no record found for this target."),
    "AVAILABLE":      ("AVAILABLE",    "Provider returned data for this target."),
}


def _display_value(value):
    if value is None or value == "": return "Not available"
    if isinstance(value, bool): return "Yes" if value else "No"
    if isinstance(value, (list, tuple)): return ", ".join(map(str, value)) if value else "Not available"
    if isinstance(value, dict): return ", ".join(f"{k.replace('_', ' ').title()}: {_display_value(v)}" for k, v in value.items()) or "Not available"
    return str(value)


def _render_urlscan_matches(matches: list) -> None:
    """Render urlscan result list as structured cards instead of a raw Python dict."""
    if not matches:
        return
    for i, m in enumerate(matches, 1):
        page = m.get("page", {}) if isinstance(m.get("page"), dict) else {}
        task = m.get("task", {}) if isinstance(m.get("task"), dict) else {}
        stats = m.get("stats", {}) if isinstance(m.get("stats"), dict) else {}
        scan_id = m.get("id") or task.get("uuid") or "—"
        domain = page.get("domain") or page.get("url") or "—"
        country = page.get("country") or "—"
        malicious = int(stats.get("malicious", 0) or 0)
        total = sum(int(stats.get(k, 0) or 0) for k in ("malicious", "undetected", "benign"))
        submitted = task.get("time") or "—"
        url_link = f"https://urlscan.io/result/{scan_id}/" if scan_id != "—" else "#"
        flag = "🔴" if malicious > 0 else "🟢"
        st.markdown(
            f'<div class="source-evidence" style="margin-bottom:6px">'
            f'<b>urlscan match {i}</b> '
            f'<a href="{html.escape(url_link)}" target="_blank" style="font-size:.8rem">view scan ↗</a>'
            f'<div><b>Domain:</b> {html.escape(str(domain))}</div>'
            f'<div><b>Country:</b> {html.escape(str(country))}</div>'
            f'<div><b>Submitted:</b> {html.escape(str(submitted))}</div>'
            f'<div><b>Verdict:</b> {flag} {malicious} malicious / {total} engines</div>'
            f'</div>',
            unsafe_allow_html=True,
        )


def evidence_card(title, data, *, hide_keys=()):
    """Render backend evidence as labeled fields; never dumps raw Python dicts."""
    data = data if isinstance(data, dict) else {"status": "UNAVAILABLE", "reason": "No response was available."}
    status = str(data.get("status", "")).upper()
    unavailable = status in UNAVAILABLE_STATUSES or bool(data.get("error"))
    card_class = "source-unavailable" if unavailable else "source-evidence"
    label, _default_note = _STATE_LABELS.get(status, (status or "UNAVAILABLE", ""))
    ignored = set(hide_keys) | {"html", "status", "reason", "error", "source", "matches"}
    # Build field rows — skip nested lists/dicts that have their own renderer
    fields = "".join(
        f"<div><b>{html.escape(k.replace('_', ' ').title())}:</b> {html.escape(_display_value(v))}</div>"
        for k, v in data.items() if k not in ignored and not isinstance(v, (list,)) and not (isinstance(v, dict) and len(v) > 3)
    )
    reason = data.get("reason") or data.get("error")
    reason_html = f"<small>{html.escape(str(reason))}</small>" if reason else ""
    st.markdown(
        f'<div class="{card_class}"><b>{html.escape(title)}</b><span>{html.escape(label)}</span>{reason_html}{fields}</div>',
        unsafe_allow_html=True,
    )
    # Render urlscan matches as structured cards
    matches = data.get("matches")
    if isinstance(matches, list) and matches:
        _render_urlscan_matches(matches)


def render_url_evidence(result, scan_type="URL"):
    """Structured shared result report for URL, QR, OCR and email scans."""
    verdict = result.get("verdict", "INSUFFICIENT_EVIDENCE")
    tone = {"CONFIRMED_MALICIOUS": "critical", "LIKELY_PHISHING": "high", "SUSPICIOUS": "medium", "LIKELY_LEGITIMATE": "low"}.get(verdict, "unknown")
    label = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "unknown": "INSUFFICIENT EVIDENCE"}[tone]
    target = result.get("normalized_url") or result.get("url") or "Unavailable"
    original_url = result.get("url") or target
    _ml_flag = result.get("model_available", False)
    risk_score = result.get("risk", 0)
    confidence = str(result.get("confidence_strength", "insufficient")).title()
    verdict_source = result.get("verdict_source", "AI/ML Classifier" if _ml_flag else "Rule-Based Heuristics & Threat Intelligence")

    # Header banner
    st.markdown(
        f'<div class="scan-result-header">'
        f'<span class="verdict-badge {tone}">{label}</span>'
        f'<code>{html.escape(str(target))}</code>'
        f'<span>Risk {risk_score}/100</span>'
        f'</div>',
        unsafe_allow_html=True
    )

    # Explicit Pipeline & Source Disclaimer Banner right below header
    if not _ml_flag:
        st.markdown(
            f'<div class="evidence-card" style="border-left:4px solid #f59e0b;margin-bottom:.75rem;padding:.75rem 1rem">'
            f'<div style="font-weight:700;color:#d97706;margin-bottom:.2rem">⚠️ ANALYSIS PIPELINE NOTICE: ML Model Unavailable</div>'
            f'<div style="font-size:.84rem;line-height:1.45;color:var(--text)">'
            f'<b>Verdict Basis:</b> Driven by <b>Rule-Based Heuristics & Threat Intelligence</b> (Brand Impersonation, Path & Keyword Analysis).<br>'
            f'<b>Risk Score ({risk_score}/100):</b> Calculated from rule-based indicators and available threat intelligence.<br>'
            f'<b>ML Telemetry:</b> The 30-feature Legacy UCI model was <i>skipped</i> because required live telemetry could not be collected for this URL.'
            f'</div></div>',
            unsafe_allow_html=True
        )
    else:
        st.markdown(
            f'<div class="evidence-card" style="border-left:4px solid #10b981;margin-bottom:.75rem;padding:.75rem 1rem">'
            f'<div style="font-weight:700;color:#059669;margin-bottom:.2rem">✅ ANALYSIS PIPELINE NOTICE: AI/ML Model Active</div>'
            f'<div style="font-size:.84rem;line-height:1.45;color:var(--text)">'
            f'<b>Verdict Basis:</b> Active 30-feature Random Forest ML Model corroborated by live threat intelligence.'
            f'</div></div>',
            unsafe_allow_html=True
        )

    # Redirect chain banner — shown only when there was at least one hop
    redirect_chain = result.get("redirect_chain") or []
    if len(redirect_chain) >= 2:
        chain_html = " &rarr; ".join(f'<code style="font-size:.78rem">{html.escape(str(u))}</code>' for u in redirect_chain)
        st.markdown(
            f'<div class="evidence-card" style="margin-bottom:.5rem">'
            f'<span class="card-kicker">REDIRECT CHAIN</span>'
            f'<div style="margin-top:.35rem;line-height:1.9">{chain_html}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

    # Final Verdict Card
    source_badge = '<span style="background:#374151;color:#f3f4f6;padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:600;margin-left:8px">RULE-BASED & THREAT INTEL</span>' if not _ml_flag else '<span style="background:#065f46;color:#a7f3d0;padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:600;margin-left:8px">AI/ML MODEL ACTIVE</span>'

    reasons = result.get("reasons", [])
    rule_count = len([r for r in reasons if "Rule:" in r or "indicator" in r.lower() or "brand" in r.lower() or "keyword" in r.lower()])
    conf_explanation = (
        f"Confidence is <b>{confidence}</b> based on {rule_count if rule_count > 0 else 'multiple'} strong rule/reputation triggers (e.g. Brand Impersonation, Credential/Verification path, Suspicious Keywords). ML Model was <i>unavailable</i>."
        if not _ml_flag else
        f"Confidence is <b>{confidence}</b> based on validated 30-feature ML model prediction corroborated by threat intelligence."
    )

    st.markdown(
        f'<div class="evidence-card"><span class="card-kicker">FINAL VERDICT & CONFIDENCE ATTRIBUTION</span>'
        f'<h4>{html.escape(verdict.replace("_", " ").title())} {source_badge}</h4>'
        f'<p style="margin-top:.4rem;font-size:.85rem">{conf_explanation}</p>'
        f'</div>',
        unsafe_allow_html=True,
    )

    def source_card(name, item):
        """Render one provider result with accurate three-state labeling."""
        if not isinstance(item, dict):
            item = {"status": "UNAVAILABLE", "reason": "Provider did not return a result"}
        status = item.get("status", "UNAVAILABLE")
        evidence = item.get("evidence")
        flat_evidence: dict = {}
        if isinstance(evidence, dict):
            flat_evidence = evidence
        elif isinstance(evidence, list):
            flat_evidence = {"matches": evidence}
        merged = {**item, **flat_evidence}
        if status == "NOT_CONFIGURED" and not item.get("reason"):
            merged["reason"] = "API key not set — this provider was NOT queried for this scan."
        elif status == "NO_MATCH" and not item.get("reason"):
            merged["reason"] = "Queried successfully — NO MATCH found. (Note: No existing record found in provider index; new zero-day phishing URLs often have no prior records. NOT proof of safety)."
        elif status == "NO_MATCH":
            existing = merged.get("reason", "")
            if "not proof of safety" not in existing.lower() and "not a clean verdict" not in existing.lower():
                merged["reason"] = existing + " — ℹ️ NO MATCH: Absence of an existing record is NOT proof of safety."
        evidence_card(name, merged, hide_keys={"evidence"})

    overview, model_tab, website_tab, network_tab, intel_tab, mitre_tab, copilot_tab = st.tabs(["◫ Overview", "⌁ ML Prediction", "◉ Website & TLS", "◌ WHOIS & DNS", "◈ Threat Intel", "▦ MITRE Mapping", "✦ Copilot Explanation"])
    with overview:
        reasons = result.get("reasons", [])
        st.markdown('<div class="evidence-card"><span class="card-kicker">RAW EVIDENCE</span><h4>Why this verdict</h4><ul>' + ''.join(f'<li>{html.escape(str(reason))}</li>' for reason in reasons) + '</ul></div>', unsafe_allow_html=True)
        # Redirect chain detail in overview when expansion happened
        if len(redirect_chain) >= 2:
            with st.expander(f"Redirect chain ({len(redirect_chain) - 1} hop{'s' if len(redirect_chain) - 1 != 1 else ''})", expanded=False):
                for i, step in enumerate(redirect_chain):
                    prefix = "Origin " if i == 0 else ("Final  " if i == len(redirect_chain) - 1 else f"Hop {i:>3} ")
                    st.code(f"{prefix}: {step}", language=None)

        # ── Pipeline Source & Risk Score Attribution Breakdown ─────────────────
        model_available = result.get("model_available", False)
        brand_val  = result.get("brand") or "Unknown"
        similarity = result.get("similarity", 0)
        strength   = str(result.get("confidence_strength", "insufficient")).title()

        _basis_parts = []
        if model_available:
            _basis_parts.append("<b>ML Model Engine:</b> ✅ Active 30-Feature Classifier")
        else:
            _basis_parts.append("<b>ML Model Engine:</b> ⚠️ Unavailable (Skipped — Telemetry missing; live data required)")

        _basis_parts.append("<b>Rule-Based Heuristic Engine:</b> ✅ Active (Evaluated Brand Impersonation, URL Path, Structural & Keyword Indicators)")

        if brand_val != "Unknown" and similarity > 0:
            _basis_parts.append(f"<b>Brand Impersonation Detector:</b> ✅ Triggered for '{brand_val.title()}' ({similarity}% similarity)")

        ps = result.get("providers", {})
        _live_providers = [n for n, v in ps.items() if isinstance(v, dict) and v.get("status") == "AVAILABLE"]
        _nm_providers   = [n for n, v in ps.items() if isinstance(v, dict) and v.get("status") == "NO_MATCH"]
        if _live_providers:
            _basis_parts.append(f"<b>Live Threat Intelligence:</b> ✅ Hits in: {', '.join(_live_providers)}")
        if _nm_providers:
            _basis_parts.append(f"<b>Reputation Databases:</b> ℹ️ NO MATCH in: {', '.join(_nm_providers)} <i>(Note: Absence of prior record is NOT proof of safety)</i>")

        basis_html = "".join(f"<li style='margin-bottom:.3rem'>{p}</li>" for p in _basis_parts)
        st.markdown(
            f'<div class="evidence-card" style="margin-top:.5rem">'
            f'<span class="card-kicker">DECISION PIPELINE & RISK SCORE BREAKDOWN</span>'
            f'<h4>Risk Score {result.get("risk", 0)}/100 · Confidence: {html.escape(strength)}</h4>'
            f'<p style="font-size:.82rem;margin:.25rem 0 .5rem;opacity:.9">'
            f'Source of Verdict & Score Breakdown:</p>'
            f'<ul style="margin:.25rem 0 0;padding-left:1.2rem;font-size:.82rem">{basis_html}</ul>'
            f'</div>',
            unsafe_allow_html=True,
        )

        left, middle, right = st.columns(3)
        left.metric("Confidence", strength, delta="High rule trigger consensus" if not model_available else "Validated ML model")
        middle.metric(
            "Brand Detected",
            brand_val.title() if brand_val != "Unknown" else "None",
            delta=f"{similarity}% similarity" if similarity > 0 else None,
        )
        right.metric(
            "ML Model",
            "Active" if model_available else "Unavailable",
            delta="Rule-based analysis used" if not model_available else "30-Feature RF",
            delta_color="off",
        )
        if not model_available:
            st.caption(
                "⚠️ <b>Note on ML Availability:</b> The Legacy UCI 30-feature ML model requires live website telemetry "
                "(traffic rank, PageRank, Google index) that could not be collected for this URL. "
                "The <b>Likely Phishing</b> verdict and <b>85/100 Risk Score</b> above are entirely based on "
                "rule-based lexical/structural heuristics (e.g. PayPal brand impersonation on non-official host, "
                "verification path `/verify`, suspicious keywords) and available threat-intelligence."
            )
    with model_tab:
        model = result.get("model", {})
        if not model.get("model_available"):
            # Don't just show UNAVAILABLE — explain what ran instead
            model_err = model.get("error") or "LEGACY UCI 30-FEATURE MODEL unavailable/conditional telemetry"
            st.markdown(
                f'<div class="source-unavailable">'
                f'<b>LEGACY UCI 30-FEATURE MODEL</b>'
                f'<span>NOT RUN</span>'
                f'<small>The 30-feature UCI phishing model requires live website telemetry '
                f'(traffic rank, PageRank, Google index) that could not be collected for this URL. '
                f'This does <strong>not</strong> mean the URL is safe — it means the ML component was skipped.</small>'
                f'<div style="margin-top:.6rem;font-size:.82rem">'
                f'<b>What ran instead:</b></div>'
                f'<ul style="font-size:.82rem;margin:.3rem 0 0;padding-left:1.2rem">'
                f'<li>Lexical / structural heuristics (brand similarity, TLD, keywords, hyphen pattern)</li>'
                f'<li>Live threat-intelligence providers (VirusTotal, URLscan, URLhaus, OpenPhish)</li>'
                f'<li>DNS, TLS, and WHOIS enrichment</li>'
                f'</ul>'
                f'<div style="margin-top:.5rem;font-size:.78rem;opacity:.75">'
                f'Technical detail: {html.escape(str(model_err))}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )
        else:
            evidence_card("LEGACY UCI 30-FEATURE MODEL", model, hide_keys={"features"})
    with website_tab:
        evidence_card("Website Analysis", result.get("website", {}))
        tls = result.get("tls", {})
        if tls.get("error"): source_card("TLS", {"status": "UNAVAILABLE", "reason": tls["error"]})
        else: evidence_card("TLS", tls)
    with network_tab:
        evidence_card("DNS", result.get("dns", {}))
        whois = result.get("whois")
        if not isinstance(whois, dict) or whois.get("status") != "AVAILABLE": source_card("WHOIS / RDAP", whois)
        else: evidence_card("WHOIS / RDAP", whois)
    with intel_tab:
        # ── Prominent Disclaimer ──────────────────────────────────────────────
        st.markdown(
            '<div class="evidence-card" style="margin-bottom:.75rem;border-left:4px solid #3b82f6">'
            '<span class="card-kicker">REPUTATION DATABASE DISTINCTION</span>'
            '<h4 style="margin-top:.2rem;font-size:.95rem">Understanding VirusTotal & URLscan Results</h4>'
            '<p style="font-size:.83rem;margin:.3rem 0 0;line-height:1.45">'
            '<strong>ℹ️ NO MATCH does NOT mean the URL is safe.</strong><br>'
            'A <i>"No Match"</i> result simply means no previous user or analyst has submitted this specific URL to VirusTotal, URLscan, or URLhaus database.<br>'
            'Because phishing campaigns frequently generate brand-new, zero-day domains, <b>the absence of an existing malicious record is typical for active phishing links</b>.<br>'
            '• <strong>AVAILABLE:</strong> Provider returned existing telemetry/scans.<br>'
            '• <strong>NO MATCH:</strong> Provider queried successfully — zero existing records found.<br>'
            '• <strong>NOT QUERIED:</strong> Provider API key not configured.'
            '</p></div>',
            unsafe_allow_html=True,
        )
        for name in ("virustotal", "urlscan", "urlhaus", "openphish"):
            source_card(name, result.get("providers", {}).get(name))
    with mitre_tab:
        mappings = result.get("mitre", [])
        if not mappings: st.info("No MITRE ATT&CK mapping was generated because observed evidence did not satisfy a mapping rule.")
        for mapping in mappings: st.markdown(f'<div class="evidence-card"><b>{html.escape(mapping.get("id", ""))} · {html.escape(mapping.get("name", ""))}</b><p>{html.escape(mapping.get("reason", ""))}</p></div>', unsafe_allow_html=True)
    with copilot_tab:
        copilot = result.get("ai_copilot", {})
        st.markdown('<div class="evidence-card"><span class="card-kicker">EVIDENCE USED</span><ul>' + ''.join(f'<li>{html.escape(str(item))}</li>' for item in copilot.get("observed_evidence", [])) + '</ul></div>', unsafe_allow_html=True)
        st.markdown(f'<div class="recommendation-card"><span class="ai-label">AI-ASSISTED, EVIDENCE-GROUNDED</span><h4>{html.escape(str(copilot.get("attack_type", "Assessment")))}</h4><p>{html.escape(str(copilot.get("strategy", "No recommendation was generated.")))}</p></div>', unsafe_allow_html=True)
    # ── Action buttons rendered OUTSIDE tabs so they appear once and do not
    #    re-render or duplicate when the user switches between tabs. ──────────
    st.divider()
    _btn_col, _ = st.columns((1, 4))
    _btn_col.download_button("Download Report", generate_canonical_report(scan_type, result), file_name="phishshield_security_report.txt", key=f"report-{scan_type}-{target}")
    if _btn_col.button("Add to History", key=f"history-{target}", type="secondary"):
        save_canonical_scan(scan_type, result)
        st.success("Evidence saved to scan history.")
        # Write the live scan result into session_state so the sidebar status
        # widget reflects this scan immediately (single source of truth).
        st.session_state["last_scan_result"] = result


def _risk_chip(value) -> str:
    verdict = str(value or "INSUFFICIENT_EVIDENCE")
    tone = "critical" if verdict == "CONFIRMED_MALICIOUS" else "high" if verdict == "LIKELY_PHISHING" else "medium" if verdict == "SUSPICIOUS" else "low" if verdict == "LIKELY_LEGITIMATE" else "unknown"
    return f'<span class="risk-chip {tone}">{html.escape(verdict.replace("_", " ").title())}</span>'


def _history_trend(history) -> str | None:
    """Return a real week-over-week scan-count change when timestamps permit."""
    if history.empty or "Timestamp" not in history:
        return None
    timestamps = __import__("pandas").to_datetime(history["Timestamp"], errors="coerce", utc=True).dropna()
    if timestamps.empty:
        return None
    now = datetime.now(timezone.utc)
    current = int((timestamps >= now - timedelta(days=7)).sum())
    previous = int(((timestamps >= now - timedelta(days=14)) & (timestamps < now - timedelta(days=7))).sum())
    if not current and not previous:
        return None
    difference = current - previous
    return f"{difference:+d} this week" if difference else "No change this week"


def _latest_signal_breakdown(history) -> tuple[int | None, list[tuple[str, int]]]:
    """Derive visible allocations only from persisted, observed risk evidence."""
    if history.empty:
        return None, []
    row = history.iloc[-1]
    try:
        local = json.loads(row.get("Local Evidence")) if isinstance(row.get("Local Evidence"), str) else {}
        providers = json.loads(row.get("Provider Evidence")) if isinstance(row.get("Provider Evidence"), str) else {}
    except (TypeError, ValueError):
        return None, []
    risk = int(row.get("Risk Score") or 0)
    signals: list[tuple[str, int]] = []
    model = local.get("model", {}) if isinstance(local, dict) else {}
    if isinstance(model, dict) and model.get("model_available") and model.get("prediction") == 1:
        signals.append(("Legacy ML telemetry", int(float(model.get("confidence") or 0))))
    if isinstance(local.get("similarity"), (int, float)) and local["similarity"] >= 65:
        signals.append(("Brand similarity", int(local["similarity"])))
    tls = local.get("tls", {}) if isinstance(local, dict) else {}
    if isinstance(tls, dict) and tls.get("https") and tls.get("connected") and not tls.get("certificate_valid"):
        signals.append(("TLS validation", 20))
    whois = local.get("whois", {}) if isinstance(local, dict) else {}
    if isinstance(whois, dict) and isinstance(whois.get("age_days"), (int, float)) and whois["age_days"] < 30:
        signals.append(("WHOIS domain age", 20))
    vt = providers.get("virustotal", {}) if isinstance(providers, dict) else {}
    detections = vt.get("evidence", {}).get("malicious", 0) if isinstance(vt, dict) else 0
    if detections:
        signals.append(("VirusTotal detections", min(100, int(detections) * 20)))
    return risk, signals


PLOTLY_CONFIG = {"displaylogo": False, "modeBarButtonsToRemove": [
    "zoom2d", "pan2d", "select2d", "lasso2d", "zoomIn2d", "zoomOut2d", "autoScale2d", "hoverClosestCartesian", "hoverCompareCartesian"
]}


def _chart_layout(fig, height: int = 300):
    fig.update_layout(
        height=height, margin=dict(l=16, r=16, t=28, b=16), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, sans-serif", color="#5c5148"), hoverlabel=dict(bgcolor="#2b2420", font=dict(color="#ffffff", family="Inter, sans-serif")),
        showlegend=False,
    )
    fig.update_xaxes(showgrid=False, zeroline=False, color="#5c5148")
    fig.update_yaxes(showgrid=False, zeroline=False, color="#5c5148")
    return fig


def _feature_importance_figure():
    """Render only the bundled Random Forest's real feature_importances_."""
    from models.model_manager import load_model
    artifact = load_model("url_detector")
    model = artifact.get("model") if isinstance(artifact, dict) else None
    names = artifact.get("feature_names", []) if isinstance(artifact, dict) else []
    values = getattr(model, "feature_importances_", None)
    if values is None or len(values) != len(names):
        return None
    ranked = sorted(zip(names, [float(value) for value in values]), key=lambda item: item[1], reverse=True)[:10]
    labels, importance = zip(*reversed(ranked))
    def _mix(index: int, total: int) -> str:
        start, end = (197, 176, 138), (178, 133, 116)
        factor = index / max(total - 1, 1)
        return "rgb(" + ",".join(str(round(a + (b - a) * factor)) for a, b in zip(start, end)) + ")"
    fig = go.Figure(go.Bar(x=importance, y=labels, orientation="h", marker_color=[_mix(i, len(labels)) for i in range(len(labels))],
                           hovertemplate="%{y}<br>Importance: %{x:.3f}<extra></extra>"))
    _chart_layout(fig, 340).update_layout(title="Feature Importance", xaxis_title="Random Forest importance")
    return fig


def render_analytics_visualizations(history) -> None:
    trend_col, distribution_col = st.columns(2, gap="large")
    with trend_col:
        st.subheader("Risk Score Trend")
        if history.empty:
            st.info("Risk trend will appear after completed scans are saved.")
        else:
            frame = history.copy(); frame["Timestamp"] = __import__("pandas").to_datetime(frame["Timestamp"], errors="coerce", utc=True)
            frame = frame.dropna(subset=["Timestamp"]).sort_values("Timestamp")
            if frame.empty:
                st.info("Saved scan timestamps are unavailable for a trend chart.")
            else:
                fig = go.Figure(go.Scatter(x=frame["Timestamp"], y=frame["Risk Score"].fillna(0), mode="lines+markers",
                    line=dict(color="#b28574", width=3), marker=dict(color="#b28574", size=6), fill="tozeroy", fillcolor="rgba(178,133,116,.15)",
                    hovertemplate="%{x|%d %b %Y, %H:%M}<br>Risk score: %{y}<extra></extra>"))
                _chart_layout(fig).update_layout(title="Recorded canonical scan risk")
                st.plotly_chart(fig, use_container_width=True, config=PLOTLY_CONFIG)
    with distribution_col:
        st.subheader("Threat Category Distribution")
        if history.empty:
            st.info("Threat distribution will appear after completed scans are saved.")
        else:
            values = history["Result"].fillna("").astype(str)
            counts = {
                "Phishing": int(values.isin(["CONFIRMED_MALICIOUS", "LIKELY_PHISHING", "Phishing"]).sum()),
                "Suspicious": int((values == "SUSPICIOUS").sum()),
                "Safe": int(values.isin(["LIKELY_LEGITIMATE", "Legitimate"]).sum()),
            }
            labels = [label for label, count in counts.items() if count]
            if not labels:
                st.info("No classified scan categories are available yet.")
            else:
                fig = go.Figure(go.Pie(labels=labels, values=[counts[label] for label in labels], hole=.68,
                    marker=dict(colors={"Phishing": "#a4453b", "Suspicious": "#d9a441", "Safe": "#6b8f71"}),
                    hovertemplate="%{label}: %{value}<extra></extra>"))
                _chart_layout(fig).update_layout(annotations=[dict(text=f"<b>{sum(counts.values())}</b><br>scans", x=.5, y=.5, showarrow=False, font=dict(color="#2b2420", size=16))])
                st.plotly_chart(fig, use_container_width=True, config=PLOTLY_CONFIG)

    feature_col, mitre_col = st.columns(2, gap="large")
    with feature_col:
        fig = _feature_importance_figure()
        if fig is None:
            st.subheader("Feature Importance")
            st.info("The bundled model does not expose Random Forest feature importances.")
        else:
            st.plotly_chart(fig, use_container_width=True, config=PLOTLY_CONFIG)
    with mitre_col:
        st.subheader("MITRE ATT&CK Technique Map")
        techniques = []
        if not history.empty:
            raw = history.iloc[-1].get("MITRE")
            try: techniques = json.loads(raw) if isinstance(raw, str) else []
            except (TypeError, ValueError): techniques = []
        catalog = [("T1566.002", "Spearphishing Link"), ("T1036.005", "Masquerading"), ("T1056", "Input Capture"), ("T1204.001", "Malicious Link")]
        observed = {item.get("id") for item in techniques if isinstance(item, dict)}
        if not observed:
            st.info("No ATT&CK techniques were returned for the latest scan.")
        else:
            values = [[1 if technique in observed else 0 for technique, _ in catalog[:2]], [1 if technique in observed else 0 for technique, _ in catalog[2:]]]
            labels = [[catalog[0][0], catalog[1][0]], [catalog[2][0], catalog[3][0]]]
            fig = go.Figure(go.Heatmap(z=values, text=labels, texttemplate="%{text}", hovertemplate="%{text}<br>%{z:Observed;Neutral}<extra></extra>",
                colorscale=[[0, "#e9e5df"], [.001, "#d9b7aa"], [1, "#8f6559"]], showscale=False, x=["", ""], y=["", ""]))
            _chart_layout(fig).update_layout(title="Latest deterministic mapping")
            st.plotly_chart(fig, use_container_width=True, config=PLOTLY_CONFIG)


def render_threat_dashboard() -> None:
    history = load_history()
    total = len(history)
    results = history["Result"].fillna("").astype(str) if not history.empty else []
    threats = int(results.isin(["CONFIRMED_MALICIOUS", "LIKELY_PHISHING", "SUSPICIOUS"]).sum()) if total else 0
    average_risk = round(float(history["Risk Score"].fillna(0).mean()), 1) if total else 0
    trend = _history_trend(history)
    cards = [("Total Scans", total, "terracotta"), ("Threats Detected", threats, "sand"),
             ("Avg Risk Score", average_risk, "terracotta"), ("Model Accuracy", "94.08%", "sand")]
    st.markdown('<div class="dashboard-stats">' + ''.join(
        f'<div class="stat-card {tone}"><span>{label}</span><strong>{value}</strong>' + (f'<small>{trend}</small>' if trend and label != "Model Accuracy" else "") + '</div>'
        for label, value, tone in cards) + '</div>', unsafe_allow_html=True)

    render_analytics_visualizations(history)

    risk, signals = _latest_signal_breakdown(history)
    left, right = st.columns((1, 1), gap="large")
    with left:
        st.subheader("Current Risk Posture")
        if risk is None:
            st.info("No completed URL scan is available yet. Run a scan to populate the risk gauge.")
        else:
            score = max(0, min(100, risk)); angle = -90 + score * 1.8
            level = "LOW" if score < 25 else "MEDIUM" if score < 50 else "HIGH" if score < 75 else "CRITICAL"
            st.markdown(f'''<div class="risk-gauge"><svg viewBox="0 0 240 140" role="img" aria-label="Risk score {score}">
              <path d="M25 120 A95 95 0 0 1 72.8 37.7" class="gauge-arc gauge-low"/><path d="M72.8 37.7 A95 95 0 0 1 120 25" class="gauge-arc gauge-medium"/>
              <path d="M120 25 A95 95 0 0 1 167.2 37.7" class="gauge-arc gauge-high"/><path d="M167.2 37.7 A95 95 0 0 1 215 120" class="gauge-arc gauge-critical"/>
              <line x1="120" y1="120" x2="120" y2="48" class="gauge-needle" transform="rotate({angle} 120 120)"/><circle cx="120" cy="120" r="5" class="gauge-hub"/>
              <text x="120" y="108" text-anchor="middle" class="gauge-score">{score}</text><text x="120" y="132" text-anchor="middle" class="gauge-level">{level}</text></svg></div>''', unsafe_allow_html=True)
    with right:
        st.subheader("Signal Breakdown")
        if not signals:
            st.info("No measured risk-contributing signals are recorded for the latest scan.")
        else:
            maximum = max(value for _, value in signals)
            st.markdown('<div class="signal-breakdown">' + ''.join(
                f'<div class="signal-row"><div><span>{html.escape(label)}</span><b>{value}</b></div><i><em style="width:{max(5, round(value / maximum * 100))}%"></em></i></div>'
                for label, value in signals) + '</div>', unsafe_allow_html=True)

    st.subheader("Recent Scan History")
    query = st.text_input("Filter scans", placeholder="Filter by URL, verdict, or scan type", label_visibility="collapsed")
    display = history.copy()
    if query and not display.empty:
        mask = display.astype(str).apply(lambda column: column.str.contains(query, case=False, na=False)).any(axis=1)
        display = display[mask]
    if display.empty:
        st.info("No scan history matches this filter.")
    else:
        compact = display[["Timestamp", "Type", "Normalized URL", "Result", "Risk Score", "Confidence"]].copy()
        compact["Result"] = compact["Result"].map(_risk_chip)
        st.markdown('<div class="history-table">' + compact.to_html(index=False, escape=False, classes="dashboard-history") + '</div>', unsafe_allow_html=True)

# =====================================================
# SIDEBAR
# =====================================================

# Missing API key warning banner — shown before navigation so it is always
# visible regardless of which page the user navigates to.
_missing_keys = [name for name, ok in _PROVIDER_KEY_CONFIG.items() if not ok]
if _missing_keys:
    st.sidebar.warning(
        "**Missing API keys**\n\n"
        + "\n".join(f"- `{k}`" for k in _missing_keys)
        + "\n\nThose providers will show **NOT QUERIED** on every scan. "
        "Add the keys to `.env` and restart the app."
    )

_nav_selection = st.sidebar.radio(
    "SECURITY OPERATIONS",
    [
        "Threat Intel",
        "URL Scan",
        "Email Analysis",
        "QR Analysis",
        "Screenshot Analysis",
        "History",
        "Reports",
    ]
)

# Navigation labels are presentation-only; analysis routes remain unchanged.
analysis_mode = {
    "Threat Intel": "Dashboard", "URL Scan": "URL Analysis",
    "Email Analysis": "Email Analysis", "QR Analysis": "QR Analysis",
    "Screenshot Analysis": "Screenshot Analysis", "History": "Scan History",
    "Reports": "Scan History",
}[_nav_selection]

_module_style = {
    "URL Analysis": ("URL Analysis", "⌁", "#b28574"),
    "Email Analysis": ("Email Analysis", "✉", "#c99b7a"),
    "QR Analysis": ("QR Analysis", "▦", "#a98d6b"),
    "Screenshot Analysis": ("Screenshot / OCR", "◉", "#c5b08a"),
    "Dashboard": ("Threat Intelligence", "◈", "#8f6559"),
    "Scan History": ("History & Reports", "◷", "#8f6559"),
}[analysis_mode]
st.markdown(f'<style>:root {{ --module-accent: {_module_style[2]}; }}</style><div class="module-marker"><span>{_module_style[1]}</span>{_module_style[0]}</div>', unsafe_allow_html=True)

def _provider_statuses_for_sidebar() -> dict[str, str]:
    """Single source of truth for sidebar System Status widget.

    Priority order:
      1. Live scan result in session_state["last_scan_result"] — set immediately
         after every scan so the sidebar reflects the current scan, not a stale
         history row.
      2. Most recent persisted history row — fallback when no scan has run yet
         this session.

    This eliminates the contradiction where the sidebar showed UNAVAILABLE while
    the Threat Intel tab showed AVAILABLE data from the same scan object.
    """
    defaults = {name: "UNAVAILABLE" for name in ("virustotal", "whois", "dns")}

    # ── Priority 1: live result from current session ─────────────────────────
    live = st.session_state.get("last_scan_result")
    if isinstance(live, dict):
        providers = live.get("providers") or live.get("provider_evidence") or {}
        if isinstance(providers.get("virustotal"), dict):
            defaults["virustotal"] = str(providers["virustotal"].get("status") or "UNAVAILABLE")
        whois = live.get("whois") or {}
        if isinstance(whois, dict) and whois.get("status"):
            defaults["whois"] = str(whois["status"])
        dns = live.get("dns") or {}
        if isinstance(dns, dict) and dns.get("status"):
            defaults["dns"] = str(dns["status"])
        return defaults

    # ── Priority 2: most recent persisted history row ────────────────────────
    history = load_history()
    if history.empty:
        return defaults
    for _, row in history.iloc[::-1].iterrows():
        raw = row.get("Provider Evidence")
        if not isinstance(raw, str) or not raw.strip():
            continue
        try:
            providers = json.loads(raw)
        except (TypeError, ValueError):
            continue
        for name in ("virustotal",):
            if isinstance(providers.get(name), dict):
                defaults[name] = str(providers[name].get("status") or "UNAVAILABLE")
        raw_local = row.get("Local Evidence")
        try:
            local = json.loads(raw_local) if isinstance(raw_local, str) else {}
        except (TypeError, ValueError):
            local = {}
        if isinstance(local.get("whois"), dict):
            defaults["whois"] = str(local["whois"].get("status") or "UNAVAILABLE")
        if isinstance(local.get("dns"), dict):
            defaults["dns"] = str(local["dns"].get("status") or "UNAVAILABLE")
        break
    return defaults

_sidebar_statuses = _provider_statuses_for_sidebar()
_status_class = lambda value: "online" if value in {"AVAILABLE", "NO_MATCH"} else "degraded" if value in {"RATE_LIMITED", "TIMEOUT", "ERROR"} else "offline"
st.sidebar.markdown(
    '<div class="system-status"><div class="system-status-title">SYSTEM STATUS</div>'
    + ''.join(f'<div class="system-status-row"><span class="status-dot {_status_class(_sidebar_statuses[name])}"></span>{label}<span>{_sidebar_statuses[name]}</span></div>'
              for name, label in (("virustotal", "VirusTotal"), ("whois", "WHOIS / RDAP"), ("dns", "DNS")))
    + '</div>', unsafe_allow_html=True)

if analysis_mode == "Dashboard":
    st.header("Threat Intelligence Console")
    st.caption("Live operational posture based on recorded canonical scan evidence.")
    render_threat_dashboard()
    st.stop()

# =====================================================
# HISTORY PAGE
# =====================================================

if analysis_mode == "Scan History":

    st.header("📜 Scan History")

    history = load_history()

    if history.empty:
        st.info("No scan history yet.")
    else:
        st.dataframe(
            history,
            use_container_width=True
        )

    st.divider()

    if st.button("🗑️ Clear All History", type="secondary", key="clear-history"):
        clear_history()
        st.success("History cleared!")
        st.rerun()

    st.stop()
# =====================================================
# QR ANALYSIS
# =====================================================

if analysis_mode == "QR Analysis":

    try:
        from qr_analyzer import analyze_qr
    except ImportError:
        st.error("QR analysis requires opencv-python-headless. Install it with: pip install opencv-python-headless")
        st.stop()

    st.header(
        "🔳 QR Code Phishing Detector"
    )

    uploaded_qr = st.file_uploader(
        "Upload QR Code Image",
        type=["png", "jpg", "jpeg"]
    )

    if uploaded_qr:

        file_path = uploaded_qr.name

        with open(
            file_path,
            "wb"
        ) as f:

            f.write(
                uploaded_qr.getbuffer()
            )

        extracted_url = analyze_qr(
            file_path
        )

        if extracted_url is None:

            st.error(
                "No QR Code detected."
            )

        else:

            st.success(
                "QR Code Detected"
            )

            st.write(
                f"Embedded Content: {extracted_url}"
            )

            if not validate_url(extracted_url):
                st.info("The QR code contains non-URL content; URL phishing analysis was not run.")
                save_scan("QR", extracted_url, "Non-URL content", 0, risk_level="NOT_APPLICABLE",
                          evidence="QR decoded successfully, but its content is not a URL.")
                st.stop()

            if not extracted_url.startswith(("http://", "https://")):
                extracted_url = "https://" + extracted_url

            complete_url_result = run_complete_url_analysis(extracted_url)
            save_canonical_scan("QR", complete_url_result)
            st.session_state["last_scan_result"] = complete_url_result
            render_url_evidence(complete_url_result, scan_type="QR")
            st.stop()
# =====================================================
# SCREENSHOT ANALYSIS
# =====================================================

if analysis_mode == "Screenshot Analysis":

    try:
        from image_analyzer import analyze_screenshot
    except ImportError:
        st.error("Screenshot analysis requires EasyOCR. Install it with: pip install easyocr")
        st.stop()

    st.header(
        "🖼 Screenshot Scam Detector"
    )

    uploaded_file = st.file_uploader(
        "Upload Screenshot",
        type=["png", "jpg", "jpeg"]
    )

    if uploaded_file:

        file_path = uploaded_file.name

        with open(
            file_path,
            "wb"
        ) as f:

            f.write(
                uploaded_file.getbuffer()
            )

        result = analyze_screenshot(
            file_path
        )

        st.image(
            uploaded_file,
            use_container_width=True
        )

        st.subheader(
            "📄 Extracted Text"
        )

        st.text_area(
            "",
            result["text"],
            height=200
        )

        st.subheader(
            "🚨 Threat Assessment"
        )

        if result["risk"] >= 50:

            st.error(
                f"{result['verdict']} ({result['risk']}/100)"
            )

        elif result["risk"] >= 20:

            st.warning(
                f"{result['verdict']} ({result['risk']}/100)"
            )

        else:

            st.success(
                f"{result['verdict']} ({result['risk']}/100)"
            )

        st.subheader(
            "🤖 AI Findings"
        )

        if result["indicators"]:

            for item in result["indicators"]:

                st.write(
                    "•",
                    item
                )

        else:

            st.write(
                "No suspicious indicators found."
            )

        if result["found_urls"]:
            st.subheader("URL Intelligence from Screenshot")
            screenshot_url_results = analyze_extracted_urls(result["found_urls"])
            for complete_url_result in screenshot_url_results:
                save_canonical_scan("Screenshot URL", complete_url_result)
                url_result = complete_url_result["model"]
                st.code(complete_url_result.get("normalized_url") or complete_url_result["url"])
                if not url_result.get("model_available", False):
                    st.warning(url_result.get("error") or "30-feature URL model unavailable for this URL.")
                else:
                    verdict = "Phishing" if url_result["prediction"] == 1 else "Legitimate"
                    st.write(f"30-feature URL model: {verdict} ({url_result['confidence']}% phishing probability)")
                render_url_evidence(complete_url_result)
        else:
            screenshot_url_results = []

        save_scan(
            "Screenshot",
            uploaded_file.name,
            result["verdict"],
            result["risk"]
        )

        report = generate_input_report("Screenshot", uploaded_file.name,
            {"ocr_indicators": result["indicators"], "extracted_urls": result["found_urls"]}, screenshot_url_results)

        st.download_button(
            "📥 Download Screenshot Report",
            report,
            file_name="screenshot_report.txt"
        )

    st.stop()
# =====================================================
# EMAIL ANALYSIS
# =====================================================

if analysis_mode == "Email Analysis":

    email_text = st.text_area(
        "Paste Email Content",
        height=300,
        placeholder="Paste suspicious email here..."
    )

    if st.button("Analyze Email"):

        if not email_text.strip():

            st.warning(
                "Please paste email content."
            )

            st.stop()

        result = analyze_email_content(
            email_text
        )

        prediction = result["prediction"]
        confidence = result["confidence"]

        if not result.get("model_available", False):
            st.warning(result.get("error") or "Email ML is unavailable; no email prediction was generated.")
            st.info("Email intelligence and extracted URL analysis remain available and are kept separate from Email ML.")

        save_scan(
            "Email",
            email_text[:100],
            "Phishing" if prediction == 1 else "Legitimate" if prediction == 0 else "ML unavailable",
            0 if confidence is None else confidence,
            confidence=confidence,
            risk_level="UNAVAILABLE" if prediction is None else None,
            evidence="; ".join(result.get("reasons", [])) or "Email ML unavailable",
        )

        st.subheader(
            "📧 Email Analysis Result"
        )

        if prediction == 1:

            st.error(
                f"⚠️ Phishing Email Detected ({confidence}%)"
            )

        elif prediction == 0:

            st.success(
                f"✅ Legitimate Email ({confidence}%)"
            )

        if confidence is not None:
            st.progress(min(int(confidence), 100))

        if not result.get("model_available", False):
            st.info(
                "ML model artifact not available. Email risk is being estimated using heuristic signals."
            )

        st.metric("Model Confidence", f"{confidence}%" if confidence is not None else "Unavailable")

        st.divider()

        st.subheader(
            "🔗 URLs Found"
        )

        urls = extract_urls(
            email_text
        )

        if urls:

            for detected_url in urls:

                st.code(
                    detected_url
                )

        else:

            st.write(
                "No URLs detected."
            )

        st.divider()

        st.subheader(
            "🔍 Embedded URL Analysis"
        )

        email_url_results = []
        if urls:
            email_url_results = analyze_extracted_urls(urls)
            for complete_url_result in email_url_results:

                st.write(
                    f"Analyzing: {complete_url_result.get('normalized_url') or complete_url_result['url']}"
                )
                save_canonical_scan("Email URL", complete_url_result)
                url_result = complete_url_result["model"]
                render_url_evidence(complete_url_result)
                if not url_result.get("model_available", False):
                    st.warning(url_result.get("error") or "URL ML result unavailable; displayed enrichment is still real evidence.")
                elif url_result["prediction"] == 1:
                    st.error(
                        "⚠️ Suspicious URL Detected"
                    )
                elif url_result["prediction"] == 0:
                    st.success(
                        "✅ URL Appears Safe"
                    )
                _tls = complete_url_result.get("tls") or {}
                _ssl_str = "enabled" if _tls.get("https") and _tls.get("connected") else "disabled" if _tls.get("connected") else "unavailable"
                _vt = complete_url_result.get("virustotal") or {}
                _vt_str = _vt.get("verdict") or _vt.get("status") or "unavailable"
                st.caption(
                    f"Brand: {complete_url_result.get('brand', 'Unknown')} · "
                    f"SSL: {_ssl_str} · "
                    f"VirusTotal: {_vt_str}"
                )

        else:

            st.write(
                "No URLs available for analysis."
            )

        st.divider()

        st.subheader(
            "🤖 Threat Indicators"
        )

        if result["reasons"]:

            # Keyword reasons alag group karo
            keyword_reasons = [r for r in result["reasons"] if r.startswith("Contains phishing keyword:")]
            other_reasons   = [r for r in result["reasons"] if not r.startswith("Contains phishing keyword:")]

            # Keywords ek hi line mein dikhao
            if keyword_reasons:
                keywords_found = [r.replace("Contains phishing keyword: ", "").strip("'") for r in keyword_reasons]
                st.write("• Phishing keywords found:", ", ".join(f"`{k}`" for k in keywords_found))

            # Baaki reasons alag alag
            for reason in other_reasons:
                st.write("•", reason)

        else:

            st.write(
                "No suspicious indicators found."
            )

        st.divider()

        st.subheader(
            "🤖 AI Email Intelligence"
        )

        if prediction is None:
            st.info(f"Email ML unavailable. Extracted {len(urls)} URL(s); use their individual URL-analysis results above. No email classification was fabricated.")
        else:
            email_ai = generate_email_intelligence(prediction, confidence, result["reasons"], urls)
            st.info(f"""Threat Level: {email_ai['threat_level']}

Summary:
{email_ai['summary']}

Likely Attacker Goal:
{email_ai['attacker_goal']}

URLs Found:
{email_ai['url_count']}""")

        st.divider()

        st.subheader(
            "🛡 Recommendation"
        )

        if prediction == 1:

            st.error(
                "Do not click links or provide credentials from this email."
            )

        elif prediction == 0:

            st.success(
                "Email appears legitimate according to the detection system."
            )

        report = generate_input_report("Email", "Email Analysis",
            {"email_content_model_available": result.get("model_available"), "content_reasons": result["reasons"], "extracted_urls": urls}, email_url_results)

        st.download_button(
            "📥 Download Email Security Report",
            report,
            file_name="email_security_report.txt"
        )


# =====================================================
# URL ANALYSIS
# =====================================================

elif analysis_mode == "URL Analysis":

    url_input_val = st.text_input(
        "Enter URL",
        placeholder="https://amaz0n-login-security.xyz",
        key="url_input"
    )

    url_to_analyze = url_input_val.strip()

    if "url_analysis_target" in st.session_state and st.session_state["url_analysis_target"] != url_to_analyze:
        st.session_state.pop("url_analysis_result", None)
        st.session_state.pop("url_analysis_target", None)

    analyze_clicked = st.button("Analyze URL", key="btn_analyze_url")

    if analyze_clicked:

        if not url_to_analyze:

            st.warning(
                "Please enter a URL."
            )

            st.stop()

        complete_url_result = run_complete_url_analysis(url_to_analyze)
        st.session_state["url_analysis_result"] = complete_url_result
        st.session_state["url_analysis_target"] = url_to_analyze
        st.session_state["last_scan_result"] = complete_url_result

    if "url_analysis_result" in st.session_state and st.session_state.get("url_analysis_target") == url_to_analyze and url_to_analyze:
        render_url_evidence(st.session_state["url_analysis_result"], scan_type="URL")
        st.stop()
