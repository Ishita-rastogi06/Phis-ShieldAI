
import socket
socket.setdefaulttimeout(2.0)

import tempfile
import json
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
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

from report_generator import generate_report, generate_input_report, generate_canonical_report, generate_pdf_report


# =====================================================
# PAGE CONFIG
# =====================================================

st.set_page_config(
    page_title="Phis-ShieldAI",
    page_icon="🛡️",
    layout="wide"
)

try:
    import extra_streamlit_components as stx
    from history_manager import get_or_create_user_id
    _cookie_mgr = stx.CookieManager(key="phishshield_cookies")
    get_or_create_user_id(_cookie_mgr)
except Exception:
    pass
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

st.markdown("""
<style>
/* Warm taupe/sand enterprise theme override. No Streamlit chrome or default radio visuals. */
:root { --sand:#C5B08A; --taupe:#4A2C24; --cream:#FDFBF7; --espresso:#2C221E; --muted-taupe:#5A4840; --border:#A89370; --chestnut:#F4A261; --peach-hover:#E98E73; }
#MainMenu,header,footer,[data-testid="stToolbar"],[data-testid="stDecoration"],[data-testid="stDeployButton"] { display:none !important; }
html,body,.stApp,[data-testid="stAppViewContainer"] { background:var(--sand) !important; color:var(--espresso) !important; }
.block-container { max-width:1380px !important; padding-top:0.4rem !important; }
section[data-testid="stSidebar"] { background:var(--taupe) !important; border-right:0 !important; } section[data-testid="stSidebar"] > div { padding:1.35rem .78rem; }
section[data-testid="stSidebar"] * { color:var(--cream) !important; } section[data-testid="stSidebar"] label p { color:var(--cream) !important; font-size:.76rem !important; font-weight:800 !important; letter-spacing:.09em; }
section[data-testid="stSidebar"] [data-baseweb="radio"] > div { width:100%; padding:.72rem .82rem; margin:.15rem 0; border:0 !important; border-radius:8px; transition:background .16s ease,transform .16s ease; } section[data-testid="stSidebar"] [data-baseweb="radio"] > div:hover { background:rgba(253,251,247,.17) !important; transform:translateX(1px); } section[data-testid="stSidebar"] [data-baseweb="radio"] > div:has(input:checked) { background:var(--cream) !important; box-shadow:0 4px 12px rgba(0,0,0,.08) !important; } section[data-testid="stSidebar"] [data-baseweb="radio"] > div:has(input:checked) * { color:var(--espresso) !important; } section[data-testid="stSidebar"] [data-baseweb="radio"] [role="radio"] > div:first-child { display:none !important; }
h1,h2,h3,h4,p,label,.stMarkdown { color:var(--espresso) !important; font-family:Inter,system-ui,-apple-system,"Segoe UI",sans-serif !important; } h1 { font-weight:800 !important; } .stCaption { color:var(--muted-taupe) !important; }
.soc-header { background:var(--cream) !important; border:1px solid var(--border) !important; border-radius:10px !important; box-shadow:none !important; backdrop-filter:none !important; margin-top:0px !important; margin-bottom:12px !important; display:flex; align-items:center; gap:14px; padding:12px 18px; }.soc-icon { background:#F4EDE4 !important; border:1px solid var(--border) !important; color:var(--chestnut) !important; border-radius:8px !important; width:40px; height:40px; display:grid; place-items:center; font-size:1.2rem; }.soc-copy { flex:1; }.soc-title { color:var(--espresso) !important; font-size:1.25rem; font-weight:850; }.soc-subtitle { color:var(--muted-taupe) !important; font-size:.78rem; margin-top:2px; }.soc-tag { background:#F4EDE4 !important; border:1px solid var(--border) !important; color:var(--muted-taupe) !important; padding:4px 8px; border-radius:5px; font-size:.65rem; font-weight:800; letter-spacing:.11em; }
[data-testid="stMetric"],[data-testid="stExpander"],[data-testid="stAlert"] { background:var(--cream) !important; border:1px solid var(--border) !important; border-radius:10px !important; box-shadow:none !important; backdrop-filter:none !important; } [data-testid="stMetric"]:hover { border-color:var(--border) !important; box-shadow:none !important; } [data-testid="stMetricLabel"] { color:var(--muted-taupe) !important; } [data-testid="stMetricValue"] { color:var(--espresso) !important; }
.stButton>button,[data-testid="stDownloadButton"] button { background:var(--chestnut) !important; color:var(--espresso) !important; border:1px solid #DD865F !important; border-radius:6px !important; box-shadow:none !important; font-weight:800 !important; }.stButton>button:hover,[data-testid="stDownloadButton"] button:hover { background:var(--peach-hover) !important; border-color:#D97B62 !important; box-shadow:none !important; }
.stTextInput input,.stTextArea textarea,[data-testid="stFileUploaderDropzone"] { background:var(--cream) !important; color:var(--espresso) !important; border:1px solid var(--border) !important; border-radius:8px !important; }.stTextInput input:focus,.stTextArea textarea:focus { border-color:var(--chestnut) !important; box-shadow:0 0 0 1px var(--chestnut) !important; }
[data-testid="stDataFrame"] { background:var(--cream) !important; border:1px solid var(--border) !important; border-radius:8px !important; } [data-testid="stDataFrame"] * { color:var(--espresso) !important; } [data-testid="stExpander"] summary { color:var(--espresso) !important; } hr { border-color:var(--border) !important; }
</style>
<div class="soc-header"><div class="soc-icon">🛡</div><div class="soc-copy"><div class="soc-title">Phis-ShieldAI</div><div class="soc-subtitle">Threat Intelligence, Detection &amp; Response</div></div><div class="soc-tag">SECURITY OPERATIONS CENTER</div></div>
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
    "NOT_QUERIED":    ("NOT QUERIED",  "Target domain offline or scan blocked before provider call was sent."),
    "NOT_CONFIGURED": ("NOT QUERIED",  "Provider key not configured — call was never sent."),
    "UNAVAILABLE":    ("UNAVAILABLE",  "Provider call attempted but returned an error."),
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


def evidence_card(title, data, *, hide_keys=()):
    """Render backend evidence as labeled fields; never dumps raw Python dicts."""
    data = data if isinstance(data, dict) else {"status": "UNAVAILABLE", "reason": "No response was available."}
    status = str(data.get("status", "")).upper()
    if not status:
        if data.get("model_available") is True:
            status = "AVAILABLE"
        elif data.get("model_available") is False:
            status = "UNAVAILABLE"
        else:
            status = "AVAILABLE"
    unavailable = status in UNAVAILABLE_STATUSES or bool(data.get("error"))
    card_class = "source-unavailable" if unavailable else "source-evidence"
    label, _default_note = _STATE_LABELS.get(status, (status or "AVAILABLE", ""))
    ignored = set(hide_keys) | {"html", "status", "reason", "error", "source", "matches"}
    # Build field rows — skip nested lists/dicts that have their own renderer
    fields = "".join(
        f"<div><b>{html.escape(k.replace('_', ' ').title())}:</b> {html.escape(_display_value(v))}</div>"
        for k, v in data.items() if k not in ignored and not isinstance(v, (list,)) and not (isinstance(v, dict) and len(v) > 3)
    )
    reason = data.get("reason") or data.get("error")
    reason_html = f"<small>{html.escape(str(reason))}</small>" if reason else ""
    display_title = str(title).upper()
    st.markdown(
        f'<div class="{card_class}"><b style="font-size:1.12rem;font-weight:850;letter-spacing:.04em;color:#3d2b1f">{html.escape(display_title)}</b><span>{html.escape(label)}</span>{reason_html}{fields}</div>',
        unsafe_allow_html=True,
    )


def render_scan_progress_step(slot, pct: int, title: str, detail: str):
    """Render an active, living status bar on screen that stays visible while backend analysis executes."""
    slot.markdown(
        f'<div style="margin: 16px 0 24px; padding: 14px 18px; background: #fffdf9; border: 1.5px solid #ded0b8; border-left: 5px solid #7c5448; border-radius: 10px; box-shadow: 0 4px 14px rgba(43,36,32,0.06);">'
        f'<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">'
        f'<span style="font: 800 0.98rem \'Inter\', sans-serif; color: #3d2b1f;">{title}</span>'
        f'<span style="font: 700 0.85rem \'Inter\', sans-serif; color: #7c5448; background: #f4ede4; padding: 2px 8px; border-radius: 4px;">{pct}%</span>'
        f'</div>'
        f'<div style="font-size: 0.82rem; color: #5c5148; margin-bottom: 8px;">{detail}</div>'
        f'<div style="height: 7px; background: #efe6dc; border-radius: 999px; overflow: hidden;">'
        f'<div style="height: 100%; width: {pct}%; background: linear-gradient(90deg, #b28574, #7c5448); border-radius: inherit; transition: width 0.2s ease;"></div>'
        f'</div>'
        f'</div>',
        unsafe_allow_html=True
    )


def source_card(name, item):
    """Render one provider result with clear, non-misleading threat intelligence badges."""
    if not isinstance(item, dict):
        item = {"status": "NOT_QUERIED", "reason": "Target host offline or unresolvable. Provider call was skipped.", "malicious": None}
    status = item.get("status", "NOT_QUERIED")
    evidence = item.get("evidence")
    flat_evidence: dict = {}
    if isinstance(evidence, dict):
        flat_evidence = evidence
    elif isinstance(evidence, list):
        flat_evidence = {"matches": evidence}

    merged = {**item, **flat_evidence}

    target_host = flat_evidence.get("target_host") or flat_evidence.get("host") or ""
    tot_engines = flat_evidence.get("total_engines")

    if status == "AVAILABLE":
        is_mal = item.get("malicious", False)
        scan_src = flat_evidence.get("scan_source") or "existing_report"
        src_text = "FRESHLY SCANNED ✅" if scan_src == "freshly_scanned" else "EXISTING REPORT ℹ️"
        merged["Scan Mode"] = src_text
        if is_mal:
            merged["Threat Status"] = "🔴 CONFIRMED MALICIOUS RECORD"
        elif flat_evidence.get("is_legit"):
            merged["Threat Status"] = "🟢 VERIFIED LEGITIMATE DOMAIN"
        elif flat_evidence.get("is_suspicious_ip"):
            merged["Threat Status"] = "⚠️ UNINDEXED THREAT (RAW IP HOST)"
        elif flat_evidence.get("is_suspicious_brand"):
            merged["Threat Status"] = "⚠️ UNINDEXED THREAT (SUSPICIOUS / FAKE DOMAIN)"
        else:
            merged["Threat Status"] = "⚠️ UNINDEXED THREAT (0 VENDOR DETECTIONS)"

        if tot_engines:
            merged["Database Index"] = f"{item.get('malicious_count', flat_evidence.get('malicious', 0))} / {tot_engines} Security Vendors Flagged"
        else:
            merged["Database Index"] = "Fresh Scan Completed" if scan_src == "freshly_scanned" else "Record Found in Provider Database"
    elif status == "PENDING":
        merged["Threat Status"] = "⏳ SCAN PENDING (Submitted to Engine)"
        merged["Database Index"] = "Scan In Progress on Provider Engine"
        merged["reason"] = (item.get("reason") or "Scan actively submitted to provider cloud engine.") + " (Analysis in progress; result will update when analysis finishes)."
    elif status == "NO_MATCH":
        if flat_evidence.get("is_legit"):
            merged["Threat Status"] = "🟢 VERIFIED LEGITIMATE DOMAIN"
            merged["Database Index"] = "0 Malicious Records (Verified Trusted Brand)"
        elif flat_evidence.get("is_suspicious_ip"):
            merged["Threat Status"] = "⚠️ UNINDEXED THREAT (RAW IP HOST)"
            merged["Database Index"] = "0 Feed Matches (Raw IP Address)"
        elif flat_evidence.get("is_suspicious_brand"):
            merged["Threat Status"] = "⚠️ UNLISTED IN FEED (SUSPICIOUS / FAKE DOMAIN)"
            merged["Database Index"] = "0 Feed Matches (Newly Generated Link)"
        else:
            merged["Threat Status"] = "⚠️ UNINDEXED THREAT (UNLISTED IN FEED)"
            if tot_engines:
                merged["Database Index"] = f"0 / {tot_engines} Security Vendors Flagged (Unindexed Target)"
            else:
                merged["Database Index"] = "0 Matches in Active Feed Records (Unlisted Target)"
        merged["reason"] = item.get("reason") or f"Link verified against database — 0 adverse malicious entries found for '{target_host}'."
    elif status in ("TIMEOUT", "UNAVAILABLE"):
        merged["Threat Status"] = "⚪ HOST UNREACHABLE / TIMED OUT"
        merged["Database Index"] = f"Unreachable Host ({target_host})" if target_host else "Unreachable Host or Engine Timeout"
        merged["reason"] = item.get("reason") or "Target host is offline, unresolvable, or provider engine timed out."
    else:
        merged["Threat Status"] = "⚪ NOT QUERIED / SKIPPED"
        merged["Database Index"] = "Not Queried (Host Offline or Provider Skipped)"
        merged["reason"] = item.get("reason") or "Target host offline, API key missing, or call skipped."

    evidence_card(name, merged, hide_keys={"evidence", "malicious", "strong", "provider", "timestamp", "target_host", "feed_size", "total_engines", "unlisted_phishing", "brand_impersonated", "verified_legitimate", "scan_source", "is_legit", "is_suspicious_brand", "is_suspicious_ip"})


def render_url_evidence(result, scan_type="URL"):
    """Render structured evidence cards for a URL scan result."""
    target = result.get("url") or result.get("normalized_url") or "URL"
    verdict = str(result.get("verdict", "INSUFFICIENT_EVIDENCE"))
    confidence = str(result.get("confidence_strength", "insufficient")).title()
    
    # Hard enforcement: model_available MUST be False if genuine features (25 or 30) were not collected
    model = result.get("model") if isinstance(result.get("model"), dict) else {}
    if not model.get("features") or len(model.get("features", [])) not in (25, 30):
        model["model_available"] = False
        result["model_available"] = False

    _ml_flag = bool(result.get("model_available", False))

    tone = {"CONFIRMED_MALICIOUS": "critical", "LIKELY_PHISHING": "high", "SUSPICIOUS": "medium", "LIKELY_LEGITIMATE": "low"}.get(verdict, "unknown")
    label = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "unknown": "INSUFFICIENT EVIDENCE"}[tone]
    original_url = result.get("url") or target
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
    model_res = result.get("model") if isinstance(result.get("model"), dict) else {}
    model_pred = model_res.get("prediction")
    model_conf = model_res.get("confidence", 0)

    is_phish_verdict = verdict in ("LIKELY_PHISHING", "SUSPICIOUS", "CONFIRMED_MALICIOUS")
    is_phish_model = (model_pred == 1)
    is_disagreement = _ml_flag and (is_phish_verdict != is_phish_model)

    if not _ml_flag:
        st.markdown(
            f'<div class="evidence-card" style="border-left:4px solid #f59e0b;margin-bottom:.75rem;padding:.75rem 1rem">'
            f'<div style="font-weight:700;color:#d97706;margin-bottom:.2rem">⚠️ ANALYSIS PIPELINE NOTICE: Live ML Classifier Skipped</div>'
            f'<div style="font-size:.84rem;line-height:1.45;color:#374151">'
            f'<b>Verdict Basis:</b> Driven by <b>Rule-Based Heuristics & Threat Intelligence</b> (Brand Impersonation, Path & Keyword Analysis).<br>'
            f'<b>Risk Score ({risk_score}/100):</b> Calculated from rule-based indicators and available threat intelligence.<br>'
            f'<b>ML Telemetry:</b> Live 25-feature signal collection was <i>skipped</i> for this target input.'
            f'</div></div>',
            unsafe_allow_html=True
        )
    elif is_disagreement:
        st.markdown(
            f'<div class="evidence-card" style="border-left:4px solid #dc2626;margin-bottom:.75rem;padding:.75rem 1rem">'
            f'<div style="font-weight:700;color:#dc2626;margin-bottom:.2rem">🛡️ ANALYSIS PIPELINE NOTICE: Security Policy Override Applied</div>'
            f'<div style="font-size:.84rem;line-height:1.45;color:#374151">'
            f'<b>Verdict Basis:</b> Overridden to <b>{html.escape(verdict.replace("_", " ").title())}</b> by Security Policy Rules (Brand Impersonation / Threat Intel).<br>'
            f'<b>ML Model Status:</b> Active (Predicted <code>{"Class 1 Phishing" if is_phish_model else "Class 0 Legitimate"}</code> with {model_conf}% score, but was overridden by rule-based brand impersonation safeguards).'
            f'</div></div>',
            unsafe_allow_html=True
        )
    else:
        st.markdown(
            f'<div class="evidence-card" style="border-left:4px solid #7c5448;margin-bottom:.75rem;padding:.75rem 1rem">'
            f'<div style="font-weight:700;color:#4a3728;margin-bottom:.2rem">✅ ANALYSIS PIPELINE NOTICE: 25-Feature Live ML Model Active</div>'
            f'<div style="font-size:.84rem;line-height:1.45;color:#374151">'
            f'<b>Verdict Basis:</b> Active 25-Feature Random Forest ML Model (schema <code>uci-live-25-v1</code>) corroborated by live threat intelligence.'
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
    if not _ml_flag:
        source_badge = '<span style="background:#374151;color:#f3f4f6;padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:600;margin-left:8px">RULE-BASED & THREAT INTEL</span>'
        conf_explanation = f"Confidence is <b>{confidence}</b> based on lexical brand-similarity analysis, path indicators, and threat intelligence. ML Model was <i>unavailable</i>."
    elif is_disagreement:
        source_badge = '<span style="background:#b91c1c;color:#fef2f2;padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:600;margin-left:8px">SECURITY POLICY OVERRIDE</span>'
        conf_explanation = f"Confidence is <b>{confidence}</b> based on brand impersonation heuristics and threat intelligence. The 25-feature ML model predicted {'Phishing' if is_phish_model else 'Legitimate'} ({model_conf}%), but security policy rules overrode the final verdict."
    else:
        source_badge = '<span style="background:#065f46;color:#a7f3d0;padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:600;margin-left:8px">AI/ML MODEL ACTIVE</span>'
        conf_explanation = f"Confidence is <b>{confidence}</b> based on validated 25-feature live ML model prediction ({model_conf}%) corroborated by threat intelligence."

    st.markdown(
        f'<div class="evidence-card"><span class="card-kicker">FINAL VERDICT & CONFIDENCE ATTRIBUTION</span>'
        f'<h4>{html.escape(verdict.replace("_", " ").title())} {source_badge}</h4>'
        f'<p style="margin-top:.4rem;font-size:.85rem">{conf_explanation}</p>'
        f'</div>',
        unsafe_allow_html=True,
    )

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
        if is_disagreement:
            _basis_parts.append(f"<b>ML Model Engine:</b> ⚠️ Disagreed (Predicted <code>{'Class 1 Phishing' if is_phish_model else 'Class 0 Legitimate'}</code> with {model_conf}% score — Overridden by Security Policy)")
        elif model_available:
            _basis_parts.append("<b>ML Model Engine:</b> ✅ Active 25-Feature Live Classifier (schema <code>uci-live-25-v1</code>)")
        else:
            _basis_parts.append("<b>ML Model Engine:</b> ⚠️ Unavailable (Live 25-feature signal collection failed or target unreachable)")

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
        left.metric("Confidence", strength, delta="High rule trigger consensus" if not model_available else ("Policy override applied" if is_disagreement else "Validated ML model"))
        middle.metric(
            "Brand Detected",
            brand_val.title() if brand_val != "Unknown" else "None",
            delta=f"{similarity}% similarity" if similarity > 0 else "No brand impersonation",
            delta_color="normal" if similarity > 0 else "off"
        )
        right.metric(
            "ML Model",
            "Overridden" if is_disagreement else ("Active" if model_available else "Unavailable"),
            delta="Rule-based override" if is_disagreement else ("Rule-based analysis used" if not model_available else "25-Feature Live RF"),
            delta_color="off",
        )
        if is_disagreement:
            st.caption(
                f"🛡️ <b>Security Policy Override:</b> The 25-feature ML model predicted <b>{'Phishing' if is_phish_model else 'Legitimate'} ({model_conf}%)</b> based on structural signals alone. "
                f"However, because the domain impersonates <b>'{brand_val.title()}'</b> ({similarity}% similarity) on an unauthorized host, "
                f"the security policy engine overrode the final verdict to <b>{verdict.replace('_', ' ').title()} ({risk_score}/100 Risk)</b> to protect against brand phishing."
            )
        elif not model_available:
            st.caption(
                "⚠️ <b>Note on ML Availability:</b> The 25-feature live ML model requires a valid URL target with reachable host data. "
                "When live signal collection is skipped or fails, the verdict is calculated from "
                "rule-based lexical/structural heuristics (e.g. brand impersonation on non-official host, "
                "suspicious paths) and available threat-intelligence."
            )
    with model_tab:
        model = result.get("model", {})
        model_available = bool(result.get("model_available", False)) and bool(model.get("model_available", False)) and len(model.get("features", [])) in (25, 30)
        if not model_available:
            model_err = model.get("error") or "Live 25-Feature Model unavailable for this input"
            st.markdown(
                f'<div class="source-unavailable">'
                f'<b>25-FEATURE LIVE RANDOM FOREST CLASSIFIER</b>'
                f'<span>UNAVAILABLE</span>'
                f'<small>The 25-feature live model requires a valid URL target with reachable host data. '
                f'This does <strong>not</strong> mean the URL is safe — it means live signal collection failed.</small>'
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
            model_copy = dict(model)
            model_copy["status"] = "AVAILABLE"
            pred_val = model_copy.get("prediction")
            pred_label = "🔴 PHISHING (Class 1)" if pred_val == 1 else "🟢 LEGITIMATE (Class 0)" if pred_val == 0 else "Unknown"
            conf_val = model_copy.get("confidence", 0)
            feats_count = len(model.get("features", []))
            model_title = f"{feats_count}-FEATURE LIVE RANDOM FOREST CLASSIFIER" if feats_count == 25 else "30-FEATURE LEGACY CLASSIFIER"

            if is_disagreement:
                st.warning(
                    f"🛡️ **SECURITY POLICY OVERRIDE APPLIED**: The ML model scored this input as **{pred_label} ({conf_val}% phishing score)** "
                    f"based on structural features. However, the overall verdict was upgraded to **{verdict.replace('_', ' ').title()} ({risk_score}/100 Risk)** "
                    f"because the security policy engine detected brand impersonation for **'{brand_val.title()}'** ({similarity}% similarity) on an unauthorized host."
                )
            else:
                st.success(
                    f"✅ **UNANIMOUS CONSENSUS**: The 25-feature ML model (**{pred_label}**) and Security Policy Rules unanimously agree on the final verdict **{verdict.replace('_', ' ').title()}**."
                )

            st.markdown(
                f'<div class="evidence-card" style="border-left:4px solid #8f6559;margin-bottom:1rem">'
                f'<span class="card-kicker">{model_title}</span>'
                f'<h4>Status: <span style="color:#7c5448">ACTIVE</span> · Prediction: {pred_label}</h4>'
                f'<p style="font-size:.85rem;margin-top:.3rem"><b>This Scan Confidence:</b> {conf_val}% Phishing Probability &nbsp;|&nbsp; <b>Model Benchmark Accuracy:</b> 94.08% (UCI Held-Out Test Set)</p>'
                f'</div>',
                unsafe_allow_html=True,
            )
            features = model.get("features", [])
            feature_names_list_25 = [
                ("having_IP_Address", "Having IP Address in URL"),
                ("URL_Length", "URL Character Length (>75 chars)"),
                ("Shortining_Service", "URL Shortening Service Detected"),
                ("having_At_Symbol", "Having '@' Symbol in URL"),
                ("double_slash_redirecting", "Double Slash '//' Redirect"),
                ("Prefix_Suffix", "Hyphen '-' in Domain Name"),
                ("having_Sub_Domain", "Subdomain Depth Level"),
                ("SSLfinal_State", "SSL / TLS Certificate State"),
                ("Domain_registeration_length", "Domain Registration Age"),
                ("Favicon", "Favicon Loaded from External Domain"),
                ("port", "Non-Standard Port Usage"),
                ("HTTPS_token", "HTTPS Token in Host Domain"),
                ("Request_URL", "External Resource Request Ratio"),
                ("URL_of_Anchor", "Anchor Tags Pointing Outside"),
                ("Links_in_tags", "Script / Meta Link Ratio"),
                ("SFH", "Server Form Handler (SFH)"),
                ("Submitting_to_email", "Submitting Credentials to Email"),
                ("Abnormal_URL", "Abnormal Hostname Pattern"),
                ("Redirect", "HTTP Redirect Hop Count"),
                ("on_mouseover", "Mouseover Status Bar Changes"),
                ("RightClick", "Right Click Context Menu Disabled"),
                ("popUpWidnow", "Pop-up Window with Form Fields"),
                ("Iframe", "Hidden IFrames Rendered"),
                ("age_of_domain", "WHOIS Domain Age"),
                ("DNSRecord", "DNS A/AAAA Record Present"),
            ]
            feature_names_list = feature_names_list_25 if feats_count == 25 else feature_names_list_25 + [
                ("web_traffic", "Alexa / Tranco Web Traffic Rank"),
                ("Page_Rank", "Google PageRank Index"),
                ("Google_Index", "Indexed on Google Search"),
                ("Links_pointing_to_page", "Inbound Backlinks Count"),
                ("Statistical_report", "Phishing Blacklist Stat Report")
            ]
            if features:
                st.subheader(f"📊 {len(features)} UCI Feature Extraction Breakdown")
                f_cols = st.columns(2)
                for idx, (f_name, f_desc) in enumerate(feature_names_list):
                    val = features[idx] if idx < len(features) else 0
                    val_str = "🔴 Phishing Indicator (-1)" if val == -1 else "🟢 Legitimate (+1)" if val == 1 else "🟡 Neutral / Suspicious (0)"
                    col = f_cols[idx % 2]
                    col.markdown(
                        f'<div style="background:#fafafa;border:1px solid #e5e7eb;border-radius:6px;padding:8px 12px;margin-bottom:8px;font-size:.82rem">'
                        f'<b>{idx+1}. {html.escape(f_desc)}</b> <code>({f_name})</code><br>'
                        f'Value: <span style="font-weight:600">{val_str}</span>'
                        f'</div>',
                        unsafe_allow_html=True,
                    )
            else:
                evidence_card("LIVE MODEL", model_copy, hide_keys={"features"})

    with website_tab:
        website = result.get("website", {})
        tls = result.get("tls", {})
        norm_url = result.get("normalized_url", target)
        parsed_url = urlparse("https://" + norm_url.lstrip("https://").lstrip("http://"))
        host_name = (parsed_url.hostname or norm_url).lower()
        tld_suffix = host_name.split(".")[-1] if "." in host_name else ""

        high_risk_tlds = {"xyz", "top", "online", "site", "live", "tech", "store", "tk", "ml", "ga", "cf", "gq", "work", "click", "link", "zip", "mov", "verify", "pay"}
        tld_risk_badge = "🔴 HIGH RISK / DISPOSABLE TLD" if tld_suffix in high_risk_tlds else "🟢 STANDARD GENERIC TLD"
        hyphen_count = host_name.count("-")
        sub_count = max(0, len(host_name.split(".")) - 2)

        st.markdown(
            f'<div class="evidence-card" style="border-left:4px solid #7c5448;margin-bottom:1rem">'
            f'<span class="card-kicker">DOMAIN & TLD STRUCTURE ANALYSIS</span>'
            f'<h4>TLD: <code style="font-size:1.1rem">.{html.escape(tld_suffix)}</code> · {tld_risk_badge}</h4>'
            f'<div style="font-size:.83rem;margin-top:.4rem;line-height:1.6">'
            f'• <b>Host Domain:</b> <code>{html.escape(host_name)}</code><br>'
            f'• <b>Hyphen Count in Domain:</b> {hyphen_count} {"⚠️ (Hyphens frequently used in brand spoofing)" if hyphen_count > 0 else "🟢 (None)"}<br>'
            f'• <b>Subdomain Count:</b> {sub_count} {"⚠️ (Multi-subdomain structure)" if sub_count > 1 else "🟢 (Standard)"}'
            f'</div></div>',
            unsafe_allow_html=True,
        )

        reachable = website.get("reachable", False)
        reach_badge = "🔴 UNREACHABLE / OFFLINE" if not reachable else "🟢 ONLINE & REACHABLE"
        notes = website.get("notes") or website.get("title") or "No HTML title extracted"
        forms_val = website.get("forms", 0)
        forms_cnt = len(forms_val) if isinstance(forms_val, (list, tuple, dict)) else int(forms_val or 0)
        iframes_val = website.get("iframes", 0)
        iframes_cnt = len(iframes_val) if isinstance(iframes_val, (list, tuple, dict)) else int(iframes_val or 0)

        st.markdown(
            f'<div class="evidence-card" style="border-left:4px solid {"#b28574" if not reachable else "#7c5448"};margin-bottom:1rem">'
            f'<span class="card-kicker">WEBSITE INSPECTION & DOM ANALYZER</span>'
            f'<h4>Status: {reach_badge}</h4>'
            f'<div style="font-size:.83rem;margin-top:.4rem;line-height:1.6">'
            f'• <b>HTTP Title / Inspection Note:</b> {html.escape(str(notes))}<br>'
            f'• <b>Form Elements Found:</b> {forms_cnt} {"⚠️ Password / Input forms present" if forms_cnt > 0 else "🟢 No forms"}<br>'
            f'• <b>Embedded IFrames:</b> {iframes_cnt} {"⚠️ Hidden iframe tags present" if iframes_cnt > 0 else "🟢 No IFrames"}'
            f'</div></div>',
            unsafe_allow_html=True,
        )

        tls_connected = tls.get("connected", False)
        tls_https = tls.get("https", False)
        tls_valid = tls.get("certificate_valid", False)
        tls_badge = "🔒 SECURE HTTPS (Valid SSL)" if (tls_https and tls_connected and tls_valid) else "⚠️ INSECURE HTTP / OFFLINE SSL"
        issuer = tls.get("issuer") or "N/A"
        days_left = tls.get("days_remaining") or "N/A"

        st.markdown(
            f'<div class="evidence-card" style="border-left:4px solid {"#4a3728" if (tls_https and tls_connected and tls_valid) else "#8f6559"}">'
            f'<span class="card-kicker">TLS & HTTPS SECURITY CERTIFICATE</span>'
            f'<h4>Status: {tls_badge}</h4>'
            f'<div style="font-size:.83rem;margin-top:.4rem;line-height:1.6">'
            f'• <b>HTTPS Connection:</b> {"Yes" if tls_https else "No"}<br>'
            f'• <b>Certificate Authority / Issuer:</b> {html.escape(str(issuer))}<br>'
            f'• <b>Certificate Validity Days Remaining:</b> {days_left}'
            f'</div></div>',
            unsafe_allow_html=True,
        )

    with network_tab:
        dns = result.get("dns", {})
        whois = result.get("whois", {})

        dns_notes = dns.get("notes") or "DNS resolution completed"
        ips = dns.get("ip_addresses") or dns.get("ips") or []
        mx_records = dns.get("mx_records") or []
        ns_records = dns.get("nameservers") or []

        st.markdown(
            f'<div class="evidence-card" style="border-left:4px solid #3d2b1f;margin-bottom:1rem">'
            f'<span class="card-kicker">DNS RECORDS INTELLIGENCE</span>'
            f'<h4>Status: {"🟢 RESOLVED" if ips else "⚠️ HOST UNRESOLVABLE / NO DNS RECORD"}</h4>'
            f'<div style="font-size:.83rem;margin-top:.4rem;line-height:1.6">'
            f'• <b>Resolved IP Addresses (A/AAAA):</b> {", ".join(f"<code>{html.escape(str(ip))}</code>" for ip in ips) if ips else "<i>None (Host unresolvable)</i>"}<br>'
            f'• <b>Mail Servers (MX Records):</b> {", ".join(html.escape(str(mx)) for mx in mx_records) if mx_records else "<i>None (No mail server configured — suspicious for business domain)</i>"}<br>'
            f'• <b>Nameservers (NS Records):</b> {", ".join(html.escape(str(ns)) for ns in ns_records) if ns_records else "<i>None</i>"}<br>'
            f'• <b>Resolution Note:</b> {html.escape(str(dns_notes))}'
            f'</div></div>',
            unsafe_allow_html=True,
        )

        whois_dict = whois if isinstance(whois, dict) else {}
        age_days = whois_dict.get("age_days")
        age_str = f"{age_days} Days" if age_days is not None else "Unknown (WHOIS record unavailable for offline/new host)"
        age_badge = "🔴 HIGH RISK (<30 Days Old)" if (age_days is not None and age_days < 30) else "🟢 ESTABLISHED DOMAIN" if (age_days is not None and age_days > 365) else "🟡 MODERATE AGE" if age_days is not None else "⚠️ UNKNOWN AGE"

        registrar = whois_dict.get("registrar") or "N/A"
        created_date = whois_dict.get("creation_date") or "N/A"
        expiry_date = whois_dict.get("expiration_date") or "N/A"
        country_code = whois_dict.get("country") or "N/A"
        whois_verdict = whois_dict.get("verdict") or whois_dict.get("notes") or "WHOIS lookup completed."

        st.markdown(
            f'<div class="evidence-card" style="border-left:4px solid #8f6559">'
            f'<span class="card-kicker">WHOIS & RDAP DOMAIN REGISTRATION INTELLIGENCE</span>'
            f'<h4>Domain Age: <code>{html.escape(str(age_str))}</code> · {age_badge}</h4>'
            f'<div style="font-size:.83rem;margin-top:.4rem;line-height:1.6">'
            f'• <b>Registrar Name:</b> {html.escape(str(registrar))}<br>'
            f'• <b>Registration Creation Date:</b> {html.escape(str(created_date))}<br>'
            f'• <b>Domain Expiration Date:</b> {html.escape(str(expiry_date))}<br>'
            f'• <b>Registrant Country:</b> {html.escape(str(country_code))}<br>'
            f'• <b>Security Verdict:</b> {html.escape(str(whois_verdict))}'
            f'</div></div>',
            unsafe_allow_html=True,
        )

    with intel_tab:
        providers = result.get("providers", {})

        # ── NO MATCH disclaimer ───────────────────────────────────────────────
        st.markdown(
            '<div class="evidence-card" style="border-left:4px solid #d97706;margin-bottom:.85rem">'
            '<span class="card-kicker">IMPORTANT — READ BEFORE INTERPRETING</span>'
            '<p style="font-size:.83rem;margin:.35rem 0 0;line-height:1.5">'
            '<strong>NO MATCH ≠ Safe.</strong> It means this URL has <em>no existing malicious record</em> in that '
            'provider\'s database — new phishing URLs appear every minute and often have zero prior records. '
            '<br><strong>Meaning of each status:</strong> '
            '<span style="background:#d1fae5;padding:1px 6px;border-radius:4px;font-size:.78rem">AVAILABLE</span> = provider returned data. '
            '<span style="background:#fef3c7;padding:1px 6px;border-radius:4px;font-size:.78rem">NO MATCH</span> = queried OK, no record found. '
            '<span style="background:#fee2e2;padding:1px 6px;border-radius:4px;font-size:.78rem">NOT QUERIED</span> = API key not configured.'
            '</p></div>',
            unsafe_allow_html=True,
        )

        # Show active threat intelligence providers
        for name in ("virustotal", "openphish"):
            source_card(name, providers.get(name))
    with mitre_tab:
        mappings = result.get("mitre", [])
        if not mappings:
            st.info("No MITRE ATT&CK mapping was generated because observed evidence did not satisfy a mapping rule.")
        else:
            tactic_colors = {
                "Initial Access": "#dc2626",
                "Execution": "#ea580c",
                "Defense Evasion": "#d97706",
                "Credential Access": "#7c3aed",
                "Resource Development": "#2563eb",
            }
            for mapping in mappings:
                m_id = mapping.get("id", "")
                m_name = mapping.get("name", "")
                m_tactic = str(mapping.get("tactic", "Threat Behavior")).title()
                m_reason = mapping.get("reason", "")
                m_conf = str(mapping.get("confidence", "observed")).upper()
                m_url = mapping.get("url") or f"https://attack.mitre.org/techniques/{m_id.replace('.', '/')}/"
                color = tactic_colors.get(m_tactic, "#4b5563")

                st.markdown(
                    f'<div class="evidence-card" style="border-left:4px solid {color};margin-bottom:.85rem;padding:.85rem 1rem">'
                    f'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.3rem">'
                    f'<span style="background:{color};color:#fff;font-size:.7rem;font-weight:700;padding:2px 8px;border-radius:4px">{html.escape(m_tactic.upper())}</span>'
                    f'<span style="background:#e5e7eb;color:#374151;font-size:.7rem;font-weight:600;padding:2px 8px;border-radius:4px">{html.escape(m_conf)}</span>'
                    f'</div>'
                    f'<h4 style="margin:.2rem 0 .4rem;font-size:1rem">'
                    f'<b>{html.escape(m_id)}</b> · {html.escape(m_name)} '
                    f'<a href="{html.escape(m_url)}" target="_blank" style="font-size:.8rem;font-weight:normal">ATT&CK Matrix ↗</a>'
                    f'</h4>'
                    f'<p style="font-size:.84rem;margin:0;line-height:1.45;color:var(--text)">'
                    f'<b>Detection Rationale:</b> {html.escape(m_reason)}'
                    f'</p>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
    with copilot_tab:
        copilot = result.get("ai_copilot", {})
        st.markdown('<div class="evidence-card"><span class="card-kicker">EVIDENCE USED</span><ul>' + ''.join(f'<li>{html.escape(str(item))}</li>' for item in copilot.get("observed_evidence", [])) + '</ul></div>', unsafe_allow_html=True)
        st.markdown(f'<div class="recommendation-card"><span class="ai-label">AI-ASSISTED, EVIDENCE-GROUNDED</span><h4>{html.escape(str(copilot.get("attack_type", "Assessment")))}</h4><p>{html.escape(str(copilot.get("strategy", "No recommendation was generated.")))}</p></div>', unsafe_allow_html=True)
    # ── Action buttons rendered OUTSIDE tabs so they appear once and do not
    #    re-render or duplicate when the user switches between tabs. ──────────
    st.divider()
    _btn_col1, _btn_col2, _ = st.columns((2, 1.5, 3.5))
    _btn_col1.download_button(
        "📥 Download Executive PDF Report",
        generate_pdf_report(scan_type, result),
        file_name=f"phishshield_audit_report_{abs(hash(str(target))) % 100000:05d}.pdf",
        mime="application/pdf",
        key=f"pdf-report-{scan_type}-{target}"
    )
    if _btn_col2.button("Add to History", key=f"history-{target}", type="secondary"):
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
        raw_local = row.get("Local Evidence")
        raw_prov = row.get("Provider Evidence")
        local = json.loads(raw_local) if isinstance(raw_local, str) and raw_local else {}
        providers = json.loads(raw_prov) if isinstance(raw_prov, str) and raw_prov else {}
        if not isinstance(local, dict):
            local = {}
        if not isinstance(providers, dict):
            providers = {}
    except (TypeError, ValueError):
        return None, []

    risk = int(row.get("Risk Score") or 0)
    signals: list[tuple[str, int]] = []

    model = local.get("model")
    if isinstance(model, dict) and model.get("model_available") and model.get("prediction") == 1:
        signals.append(("Legacy ML telemetry", int(float(model.get("confidence") or 0))))

    sim = local.get("similarity")
    if isinstance(sim, (int, float)) and sim >= 65:
        signals.append(("Brand similarity", int(sim)))

    tls = local.get("tls")
    if isinstance(tls, dict) and tls.get("https") and tls.get("connected") and not tls.get("certificate_valid"):
        signals.append(("TLS validation", 20))

    whois = local.get("whois")
    if isinstance(whois, dict) and isinstance(whois.get("age_days"), (int, float)) and whois["age_days"] < 30:
        signals.append(("WHOIS domain age", 20))

    vt = providers.get("virustotal")
    if isinstance(vt, dict):
        ev = vt.get("evidence")
        detections = 0
        if isinstance(ev, dict):
            detections = ev.get("malicious", 0) or ev.get("Malicious", 0)
        if not detections and isinstance(vt.get("malicious_count"), (int, float)):
            detections = vt["malicious_count"]
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
    artifact = load_model("url_live_25_detector")
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
                color_map = {"Phishing": "#a4453b", "Suspicious": "#d9a441", "Safe": "#6b8f71"}
                pie_colors = [color_map.get(label, "#8f6559") for label in labels]
                fig = go.Figure(go.Pie(labels=labels, values=[counts[label] for label in labels], hole=.68,
                    marker=dict(colors=pie_colors),
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

    # Intermediate Security Operations & Architecture Section — Warm Walnut / Mocha / Espresso Theme with spacious cards
    st.markdown("""
    <div class="pipeline-feature-section" style="margin: 28px 0 64px;">
      <div style="font: 700 1.05rem 'Inter', sans-serif; color: #3d2b1f; margin-bottom: 18px; display: flex; align-items: center; gap: 8px;">
        <span style="color: #7c5448;">◈</span> Active Security Operations & Engine Architecture
      </div>
      <div style="display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px;">
        <div style="background: #fffdf9; border: 1px solid #ded0b8; border-top: 4px solid #7c5448; border-radius: 10px; padding: 16px 18px; min-height: 110px; display: flex; flex-direction: column; justify-content: space-between; box-shadow: 0 4px 16px rgba(43, 36, 32, 0.06);">
          <div>
            <div style="font: 700 0.94rem 'Inter', sans-serif; color: #3d2b1f; margin-bottom: 6px;">Live ML Classifier</div>
            <div style="font-size: 0.8rem; color: #5c5148; line-height: 1.4;">25-Feature Random Forest model running real-time inference on DOM & WHOIS.</div>
          </div>
          <div>
            <div style="margin-top: 12px; font-size: 0.72rem; font-weight: 700; color: #4a3728; background: #f4ede4; border: 1px solid #d8c8b8; padding: 3px 8px; border-radius: 5px; display: inline-block;">94.08% Accuracy (OpenML 4534)</div>
          </div>
        </div>
        <div style="background: #fffdf9; border: 1px solid #ded0b8; border-top: 4px solid #8f6559; border-radius: 10px; padding: 16px 18px; min-height: 110px; display: flex; flex-direction: column; justify-content: space-between; box-shadow: 0 4px 16px rgba(43, 36, 32, 0.06);">
          <div>
            <div style="font: 700 0.94rem 'Inter', sans-serif; color: #3d2b1f; margin-bottom: 6px;">Multi-Vector Analysis</div>
            <div style="font-size: 0.8rem; color: #5c5148; line-height: 1.4;">Unified engine analyzing URLs, Email header/body text, QR codes & OCR.</div>
          </div>
          <div>
            <div style="margin-top: 12px; font-size: 0.72rem; font-weight: 700; color: #4a3728; background: #ebdcd0; border: 1px solid #cbb6a5; padding: 3px 8px; border-radius: 5px; display: inline-block;">4 Active Analysis Modalities</div>
          </div>
        </div>
        <div style="background: #fffdf9; border: 1px solid #ded0b8; border-top: 4px solid #4a3728; border-radius: 10px; padding: 16px 18px; min-height: 110px; display: flex; flex-direction: column; justify-content: space-between; box-shadow: 0 4px 16px rgba(43, 36, 32, 0.06);">
          <div>
            <div style="font: 700 0.94rem 'Inter', sans-serif; color: #3d2b1f; margin-bottom: 6px;">Threat Intelligence</div>
            <div style="font-size: 0.8rem; color: #5c5148; line-height: 1.4;">Real-time VirusTotal API v3 cloud submissions and OpenPhish feeds.</div>
          </div>
          <div>
            <div style="margin-top: 12px; font-size: 0.72rem; font-weight: 700; color: #3d2b1f; background: #e5d5c5; border: 1px solid #bfaea0; padding: 3px 8px; border-radius: 5px; display: inline-block;">VirusTotal & OpenPhish Connected</div>
          </div>
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)

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
    ]
)

# Navigation labels are presentation-only; analysis routes remain unchanged.
analysis_mode = {
    "Threat Intel": "Dashboard", "URL Scan": "URL Analysis",
    "Email Analysis": "Email Analysis", "QR Analysis": "QR Analysis",
    "Screenshot Analysis": "Screenshot Analysis", "History": "Scan History",
}[_nav_selection]

_module_style = {
    "URL Analysis": ("URL Analysis", "⌁", "#b28574"),
    "Email Analysis": ("Email Analysis", "✉", "#c99b7a"),
    "QR Analysis": ("QR Analysis", "▦", "#a98d6b"),
    "Screenshot Analysis": ("Screenshot / OCR", "◉", "#c5b08a"),
    "Dashboard": ("Threat Operations", "◈", "#8f6559"),
    "Scan History": ("History & Reports", "◷", "#8f6559"),
}[analysis_mode]
st.markdown(f'<style>:root {{ --module-accent: {_module_style[2]}; }}</style><div class="module-marker"><span>{_module_style[1]}</span>{_module_style[0]}</div>', unsafe_allow_html=True)

def _provider_statuses_for_sidebar() -> dict[str, str]:
    """Instant cached source of truth for sidebar System Status widget."""
    defaults = {name: "UNAVAILABLE" for name in ("virustotal", "whois", "dns")}

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

    if "_sidebar_statuses_cached" in st.session_state:
        return st.session_state["_sidebar_statuses_cached"]

    st.session_state["_sidebar_statuses_cached"] = defaults
    return defaults

_sidebar_statuses = _provider_statuses_for_sidebar()
_status_class = lambda value: "online" if value in {"AVAILABLE", "NO_MATCH"} else "degraded" if value in {"RATE_LIMITED", "TIMEOUT", "ERROR", "PENDING"} else "offline"
st.sidebar.markdown(
    '<div class="system-status"><div class="system-status-title">SYSTEM STATUS</div>'
    + ''.join(f'<div class="system-status-row"><span class="status-dot {_status_class(_sidebar_statuses[name])}"></span>{label}<span>{_sidebar_statuses[name]}</span></div>'
              for name, label in (("virustotal", "VirusTotal"), ("whois", "WHOIS / RDAP"), ("dns", "DNS")))
    + '</div>', unsafe_allow_html=True)

if analysis_mode == "Dashboard":
    st.markdown("""
    <div style="margin-top: 4px; margin-bottom: 6px;">
        <h2 style="font-size: 1.6rem !important; font-weight: 850 !important; margin: 0 0 2px 0 !important; color: #2b2420 !important; line-height: 1.2 !important;">Threat Intelligence Console</h2>
        <div style="font-size: 0.84rem; color: #5c5148; margin: 0 !important; padding: 0 !important;">Live operational posture based on recorded canonical scan evidence.</div>
    </div>
    """, unsafe_allow_html=True)
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
            st.success("QR Code Detected")
            st.write(f"Embedded Content: {extracted_url}")

            from urllib.parse import unquote
            unquoted_content = unquote(str(extracted_url))
            target_url = None

            if validate_url(extracted_url):
                target_url = extracted_url
            else:
                found_urls = extract_urls(unquoted_content)
                if found_urls:
                    target_url = found_urls[0]
                    st.warning(f"🔗 <b>EXTRACTED EMBEDDED LINK:</b> Found URL <code>{html.escape(target_url)}</code> embedded inside QR text payload.")

            if not target_url:
                st.info("The QR code contains text content without any embedded web links.")
                save_scan("QR", str(extracted_url), "Non-URL content", 0, risk_level="NOT_APPLICABLE",
                          evidence="QR decoded successfully, but its content contains no web URLs.")
                st.stop()

            if not target_url.startswith(("http://", "https://")):
                target_url = "https://" + target_url

            complete_url_result = run_complete_url_analysis(target_url)
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

        _img_col, _ = st.columns((2.5, 2.5))
        with _img_col:
            st.image(
                uploaded_file,
                width=360,
                caption="Uploaded Screenshot Preview"
            )

        st.subheader(
            "📄 Extracted Text (OCR)"
        )

        st.text_area(
            "",
            result["text"],
            height=160
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
            st.subheader(f"🔍 Screenshot Embedded URL Analysis ({len(result['found_urls'])} Targets Identified)")
            screenshot_url_results = analyze_extracted_urls(result["found_urls"])
            for complete_url_result in screenshot_url_results:
                save_canonical_scan("Screenshot URL", complete_url_result)
                target_url_str = complete_url_result.get("normalized_url") or complete_url_result["url"]
                st.markdown(
                    f'<div style="margin:16px 0 10px;padding:10px 14px;background:#f4ede4;border:1px solid #ded0b8;border-left:4px solid #7c5448;border-radius:6px">'
                    f'<span style="font-size:0.75rem;font-weight:700;letter-spacing:0.08em;color:#7c5448;text-transform:uppercase">EXTRACTED SCREENSHOT LINK</span>'
                    f'<div style="font:700 0.95rem \'JetBrains Mono\',monospace;color:#3d2b1f;margin-top:2px;word-break:break-all">{html.escape(target_url_str)}</div>'
                    f'</div>',
                    unsafe_allow_html=True
                )
                render_url_evidence(complete_url_result)
        else:
            screenshot_url_results = []

        save_scan(
            "Screenshot",
            uploaded_file.name,
            result["verdict"],
            result["risk"]
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
            st.warning("Please paste email content.")
            st.stop()

        progress_slot = st.empty()
        render_scan_progress_step(progress_slot, 50, "🔍 Analysing Email Text & Extracted Links...", "Scanning email headers, phishing indicators & extracting embedded target URLs...")
        result = analyze_email_content(email_text)
        urls = extract_urls(email_text)

        # Analyze extracted URLs FIRST so embedded link threat levels can influence the final email verdict
        email_url_results = []
        highest_url_risk = 0
        phishing_url_found = False
        phishing_url_target = ""

        if urls:
            email_url_results = analyze_extracted_urls(urls)
            for complete_url_result in email_url_results:
                u_verdict = str(complete_url_result.get("verdict", "UNKNOWN")).upper()
                u_risk = int(complete_url_result.get("risk", 0))
                if u_risk > highest_url_risk:
                    highest_url_risk = u_risk
                if u_verdict in ("LIKELY_PHISHING", "CONFIRMED_MALICIOUS") or u_risk >= 50:
                    phishing_url_found = True
                    phishing_url_target = complete_url_result.get("normalized_url") or complete_url_result.get("url")

        progress_slot.empty()

        prediction = result["prediction"]
        confidence = result["confidence"]
        url_override = False

        # If an embedded URL is a phishing hazard, OVERRIDE email verdict to PHISHING
        if phishing_url_found:
            prediction = 1
            confidence = max(confidence or 0, highest_url_risk)
            url_override = True
            if not any("Contains confirmed phishing URL" in str(r) for r in result["reasons"]):
                result["reasons"].insert(0, f"CRITICAL HAZARD: Contains confirmed phishing URL ('{phishing_url_target}')")

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
                f"⚠️ Phishing Email Detected ({confidence}% Risk)"
            )
            if url_override:
                st.warning(f"🛡️ <b>EMBEDDED LINK HAZARD OVERRIDE:</b> Although the email text body appeared neutral, an embedded link in this email (<code>{html.escape(phishing_url_target)}</code>) was identified as a <b>Phishing Hazard</b>. The overall email verdict has been upgraded to <b>Phishing Email</b>.")
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

        if urls:
            for detected_url in urls:
                st.code(detected_url)
        else:
            st.write("No URLs detected.")

        st.divider()

        st.subheader(
            "🔍 Embedded URL Analysis"
        )

        if email_url_results:
            for i, complete_url_result in enumerate(email_url_results, 1):
                target_url_str = complete_url_result.get('normalized_url') or complete_url_result['url']
                st.markdown(
                    f'<div style="margin:20px 0 12px;padding:12px 16px;background:#f4ede4;border:1px solid #ded0b8;border-left:4px solid #7c5448;border-radius:8px">'
                    f'<span style="font-size:0.75rem;font-weight:700;letter-spacing:0.08em;color:#7c5448;text-transform:uppercase">EXTRACTED LINK TARGET #{i}</span>'
                    f'<div style="font:700 0.98rem \'JetBrains Mono\',monospace;color:#3d2b1f;margin-top:4px;word-break:break-all">{html.escape(target_url_str)}</div>'
                    f'</div>',
                    unsafe_allow_html=True
                )
                save_canonical_scan("Email URL", complete_url_result)
                render_url_evidence(complete_url_result)
        else:
            st.info("No URLs detected in the email body content for link-level analysis.")

        st.divider()

        st.subheader(
            "🤖 Threat Indicators"
        )

        if result["reasons"]:
            keyword_reasons = [r for r in result["reasons"] if r.startswith("Contains phishing keyword:")]
            other_reasons   = [r for r in result["reasons"] if not r.startswith("Contains phishing keyword:")]

            if keyword_reasons:
                keywords_found = [r.replace("Contains phishing keyword: ", "").strip("'") for r in keyword_reasons]
                st.write("• Phishing keywords found:", ", ".join(f"`{k}`" for k in keywords_found))

            for reason in other_reasons:
                st.write("•", reason)
        else:
            st.write("No suspicious indicators found.")

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
                "🚨 HIGH THREAT HAZARD: Do NOT click links or provide credentials from this email. Embedded phishing URLs detected."
            )
        elif prediction == 0:
            st.success(
                "Email and embedded URLs appear legitimate according to the multi-factor detection system."
            )

        pass


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
            st.warning("Please enter a URL.")
            st.stop()

        progress_slot = st.empty()
        render_scan_progress_step(progress_slot, 45, "🔍 Analysing & Evaluating...", "Inspecting URL structure, SSL/TLS certificate, DNS records & WHOIS age...")
        complete_url_result = run_complete_url_analysis(url_to_analyze)
        save_canonical_scan("URL", complete_url_result)
        st.session_state["url_analysis_result"] = complete_url_result
        st.session_state["url_analysis_target"] = url_to_analyze
        st.session_state["last_scan_result"] = complete_url_result
        progress_slot.empty()
        render_url_evidence(complete_url_result, scan_type="URL")
        st.stop()

    if "url_analysis_result" in st.session_state and st.session_state.get("url_analysis_target") == url_to_analyze and url_to_analyze:
        render_url_evidence(st.session_state["url_analysis_result"], scan_type="URL")
        st.stop()
