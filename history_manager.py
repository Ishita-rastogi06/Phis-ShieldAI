"""Local session-isolated scan history manager.

Each user's searches/queries are saved independently in Streamlit's st.session_state
so that histories are never mixed between different users or persistent files.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
import pandas as pd

HISTORY_COLUMNS = [
    "Timestamp", "Type", "Target", "Normalized URL", "Result",
    "Confidence", "Risk Score", "Risk Level", "Evidence",
    "Provider Evidence", "Local Evidence", "MITRE", "Copilot", "Legacy ML Available"
]


def _get_history_list() -> list[dict]:
    """Return the current user's session-isolated history list from st.session_state."""
    try:
        import streamlit as st
        if "user_scan_history" not in st.session_state:
            st.session_state["user_scan_history"] = []
        return st.session_state["user_scan_history"]
    except Exception:
        # Fallback for standalone unit tests running outside Streamlit context
        if not hasattr(_get_history_list, "_test_store"):
            _get_history_list._test_store = []
        return _get_history_list._test_store


def save_scan(scan_type, target, result, risk, *, confidence=None, risk_level=None, evidence=None, providers=None,
              normalized_url=None, local_evidence=None, mitre=None, copilot=None, legacy_ml_available=None):
    """Save a scan entry into the current user's session state history."""
    entry = {
        "Timestamp": datetime.now(timezone.utc).isoformat(),
        "Type": scan_type,
        "Target": str(target),
        "Result": result,
        "Confidence": confidence,
        "Risk Score": risk,
        "Risk Level": risk_level,
        "Normalized URL": normalized_url,
        "Evidence": evidence,
        "Provider Evidence": json.dumps(providers, default=str) if providers is not None else None,
        "Local Evidence": json.dumps(local_evidence, default=str) if local_evidence is not None else None,
        "MITRE": json.dumps(mitre, default=str) if mitre is not None else None,
        "Copilot": json.dumps(copilot, default=str) if copilot is not None else None,
        "Legacy ML Available": legacy_ml_available,
    }
    history_list = _get_history_list()
    history_list.append(entry)


def clear_history():
    """Clear history for the current user's session only."""
    try:
        import streamlit as st
        st.session_state["user_scan_history"] = []
    except Exception:
        _get_history_list._test_store = []


def load_history() -> pd.DataFrame:
    """Load the current user's session history as a pandas DataFrame."""
    history_list = _get_history_list()
    if not history_list:
        return pd.DataFrame(columns=HISTORY_COLUMNS)
    history = pd.DataFrame(history_list)
    for column in HISTORY_COLUMNS:
        if column not in history:
            history[column] = None
    return history[HISTORY_COLUMNS]


def save_canonical_scan(scan_type: str, analysis: dict) -> None:
    """Persist the complete normalized result into the user's session history."""
    local = {name: analysis.get(name) for name in ("dns", "tls", "whois", "website", "brand", "similarity", "model")}
    if isinstance(local.get("website"), dict):
        local["website"] = {k: v for k, v in local["website"].items() if k != "html"}
    save_scan(
        scan_type, analysis.get("url"), analysis.get("verdict"), analysis.get("risk"),
        confidence=analysis.get("confidence_strength"), risk_level=analysis.get("risk_level"),
        evidence="; ".join(analysis.get("reasons", [])), providers=analysis.get("providers"),
        normalized_url=analysis.get("normalized_url"), local_evidence=local, mitre=analysis.get("mitre"),
        copilot=analysis.get("ai_copilot"), legacy_ml_available=analysis.get("model_available")
    )
