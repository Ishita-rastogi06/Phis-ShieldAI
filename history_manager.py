"""Local scan history. Entries contain analysis evidence, never configuration secrets."""
from __future__ import annotations

import os
from datetime import datetime, timezone

import pandas as pd
import json

HISTORY_FILE = "scan_history.csv"
HISTORY_COLUMNS = ["Timestamp", "Type", "Target", "Normalized URL", "Result", "Confidence", "Risk Score", "Risk Level", "Evidence", "Provider Evidence", "Local Evidence", "MITRE", "Copilot", "Legacy ML Available"]


def save_scan(scan_type, target, result, risk, *, confidence=None, risk_level=None, evidence=None, providers=None,
              normalized_url=None, local_evidence=None, mitre=None, copilot=None, legacy_ml_available=None):
    entry = {"Timestamp": datetime.now(timezone.utc).isoformat(), "Type": scan_type, "Target": str(target),
             "Result": result, "Confidence": confidence, "Risk Score": risk, "Risk Level": risk_level,
             "Normalized URL": normalized_url, "Evidence": evidence,
             "Provider Evidence": json.dumps(providers, default=str) if providers is not None else None,
             "Local Evidence": json.dumps(local_evidence, default=str) if local_evidence is not None else None,
             "MITRE": json.dumps(mitre, default=str) if mitre is not None else None,
             "Copilot": json.dumps(copilot, default=str) if copilot is not None else None,
             "Legacy ML Available": legacy_ml_available}
    history = load_history()
    pd.concat([history, pd.DataFrame([entry])], ignore_index=True)[HISTORY_COLUMNS].to_csv(HISTORY_FILE, index=False)


def clear_history():
    if os.path.exists(HISTORY_FILE):
        os.remove(HISTORY_FILE)


def load_history():
    if not os.path.exists(HISTORY_FILE):
        return pd.DataFrame(columns=HISTORY_COLUMNS)
    try:
        history = pd.read_csv(HISTORY_FILE)
    except (OSError, pd.errors.ParserError):
        return pd.DataFrame(columns=HISTORY_COLUMNS)
    for column in HISTORY_COLUMNS:
        if column not in history:
            history[column] = None
    return history[HISTORY_COLUMNS]


def save_canonical_scan(scan_type: str, analysis: dict) -> None:
    """Persist the complete normalized result without credentials or HTML payloads."""
    local = {name: analysis.get(name) for name in ("dns", "tls", "whois", "website", "brand", "similarity", "model")}
    if isinstance(local.get("website"), dict): local["website"] = {k: v for k, v in local["website"].items() if k != "html"}
    save_scan(scan_type, analysis.get("url"), analysis.get("verdict"), analysis.get("risk"),
              confidence=analysis.get("confidence_strength"), risk_level=analysis.get("risk_level"),
              evidence="; ".join(analysis.get("reasons", [])), providers=analysis.get("providers"),
              normalized_url=analysis.get("normalized_url"), local_evidence=local, mitre=analysis.get("mitre"),
              copilot=analysis.get("ai_copilot"), legacy_ml_available=analysis.get("model_available"))
