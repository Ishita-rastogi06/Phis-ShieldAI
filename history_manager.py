"""Persistent per-user scan history manager backed by SQLite.

User histories are persisted locally in SQLite (history.db) and isolated
per browser using a persistent cookie identifier (phishshield_user_id).
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import pandas as pd

DB_PATH = Path(__file__).resolve().parent / "history.db"

HISTORY_COLUMNS = [
    "Timestamp", "Type", "Target", "Normalized URL", "Result",
    "Confidence", "Risk Score", "Risk Level", "Evidence",
    "Provider Evidence", "Local Evidence", "MITRE", "Copilot", "Legacy ML Available"
]


def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db() -> None:
    with _get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                type TEXT,
                target TEXT,
                normalized_url TEXT,
                result TEXT,
                confidence TEXT,
                risk_score REAL,
                risk_level TEXT,
                evidence TEXT,
                provider_evidence TEXT,
                local_evidence TEXT,
                mitre TEXT,
                copilot TEXT,
                legacy_ml_available TEXT
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);")
        conn.commit()


_init_db()


def get_or_create_user_id(cookie_manager: Any = None) -> str:
    """Return persistent browser UUID for current session & cookie."""
    try:
        import streamlit as st
        # 1. Fast lookup from st.session_state
        if "user_id" in st.session_state and st.session_state["user_id"]:
            return str(st.session_state["user_id"])

        user_id: Optional[str] = None

        # 2. Check native Streamlit request context cookies if present (sent in HTTP headers on reload!)
        if hasattr(st, "context") and hasattr(st.context, "cookies"):
            user_id = st.context.cookies.get("phishshield_user_id")

        # 3. Check CookieManager component if provided
        if not user_id and cookie_manager is not None:
            try:
                user_id = cookie_manager.get("phishshield_user_id")
            except Exception:
                pass

        # 4. Check query params if passed (?user_id=...)
        if not user_id:
            try:
                qp = st.query_params
                if "user_id" in qp:
                    user_id = qp["user_id"]
            except Exception:
                pass

        # 5. If cookie or user_id found, save to session state and return
        if user_id:
            st.session_state["user_id"] = str(user_id)
            return str(user_id)

        # 6. Generate a unique browser UUID for this visitor
        new_id = f"u_{uuid.uuid4().hex}"
        st.session_state["user_id"] = new_id

        # Set cookie asynchronously via CookieManager if provided
        if cookie_manager is not None:
            try:
                expires = datetime.now(timezone.utc) + timedelta(days=365)
                cookie_manager.set("phishshield_user_id", new_id, expires_at=expires, key="set_user_id_cookie")
            except Exception:
                pass

        return new_id
    except Exception:
        if not hasattr(get_or_create_user_id, "_test_user_id"):
            get_or_create_user_id._test_user_id = "test_user_123"
        return get_or_create_user_id._test_user_id


def save_scan(scan_type: Any, target: Any, result: Any, risk: Any, *,
              confidence: Any = None, risk_level: Any = None, evidence: Any = None,
              providers: Any = None, normalized_url: Any = None, local_evidence: Any = None,
              mitre: Any = None, copilot: Any = None, legacy_ml_available: Any = None,
              user_id: Optional[str] = None) -> None:
    """Save a scan entry into SQLite tagged with user_id."""
    uid = user_id or get_or_create_user_id()
    ts = datetime.now(timezone.utc).isoformat()

    prov_str = json.dumps(providers, default=str) if providers is not None else None
    loc_str = json.dumps(local_evidence, default=str) if local_evidence is not None else None
    mitre_str = json.dumps(mitre, default=str) if mitre is not None else None
    copilot_str = json.dumps(copilot, default=str) if copilot is not None else None
    legacy_ml_str = str(legacy_ml_available) if legacy_ml_available is not None else None

    with _get_connection() as conn:
        conn.execute("""
            INSERT INTO scans (
                user_id, timestamp, type, target, normalized_url, result,
                confidence, risk_score, risk_level, evidence, provider_evidence,
                local_evidence, mitre, copilot, legacy_ml_available
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            uid, ts, str(scan_type) if scan_type is not None else None,
            str(target) if target is not None else None,
            str(normalized_url) if normalized_url is not None else None,
            str(result) if result is not None else None,
            str(confidence) if confidence is not None else None,
            float(risk) if risk is not None else None,
            str(risk_level) if risk_level is not None else None,
            str(evidence) if evidence is not None else None,
            prov_str, loc_str, mitre_str, copilot_str, legacy_ml_str
        ))
        conn.commit()


def clear_history(user_id: Optional[str] = None) -> None:
    """Clear history entries matching user_id from SQLite."""
    uid = user_id or get_or_create_user_id()
    with _get_connection() as conn:
        conn.execute("DELETE FROM scans WHERE user_id = ?", (uid,))
        conn.commit()


def load_history(user_id: Optional[str] = None) -> pd.DataFrame:
    """Load history for user_id from SQLite as a pandas DataFrame."""
    uid = user_id or get_or_create_user_id()
    with _get_connection() as conn:
        rows = conn.execute("""
            SELECT
                timestamp AS "Timestamp",
                type AS "Type",
                target AS "Target",
                normalized_url AS "Normalized URL",
                result AS "Result",
                confidence AS "Confidence",
                risk_score AS "Risk Score",
                risk_level AS "Risk Level",
                evidence AS "Evidence",
                provider_evidence AS "Provider Evidence",
                local_evidence AS "Local Evidence",
                mitre AS "MITRE",
                copilot AS "Copilot",
                legacy_ml_available AS "Legacy ML Available"
            FROM scans
            WHERE user_id = ?
            ORDER BY id ASC
        """, (uid,)).fetchall()

    if not rows:
        return pd.DataFrame(columns=HISTORY_COLUMNS)

    data = [dict(row) for row in rows]
    df = pd.DataFrame(data)
    for col in HISTORY_COLUMNS:
        if col not in df:
            df[col] = None
    return df[HISTORY_COLUMNS]


def save_canonical_scan(scan_type: str, analysis: dict, user_id: Optional[str] = None) -> None:
    """Persist normalized result into SQLite history for user_id."""
    local = {name: analysis.get(name) for name in ("dns", "tls", "whois", "website", "brand", "similarity", "model")}
    if isinstance(local.get("website"), dict):
        local["website"] = {k: v for k, v in local["website"].items() if k != "html"}
    save_scan(
        scan_type, analysis.get("url"), analysis.get("verdict"), analysis.get("risk"),
        confidence=analysis.get("confidence_strength"), risk_level=analysis.get("risk_level"),
        evidence="; ".join(analysis.get("reasons", [])), providers=analysis.get("providers"),
        normalized_url=analysis.get("normalized_url"), local_evidence=local, mitre=analysis.get("mitre"),
        copilot=analysis.get("ai_copilot"), legacy_ml_available=analysis.get("model_available"),
        user_id=user_id
    )
