"""Safe operational diagnostics for optional threat-intelligence providers.

Logging is directed to the 'phishshield.diagnostics' logger AND mirrored to
stderr via a bootstrap StreamHandler so critical startup messages are visible
even when no external log handler has been configured (e.g. bare python runs,
Streamlit processes that suppress root-logger output).
"""
from __future__ import annotations

import logging
import os
import sys
from typing import Any

from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Logger bootstrap
# ---------------------------------------------------------------------------
# Install a stderr StreamHandler once so diagnostic output is always visible
# regardless of whether the caller has configured the root logger.
LOGGER = logging.getLogger("phishshield.diagnostics")
if not LOGGER.handlers and not logging.root.handlers:
    _handler = logging.StreamHandler(sys.stderr)
    _handler.setFormatter(logging.Formatter("[PhishShield] %(levelname)s %(message)s"))
    LOGGER.addHandler(_handler)
    LOGGER.setLevel(logging.DEBUG)

KEY_NAMES = ("VIRUSTOTAL_API_KEY",)
_startup_reported = False


# ---------------------------------------------------------------------------
# Secret masking
# ---------------------------------------------------------------------------

def mask_secret(value: str) -> str:
    """Return a safe confirmation string without exposing a credential.

    Shows the first 2 characters, then '***', then the last 4 characters so
    the operator can confirm the right key is loaded without leaking it.
    E.g. "abcdef1234567890" → "ab***7890"
    """
    if not value:
        return "<missing>"
    if len(value) <= 6:
        # For very short values expose only the class/length, not content.
        return f"<{len(value)}-char key>"
    return f"{value[:2]}***{value[-4:]}"


# ---------------------------------------------------------------------------
# Startup key-presence check
# ---------------------------------------------------------------------------

def load_and_report_provider_configuration() -> dict[str, bool]:
    """Load the project .env once and log the configured provider keys safely.

    Returns a mapping of key-name → is_configured (bool).

    The function is safe to call multiple times; the verbose startup log is
    emitted only once per process (guarded by _startup_reported).  Subsequent
    calls still return the live os.environ state so callers can check whether
    a key became available after a dynamic reload.
    """
    global _startup_reported
    load_dotenv(override=False)
    configured: dict[str, bool] = {}

    if _startup_reported:
        return {name: bool(os.getenv(name, "").strip()) for name in KEY_NAMES}

    _startup_reported = True
    missing: list[str] = []

    LOGGER.info("=" * 60)
    LOGGER.info("PhishShield AI — provider key startup diagnostic")
    LOGGER.info("=" * 60)

    for name in KEY_NAMES:
        value = os.getenv(name, "").strip()
        configured[name] = bool(value)
        if value:
            # Mirror to stdout as well so Streamlit terminal output captures it
            msg = f"{name} loaded: {mask_secret(value)}"
            LOGGER.info(msg)
            print(f"[PhishShield] INFO  {msg}", file=sys.stdout, flush=True)
        else:
            missing.append(name)
            msg = f"{name} is MISSING or EMPTY — provider will return NOT_CONFIGURED for every scan"
            LOGGER.warning(msg)
            print(f"[PhishShield] WARN  {msg}", file=sys.stdout, flush=True)

    if missing:
        summary = (
            f"STARTUP WARNING: {len(missing)} provider key(s) not configured: "
            + ", ".join(missing)
            + ". Threat-intelligence lookups for those providers will be skipped."
        )
        LOGGER.warning(summary)
        print(f"[PhishShield] WARN  {summary}", file=sys.stdout, flush=True)
    else:
        LOGGER.info("All provider keys are present.")
        print("[PhishShield] INFO  All provider keys are present.", file=sys.stdout, flush=True)

    LOGGER.info("=" * 60)
    return configured


# ---------------------------------------------------------------------------
# Per-call trace helpers (called by adapters and the pipeline)
# ---------------------------------------------------------------------------

def log_provider_result(provider: str, input_url: str, response: dict) -> None:
    """Trace the adapter contract result without logging secrets or response bodies."""
    LOGGER.info(
        "provider=%s input=%r contract_status=%s malicious=%s reason=%r",
        provider,
        input_url,
        response.get("status"),
        response.get("malicious"),
        response.get("reason"),
    )


def log_provider_http(provider: str, input_url: str, status_code: int) -> None:
    """Record that an outbound request reached a provider and its HTTP status."""
    level = logging.WARNING if status_code not in (200, 201, 404) else logging.INFO
    LOGGER.log(
        level,
        "provider=%s input=%r http_status=%s",
        provider,
        input_url,
        status_code,
    )


def log_scan_stage(stage: str, **details: Any) -> None:
    """Emit a structured, grep-friendly pipeline trace line.

    Usage example:
        log_scan_stage("remote_complete", normalized_url=url, provider_statuses={...})
    Produces:
        scan_stage=remote_complete normalized_url='...' provider_statuses={...}
    """
    fields = " ".join(f"{key}={value!r}" for key, value in details.items())
    LOGGER.info("scan_stage=%s %s", stage, fields)


# ---------------------------------------------------------------------------
# Pipeline summary helper (used by run_diagnostics.py)
# ---------------------------------------------------------------------------

def summarise_provider_outcomes(providers: dict) -> dict[str, str]:
    """Extract just the status string from each provider's contract dict."""
    return {
        name: (item.get("status", "UNAVAILABLE") if isinstance(item, dict) else "UNAVAILABLE")
        for name, item in providers.items()
    }
