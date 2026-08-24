"""Shared, evidence-preserving contract for threat-intelligence providers."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

AVAILABLE = "AVAILABLE"
NO_MATCH = "NO_MATCH"
NOT_CONFIGURED = "NOT_CONFIGURED"
NOT_QUERIED = "NOT_QUERIED"
RATE_LIMITED = "RATE_LIMITED"
TIMEOUT = "TIMEOUT"
UNAVAILABLE = "UNAVAILABLE"
ERROR = "ERROR"
PENDING = "PENDING"
STATUSES = {AVAILABLE, NO_MATCH, NOT_CONFIGURED, NOT_QUERIED, RATE_LIMITED, TIMEOUT, UNAVAILABLE, ERROR, PENDING}


def result(provider: str, status: str, *, evidence: Any = None, reason: str | None = None,
           malicious: bool | None = False, strong: bool = False) -> dict:
    if status not in STATUSES:
        raise ValueError(f"Invalid provider status: {status}")
    if status in (UNAVAILABLE, NOT_CONFIGURED, NOT_QUERIED, TIMEOUT, ERROR, RATE_LIMITED, PENDING):
        malicious = None
    return {"provider": provider, "status": status, "timestamp": datetime.now(timezone.utc).isoformat(),
            "evidence": evidence or {}, "reason": reason, "malicious": malicious, "strong": strong}
