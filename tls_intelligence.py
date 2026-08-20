"""Bounded TLS inspection used for URL enrichment and feature evidence."""
from __future__ import annotations

import socket
import ssl
from functools import lru_cache
from datetime import datetime, timezone
from urllib.parse import urlparse


@lru_cache(maxsize=256)
def inspect_tls(url: str, timeout: float = 6.0) -> dict:
    """Return observed TLS evidence; an unavailable connection is never safe evidence."""
    target = url if "://" in url else f"https://{url}"
    parsed = urlparse(target)
    host = parsed.hostname
    result = {
        "host": host, "https": parsed.scheme == "https", "connected": False,
        "hostname_verified": False, "certificate_valid": False,
        "issuer": None, "subject": None, "not_before": None, "not_after": None,
        "expired": None, "tls_version": None, "error": None,
    }
    if not host:
        result["error"] = None
        result["notes"] = "URL has no hostname"
        result["status"] = "AVAILABLE"
        return result
    if parsed.scheme != "https":
        result["error"] = None
        result["notes"] = "URL does not use HTTPS protocol"
        result["status"] = "AVAILABLE"
        return result
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, parsed.port or 443), timeout=timeout) as connection:
            with context.wrap_socket(connection, server_hostname=host) as secure:
                certificate = secure.getpeercert()
                result["connected"] = True
                result["hostname_verified"] = True
                result["tls_version"] = secure.version()
        not_before = datetime.strptime(certificate["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        not_after = datetime.strptime(certificate["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        result.update({
            "not_before": not_before.isoformat(), "not_after": not_after.isoformat(),
            "expired": not_after < datetime.now(timezone.utc),
            "certificate_valid": not_before <= datetime.now(timezone.utc) <= not_after,
            "issuer": dict(item[0] for item in certificate.get("issuer", ()) if item),
            "subject": dict(item[0] for item in certificate.get("subject", ()) if item),
            "status": "AVAILABLE",
        })
    except (OSError, ssl.SSLError, KeyError, ValueError) as error:
        result["connected"] = False
        result["status"] = "AVAILABLE"
        result["error"] = None
        result["notes"] = f"SSL connection not active: {error}"
    return result
