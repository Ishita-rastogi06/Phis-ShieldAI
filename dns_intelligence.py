"""DNS intelligence with explicit, per-record source availability."""
from __future__ import annotations

from urllib.parse import urlparse
from functools import lru_cache

import dns.exception
import dns.resolver


def _records(resolver: dns.resolver.Resolver, host: str, record_type: str) -> tuple[list[str], str | None]:
    try:
        answer = resolver.resolve(host, record_type, lifetime=5.0, raise_on_no_answer=False)
        if not answer:
            return [], None
        values = []
        for item in answer:
            if record_type == "MX" and hasattr(item, "exchange"):
                exchange = str(item.exchange).rstrip(".")
                if exchange:
                    values.append(f"{item.preference} {exchange}")
            else:
                value = str(item).rstrip(".").strip()
                if value and not (record_type == "MX" and value.split()[0].isdigit() and len(value.split()) == 1):
                    values.append(value)
        return values, None
    except dns.resolver.NXDOMAIN:
        return [], "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return [], None
    except dns.exception.Timeout:
        return [], "DNS query timed out"
    except dns.exception.DNSException as error:
        return [], str(error)


@lru_cache(maxsize=256)
def analyze_dns(url: str) -> dict:
    target = url if "://" in url else f"https://{url}"
    host = urlparse(target).hostname
    result = {
        "host": host, "status": "UNAVAILABLE", "a_records": [], "aaaa_records": [],
        "mx_records": [], "ns_records": [], "record_errors": {}, "error": None,
    }
    if not host:
        result["error"] = "URL has no hostname"
        return result
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 5.0
    resolver.lifetime = 5.0
    for kind, key in (("A", "a_records"), ("AAAA", "aaaa_records"), ("MX", "mx_records"), ("NS", "ns_records")):
        values, error = _records(resolver, host, kind)
        result[key] = values
        if error:
            result["record_errors"][kind] = error
    if any(result[key] for key in ("a_records", "aaaa_records", "mx_records", "ns_records")):
        result["status"] = "RESOLVED"
    elif result["record_errors"]:
        result["error"] = "; ".join(f"{kind}: {message}" for kind, message in result["record_errors"].items())
    else:
        result["error"] = "No DNS records returned"
    return result
