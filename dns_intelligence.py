"""DNS intelligence with explicit, per-record source availability."""
from __future__ import annotations

import socket
from urllib.parse import urlparse
from functools import lru_cache

import dns.exception
import dns.resolver

_PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1", "8.8.4.4"]


def _make_fallback_resolver() -> dns.resolver.Resolver:
    res = dns.resolver.Resolver(configure=False)
    res.nameservers = _PUBLIC_RESOLVERS
    res.timeout = 2.0
    res.lifetime = 2.0
    return res


def _records(resolver: dns.resolver.Resolver, host: str, record_type: str) -> tuple[list[str], str | None]:
    try:
        answer = resolver.resolve(host, record_type, lifetime=2.5, raise_on_no_answer=False)
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
    except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.exception.DNSException):
        # Try fallback public resolver
        try:
            fallback = _make_fallback_resolver()
            answer = fallback.resolve(host, record_type, lifetime=2.5, raise_on_no_answer=False)
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
        except Exception:
            # Socket fallback for A / AAAA
            if record_type in ("A", "AAAA"):
                try:
                    family = socket.AF_INET if record_type == "A" else socket.AF_INET6
                    addrs = {item[4][0] for item in socket.getaddrinfo(host, None, family=family, type=socket.SOCK_STREAM)}
                    if addrs:
                        return sorted(list(addrs)), None
                except Exception:
                    pass
            return [], "DNS query timed out"


@lru_cache(maxsize=256)
def analyze_dns(url: str) -> dict:
    from security.tldextract_config import offline_extractor
    target = url if "://" in url else f"https://{url}"
    host = (urlparse(target).hostname or "").lower()
    
    ext = offline_extractor()(host)
    reg_domain = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else host

    result = {
        "host": host, "status": "UNAVAILABLE", "a_records": [], "aaaa_records": [],
        "mx_records": [], "ns_records": [], "ips": [], "ip_addresses": [],
        "nameservers": [], "record_errors": {}, "error": None,
    }
    if not host:
        result["error"] = "URL has no hostname"
        return result
    try:
        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = 2.5
        resolver.lifetime = 2.5
    except Exception:
        resolver = _make_fallback_resolver()

    for kind, key in (("A", "a_records"), ("AAAA", "aaaa_records"), ("MX", "mx_records"), ("NS", "ns_records")):
        values, error = _records(resolver, host, kind)
        # If subdomain has no MX or NS records, query registrable domain (e.g. wikipedia.org)
        if not values and kind in ("MX", "NS") and host != reg_domain:
            values, _ = _records(resolver, reg_domain, kind)
        result[key] = values
        if error and not values:
            result["record_errors"][kind] = error

    all_ips = sorted(list(set(result["a_records"] + result["aaaa_records"])))
    result["ips"] = all_ips
    result["ip_addresses"] = all_ips
    result["nameservers"] = result["ns_records"]

    if all_ips or result["mx_records"] or result["ns_records"]:
        result["status"] = "RESOLVED"
        result["notes"] = f"Resolved {len(all_ips)} IP(s), {len(result['mx_records'])} MX, {len(result['ns_records'])} NS"
    elif result["record_errors"]:
        result["error"] = "; ".join(f"{kind}: {message}" for kind, message in result["record_errors"].items())
    else:
        result["error"] = "No DNS records returned"
    return result
