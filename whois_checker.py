import tldextract
import requests
import whois
from datetime import datetime, timezone
from functools import lru_cache
from urllib.parse import urlparse


def _registrable_domain(host: str) -> str:
    parts = tldextract.extract(host)
    if parts.domain and parts.suffix:
        return f"{parts.domain}.{parts.suffix}"
    return host


def _first(value):
    return value[0] if isinstance(value, (list, tuple)) and value else value


def _iso(value):
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, str):
        return value
    return None


def _parse_dt(val):
    if isinstance(val, datetime):
        return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
    if isinstance(val, str):
        try:
            val = val.replace("Z", "+00:00")
            dt = datetime.fromisoformat(val)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None
    return None


@lru_cache(maxsize=256)
def check_domain_age(url: str) -> dict:
    target = url if "://" in url else f"https://{url}"
    host = (urlparse(target).hostname or "").lower()
    reg_domain = _registrable_domain(host)
    unavailable = {"domain": host or reg_domain, "status": "UNAVAILABLE", "reason": None, "creation_date": None,
                   "expiry_date": None, "updated_date": None, "registration_days": None,
                   "remaining_days": None, "age_days": None, "registrar": None, "country": None,
                   "nameservers": [], "domain_status": [], "privacy_protected": None,
                   "verdict": "WHOIS unavailable"}
    if not host:
        unavailable["reason"] = "URL has no hostname"
        return unavailable

    now = datetime.now(timezone.utc)

    # ── Attempt 1: Standard HTTPS RDAP Lookup (Fast & Network-Resilient) ─────
    try:
        rdap_url = f"https://rdap.org/domain/{reg_domain}"
        resp = requests.get(rdap_url, timeout=1.8, headers={"Accept": "application/rdap+json", "User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            data = resp.json()
            events = {item.get("eventAction"): item.get("eventDate") for item in data.get("events", []) if isinstance(item, dict)}
            c_str = events.get("registration") or events.get("creation")
            e_str = events.get("expiration")
            u_str = events.get("last changed") or events.get("last update")
            
            creation = _parse_dt(c_str)
            expiry = _parse_dt(e_str)
            updated = _parse_dt(u_str)

            if creation or expiry:
                age_days = (now - creation).days if creation else None
                registration_days = (expiry - creation).days if creation and expiry else None
                remaining_days = (expiry - now).days if expiry else None
                verdict = "Very new domain" if age_days is not None and age_days < 30 else "Recently created domain" if age_days is not None and age_days < 180 else "Established domain" if age_days is not None else "WHOIS dates unavailable"

                # Extract registrar safely
                registrar = None
                try:
                    for entity in data.get("entities", []):
                        if isinstance(entity, dict) and "registrar" in entity.get("roles", []):
                            vcard = entity.get("vcardArray")
                            if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
                                for prop in vcard[1]:
                                    if isinstance(prop, list) and len(prop) > 3 and prop[0] == "fn":
                                        registrar = str(prop[3])
                                        break
                except Exception:
                    registrar = None
                
                # Extract nameservers safely
                ns = []
                try:
                    ns = [str(item.get("ldhName")) for item in data.get("nameservers", []) if isinstance(item, dict) and item.get("ldhName")]
                except Exception:
                    ns = []

                return {
                    "domain": reg_domain,
                    "status": "AVAILABLE",
                    "reason": None,
                    "creation_date": _iso(creation),
                    "expiry_date": _iso(expiry),
                    "updated_date": _iso(updated),
                    "registration_days": registration_days,
                    "remaining_days": remaining_days,
                    "age_days": age_days,
                    "registrar": registrar,
                    "country": None,
                    "nameservers": ns,
                    "domain_status": [str(item.get("status")) for item in data.get("status", []) if isinstance(item, dict) and item.get("status")] if isinstance(data.get("status"), list) else [],
                    "privacy_protected": None,
                    "verdict": verdict,
                }
    except Exception:
        pass

    # ── Attempt 2: Bounded WHOIS Port 43 Lookup ──────────────────────────────
    from concurrent.futures import ThreadPoolExecutor
    try:
        executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="whois_port43")
        future = executor.submit(whois.whois, reg_domain)
        try:
            record = future.result(timeout=1.2)
        finally:
            executor.shutdown(wait=False, cancel_futures=True)
        creation, expiry, updated = _first(record.creation_date), _first(record.expiration_date), _first(record.updated_date)
        creation = _parse_dt(creation)
        expiry = _parse_dt(expiry)
        updated = _parse_dt(updated)
        raw = str(record).lower()
        age_days = (now - creation).days if creation else None
        registration_days = (expiry - creation).days if creation and expiry else None
        remaining_days = (expiry - now).days if expiry else None
        privacy = any(token in raw for token in ("privacy", "redacted", "withheld"))
        verdict = "Very new domain" if age_days is not None and age_days < 30 else "Recently created domain" if age_days is not None and age_days < 180 else "Established domain" if age_days is not None else "WHOIS dates unavailable"
        nameservers = record.name_servers or []
        nameservers = nameservers if isinstance(nameservers, (list, tuple, set)) else [nameservers]
        status = record.status or []
        status = status if isinstance(status, (list, tuple, set)) else [status]
        return {"domain": reg_domain, "status": "AVAILABLE", "reason": None, "creation_date": _iso(creation),
                "expiry_date": _iso(expiry), "updated_date": _iso(updated), "registration_days": registration_days,
                "remaining_days": remaining_days, "age_days": age_days,
                "registrar": _first(record.registrar), "country": _first(record.country),
                "nameservers": [str(item) for item in nameservers if item], "domain_status": [str(item) for item in status if item],
                "privacy_protected": privacy, "verdict": verdict}
    except Exception as error:
        unavailable["reason"] = f"WHOIS/RDAP unavailable: {error}"
        return unavailable
