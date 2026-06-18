from urllib.parse import urlparse
import re

def extract_features(url):
    try:
        url = str(url).strip()
        if not url or url != url:  # catch NaN
            return [0] * 20

        parsed = urlparse(url if "://" in url else "https://" + url)
        netloc = parsed.netloc.lower()
        path = parsed.path.lower()
        full = url.lower()

    except Exception:
        return [0] * 20

    features = []

    # 1. URL total length
    features.append(len(url))

    # 2. Number of dots
    features.append(url.count("."))

    # 3. Number of hyphens
    features.append(url.count("-"))

    # 4. Number of @ symbols
    features.append(url.count("@"))

    # 5. Number of digits
    features.append(sum(c.isdigit() for c in url))

    # 6. Suspicious keywords count
    suspicious_words = [
        "login", "verify", "secure", "update", "account", "bank",
        "confirm", "reset", "password", "credential", "signin", "sign-in",
        "authenticate", "validation", "wallet", "otp", "suspended",
        "billing", "invoice", "payment", "urgent", "alert", "support",
        "helpdesk", "recover", "unlock", "reactivate"
    ]
    features.append(sum(w in full for w in suspicious_words))

    # 7. Netloc length
    features.append(len(netloc))

    # 8. Path length
    features.append(len(path))

    # 9. Number of subdomains (dots in netloc)
    features.append(netloc.count("."))

    # 10. Uses IP address instead of domain?
    ip_pattern = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
    netloc_host = netloc.split(":")[0].strip("[]")  # strip IPv6 brackets too
    features.append(1 if ip_pattern.match(netloc_host) else 0)

    # 11. Has port number?
    features.append(1 if re.search(r':\d+', netloc) else 0)

    # 12. URL contains encoded chars (%xx)?
    features.append(1 if "%" in url else 0)

    # 13. Number of slashes in path
    features.append(path.count("/"))

    # 14. Number of query parameters
    features.append(len(parsed.query.split("&")) if parsed.query else 0)

    # 15. TLD is suspicious?
    common_tlds = {".com", ".org", ".net", ".gov", ".edu", ".co", ".io", ".in"}
    tld_match = re.search(r'\.[a-z]{2,}$', netloc)
    tld = tld_match.group(0) if tld_match else ""
    features.append(0 if tld in common_tlds else 1)

    # 16. Domain contains digits?
    domain_part = netloc.split(".")[0]
    features.append(1 if any(c.isdigit() for c in domain_part) else 0)

    # 17. Consonant ratio (random-looking domain proxy)
    consonants = set("bcdfghjklmnpqrstvwxyz")
    consonant_ratio = sum(1 for c in domain_part if c in consonants) / max(len(domain_part), 1)
    features.append(round(consonant_ratio, 2))

    # 18. Double slashes inside path?
    features.append(1 if "//" in path else 0)

    # 19. Fragment (#) present?
    features.append(1 if parsed.fragment else 0)

    # 20. Uses HTTP (not HTTPS)?
    features.append(1 if url.startswith("http://") else 0)

    return features