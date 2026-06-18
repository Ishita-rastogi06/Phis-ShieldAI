import re
from urllib.parse import urlparse

# Well-known trusted domains — keyword hits on these should NOT trigger threat reasons
TRUSTED_DOMAINS = {
    "google.com", "gmail.com", "youtube.com", "googleapis.com",
    "microsoft.com", "outlook.com", "live.com", "office.com", "microsoft365.com",
    "apple.com", "icloud.com",
    "amazon.com", "amazon.in", "amazonaws.com",
    "facebook.com", "instagram.com", "meta.com",
    "twitter.com", "x.com",
    "linkedin.com",
    "netflix.com",
    "github.com", "githubusercontent.com",
    "dropbox.com",
    "paypal.com",
    "stripe.com",
    "zoom.us",
    "slack.com",
    "adobe.com",
    "salesforce.com",
    "shopify.com",
    "ebay.com",
    "walmart.com",
    "flipkart.com",
    "paytm.com",
    "phonepe.com",
    "sbi.co.in", "onlinesbi.sbi",
    "hdfcbank.com",
    "icicibank.com",
    "axisbank.com",
    "kotak.com",
    "irctc.co.in",
    "incometax.gov.in",
    "uidai.gov.in",
    "npci.org.in",
    "gov.in", "nic.in",
    "wikipedia.org",
    "stackoverflow.com",
    "stackexchange.com",
    "cloudflare.com",
    "akamai.com",
    "bbc.com", "bbc.co.uk",
    "reuters.com",
    "nytimes.com",
    "cnn.com",
    "reddit.com",
    "medium.com",
    "wordpress.com",
    "blogger.com",
    "twitter.com",
    "whatsapp.com",
    "wa.me",
    "t.me",
    "npmjs.com",
    "pypi.org",
    "docker.com",
    "aws.amazon.com",
    "azure.microsoft.com",
    "cloud.google.com",
}

def _is_trusted(netloc: str) -> bool:
    """Return True if the netloc belongs to a known-trusted domain."""
    netloc = netloc.lower()
    if netloc.startswith("www."):
        netloc = netloc[4:]
    for trusted in TRUSTED_DOMAINS:
        if netloc == trusted or netloc.endswith("." + trusted):
            return True
    return False


def _word_in_url(word: str, text: str) -> bool:
    """
    More precise than bare substring match.
    Checks that the keyword appears as a standalone token
    (surrounded by non-alphanumeric chars or at string boundaries),
    so 'secure' doesn't match 'securely' or 'insecure'.
    """
    pattern = r'(?<![a-z0-9])' + re.escape(word) + r'(?![a-z0-9])'
    return bool(re.search(pattern, text, re.IGNORECASE))


def explain_threat(prediction, similarity, ssl_enabled, url, title):
    reasons = []
    url_lower = url.lower()
    parsed = urlparse(url if "://" in url else "https://" + url)
    netloc = parsed.netloc.lower().lstrip("www.")

    trusted = _is_trusted(netloc)

    # --- ML model flag ---
    # Only report this if the domain is NOT trusted (avoids false positives on
    # old/poorly-trained model flagging known-good domains)
    if prediction == 1 and not trusted:
        reasons.append("Machine Learning model flagged this URL as phishing.")

    # --- Brand impersonation ---
    # Only meaningful if the domain is NOT the actual brand's own domain
    if similarity > 80 and not trusted:
        reasons.append("Strong brand name impersonation detected in URL.")
    elif similarity > 60 and not trusted:
        reasons.append("Possible brand name similarity detected — could be spoofing.")

    # --- SSL ---
    if not ssl_enabled and not trusted:
        reasons.append("Website does not use HTTPS (no SSL/TLS encryption).")

    # --- Keyword check (only on non-trusted domains) ---
    # Uses word-boundary matching and only flags high-signal words
    if not trusted:
        # High-risk keywords — strong indicators on their own
        high_risk_words = [
            "signin", "sign-in", "otp", "password", "credential",
            "suspended", "verify-account", "login-secure",
            "banking-login", "secure-update",
        ]
        # Medium-risk keywords — only flag if 2+ appear together
        medium_risk_words = [
            "login", "verify", "secure", "account", "update", "bank",
            "confirm", "reset", "billing", "payment", "unlock",
            "recover", "reactivate", "validate", "wallet",
        ]

        high_found = [w for w in high_risk_words if _word_in_url(w, url_lower)]
        medium_found = [w for w in medium_risk_words if _word_in_url(w, url_lower)]

        # Only report high-risk words individually
        if high_found:
            reasons.append(f"URL contains high-risk keywords: {', '.join(high_found)}.")

        # Only report medium-risk if 2 or more co-occur (single generic word is not enough)
        if len(medium_found) >= 2:
            reasons.append(
                f"URL contains multiple suspicious keywords: {', '.join(medium_found)}."
            )
        elif len(medium_found) == 1 and prediction == 1:
            # One medium keyword + ML flag together = worth reporting
            reasons.append(f"URL contains suspicious keyword: {medium_found[0]}.")

    # --- IP address used as host ---
    ip_pattern = re.compile(r'\d{1,3}(\.\d{1,3}){3}')
    if ip_pattern.search(netloc):
        reasons.append("URL uses a raw IP address instead of a domain name — highly suspicious.")

    # --- Deep subdomain structure (only if not trusted) ---
    dots = netloc.count(".")
    if dots >= 3 and not trusted:
        reasons.append(f"Unusually deep subdomain structure ({dots} levels) — common in phishing.")

    # --- Multiple hyphens (only if not trusted) ---
    if netloc.count("-") >= 2 and not trusted:
        reasons.append("Multiple hyphens in domain — often used to mimic legitimate brands.")

    # --- Encoded characters ---
    if "%" in url:
        reasons.append("URL contains encoded characters — possible obfuscation attempt.")

    # --- Open redirect ---
    if "redirect" in url_lower or "url=" in url_lower or "next=" in url_lower:
        if not trusted:
            reasons.append("Open redirect pattern detected in URL.")

    # --- Long URL ---
    if len(url) > 120 and not trusted:
        reasons.append(f"Unusually long URL ({len(url)} chars) — often used to hide destination.")

    # --- Suspicious TLD ---
    suspicious_tlds = [".xyz", ".top", ".click", ".work", ".loan", ".gq", ".ml", ".cf", ".tk", ".pw"]
    for tld in suspicious_tlds:
        if netloc.endswith(tld):
            reasons.append(f"Suspicious top-level domain '{tld}' — commonly used in phishing.")
            break

    # --- Page title analysis (only non-trusted) ---
    if title and not trusted:
        title_lower = title.lower()
        # Only flag if multiple suspicious title words co-occur
        title_suspicious = ["verify", "login", "confirm", "suspended", "secure", "alert"]
        found_title = [w for w in title_suspicious if w in title_lower]
        if len(found_title) >= 2:
            reasons.append(f"Page title contains suspicious words: {', '.join(found_title)}.")

    return reasons
