from urllib.parse import urlparse

TRUSTED_DOMAINS = {
    "google.com", "gmail.com", "youtube.com",
    "microsoft.com", "outlook.com", "live.com", "office.com",
    "apple.com", "icloud.com",
    "amazon.com", "amazon.in", "amazonaws.com",
    "facebook.com", "instagram.com", "meta.com",
    "twitter.com", "x.com", "linkedin.com", "netflix.com",
    "github.com", "paypal.com", "stripe.com", "zoom.us",
    "slack.com", "adobe.com", "shopify.com",
    "flipkart.com", "paytm.com", "phonepe.com",
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com",
    "irctc.co.in", "incometax.gov.in", "uidai.gov.in",
    "wikipedia.org", "stackoverflow.com", "reddit.com",
    "bbc.com", "bbc.co.uk", "reuters.com",
}

def _is_trusted(url):
    try:
        parsed = urlparse(url if "://" in url else "https://" + url)
        netloc = parsed.netloc.lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]
        for d in TRUSTED_DOMAINS:
            if netloc == d or netloc.endswith("." + d):
                return True
    except Exception:
        pass
    return False


def map_to_mitre(url, similarity, risk, reasons):
    # Trusted domains pe koi MITRE technique flag mat karo
    if _is_trusted(url):
        return []

    url_lower = url.lower()
    techniques = []

    # T1566.002 — Spearphishing Link
    if risk >= 50:
        techniques.append({
            "id": "T1566.002",
            "name": "Spearphishing Link",
            "tactic": "Initial Access",
            "detail": "Malicious URL used to trick user into clicking.",
            "groups": "APT28, Lazarus Group, TA453"
        })

    # T1598.003 — Phishing for Information
    keywords = ["login", "verify", "account", "password", "otp", "credential"]
    if any(k in url_lower for k in keywords):
        techniques.append({
            "id": "T1598.003",
            "name": "Phishing for Information — Credential Harvesting",
            "tactic": "Reconnaissance",
            "detail": "URL attempts to steal credentials via fake login page.",
            "groups": "APT29, FIN7, Kimsuky"
        })

    # T1204.001 — Malicious Link (User Execution)
    if risk >= 60:
        techniques.append({
            "id": "T1204.001",
            "name": "Malicious Link — User Execution",
            "tactic": "Execution",
            "detail": "Relies on user clicking the link to trigger attack.",
            "groups": "Multiple threat actors"
        })

    # T1036.005 — Masquerading (Brand Impersonation)
    if similarity > 70:
        techniques.append({
            "id": "T1036.005",
            "name": "Masquerading — Brand Impersonation",
            "tactic": "Defense Evasion",
            "detail": "Domain mimics a trusted brand to appear legitimate.",
            "groups": "TA416, APT32"
        })

    # T1027 — Obfuscation
    if "%" in url or len(url) > 100:
        techniques.append({
            "id": "T1027",
            "name": "Obfuscated Files or Information",
            "tactic": "Defense Evasion",
            "detail": "URL uses encoding or excessive length to hide destination.",
            "groups": "APT41, Sandworm"
        })

    # T1583.001 — Acquire Infrastructure (Suspicious TLD)
    bad_tlds = [".xyz", ".tk", ".ml", ".cf", ".gq", ".top", ".click", ".pw"]
    if any(url_lower.endswith(t) or ("." + t.strip(".") + "/") in url_lower for t in bad_tlds):
        techniques.append({
            "id": "T1583.001",
            "name": "Acquire Infrastructure — Disposable Domain",
            "tactic": "Resource Development",
            "detail": "Free or throwaway TLD used to avoid tracking.",
            "groups": "TA505, FIN6"
        })

    return techniques
