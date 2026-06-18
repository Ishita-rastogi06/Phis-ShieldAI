from urllib.parse import urlparse
import re

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

def _classify_attack(url, risk, reasons):
    url_lower = url.lower()

    if any(w in url_lower for w in ["wallet", "crypto", "bitcoin", "coin", "metamask", "binance"]):
        return "Crypto Wallet Phishing"
    if any(w in url_lower for w in ["bank", "netbank", "ibanking", "axis", "hdfc", "icici", "sbi",
                                     "chase", "wellsfargo", "citibank", "hsbc", "barclays"]):
        return "Banking Credential Theft"
    if any(w in url_lower for w in ["kyc", "aadhaar", "aadhar", "pan", "irctc", "epfo", "irs", "tax"]):
        return "Government/KYC Impersonation"
    if any(w in url_lower for w in ["prize", "winner", "reward", "gift", "lottery", "lucky"]):
        return "Lottery / Prize Scam"
    if any(w in url_lower for w in ["parcel", "delivery", "tracking", "shipment", "fedex", "dhl", "ups"]):
        return "Fake Delivery Notification"
    if any(w in url_lower for w in ["invoice", "billing", "payment", "order"]):
        return "Invoice / Payment Fraud"
    if "redirect" in url_lower or "url=" in url_lower:
        return "Open Redirect Exploit"
    if re.search(r'\d{1,3}(\.\d{1,3}){3}', urlparse(url if "://" in url else "https://"+url).netloc):
        return "IP-Based Phishing (No Domain)"
    if any(w in url_lower for w in ["login", "signin", "sign-in", "verify", "account", "password", "secure"]):
        return "Credential Harvesting"
    if risk >= 50:
        return "Suspicious Phishing Attempt"
    return "Likely Legitimate"

def _infer_target(url, brand):
    if brand and brand.lower() != "unknown":
        return brand.title()
    url_lower = url.lower()
    segments = re.findall(r'[a-z]{4,}', url_lower)
    finance_terms = {"bank", "finance", "invest", "fund", "loan", "pay", "cash"}
    gov_terms = {"gov", "tax", "irs", "kyc", "epfo", "irctc", "aadhaar"}
    for seg in segments:
        if seg in finance_terms:
            return "Financial Institution"
        if seg in gov_terms:
            return "Government Agency"
    return "Generic User / Any Victim"

def _build_impact(attack_type, risk):
    base = {
        "Credential Harvesting": ["Email/password theft", "Account takeover", "Identity fraud"],
        "Banking Credential Theft": ["Online banking access stolen", "Unauthorized fund transfers", "Financial loss"],
        "Crypto Wallet Phishing": ["Wallet private key theft", "Irreversible crypto fund loss"],
        "Government/KYC Impersonation": ["Aadhaar/PAN misuse", "Identity theft", "Financial fraud via stolen ID"],
        "Lottery / Prize Scam": ["Upfront fee fraud", "Personal data harvested", "No prize exists"],
        "Fake Delivery Notification": ["Credential theft", "Device malware via fake tracking app"],
        "Invoice / Payment Fraud": ["Fraudulent payment", "Business email compromise"],
        "Open Redirect Exploit": ["Victim redirected to malware/phishing page", "Bypasses domain reputation filters"],
        "IP-Based Phishing (No Domain)": ["Hard to trace attacker", "Bypasses domain blacklists"],
        "Suspicious Phishing Attempt": ["Data theft", "Account compromise"],
        "Likely Legitimate": ["No significant impact detected"],
    }
    impacts = base.get(attack_type, ["Data theft", "Account compromise"])
    if risk >= 70:
        impacts.append("HIGH probability of real victim harm if interacted with.")
    return impacts

def generate_ai_explanation(target, verdict, risk, reasons, brand="Unknown"):
    # Trusted domain pe generic safe response do
    if _is_trusted(target):
        return {
            "attack_type": "None — Legitimate Website",
            "brand": brand.title() if brand and brand.lower() != "unknown" else "Trusted Domain",
            "impact": ["No threat detected", "This is a verified legitimate website"],
            "strategy": (
                "This URL belongs to a well-known trusted domain. "
                "No phishing indicators detected. Safe to use."
            ),
        }

    attack_type = _classify_attack(target, risk, reasons)
    target_brand = _infer_target(target, brand)

    if risk >= 70:
        strategy = (
            f"This resource displays strong phishing characteristics consistent with a '{attack_type}' attack. "
            "The URL structure, keywords, and/or domain patterns strongly suggest it is designed to deceive victims "
            "into surrendering sensitive information. Do not interact."
        )
    elif risk >= 40:
        strategy = (
            f"Several indicators suggest this could be a '{attack_type}' attempt. "
            "The resource contains patterns commonly used by attackers but lacks some hallmarks of a confirmed attack. "
            "Exercise caution — avoid submitting any personal or financial data."
        )
    else:
        strategy = (
            "No significant phishing indicators were detected. This resource appears to be legitimate based on "
            "current analysis. Standard caution always applies when sharing personal data online."
        )

    return {
        "attack_type": attack_type,
        "brand": target_brand,
        "impact": _build_impact(attack_type, risk),
        "strategy": strategy,
    }