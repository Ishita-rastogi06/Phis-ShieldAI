from rapidfuzz import fuzz
from urllib.parse import urlparse
import re

brands = [
    # Global tech / social
    "amazon", "google", "microsoft", "apple", "facebook", "instagram",
    "netflix", "youtube", "twitter", "linkedin", "whatsapp", "telegram",
    "dropbox", "adobe", "salesforce", "zoom", "slack", "github",
    # Finance / payments
    "paypal", "stripe", "visa", "mastercard", "americanexpress",
    "wellsfargo", "bankofamerica", "chase", "citibank", "hsbc",
    "barclays", "halifax", "lloyds", "natwest", "santander",
    # Indian brands
    "paytm", "sbi", "hdfc", "icici", "axisbank", "kotak", "pnb",
    "phonepe", "gpay", "mobikwik", "ola", "uber", "swiggy", "zomato",
    "flipkart", "myntra", "meesho", "jiomart", "bigbasket", "blinkit",
    "airtel", "jio", "vodafone", "bsnl", "irctc",
    "incometax", "aadhaar", "epfo", "npci",
    # Crypto / fintech
    "coinbase", "binance", "kraken", "metamask", "wazirx", "coindcx",
    # Retail / ecommerce
    "walmart", "target", "ebay", "etsy", "shopify", "aliexpress",
    # Telecoms / ISPs
    "att", "verizon", "tmobile", "comcast", "spectrum",
    # Gov / utilities  (removed ultra-short ones like "gov","irs","upi","nhs","hmrc"
    #                    that cause false matches on unrelated short domains)
    "medicare", "socialsecurity",
]

# Brands that are short (≤4 chars) need exact match in domain, not fuzzy
SHORT_BRANDS = {b for b in brands if len(b) <= 4}

# Authoritative domains — if the URL belongs to one of these, no impersonation possible
AUTHORITATIVE_DOMAINS = {
    "google.com", "gmail.com", "youtube.com",
    "microsoft.com", "outlook.com", "live.com", "office.com",
    "apple.com", "icloud.com",
    "amazon.com", "amazon.in", "amazonaws.com",
    "facebook.com", "instagram.com", "meta.com",
    "twitter.com", "x.com",
    "linkedin.com", "netflix.com", "github.com",
    "paypal.com", "stripe.com", "zoom.us", "slack.com",
    "adobe.com", "salesforce.com", "shopify.com",
    "flipkart.com", "paytm.com", "phonepe.com",
    "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com",
    "icicibank.com", "axisbank.com", "kotak.com",
    "irctc.co.in", "incometax.gov.in", "uidai.gov.in",
    "npci.org.in",
    # Additional well-known legitimate domains
    "wikipedia.org", "stackoverflow.com", "stackexchange.com",
    "reddit.com", "bbc.com", "bbc.co.uk", "reuters.com",
    "nytimes.com", "cnn.com", "medium.com",
    "cloudflare.com", "akamai.com",
    "npmjs.com", "pypi.org", "docker.com",
    "ebay.com", "walmart.com",
}


def _is_authoritative(netloc: str) -> bool:
    netloc = netloc.lower()
    # Remove www. prefix properly (not lstrip which strips chars, not strings)
    if netloc.startswith("www."):
        netloc = netloc[4:]
    for auth in AUTHORITATIVE_DOMAINS:
        if netloc == auth or netloc.endswith("." + auth):
            return True
    return False


def _extract_domain_tokens(url):
    try:
        parsed = urlparse(url if "://" in url else "https://" + url)
        host = parsed.netloc.lower().replace("www.", "")
        path = parsed.path.lower()
        # Strip TLD for matching (e.g. "amazon" from "amazon.com")
        host_no_tld = re.sub(r'\.[a-z]{2,}(\.[a-z]{2,})?$', '', host)
        return host, host_no_tld, path
    except Exception:
        return url.lower(), url.lower(), ""


def detect_brand(url):
    parsed = urlparse(url if "://" in url else "https://" + url)
    netloc = parsed.netloc.lower().lstrip("www.")

    # If URL belongs to the brand's own domain, return no impersonation
    if _is_authoritative(netloc):
        return "Unknown", 0

    host, host_no_tld, path = _extract_domain_tokens(url)
    search_text = host + " " + host_no_tld

    best_brand = "Unknown"
    best_score = 0

    for brand in brands:
        if brand in SHORT_BRANDS:
            # Short brands: only count exact token match in host_no_tld
            # e.g. "sbi" must appear as a standalone part of the subdomain/domain
            pattern = r'(?<![a-z0-9])' + re.escape(brand) + r'(?![a-z0-9])'
            if re.search(pattern, host_no_tld):
                score = 90
            else:
                continue  # skip fuzzy for short brands — too many false positives
        else:
            if brand in search_text:
                score = 95
            else:
                score = fuzz.partial_ratio(brand, search_text)

        if score > best_score:
            best_score = score
            best_brand = brand

    # Raise minimum threshold to reduce false positives
    if best_score < 70:
        return "Unknown", 0

    return best_brand, best_score
