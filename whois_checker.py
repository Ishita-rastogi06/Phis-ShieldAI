import whois
from datetime import datetime, timezone

def check_domain_age(url):
    try:
        # Domain nikalo URL se
        domain = url.replace("https://", "").replace("http://", "").split("/")[0]
        domain = domain.replace("www.", "")

        w = whois.whois(domain)

        creation_date = w.creation_date

        # Kabhi kabhi list aata hai, pehla lo
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            return {
                "domain": domain,
                "age_days": None,
                "registrar": w.registrar or "Unknown",
                "country": w.country or "Unknown",
                "verdict": "Unknown — WHOIS data not available"
            }

        # Age calculate karo
        if creation_date.tzinfo is not None:
            now = datetime.now(timezone.utc)
        else:
            now = datetime.now()

        age_days = (now - creation_date).days

        # Verdict
        if age_days < 30:
            verdict = "🚨 Very New Domain — High Risk"
        elif age_days < 180:
            verdict = "⚠️ Recently Created — Moderate Risk"
        elif age_days < 365:
            verdict = "🟡 Less than 1 year old"
        else:
            years = age_days // 365
            verdict = f"✅ Established Domain — {years} year(s) old"

        return {
            "domain": domain,
            "age_days": age_days,
            "created": creation_date.strftime("%d %B %Y"),
            "registrar": w.registrar or "Unknown",
            "country": w.country or "Unknown",
            "verdict": verdict
        }

    except Exception:
        return None
