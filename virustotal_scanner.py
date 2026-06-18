import requests
import time

VT_API_KEY = "c863705a9320553cb4a48468cd3e0844ac6b3f573ad9cc0859aa9e4643bdc84d"

def scan_url_virustotal(url):
    headers = {"x-apikey": VT_API_KEY}

    try:
        # Step 1: URL submit karo scan ke liye
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=15
        )

        if response.status_code != 200:
            return None

        scan_id = response.json()["data"]["id"]

        # Step 2: Retry loop — wait karo jab tak result ready na ho
        stats = None
        for attempt in range(6):
            time.sleep(4)
            result = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{scan_id}",
                headers=headers,
                timeout=15
            )
            if result.status_code != 200:
                continue
            data = result.json()["data"]["attributes"]
            if data.get("status") == "completed":
                stats = data["stats"]
                break

        if stats is None:
            return None

        malicious   = stats.get("malicious", 0)
        suspicious  = stats.get("suspicious", 0)
        harmless    = stats.get("harmless", 0)
        undetected  = stats.get("undetected", 0)
        total       = malicious + suspicious + harmless + undetected

        if total == 0:
            return None

        return {
            "malicious":  malicious,
            "suspicious": suspicious,
            "harmless":   harmless,
            "undetected": undetected,
            "total":      total,
            "verdict": (
                "Dangerous"  if malicious >= 3 else
                "Suspicious" if malicious >= 1 or suspicious >= 1 else
                "Clean"
            )
        }

    except Exception:
        return None
