import requests
from bs4 import BeautifulSoup

def analyze_website(url):

    result = {
        "ssl": False,
        "title": None,
        "reachable": False
    }

    try:

        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        response = requests.get(
            url,
            timeout=10,
            headers={
                "User-Agent":
                "Mozilla/5.0"
            }
        )

        result["reachable"] = True

        result["ssl"] = url.startswith(
            "https://"
        )

        soup = BeautifulSoup(
            response.text,
            "html.parser"
        )

        if soup.title:
            result["title"] = (
                soup.title.text.strip()
            )

    except:
        pass

    return result