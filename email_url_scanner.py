import re

def extract_urls(email_text):

    urls = re.findall(
        r'https?://[^\s]+',
        email_text
    )

    return urls