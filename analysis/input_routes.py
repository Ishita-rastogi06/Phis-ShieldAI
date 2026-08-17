"""Adapters that route extracted input URLs into the one canonical pipeline."""
from __future__ import annotations

from analysis.url_analysis_pipeline import analyze_url


def analyze_extracted_urls(urls: list[str]) -> list[dict]:
    """Analyze each already-extracted, deduplicated URL exactly once.

    QR, OCR, and email concerns stop at extraction.  They must not add a
    separate risk calculation or verdict before this canonical route.
    """
    return [analyze_url(url) for url in urls]
