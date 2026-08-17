"""Offline, writable Public Suffix List configuration for tldextract."""
from __future__ import annotations

from pathlib import Path

import tldextract


_CACHE_DIR = Path(__file__).resolve().parents[1] / ".cache" / "tldextract"
_CACHE_DIR.mkdir(parents=True, exist_ok=True)


def offline_extractor() -> tldextract.TLDExtract:
    """Use the packaged suffix snapshot without runtime network retrieval."""
    return tldextract.TLDExtract(suffix_list_urls=(), cache_dir=str(_CACHE_DIR))
