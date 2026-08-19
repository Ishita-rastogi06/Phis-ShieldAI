"""Shared per-provider result cache and rate-limit backoff state.

Both the cache and the backoff state live in module-level dictionaries so they
are shared across all calls within a single Python process (i.e. one Streamlit
run / one batch diagnostic run).

Cache:
  TTL = 10 minutes.  Keyed by (provider_name, url).  On a cache hit the stored
  contract dict is returned directly — no outbound call is made.  This prevents
  burning free-tier quota when the same URL is scanned multiple times in a demo
  session.

Backoff:
  When a provider returns HTTP 429 (RATE_LIMITED) the adapter calls
  record_rate_limit().  Subsequent calls within the backoff window return the
  stored RATE_LIMITED result immediately without even attempting the request.
  Backoff schedule: 30 s → 60 s → 120 s → 240 s (capped at 240 s, resets after
  a successful call).
"""
from __future__ import annotations

import logging
import time
from typing import Any

_LOGGER = logging.getLogger("phishshield.provider_cache")

# ── Result cache ──────────────────────────────────────────────────────────────
CACHE_TTL_SECONDS = 600  # 10 minutes

# {(provider, url): (expires_at: float, result: dict)}
_cache: dict[tuple[str, str], tuple[float, dict]] = {}


def cache_get(provider: str, url: str) -> dict | None:
    """Return a cached result if it is still within TTL, else None."""
    key = (provider, url)
    entry = _cache.get(key)
    if entry is None:
        return None
    expires_at, cached_result = entry
    if time.monotonic() > expires_at:
        del _cache[key]
        return None
    _LOGGER.debug("cache_hit provider=%s url=%r age_remaining=%.0fs",
                  provider, url, expires_at - time.monotonic())
    return cached_result


def cache_set(provider: str, url: str, result: dict) -> None:
    """Store a result in the cache with a fresh TTL."""
    key = (provider, url)
    _cache[key] = (time.monotonic() + CACHE_TTL_SECONDS, result)
    _LOGGER.debug("cache_set provider=%s url=%r ttl=%ds", provider, url, CACHE_TTL_SECONDS)


def cache_clear(provider: str | None = None) -> None:
    """Clear the cache — optionally for one provider only (useful in tests)."""
    if provider is None:
        _cache.clear()
        _backoff.clear()
    else:
        for key in list(_cache):
            if key[0] == provider:
                del _cache[key]
        if provider in _backoff:
            del _backoff[provider]


# ── Rate-limit backoff ────────────────────────────────────────────────────────
# Backoff windows in seconds (exponential, capped at 240 s)
_BACKOFF_STEPS = (30, 60, 120, 240)

# {provider: {"until": float, "step": int, "last_result": dict}}
_backoff: dict[str, dict[str, Any]] = {}


def is_rate_limited(provider: str) -> tuple[bool, dict | None]:
    """Return (True, cached_rate_limited_result) if still inside a backoff window."""
    state = _backoff.get(provider)
    if state is None:
        return False, None
    if time.monotonic() < state["until"]:
        remaining = round(state["until"] - time.monotonic())
        _LOGGER.warning(
            "backoff_active provider=%s retry_in=%ds", provider, remaining
        )
        # Refresh the reason so the UI shows an accurate countdown.
        result = dict(state["last_result"])
        result["reason"] = (
            f"Rate limited — retry in {remaining}s "
            f"(backoff step {state['step'] + 1}/{len(_BACKOFF_STEPS)})"
        )
        return True, result
    # Window expired — clear state so the next call goes through.
    del _backoff[provider]
    return False, None


def record_rate_limit(provider: str, result: dict) -> None:
    """Record a 429 response and advance the exponential backoff step."""
    state = _backoff.get(provider, {"step": -1, "until": 0.0, "last_result": result})
    step = min(state["step"] + 1, len(_BACKOFF_STEPS) - 1)
    window = _BACKOFF_STEPS[step]
    _backoff[provider] = {
        "step": step,
        "until": time.monotonic() + window,
        "last_result": result,
    }
    _LOGGER.warning(
        "rate_limited provider=%s backoff_step=%d window=%ds",
        provider, step, window,
    )


def record_success(provider: str) -> None:
    """Reset the backoff counter after a successful (non-429) provider call."""
    if provider in _backoff:
        del _backoff[provider]
        _LOGGER.debug("backoff_reset provider=%s", provider)
