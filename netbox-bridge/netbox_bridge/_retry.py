"""Retry helper with exponential backoff for transient HTTP failures.

Used by both NetBoxClient and OpenSearchClient to defend against:
- transient 5xx (server hiccup)
- 429 throttle (honors Retry-After)
- ConnectionError / Timeout (network blip)

Permanent 4xx (other than 429) propagates immediately — retrying a 401 or 404 wastes time and
risks lockout. ValueError, TypeError, etc. also propagate — they're not transport issues.
"""
from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Callable, TypeVar

import requests

T = TypeVar("T")


@dataclass
class RetryConfig:
    max_attempts: int = 4
    base_delay: float = 0.5
    max_delay: float = 30.0
    jitter: float = 0.5  # uniform 0..jitter added to each delay


def _is_transient_http_error(exc: BaseException) -> bool:
    if isinstance(exc, (requests.ConnectionError, requests.Timeout)):
        return True
    if isinstance(exc, requests.HTTPError):
        status = getattr(exc.response, "status_code", None)
        if status is None:
            return True  # treat unknown as transient
        if status == 429:
            return True
        if 500 <= status < 600:
            return True
    return False


def _retry_after_seconds(exc: requests.HTTPError) -> float | None:
    """Parse Retry-After (seconds-only form). Per RFC 7231 it can also be a date; we ignore that."""
    response = getattr(exc, "response", None)
    if response is None:
        return None
    raw = response.headers.get("Retry-After") if hasattr(response, "headers") else None
    if not raw:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def with_retry(fn: Callable[[], T], *, config: RetryConfig | None = None) -> T:
    """Call fn() with retry on transient failures."""
    cfg = config or RetryConfig()
    last_exc: BaseException | None = None
    for attempt in range(cfg.max_attempts):
        try:
            return fn()
        except BaseException as exc:
            last_exc = exc
            if not _is_transient_http_error(exc):
                raise
            if attempt == cfg.max_attempts - 1:
                raise

            delay = min(cfg.base_delay * (2 ** attempt), cfg.max_delay)
            if isinstance(exc, requests.HTTPError):
                ra = _retry_after_seconds(exc)
                if ra is not None:
                    delay = min(max(delay, ra), cfg.max_delay)
            if cfg.jitter > 0:
                delay += random.uniform(0, cfg.jitter)
                delay = min(delay, cfg.max_delay)
            time.sleep(delay)

    # Unreachable: the final iteration either returns or re-raises. Guard anyway.
    assert last_exc is not None
    raise last_exc
