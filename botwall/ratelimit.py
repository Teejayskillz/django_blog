"""Cache-based rate limiting and concurrency control.

All counters are atomic cache increments; no database rows are touched.
Fixed windows keep the hot path to a single ``INCR`` per profile and are
combined with a short burst window so request floods are caught quickly.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from .cache import get_cache


@dataclass(frozen=True)
class RateVerdict:
    allowed: bool
    profile: str
    count: int
    limit: int
    window: int
    exceeded: bool = False
    retry_after: int = 0


def _window_id(window_seconds: int, now: float | None = None) -> tuple[int, int]:
    now = time.time() if now is None else now
    window = max(int(window_seconds or 60), 1)
    return int(now // window), int(window - (now % window))


def window_id(window_seconds: int, now: float | None = None) -> int:
    return _window_id(window_seconds, now)[0]


def counter_key(profile: str, ip_key: str, window_id: int) -> str:
    return f"bw:rl:{profile}:{ip_key}:{window_id}"


def check(
    ip_key: str,
    profile: str,
    limit: int,
    window_seconds: int,
    *,
    now: float | None = None,
    factor: float = 1.0,
) -> RateVerdict:
    """Increment and evaluate a fixed-window counter."""
    limit = int(limit or 0)
    if limit <= 0 or not ip_key:
        return RateVerdict(True, profile, 0, limit, int(window_seconds or 0))
    effective_limit = max(1, int(limit * float(factor or 1.0)))
    window_id, retry_after = _window_id(window_seconds, now)
    key = counter_key(profile, ip_key, window_id)
    count = int(get_cache().incr(key, 1, max(int(window_seconds) * 2, 60)))
    allowed = count <= effective_limit
    return RateVerdict(
        allowed=allowed,
        profile=profile,
        count=count,
        limit=effective_limit,
        window=int(window_seconds),
        exceeded=not allowed,
        retry_after=retry_after,
    )


# ---------------------------------------------------------------------------
# concurrency protection
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ConcurrencyVerdict:
    allowed: bool
    current: int
    limit: int
    key: str

    def release(self):
        if self.key:
            get_cache().incr(self.key, -1, 60)


def acquire_concurrency(ip_key: str, limit: int) -> ConcurrencyVerdict:
    limit = int(limit or 0)
    if limit <= 0 or not ip_key:
        return ConcurrencyVerdict(True, 0, limit, "")
    key = f"bw:conc:{ip_key}"
    current = int(get_cache().incr(key, 1, 60))
    return ConcurrencyVerdict(current <= limit, current, limit, key)


# ---------------------------------------------------------------------------
# violation tracking (drives progressive restrictions)
# ---------------------------------------------------------------------------
def note_violation(ip_key: str, ttl: int = 3600) -> int:
    return int(get_cache().incr(f"bw:viol:{ip_key}", 1, ttl))


def violations(ip_key: str) -> int:
    return int(get_cache().get(f"bw:viol:{ip_key}", 0) or 0)


def clear_violations(ip_key: str):
    get_cache().delete(f"bw:viol:{ip_key}")
