"""Traffic statistics kept in the cache, aggregated hourly in the database.

Design goals
------------
* normal page views never write to the database (only atomic cache ``INCR``),
* minute buckets live in the cache for two hours and feed the live dashboard,
* a five-minute flush rolls completed minutes into :class:`TrafficStat` rows,
  so charts survive cache evictions and process restarts,
* unique IPs are estimated with a per-minute "first seen" marker, which is
  cheap on both Redis and file caches.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone as dt_timezone

from django.db.models import F
from django.utils import timezone

from .cache import get_cache

logger = logging.getLogger("botwall.stats")

MINUTE = 60
BUCKET_TTL = 7200  # two hours of minute counters

_KIND_REQUESTS = "req"
_KIND_SUSPICIOUS = "susp"
_KIND_BLOCKED = "blk"
_KIND_RATE_LIMITED = "rl"
_KIND_CHALLENGES = "ch"
_KIND_UNIQUE = "uniq"

_ALL_KINDS = (
    _KIND_REQUESTS,
    _KIND_SUSPICIOUS,
    _KIND_BLOCKED,
    _KIND_RATE_LIMITED,
    _KIND_CHALLENGES,
    _KIND_UNIQUE,
)


def current_minute(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // MINUTE)


def bucket_key(kind: str, minute: int) -> str:
    return f"bw:st:{kind}:{minute}"


def _incr(kind: str, minute: int | None = None) -> int:
    minute = current_minute() if minute is None else minute
    return int(get_cache().incr(bucket_key(kind, minute), 1, BUCKET_TTL))


# ---------------------------------------------------------------------------
# recording
# ---------------------------------------------------------------------------
def record_request(ip: str = "", unique_tracking: bool = True) -> int:
    minute = current_minute()
    total = _incr(_KIND_REQUESTS, minute)
    if unique_tracking and ip:
        # ``add`` returns True only for the first request of this IP in the
        # minute, giving a cheap unique-visitor estimate without a SET scan.
        if get_cache().add(f"bw:su:{minute}:{ip}", 1, BUCKET_TTL):
            _incr(_KIND_UNIQUE, minute)
    return total


def record_suspicious():
    _incr(_KIND_SUSPICIOUS)


def record_blocked():
    _incr(_KIND_BLOCKED)


def record_rate_limited():
    _incr(_KIND_RATE_LIMITED)


def record_challenge():
    _incr(_KIND_CHALLENGES)


# ---------------------------------------------------------------------------
# reading
# ---------------------------------------------------------------------------
def read_minutes(kinds=_ALL_KINDS, minutes: int = 60, now: float | None = None):
    """Return ``{kind: {minute: value}}`` for the last ``minutes`` minutes."""
    end = current_minute(now)
    start = end - max(minutes, 1) + 1
    keys = [bucket_key(kind, minute) for kind in kinds for minute in range(start, end + 1)]
    values = get_cache().get_many(keys)
    result = {kind: {} for kind in kinds}
    for kind in kinds:
        for minute in range(start, end + 1):
            value = values.get(bucket_key(kind, minute))
            if value:
                result[kind][minute] = int(value)
    return result


def window_totals(minutes: int = 60, now: float | None = None) -> dict:
    data = read_minutes(minutes=minutes, now=now)
    totals = {kind: sum(data[kind].values()) for kind in _ALL_KINDS}
    return {
        "requests": totals[_KIND_REQUESTS],
        "suspicious": totals[_KIND_SUSPICIOUS],
        "blocked": totals[_KIND_BLOCKED],
        "rate_limited": totals[_KIND_RATE_LIMITED],
        "challenges": totals[_KIND_CHALLENGES],
        "unique_ips": totals[_KIND_UNIQUE],
    }


def requests_per_minute(minutes: int = 5) -> float:
    total = 0
    end = current_minute()
    keys = [bucket_key(_KIND_REQUESTS, minute) for minute in range(end - minutes + 1, end + 1)]
    values = get_cache().get_many(keys)
    for key in keys:
        total += int(values.get(key) or 0)
    return round(total / max(minutes, 1), 1)


def attack_mode(config, now: float | None = None) -> bool:
    """Detect a sudden traffic spike relative to the recent baseline.

    The verdict is cached in-process for ten seconds so the dashboard and the
    middleware do not re-read eleven counters on every single request.
    """
    global _attack_state
    if not getattr(config, "spike_enabled", False):
        return False
    current_time = time.monotonic()
    state = _attack_state
    if state["expires"] > current_time:
        return state["value"]

    minute = current_minute(now)
    keys = [bucket_key(_KIND_REQUESTS, minute)] + [
        bucket_key(_KIND_REQUESTS, minute - offset) for offset in range(1, 11)
    ]
    values = get_cache().get_many(keys)
    current = int(values.get(keys[0]) or 0)
    previous = [int(values.get(key) or 0) for key in keys[1:]]
    baseline = sum(previous) / len(previous) if previous else 0.0

    active = False
    minimum = int(getattr(config, "spike_min_requests", 120) or 0)
    multiplier = float(getattr(config, "spike_multiplier", 5.0) or 5.0)
    if current >= minimum and baseline > 0:
        active = current >= baseline * multiplier
    elif current >= minimum and baseline == 0:
        active = current >= minimum

    _attack_state = {"value": active, "expires": current_time + 10}
    if active:
        logger.warning(
            "botwall: traffic spike detected (%s requests in the current minute, "
            "%.1f baseline)",
            current,
            baseline,
        )
    return active


_attack_state = {"value": False, "expires": 0.0}


def reset_attack_state():
    global _attack_state
    _attack_state = {"value": False, "expires": 0.0}


# ---------------------------------------------------------------------------
# hourly aggregation
# ---------------------------------------------------------------------------
def _hour_start(minute_ts: int) -> datetime:
    return datetime.fromtimestamp(minute_ts * MINUTE, tz=dt_timezone.utc).replace(
        minute=0, second=0, microsecond=0
    )


def _live_hour_data(minutes: int = 130, now: float | None = None) -> dict:
    """Aggregate cache buckets per hour for the recent window."""
    data = read_minutes(minutes=minutes, now=now)
    hours: dict[int, dict] = {}
    for kind in _ALL_KINDS:
        for minute, value in data[kind].items():
            hour_ts = int(minute * MINUTE // 3600 * 3600)
            bucket = hours.setdefault(
                hour_ts,
                {
                    "requests": 0,
                    "suspicious": 0,
                    "blocked": 0,
                    "rate_limited": 0,
                    "challenges": 0,
                    "unique_ips": 0,
                },
            )
            bucket[_kind_to_field(kind)] += value
    return hours


def _kind_to_field(kind: str) -> str:
    return {
        _KIND_REQUESTS: "requests",
        _KIND_SUSPICIOUS: "suspicious",
        _KIND_BLOCKED: "blocked",
        _KIND_RATE_LIMITED: "rate_limited",
        _KIND_CHALLENGES: "challenges",
        _KIND_UNIQUE: "unique_ips",
    }[kind]


def flush_recent(minutes: int = 25) -> int:
    """Roll completed minute buckets into hourly TrafficStat rows.

    Each minute is flushed at most once (guarded by a cache marker). Safe to
    call from multiple worker processes.
    """
    from .models import TrafficStat

    cache = get_cache()
    end = current_minute() - 1
    start = end - max(minutes, 1) + 1
    flushed_minutes = []
    for minute in range(start, end + 1):
        if cache.add(f"bw:fl:{minute}", 1, 3600):
            flushed_minutes.append(minute)
    if not flushed_minutes:
        return 0

    keys = [
        bucket_key(kind, minute) for kind in _ALL_KINDS for minute in flushed_minutes
    ]
    values = cache.get_many(keys)

    per_hour: dict[datetime, dict] = {}
    for minute in flushed_minutes:
        bucket = per_hour.setdefault(
            _hour_start(minute),
            {
                "requests": 0,
                "suspicious": 0,
                "blocked": 0,
                "rate_limited": 0,
                "challenges": 0,
                "unique_ips": 0,
            },
        )
        for kind in _ALL_KINDS:
            value = int(values.get(bucket_key(kind, minute)) or 0)
            if value:
                bucket[_kind_to_field(kind)] += value

    written = 0
    for hour, totals in per_hour.items():
        if not any(totals.values()):
            continue
        try:
            from django.db import transaction

            with transaction.atomic():
                obj, created = TrafficStat.objects.get_or_create(
                    bucket_start=hour, defaults=dict(totals)
                )
                if not created:
                    TrafficStat.objects.filter(pk=obj.pk).update(
                        requests=F("requests") + totals["requests"],
                        suspicious=F("suspicious") + totals["suspicious"],
                        blocked=F("blocked") + totals["blocked"],
                        rate_limited=F("rate_limited") + totals["rate_limited"],
                        challenges=F("challenges") + totals["challenges"],
                        unique_ips=F("unique_ips") + totals["unique_ips"],
                    )
            written += 1
        except Exception as exc:  # noqa: BLE001 - stats must never break requests
            logger.warning("botwall: could not flush traffic stats: %s", exc)
    return written


def hourly_series(hours: int = 24, now: datetime | None = None):
    """Return one row per hour for the dashboard charts.

    The most recent two hours come from the live cache (which is always
    current), older hours come from the ``TrafficStat`` table.
    """
    from .models import TrafficStat

    hours = max(int(hours), 1)
    now = now or timezone.now()
    current_hour = now.replace(minute=0, second=0, microsecond=0)
    start = current_hour - timedelta(hours=hours - 1)
    live = _live_hour_data()

    db_rows = {
        row.bucket_start: row
        for row in TrafficStat.objects.filter(bucket_start__gte=start)
    }

    series = []
    for index in range(hours):
        hour = start + timedelta(hours=index)
        hour_ts = int(hour.timestamp())
        if hour_ts in live:
            entry = dict(live[hour_ts])
            entry["source"] = "live"
        else:
            row = db_rows.get(hour)
            entry = {
                "requests": row.requests if row else 0,
                "suspicious": row.suspicious if row else 0,
                "blocked": row.blocked if row else 0,
                "rate_limited": row.rate_limited if row else 0,
                "challenges": row.challenges if row else 0,
                "unique_ips": row.unique_ips if row else 0,
                "source": "database",
            }
        entry["hour"] = hour
        entry["label"] = hour.strftime("%H:00")
        series.append(entry)
    return series


_FIELDS = (
    "requests",
    "suspicious",
    "blocked",
    "rate_limited",
    "challenges",
    "unique_ips",
)


def totals(hours: int = 24) -> dict:
    """Aggregate counters for the dashboard without double counting.

    Hours covered by the live cache window (current + previous hour) are
    summed from the cache; older hours are summed from ``TrafficStat``.
    """
    from django.db.models import Sum

    from .models import TrafficStat

    hours = max(int(hours), 1)
    now = timezone.now()
    current_hour = now.replace(minute=0, second=0, microsecond=0)
    live_start = current_hour - timedelta(hours=1)

    live_totals = {field: 0 for field in _FIELDS}
    for hour_ts, bucket in _live_hour_data().items():
        hour_dt = datetime.fromtimestamp(hour_ts, tz=dt_timezone.utc)
        if hour_dt >= live_start:
            for field in _FIELDS:
                live_totals[field] += int(bucket.get(field, 0))

    older_start = current_hour - timedelta(hours=hours)
    aggregate = TrafficStat.objects.filter(
        bucket_start__gte=older_start, bucket_start__lt=live_start
    ).aggregate(**{field: Sum(field) for field in _FIELDS})

    return {
        field: int(aggregate.get(field) or 0) + live_totals[field]
        for field in _FIELDS
    }
