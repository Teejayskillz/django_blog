"""IP reputation: whitelists, temporary bans, permanent bans, CIDR ranges.

Storage strategy
----------------
* The authoritative rules live in :class:`botwall.models.IPRule`.
* A small in-process snapshot (refreshed every ``BOTWALL_RULES_REFRESH_SECONDS``)
  answers CIDR membership without a database query per request.
* Exact-IP blocks additionally get a cache marker, so a ban takes effect on
  every worker process immediately and expires automatically.
* Bans are *always* written with a reason. Automatic bans can never be
  permanent and always carry an expiry time.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone

from django.conf import settings
from django.utils import timezone

from .cache import get_cache
from .ip import ip_in_networks, normalize_ip, normalize_network

logger = logging.getLogger("botwall.blocking")

REFRESH_SECONDS = float(getattr(settings, "BOTWALL_RULES_REFRESH_SECONDS", 30))

STRIKE_TTL = 86400
HIT_UPDATE_TTL = 60


@dataclass(frozen=True)
class RuleInfo:
    id: int | None
    value: str
    rule_type: str
    source: str
    permanent: bool
    reason: str
    expires_at: object | None = None
    strike_level: int = 0

    @property
    def retry_after(self) -> int:
        if self.permanent or self.expires_at is None:
            return 0
        try:
            return max(int((self.expires_at - timezone.now()).total_seconds()), 0)
        except TypeError:
            return 0


@dataclass(frozen=True)
class RuleCheck:
    whitelisted: bool = False
    block: RuleInfo | None = None
    from_cache: bool = False


@dataclass(frozen=True)
class _Snapshot:
    whitelist: tuple[RuleInfo, ...] = ()
    blocks: tuple[RuleInfo, ...] = ()
    loaded_at: float = 0.0
    from_db: bool = False


_snapshot = _Snapshot()


def _rule_from_marker(ip: str, payload) -> RuleInfo | None:
    if not isinstance(payload, dict):
        return None
    expires_at = payload.get("expires_at")
    if isinstance(expires_at, str):
        try:
            expires_at = datetime.fromisoformat(expires_at)
        except ValueError:
            expires_at = None
    if isinstance(expires_at, datetime) and timezone.is_naive(expires_at):
        expires_at = timezone.make_aware(expires_at, dt_timezone.utc)
    if expires_at is not None and expires_at <= timezone.now():
        return None
    return RuleInfo(
        id=payload.get("rule_id"),
        value=ip,
        rule_type="block",
        source=payload.get("source", "auto"),
        permanent=bool(payload.get("permanent")),
        reason=payload.get("reason", ""),
        expires_at=expires_at if not payload.get("permanent") else None,
        strike_level=int(payload.get("strike_level") or 0),
    )


def normalize_ip_value(value) -> str | None:
    """Return a canonical single IP or CIDR string (``None`` when invalid)."""
    network = normalize_network(value)
    if network is None:
        return None
    if network.num_addresses == 1:
        return str(network.network_address)
    return str(network)


def marker_payload(rule) -> dict:
    return {
        "reason": rule.reason or "",
        "permanent": bool(rule.is_permanent),
        "source": rule.source,
        "rule_id": rule.pk,
        "strike_level": rule.strike_level,
        "expires_at": rule.expires_at.isoformat() if rule.expires_at else None,
    }


# ---------------------------------------------------------------------------
# snapshot
# ---------------------------------------------------------------------------
def get_snapshot(force: bool = False) -> _Snapshot:
    global _snapshot
    now = time.monotonic()
    if not force and _snapshot.loaded_at and now - _snapshot.loaded_at < REFRESH_SECONDS:
        return _snapshot

    whitelist: list[RuleInfo] = []
    blocks: list[RuleInfo] = []
    from_db = False
    try:
        from .models import IPRule

        rows = IPRule.objects.filter(is_active=True).only(
            "id",
            "value",
            "rule_type",
            "source",
            "is_permanent",
            "reason",
            "expires_at",
            "strike_level",
        )
        now_dt = timezone.now()
        for row in rows:
            if row.expires_at is not None and row.expires_at <= now_dt:
                continue
            info = RuleInfo(
                id=row.pk,
                value=row.value,
                rule_type=row.rule_type,
                source=row.source,
                permanent=row.is_permanent,
                reason=row.reason,
                expires_at=row.expires_at,
                strike_level=row.strike_level,
            )
            if row.rule_type == IPRule.RULE_WHITELIST:
                whitelist.append(info)
            else:
                blocks.append(info)
        from_db = True
    except Exception as exc:  # noqa: BLE001 - missing table / DB outage: fail open
        logger.debug("botwall: IP rule snapshot unavailable: %s", exc)

    _snapshot = _Snapshot(
        whitelist=tuple(whitelist),
        blocks=tuple(blocks),
        loaded_at=time.monotonic(),
        from_db=from_db,
    )
    return _snapshot


def invalidate_rules():
    global _snapshot
    _snapshot = _Snapshot()


# ---------------------------------------------------------------------------
# lookups
# ---------------------------------------------------------------------------
def evaluate_ip(ip: str, config) -> RuleCheck:
    """Return whether ``ip`` is whitelisted or actively blocked."""
    ip = normalize_ip(ip) or ""
    if not ip:
        return RuleCheck()

    keys = (f"bw:wl:{ip}", f"bw:blk:{ip}")
    markers = get_cache().get_many(keys)
    if markers.get(keys[0]):
        return RuleCheck(whitelisted=True, from_cache=True)

    snapshot = get_snapshot()
    if _matches(ip, snapshot.whitelist):
        return RuleCheck(whitelisted=True)

    if markers.get(keys[1]):
        block = _rule_from_marker(ip, markers[keys[1]])
        if block is not None:
            return RuleCheck(block=block, from_cache=True)

    for rule in snapshot.blocks:
        if _rule_matches(ip, rule):
            return RuleCheck(block=rule)

    if config is not None and ip_in_networks(ip, config.blocked_networks):
        return RuleCheck(
            block=RuleInfo(
                id=None,
                value="settings:blocked_networks",
                rule_type="block",
                source="manual",
                permanent=True,
                reason="Listed in the configured blocked networks",
            )
        )
    return RuleCheck()


def _rule_matches(ip: str, rule: RuleInfo) -> bool:
    from .ip import normalize_network

    network = normalize_network(rule.value)
    if network is None:
        return False
    return ip_in_networks(ip, (network,))


def _matches(ip: str, rules) -> bool:
    return any(_rule_matches(ip, rule) for rule in rules)


def is_whitelisted(ip: str) -> bool:
    snapshot = get_snapshot()
    if _matches(ip, snapshot.whitelist):
        return True
    return bool(get_cache().get(f"bw:wl:{ip}"))


def strikes(ip: str) -> int:
    return int(get_cache().get(f"bw:strike:{ip}", 0) or 0)


def note_strike(ip: str) -> int:
    return int(get_cache().incr(f"bw:strike:{ip}", 1, STRIKE_TTL))


def clear_strikes(ip: str):
    get_cache().delete(f"bw:strike:{ip}")


def ban_minutes(strike_count: int, config) -> int:
    """Progressive ban duration for a repeat offender."""
    base = max(int(getattr(config, "temp_ban_minutes", 30) or 30), 1)
    if not getattr(config, "progressive_ban", True):
        return base
    level = max(int(strike_count) - 1, 0)
    factor = float(getattr(config, "ban_escalation", 2.0) or 2.0)
    cap = max(int(getattr(config, "max_ban_hours", 168) or 168), 1) * 60
    try:
        duration = base * (factor**level)
    except OverflowError:
        duration = cap
    return int(min(duration, cap))


# ---------------------------------------------------------------------------
# mutations
# ---------------------------------------------------------------------------
def _set_block_marker(ip: str, rule):
    ttl = None
    if not rule.is_permanent and rule.expires_at:
        ttl = max(int((rule.expires_at - timezone.now()).total_seconds()), 1)
    get_cache().set(f"bw:blk:{ip}", marker_payload(rule), ttl)


def block_ip(
    ip: str,
    reason: str,
    *,
    minutes: int | None = None,
    source: str = "auto",
    permanent: bool = False,
    strike_level: int | None = None,
    created_by=None,
    force: bool = False,
):
    """Create (or refresh) a block rule. Automatic rules are never permanent."""
    value = normalize_ip_value(ip)
    if not value:
        raise ValueError("A valid IP address or CIDR range is required")
    is_single = "/" not in value
    if permanent and source != "manual":
        permanent = False
    if not force and is_single and is_whitelisted(value):
        logger.info("botwall: refusing to block whitelisted IP %s", value)
        return None

    from .models import IPRule

    if permanent:
        expires_at = None
    else:
        minutes = int(minutes if minutes is not None else 30)
        expires_at = timezone.now() + timedelta(minutes=max(minutes, 1))

    strike_level = strikes(value) if strike_level is None else strike_level
    try:
        rule, _created = IPRule.objects.update_or_create(
            rule_type=IPRule.RULE_BLOCK,
            value=value,
            defaults={
                "source": source,
                "is_permanent": permanent,
                "is_active": True,
                "expires_at": expires_at,
                "reason": (reason or "")[:2000],
                "strike_level": max(int(strike_level or 0), 0),
                "created_by": created_by if source == "manual" else None,
            },
        )
    except Exception as exc:  # noqa: BLE001 - never break the request
        logger.error("botwall: could not persist block for %s: %s", value, exc)
        # Still apply an in-memory block marker so a single IP is stopped.
        if is_single:
            payload = {
                "reason": reason,
                "permanent": permanent,
                "source": source,
                "rule_id": None,
                "strike_level": strike_level,
                "expires_at": expires_at.isoformat() if expires_at else None,
            }
            ttl = (
                None
                if permanent
                else max(int((expires_at - timezone.now()).total_seconds()), 1)
            )
            get_cache().set(f"bw:blk:{value}", payload, ttl)
        invalidate_rules()
        return None

    if is_single:
        _set_block_marker(value, rule)
    invalidate_rules()
    logger.info(
        "botwall: blocked %s for %s (%s)",
        value,
        "permanently" if permanent else f"{minutes} minutes",
        reason,
    )
    return rule


def unblock_ip(ip: str):
    value = normalize_ip_value(ip)
    if not value:
        return False
    from .models import IPRule

    updated = IPRule.objects.filter(
        rule_type=IPRule.RULE_BLOCK, value=value, is_active=True
    ).update(is_active=False)
    get_cache().delete(f"bw:blk:{value}")
    invalidate_rules()
    return bool(updated)


def whitelist_ip(ip: str, reason: str = "", created_by=None):
    value = normalize_ip_value(ip)
    if not value:
        raise ValueError("A valid IP address or CIDR range is required")
    is_single = "/" not in value
    from .models import IPRule

    rule, _created = IPRule.objects.update_or_create(
        rule_type=IPRule.RULE_WHITELIST,
        value=value,
        defaults={
            "source": IPRule.SOURCE_MANUAL,
            "is_permanent": True,
            "is_active": True,
            "expires_at": None,
            "reason": (reason or "")[:2000],
            "created_by": created_by,
        },
    )
    # A whitelist entry must win immediately, even over a cached ban marker.
    IPRule.objects.filter(rule_type=IPRule.RULE_BLOCK, value=value).update(is_active=False)
    get_cache().delete(f"bw:blk:{value}")
    if is_single:
        get_cache().set(f"bw:wl:{value}", 1, 86400)
    invalidate_rules()
    logger.info("botwall: whitelisted %s (%s)", value, reason)
    return rule


def remove_rule(rule):
    """Delete a rule and clear every cache artefact attached to it."""
    ip = normalize_ip(rule.value)
    rule.delete()
    if ip:
        get_cache().delete(f"bw:blk:{ip}")
        get_cache().delete(f"bw:wl:{ip}")
    invalidate_rules()


def note_hit(block: RuleInfo):
    """Count blocked requests at most once per minute per IP."""
    ip = normalize_ip(block.value.split("/")[0] if block.value else "")
    if not ip or not get_cache().add(f"bw:hit:{ip}", 1, HIT_UPDATE_TTL):
        return
    if not block.id:
        return
    from django.db.models import F

    from .models import IPRule

    try:
        IPRule.objects.filter(pk=block.id).update(
            hit_count=F("hit_count") + 1, last_hit_at=timezone.now()
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("botwall: could not update hit counter: %s", exc)


def cleanup_expired(grace_days: int = 7, limit: int = 500) -> int:
    """Remove expired automatic rules (keeps a grace window for audit)."""
    from .models import IPRule

    cutoff = timezone.now() - timedelta(days=grace_days)
    try:
        stale = IPRule.objects.filter(
            source=IPRule.SOURCE_AUTO, expires_at__lt=cutoff
        )[:limit]
        ids = list(stale.values_list("id", flat=True))
        if not ids:
            return 0
        IPRule.objects.filter(id__in=ids).delete()
        invalidate_rules()
        return len(ids)
    except Exception as exc:  # noqa: BLE001
        logger.warning("botwall: expired rule cleanup failed: %s", exc)
        return 0
