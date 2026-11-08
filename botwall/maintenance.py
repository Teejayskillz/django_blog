"""Retention and maintenance helpers (used by the command and the middleware)."""

from __future__ import annotations

import logging
from datetime import timedelta

from django.utils import timezone

from . import blocking

logger = logging.getLogger("botwall.maintenance")

DEFAULT_MAX_ROWS = 250


def cleanup_retention(config, max_rows: int | None = None) -> dict:
    """Delete old security events and traffic aggregates (bounded work)."""
    from .models import SecurityEvent, TrafficStat

    max_rows = int(max_rows or getattr(config, "cleanup_max_rows", DEFAULT_MAX_ROWS) or DEFAULT_MAX_ROWS)
    max_rows = max(50, min(max_rows, 5000))
    now = timezone.now()
    result = {
        "events": 0,
        "stats": 0,
        "rules": 0,
    }

    event_days = int(getattr(config, "log_retention_days", 30) or 0)
    if event_days > 0:
        cutoff = now - timedelta(days=event_days)
        try:
            ids = list(
                SecurityEvent.objects.filter(created_at__lt=cutoff)
                .order_by("created_at")
                .values_list("id", flat=True)[:max_rows]
            )
            if ids:
                result["events"] = SecurityEvent.objects.filter(id__in=ids).delete()[0]
        except Exception as exc:  # noqa: BLE001
            logger.warning("botwall: event retention failed: %s", exc)

    stat_days = int(getattr(config, "stats_retention_days", 0) or 0)
    if stat_days > 0:
        cutoff = now - timedelta(days=stat_days)
        try:
            ids = list(
                TrafficStat.objects.filter(bucket_start__lt=cutoff)
                .order_by("bucket_start")
                .values_list("id", flat=True)[:max_rows]
            )
            if ids:
                result["stats"] = TrafficStat.objects.filter(id__in=ids).delete()[0]
        except Exception as exc:  # noqa: BLE001
            logger.warning("botwall: stats retention failed: %s", exc)

    try:
        result["rules"] = blocking.cleanup_expired(limit=max_rows)
    except Exception as exc:  # noqa: BLE001
        logger.warning("botwall: rule cleanup failed: %s", exc)
    return result
