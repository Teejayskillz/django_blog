"""Views: verification endpoint, administrator dashboard and quick actions."""

from __future__ import annotations

import json
import logging
from datetime import timedelta

from django.conf import settings
from django.contrib import messages
from django.contrib.admin.views.decorators import staff_member_required
from django.db.models import Count, Max
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from . import blocking, challenge, conf, ratelimit, stats
from .cache import get_cache
from .ip import get_client_ip
from .models import IPRule, SecurityEvent, TrafficStat

logger = logging.getLogger("botwall.views")

RANGE_CHOICES = (
    (1, "1 hour"),
    (6, "6 hours"),
    (24, "24 hours"),
    (168, "7 days"),
)


def _safe_next(value: str, request) -> str:
    if not value or not isinstance(value, str):
        return "/"
    if not value.startswith("/") or value.startswith("//"):
        return "/"
    if url_has_allowed_host_and_scheme(
        value, allowed_hosts={request.get_host()}, require_https=False
    ):
        return value[:500]
    return "/"


def _json_body(request) -> dict:
    try:
        if request.content_type and "json" in request.content_type:
            payload = json.loads(request.body.decode("utf-8") or "{}")
            return payload if isinstance(payload, dict) else {}
    except (ValueError, UnicodeDecodeError):
        return {}
    return request.POST.dict()


@csrf_exempt
@require_POST
def challenge_verify(request):
    """Validate a proof-of-work submission and set the verification cookie.

    CSRF exempt by design: the endpoint is authenticated by a signed,
    single-use, IP/UA-bound token that is only issued on the challenge page,
    and it changes no server-side state besides the visitor's own cookie.
    """
    config = conf.get_config()
    client = get_client_ip(request)
    user_agent = (request.META.get("HTTP_USER_AGENT") or "")[:1024]
    payload = _json_body(request)

    verdict = ratelimit.check(
        client.limit_key,
        "challenge",
        int(config.challenge_limit or 0),
        max(int(config.window_seconds or 60), 1),
    )
    if verdict.exceeded:
        return JsonResponse(
            {"ok": False, "reason": "rate_limited"},
            status=429,
            headers={"Retry-After": str(verdict.retry_after)},
        )

    token = payload.get("token") or ""
    proof = payload.get("proof")
    if not token:
        return JsonResponse({"ok": False, "reason": "missing_token"}, status=400)

    result = challenge.verify_submission(token, proof, client.address, user_agent, config)
    if not result.ok:
        _log_verification_failure(request, client, user_agent, result.reason)
        return JsonResponse({"ok": False, "reason": result.reason}, status=400)

    name, value, max_age = challenge.issue_cookie(client.address, user_agent, config)
    next_url = _safe_next(payload.get("next") or "", request)
    response = JsonResponse({"ok": True, "next": next_url})
    response.set_cookie(
        name,
        value,
        max_age=max_age,
        httponly=True,
        secure=request.is_secure(),
        samesite="Lax",
        path="/",
    )
    logger.info("botwall: visitor %s verified successfully", client.address)
    return response


def _log_verification_failure(request, client, user_agent, reason):
    config = conf.get_config()
    if not config.log_suspicious:
        return
    try:
        event = SecurityEvent(
            ip=client.address,
            method=request.method[:10],
            path=request.path[:500],
            user_agent=user_agent[:500],
            category=SecurityEvent.CAT_CHALLENGE,
            action=SecurityEvent.ACTION_LOGGED,
            request_count=ratelimit.violations(client.limit_key),
            country="",
        )
        event.set_reasons([f"challenge_failed:{reason}"])
        event.save()
    except Exception as exc:  # noqa: BLE001
        logger.debug("botwall: could not log verification failure: %s", exc)


def challenge_info(request):
    """Direct visits to the challenge URL simply go home."""
    return redirect("/")


# ---------------------------------------------------------------------------
# dashboard
# ---------------------------------------------------------------------------
@staff_member_required
def dashboard(request):
    config = conf.get_config()
    try:
        hours = int(request.GET.get("hours") or 24)
    except (TypeError, ValueError):
        hours = 24
    valid = [choice[0] for choice in RANGE_CHOICES]
    if hours not in valid:
        hours = 24

    now = timezone.now()
    start = now - timedelta(hours=hours)
    events = SecurityEvent.objects.filter(created_at__gte=start)

    series = stats.hourly_series(hours=24)
    max_requests = max([row["requests"] for row in series] + [1])
    for row in series:
        row["percent"] = round((row["requests"] / max_requests) * 100, 1)
        row["blocked_percent"] = round(
            (row["blocked"] / max(row["requests"], 1)) * 100, 1
        )

    minute_data = stats.read_minutes(kinds=("req",), minutes=60)["req"]
    minute_values = [minute_data.get(minute, 0) for minute in sorted(minute_data)]
    if not minute_values:
        minute_values = [0]
    spark_max = max(minute_values + [1])
    points = []
    total_points = max(len(minute_values) - 1, 1)
    for index, value in enumerate(minute_values):
        x = round(index / total_points * 600, 1)
        y = round(60 - (value / spark_max) * 60, 1)
        points.append(f"{x},{y}")

    totals = stats.totals(hours=hours)
    live = stats.window_totals(minutes=60)
    cache = get_cache()

    top_ips = list(
        events.values("ip")
        .annotate(count=Count("id"), last=Max("created_at"))
        .order_by("-count")[:10]
    )
    top_paths = list(
        events.values("path").annotate(count=Count("id")).order_by("-count")[:10]
    )
    top_agents = list(
        events.exclude(user_agent="")
        .values("user_agent", "bot_name")
        .annotate(count=Count("id"))
        .order_by("-count")[:10]
    )
    countries = list(
        events.exclude(country="")
        .values("country")
        .annotate(count=Count("id"))
        .order_by("-count")[:10]
    )
    category_counts = list(
        events.values("category").annotate(count=Count("id")).order_by("-count")
    )
    action_counts = list(
        events.values("action").annotate(count=Count("id")).order_by("-count")
    )
    category_labels = dict(SecurityEvent.CATEGORY_CHOICES)
    action_labels = dict(SecurityEvent.ACTION_CHOICES)
    for row in category_counts:
        row["label"] = category_labels.get(row["category"], row["category"])
    for row in action_counts:
        row["label"] = action_labels.get(row["action"], row["action"])

    active_blocks = list(
        IPRule.objects.filter(rule_type=IPRule.RULE_BLOCK, is_active=True)
        .filter(models_expired())
        .order_by("-created_at")[:20]
    )

    context = {
        "config": config,
        "protection_enabled": bool(
            getattr(settings, "BOTWALL_ENABLED", True) and config.enabled
        ),
        "attack_mode": stats.attack_mode(config),
        "generated_at": now,
        "hours": hours,
        "range_choices": RANGE_CHOICES,
        "totals": totals,
        "live": live,
        "rpm": stats.requests_per_minute(5),
        "series": series,
        "max_requests": max_requests,
        "spark_points": " ".join(points),
        "spark_max": spark_max,
        "top_ips": top_ips,
        "top_paths": top_paths,
        "top_agents": top_agents,
        "countries": countries,
        "category_counts": category_counts,
        "action_counts": action_counts,
        "recent_events": list(events[:40]),
        "active_blocks": active_blocks,
        "blocked_total": IPRule.objects.filter(
            rule_type=IPRule.RULE_BLOCK, is_active=True
        ).count(),
        "whitelist_total": IPRule.objects.filter(
            rule_type=IPRule.RULE_WHITELIST, is_active=True
        ).count(),
        "cache_health": cache.health(),
        "settings_url": reverse("admin:botwall_botwallsettings_changelist"),
        "rules_url": reverse("admin:botwall_iprule_changelist"),
        "events_url": reverse("admin:botwall_securityevent_changelist"),
        "stats_url": reverse("admin:botwall_trafficstat_changelist"),
    }
    return render(request, "botwall/dashboard.html", context)


def models_expired():
    from django.db.models import Q

    return Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now())


# ---------------------------------------------------------------------------
# quick actions
# ---------------------------------------------------------------------------
def _action_target(request):
    ip = (request.POST.get("ip") or "").strip()
    return ip


@require_POST
@staff_member_required
def ban_ip(request):
    ip = _action_target(request)
    permanent = request.POST.get("permanent") == "1"
    minutes = request.POST.get("minutes") or "60"
    try:
        minutes = int(minutes)
    except (TypeError, ValueError):
        minutes = 60
    reason = (request.POST.get("reason") or "Manual ban from the security dashboard")[:2000]
    try:
        blocking.block_ip(
            ip,
            reason,
            minutes=minutes,
            source="manual",
            permanent=permanent,
            created_by=request.user,
            force=True,
        )
        messages.success(request, f"{ip} has been {'permanently ' if permanent else ''}blocked.")
    except ValueError as exc:
        messages.error(request, str(exc))
    except Exception as exc:  # noqa: BLE001
        logger.exception("botwall: manual ban failed")
        messages.error(request, f"Could not block {ip}: {exc}")
    return redirect(reverse("botwall:dashboard"))


@require_POST
@staff_member_required
def unban_ip(request):
    ip = _action_target(request)
    if blocking.unblock_ip(ip):
        messages.success(request, f"{ip} has been unblocked.")
    else:
        messages.info(request, f"No active block found for {ip}.")
    return redirect(reverse("botwall:dashboard"))


@require_POST
@staff_member_required
def whitelist_ip(request):
    ip = _action_target(request)
    reason = (request.POST.get("reason") or "Whitelisted from the security dashboard")[:2000]
    try:
        blocking.whitelist_ip(ip, reason, created_by=request.user)
        messages.success(request, f"{ip} is now whitelisted.")
    except ValueError as exc:
        messages.error(request, str(exc))
    return redirect(reverse("botwall:dashboard"))


@staff_member_required
def traffic_series(request):
    """Small JSON API used by the dashboard (kept for future charts)."""
    hours = 24
    return JsonResponse(
        {
            "series": [
                {
                    "hour": row["hour"].isoformat(),
                    "requests": row["requests"],
                    "blocked": row["blocked"],
                }
                for row in stats.hourly_series(hours=hours)
            ]
        }
    )
