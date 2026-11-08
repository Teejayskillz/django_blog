"""Django admin integration: settings, IP rules, event log and stats."""

from __future__ import annotations

import csv
import logging

from django import forms
from django.contrib import admin, messages
from django.db.models import Q
from django.http import HttpResponse
from django.shortcuts import redirect
from django.urls import reverse
from django.utils import timezone
from django.utils.html import format_html

from . import blocking, conf
from .models import BotWallSettings, IPRule, SecurityEvent, TrafficStat

logger = logging.getLogger("botwall.admin")


class BotWallSettingsForm(forms.ModelForm):
    class Meta:
        model = BotWallSettings
        fields = "__all__"

    def clean(self):
        cleaned = super().clean()
        browse = cleaned.get("browse_limit")
        sensitive = cleaned.get("sensitive_limit")
        if browse and sensitive and sensitive > browse:
            self.add_error(
                "sensitive_limit",
                "The sensitive-endpoint limit is usually lower than the normal browse limit.",
            )
        challenge = cleaned.get("challenge_threshold")
        block = cleaned.get("block_threshold")
        if challenge and block and challenge >= block:
            self.add_error(
                "block_threshold",
                "The block threshold must be higher than the challenge threshold.",
            )
        difficulty = cleaned.get("challenge_difficulty")
        if difficulty is not None and not (8 <= int(difficulty) <= 24):
            self.add_error(
                "challenge_difficulty",
                "Use a difficulty between 8 and 24 bits (16 is a good default).",
            )
        for field in ("exempt_paths", "sensitive_paths"):
            value = cleaned.get(field) or ""
            for line in value.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if field == "sensitive_paths":
                    import re

                    try:
                        re.compile(line)
                    except re.error as exc:
                        self.add_error(field, f"Invalid regular expression {line!r}: {exc}")
        return cleaned


@admin.register(BotWallSettings)
class BotWallSettingsAdmin(admin.ModelAdmin):
    form = BotWallSettingsForm
    list_display = ("__str__", "enabled", "auto_block", "challenge_enabled", "updated_at")
    readonly_fields = ("updated_at", "created_at", "dashboard_link", "cache_status")

    fieldsets = (
        (
            "Master switches",
            {
                "fields": (
                    "enabled",
                    "auto_block",
                    "challenge_enabled",
                    "log_suspicious",
                    "log_verified_crawlers",
                    "dashboard_link",
                    "cache_status",
                )
            },
        ),
        (
            "Rate limiting",
            {
                "fields": (
                    "window_seconds",
                    "browse_limit",
                    "burst_window_seconds",
                    "burst_limit",
                    "sensitive_limit",
                    "challenge_limit",
                    "crawler_limit",
                    "verified_multiplier",
                    "max_concurrent",
                )
            },
        ),
        (
            "Detection thresholds",
            {
                "fields": (
                    "log_threshold",
                    "challenge_threshold",
                    "block_threshold",
                    "require_multiple_signals",
                    "repeat_path_limit",
                    "not_found_limit",
                    "not_found_ratio",
                )
            },
        ),
        (
            "Automatic blocking",
            {
                "fields": (
                    "temp_ban_minutes",
                    "progressive_ban",
                    "ban_escalation",
                    "max_ban_hours",
                    "violation_block_after",
                )
            },
        ),
        (
            "Browser verification",
            {
                "fields": (
                    "challenge_difficulty",
                    "challenge_ttl",
                    "verification_ttl_hours",
                    "verification_ip_binding",
                    "verification_bind_ua",
                )
            },
        ),
        (
            "Search engine crawlers (SEO)",
            {
                "fields": (
                    "crawler_verification",
                    "crawler_dns_ttl",
                    "crawler_fail_open",
                    "challenge_unverified_crawler",
                    "trusted_crawler_domains",
                    "extra_trusted_crawlers",
                    "blocked_agents",
                )
            },
        ),
        (
            "Paths",
            {
                "fields": ("exempt_paths", "sensitive_paths", "blocked_networks"),
                "description": "One entry per line. Exempt paths are never challenged or blocked, "
                "which keeps robots.txt, sitemaps and search-console verification reachable.",
            },
        ),
        (
            "Logging and retention",
            {
                "fields": (
                    "log_retention_days",
                    "stats_retention_days",
                    "cleanup_enabled",
                    "cleanup_interval_hours",
                    "cleanup_max_rows",
                    "event_log_cap",
                )
            },
        ),
        (
            "Traffic spikes and geolocation",
            {
                "fields": (
                    "spike_enabled",
                    "spike_multiplier",
                    "spike_min_requests",
                    "attack_limit_factor",
                    "unique_tracking",
                    "geo_enabled",
                    "trust_cf_country",
                )
            },
        ),
        ("Timestamps", {"fields": ("created_at", "updated_at"), "classes": ("collapse",)}),
    )

    def has_add_permission(self, request):
        return not BotWallSettings.objects.exists()

    def has_delete_permission(self, request, obj=None):
        return False

    def changelist_view(self, request, extra_context=None):
        obj = BotWallSettings.load()
        url = reverse("admin:botwall_botwallsettings_change", args=[obj.pk])
        return redirect(url)

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        conf.invalidate_config()
        messages.success(request, "Bot protection settings saved.")

    @admin.display(description="Security dashboard")
    def dashboard_link(self, obj=None):
        url = reverse("botwall:dashboard")
        return format_html('<a class="button" href="{}">Open the security dashboard</a>', url)

    @admin.display(description="Cache backend")
    def cache_status(self, obj=None):
        from .cache import get_cache

        health = get_cache().health()
        state = "OK" if health["reachable"] else "UNREACHABLE"
        return format_html(
            "<code>{}</code> ({}) &middot; fallback <code>{}</code>",
            health["primary_backend"],
            state,
            health["fallback_backend"],
        )


@admin.register(IPRule)
class IPRuleAdmin(admin.ModelAdmin):
    list_display = (
        "value",
        "rule_type",
        "source",
        "state",
        "strike_level",
        "hit_count",
        "reason_short",
        "created_at",
    )
    list_filter = ("rule_type", "source", "is_active", "is_permanent")
    search_fields = ("value", "reason")
    readonly_fields = ("created_at", "updated_at", "hit_count", "last_hit_at")
    date_hierarchy = "created_at"
    actions = (
        "action_block_1h",
        "action_block_24h",
        "action_block_permanent",
        "action_whitelist",
        "action_unblock",
    )
    fieldsets = (
        (
            None,
            {
                "fields": (
                    "value",
                    "rule_type",
                    "source",
                    "is_active",
                    "is_permanent",
                    "expires_at",
                    "reason",
                )
            },
        ),
        (
            "Statistics",
            {"fields": ("strike_level", "hit_count", "last_hit_at", "created_at", "updated_at")},
        ),
    )

    @admin.display(description="State")
    def state(self, obj):
        if not obj.is_active:
            return format_html('<span style="color:#888;">inactive</span>')
        if obj.is_expired:
            return format_html('<span style="color:#a86600;">expired</span>')
        if obj.is_permanent:
            return format_html('<b style="color:#b3261e;">permanent</b>')
        return format_html(
            '<span style="color:#0b6bcb;">until {}</span>',
            obj.expires_at.strftime("%Y-%m-%d %H:%M") if obj.expires_at else "-",
        )

    @admin.display(description="Reason")
    def reason_short(self, obj):
        return (obj.reason or "")[:70]

    def _apply_block(self, request, queryset, minutes=None, permanent=False):
        created = 0
        for rule in queryset:
            ip = blocking.normalize_ip_value(rule.value)
            if not ip:
                continue
            try:
                blocking.block_ip(
                    ip,
                    f"Manual action in the Django admin (rule #{rule.pk})",
                    minutes=minutes or 60,
                    source="manual",
                    permanent=permanent,
                    created_by=request.user,
                    force=True,
                )
                created += 1
            except ValueError:
                continue
        messages.success(request, f"{created} rule(s) converted into block(s).")

    @admin.action(description="Block these IPs for 1 hour")
    def action_block_1h(self, request, queryset):
        self._apply_block(request, queryset, minutes=60)

    @admin.action(description="Block these IPs for 24 hours")
    def action_block_24h(self, request, queryset):
        self._apply_block(request, queryset, minutes=1440)

    @admin.action(description="Permanently block these IPs (manual only)")
    def action_block_permanent(self, request, queryset):
        self._apply_block(request, queryset, permanent=True)

    @admin.action(description="Whitelist these IPs")
    def action_whitelist(self, request, queryset):
        count = 0
        for rule in queryset:
            ip = blocking.normalize_ip_value(rule.value)
            if not ip:
                continue
            try:
                blocking.whitelist_ip(ip, "Whitelisted from the Django admin", request.user)
                count += 1
            except ValueError:
                continue
        messages.success(request, f"{count} address(es) whitelisted.")

    @admin.action(description="Unblock / deactivate these rules")
    def action_unblock(self, request, queryset):
        count = 0
        for rule in queryset:
            ip = blocking.normalize_ip_value(rule.value)
            if ip:
                blocking.unblock_ip(ip)
                count += 1
        messages.success(request, f"{count} rule(s) deactivated.")


@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = (
        "created_at",
        "ip",
        "action_badge",
        "category",
        "method",
        "path_short",
        "score",
        "request_count",
        "bot_name",
    )
    list_filter = ("category", "action", "method", "created_at")
    search_fields = ("ip", "path", "user_agent", "reasons", "request_id")
    date_hierarchy = "created_at"
    list_per_page = 100
    actions = (
        "action_block_1h",
        "action_block_24h",
        "action_block_permanent",
        "action_whitelist",
        "action_export_csv",
    )
    readonly_fields = tuple(field.name for field in SecurityEvent._meta.fields)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    @admin.display(description="Action")
    def action_badge(self, obj):
        colors = {
            SecurityEvent.ACTION_BLOCKED: "#b3261e",
            SecurityEvent.ACTION_RATE_LIMITED: "#a86600",
            SecurityEvent.ACTION_CHALLENGED: "#a86600",
            SecurityEvent.ACTION_ALLOWED: "#137a4b",
            SecurityEvent.ACTION_VERIFIED: "#137a4b",
        }
        color = colors.get(obj.action, "#415063")
        return format_html(
            '<b style="color:{};">{}</b>', color, obj.get_action_display()
        )

    @admin.display(description="Path")
    def path_short(self, obj):
        return (obj.path or "")[:70]

    def _block(self, request, queryset, minutes=None, permanent=False):
        ips = {obj.ip for obj in queryset if obj.ip}
        count = 0
        for ip in ips:
            try:
                blocking.block_ip(
                    ip,
                    f"Manual action from the security event log ({len(ips)} address(es))",
                    minutes=minutes or 60,
                    source="manual",
                    permanent=permanent,
                    created_by=request.user,
                    force=True,
                )
                count += 1
            except ValueError:
                continue
        messages.success(request, f"{count} IP address(es) blocked.")

    @admin.action(description="Block the IPs of these events for 1 hour")
    def action_block_1h(self, request, queryset):
        self._block(request, queryset, minutes=60)

    @admin.action(description="Block the IPs of these events for 24 hours")
    def action_block_24h(self, request, queryset):
        self._block(request, queryset, minutes=1440)

    @admin.action(description="Permanently block the IPs of these events")
    def action_block_permanent(self, request, queryset):
        self._block(request, queryset, permanent=True)

    @admin.action(description="Whitelist the IPs of these events")
    def action_whitelist(self, request, queryset):
        ips = {obj.ip for obj in queryset if obj.ip}
        for ip in ips:
            try:
                blocking.whitelist_ip(ip, "Whitelisted from the security event log", request.user)
            except ValueError:
                continue
        messages.success(request, f"{len(ips)} address(es) whitelisted.")

    @admin.action(description="Export selected events as CSV")
    def action_export_csv(self, request, queryset):
        response = HttpResponse(content_type="text/csv")
        stamp = timezone.now().strftime("%Y%m%d-%H%M%S")
        response["Content-Disposition"] = f'attachment; filename="botwall-events-{stamp}.csv"'
        writer = csv.writer(response)
        writer.writerow(
            [
                "created_at",
                "ip",
                "method",
                "path",
                "query_string",
                "status_code",
                "category",
                "action",
                "score",
                "request_count",
                "bot_name",
                "verified_bot",
                "country",
                "user_agent",
                "reasons",
            ]
        )
        for event in queryset.iterator(chunk_size=500):
            writer.writerow(
                [
                    event.created_at.isoformat() if event.created_at else "",
                    event.ip,
                    event.method,
                    event.path,
                    event.query_string,
                    event.status_code or "",
                    event.category,
                    event.action,
                    event.score,
                    event.request_count,
                    event.bot_name,
                    "yes" if event.is_verified_bot else "no",
                    event.country,
                    event.user_agent,
                    event.reasons,
                ]
            )
        return response


@admin.register(TrafficStat)
class TrafficStatAdmin(admin.ModelAdmin):
    list_display = (
        "bucket_start",
        "requests",
        "suspicious",
        "blocked",
        "rate_limited",
        "challenges",
        "unique_ips",
    )
    list_filter = ("bucket_start",)
    date_hierarchy = "bucket_start"
    ordering = ("-bucket_start",)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


def annotate_dashboard_link():
    """Small helper used by deployment checks (kept for backwards compatibility)."""
    return reverse("botwall:dashboard")
