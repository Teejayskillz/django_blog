"""Database models for the bot protection firewall.

The hot request path never writes these tables. Rows are created only for
security relevant events (blocks, challenges, rate-limit violations, ...) and
for hourly traffic aggregates written by a five-minute flush.
"""

from __future__ import annotations

import ipaddress

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from .defaults import DEFAULTS


class BotWallSettings(models.Model):
    """Singleton with every tunable runtime setting (editable in the admin)."""

    # --- master switches -----------------------------------------------------
    enabled = models.BooleanField(
        default=DEFAULTS["enabled"],
        help_text="Master switch for all request inspection, rate limiting, "
        "challenges and blocking. Disable to put the firewall in bypass mode.",
    )
    auto_block = models.BooleanField(
        default=DEFAULTS["auto_block"],
        help_text="Allow the firewall to create temporary automatic IP bans.",
    )
    challenge_enabled = models.BooleanField(
        default=DEFAULTS["challenge_enabled"],
        help_text="Serve the browser verification page to suspicious visitors.",
    )
    log_suspicious = models.BooleanField(
        default=DEFAULTS["log_suspicious"],
        help_text="Store suspicious requests in the security event log.",
    )
    log_verified_crawlers = models.BooleanField(
        default=DEFAULTS["log_verified_crawlers"],
        help_text="Also log requests from DNS-verified search engine crawlers.",
    )

    # --- rate limiting -------------------------------------------------------
    window_seconds = models.PositiveIntegerField(
        default=DEFAULTS["window_seconds"],
        help_text="Length of the main rate-limit window in seconds.",
    )
    browse_limit = models.PositiveIntegerField(
        default=DEFAULTS["browse_limit"],
        help_text="Maximum normal page requests per IP per window.",
    )
    burst_window_seconds = models.PositiveIntegerField(
        default=DEFAULTS["burst_window_seconds"],
        help_text="Short window used to detect request floods.",
    )
    burst_limit = models.PositiveIntegerField(
        default=DEFAULTS["burst_limit"],
        help_text="Maximum requests per IP inside the short burst window.",
    )
    sensitive_limit = models.PositiveIntegerField(
        default=DEFAULTS["sensitive_limit"],
        help_text="Stricter limit for sensitive endpoints (search, downloads, "
        "admin, comments, all non-GET requests).",
    )
    challenge_limit = models.PositiveIntegerField(
        default=DEFAULTS["challenge_limit"],
        help_text="Maximum verification page requests per IP per window.",
    )
    crawler_limit = models.PositiveIntegerField(
        default=DEFAULTS["crawler_limit"],
        help_text="Rate limit applied to verified search engine crawlers "
        "(kept generous so indexing is never harmed).",
    )
    verified_multiplier = models.FloatField(
        default=DEFAULTS["verified_multiplier"],
        help_text="Multiplier applied to limits for already-verified visitors.",
    )
    max_concurrent = models.PositiveIntegerField(
        default=DEFAULTS["max_concurrent"],
        help_text="Maximum simultaneous in-flight requests per IP "
        "(protection against concurrent floods).",
    )

    # --- detection thresholds ------------------------------------------------
    log_threshold = models.PositiveIntegerField(
        default=DEFAULTS["log_threshold"],
        help_text="Risk score at which a request is logged as suspicious.",
    )
    challenge_threshold = models.PositiveIntegerField(
        default=DEFAULTS["challenge_threshold"],
        help_text="Risk score at which the verification page is served.",
    )
    block_threshold = models.PositiveIntegerField(
        default=DEFAULTS["block_threshold"],
        help_text="Risk score at which an automatic temporary block is created. "
        "Automatic blocks are never permanent.",
    )
    require_multiple_signals = models.BooleanField(
        default=DEFAULTS["require_multiple_signals"],
        help_text="Require at least two independent detection signals before "
        "an automatic block. Strongly recommended.",
    )
    repeat_path_limit = models.PositiveIntegerField(
        default=DEFAULTS["repeat_path_limit"],
        help_text="Number of identical URL requests from one IP inside the "
        "main window before it counts as hammering.",
    )
    not_found_limit = models.PositiveIntegerField(
        default=DEFAULTS["not_found_limit"],
        help_text="Number of 404 responses from one IP inside the main window "
        "that indicates URL scanning.",
    )
    not_found_ratio = models.FloatField(
        default=DEFAULTS["not_found_ratio"],
        help_text="Minimum share of 404 responses (0-1) required for the "
        "not-found scanning signal.",
    )

    # --- blocking ------------------------------------------------------------
    temp_ban_minutes = models.PositiveIntegerField(
        default=DEFAULTS["temp_ban_minutes"],
        help_text="Base duration of an automatic temporary ban.",
    )
    progressive_ban = models.BooleanField(
        default=DEFAULTS["progressive_ban"],
        help_text="Increase the ban duration for repeat offenders.",
    )
    max_ban_hours = models.PositiveIntegerField(
        default=DEFAULTS["max_ban_hours"],
        help_text="Upper bound for an automatically escalated ban.",
    )
    ban_escalation = models.FloatField(
        default=DEFAULTS["ban_escalation"],
        help_text="Multiplier applied to the ban duration per repeat offence.",
    )
    violation_block_after = models.PositiveIntegerField(
        default=DEFAULTS["violation_block_after"],
        help_text="Number of rate-limit violations tolerated before a "
        "temporary ban is created.",
    )

    # --- challenge / verification -------------------------------------------
    challenge_difficulty = models.PositiveIntegerField(
        default=DEFAULTS["challenge_difficulty"],
        help_text="Proof-of-work difficulty in leading zero bits (8-24). "
        "16 is typically solved in well under a second.",
    )
    challenge_ttl = models.PositiveIntegerField(
        default=DEFAULTS["challenge_ttl"],
        help_text="Lifetime of a verification challenge in seconds.",
    )
    verification_ttl_hours = models.PositiveIntegerField(
        default=DEFAULTS["verification_ttl_hours"],
        help_text="How long a successful verification stays valid.",
    )
    verification_ip_binding = models.CharField(
        max_length=16,
        default=DEFAULTS["verification_ip_binding"],
        choices=[
            ("exact", "Exact IP address"),
            ("prefix", "Network prefix (/24 IPv4, /64 IPv6)"),
            ("none", "No IP binding"),
        ],
        help_text="How strictly the verification cookie is bound to the IP.",
    )
    verification_bind_ua = models.BooleanField(
        default=DEFAULTS["verification_bind_ua"],
        help_text="Bind the verification cookie to the User-Agent string.",
    )

    # --- crawler / SEO -------------------------------------------------------
    crawler_verification = models.BooleanField(
        default=DEFAULTS["crawler_verification"],
        help_text="Verify claimed search engine crawlers with reverse+forward "
        "DNS before trusting them.",
    )
    crawler_dns_ttl = models.PositiveIntegerField(
        default=DEFAULTS["crawler_dns_ttl"],
        help_text="How long a crawler DNS verification result is cached.",
    )
    crawler_fail_open = models.BooleanField(
        default=DEFAULTS["crawler_fail_open"],
        help_text="If DNS verification cannot run (timeout/error), allow the "
        "claimed crawler instead of challenging it. Recommended for SEO.",
    )
    challenge_unverified_crawler = models.BooleanField(
        default=DEFAULTS["challenge_unverified_crawler"],
        help_text="Challenge clients that claim to be a search engine but fail "
        "DNS verification (fake Googlebot).",
    )
    trusted_crawler_domains = models.TextField(
        blank=True,
        default=DEFAULTS["trusted_crawler_domains"],
        help_text="Optional overrides, one per line: ua-token: domain1, domain2",
    )
    extra_trusted_crawlers = models.TextField(
        blank=True,
        default=DEFAULTS["extra_trusted_crawlers"],
        help_text="Additional trusted crawlers, one per line: ua-token: domain1, domain2",
    )
    blocked_agents = models.TextField(
        blank=True,
        default=DEFAULTS["blocked_agents"],
        help_text="Extra malicious User-Agent substrings, one per line "
        "(case-insensitive).",
    )

    # --- paths ---------------------------------------------------------------
    exempt_paths = models.TextField(
        default=DEFAULTS["exempt_paths"],
        help_text="Path prefixes that are always allowed (one per line). "
        "robots.txt, sitemaps and Search Console verification live here.",
    )
    sensitive_paths = models.TextField(
        default=DEFAULTS["sensitive_paths"],
        help_text="Regular expressions for stricter rate limits (one per line).",
    )
    blocked_networks = models.TextField(
        blank=True,
        default=DEFAULTS["blocked_networks"],
        help_text="Manually blocked CIDR ranges, one per line. Permanent.",
    )

    # --- logging / retention -------------------------------------------------
    log_retention_days = models.PositiveIntegerField(
        default=DEFAULTS["log_retention_days"],
        help_text="Security events older than this are deleted automatically.",
    )
    stats_retention_days = models.PositiveIntegerField(
        default=DEFAULTS["stats_retention_days"],
        help_text="Hourly traffic aggregates older than this are deleted.",
    )
    cleanup_enabled = models.BooleanField(
        default=DEFAULTS["cleanup_enabled"],
        help_text="Run a small opportunistic cleanup from the web process.",
    )
    cleanup_max_rows = models.PositiveIntegerField(
        default=DEFAULTS["cleanup_max_rows"],
        help_text="Maximum rows removed per opportunistic cleanup run.",
    )
    cleanup_interval_hours = models.PositiveIntegerField(
        default=DEFAULTS["cleanup_interval_hours"],
        help_text="Minimum time between opportunistic cleanups.",
    )
    event_log_cap = models.PositiveIntegerField(
        default=DEFAULTS["event_log_cap"],
        help_text="Maximum security events stored per IP per minute "
        "(protects the database during an attack).",
    )

    # --- traffic spike handling ---------------------------------------------
    spike_enabled = models.BooleanField(
        default=DEFAULTS["spike_enabled"],
        help_text="Detect abnormal traffic spikes and tighten limits temporarily.",
    )
    spike_multiplier = models.FloatField(
        default=DEFAULTS["spike_multiplier"],
        help_text="Traffic must exceed the recent average by this factor to "
        "activate attack mode.",
    )
    spike_min_requests = models.PositiveIntegerField(
        default=DEFAULTS["spike_min_requests"],
        help_text="Minimum requests per minute before attack mode can trigger.",
    )
    attack_limit_factor = models.FloatField(
        default=DEFAULTS["attack_limit_factor"],
        help_text="Rate limits are multiplied by this factor while attack mode "
        "is active (0.5 halves them).",
    )

    # --- stats / geolocation -------------------------------------------------
    unique_tracking = models.BooleanField(
        default=DEFAULTS["unique_tracking"],
        help_text="Estimate unique IPs for the dashboard. Disable to save one "
        "cache operation per request.",
    )
    geo_enabled = models.BooleanField(
        default=DEFAULTS["geo_enabled"],
        help_text="Resolve visitor country codes (requires a MaxMind database "
        "or trusted Cloudflare country headers).",
    )
    trust_cf_country = models.BooleanField(
        default=DEFAULTS["trust_cf_country"],
        help_text="Accept the Cloudflare CF-IPCountry header (only honoured "
        "when the request comes from a trusted proxy).",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Bot protection settings"
        verbose_name_plural = "Bot protection settings"

    def __str__(self):
        return "Bot protection settings"

    def save(self, *args, **kwargs):
        self.pk = 1
        super().save(*args, **kwargs)

    @classmethod
    def load(cls):
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj


class IPRule(models.Model):
    """Whitelist entry, manual ban or automatic temporary ban."""

    RULE_BLOCK = "block"
    RULE_WHITELIST = "whitelist"
    RULE_CHOICES = [
        (RULE_BLOCK, "Block"),
        (RULE_WHITELIST, "Whitelist"),
    ]

    SOURCE_AUTO = "auto"
    SOURCE_MANUAL = "manual"
    SOURCE_CHOICES = [
        (SOURCE_AUTO, "Automatic"),
        (SOURCE_MANUAL, "Manual"),
    ]

    value = models.CharField(
        max_length=64,
        help_text="A single IP address or a CIDR range (e.g. 203.0.113.0/24).",
    )
    rule_type = models.CharField(max_length=16, choices=RULE_CHOICES, default=RULE_BLOCK)
    source = models.CharField(max_length=16, choices=SOURCE_CHOICES, default=SOURCE_MANUAL)
    is_permanent = models.BooleanField(
        default=False,
        help_text="Permanent bans are only allowed for manual rules.",
    )
    is_active = models.BooleanField(default=True)
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Empty for permanent bans; required for temporary bans.",
    )
    reason = models.TextField(blank=True)
    strike_level = models.PositiveSmallIntegerField(
        default=0,
        help_text="How many times this address has offended.",
    )
    hit_count = models.PositiveIntegerField(default=0)
    last_hit_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="botwall_rules",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "IP rule"
        verbose_name_plural = "IP rules"
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["rule_type", "value"], name="botwall_unique_rule"
            )
        ]
        indexes = [
            models.Index(fields=["rule_type", "is_active"]),
            models.Index(fields=["expires_at"]),
        ]

    def __str__(self):
        suffix = " (permanent)" if self.is_permanent else ""
        return f"{self.get_rule_type_display()}: {self.value}{suffix}"

    # -- helpers --------------------------------------------------------------
    @property
    def is_expired(self) -> bool:
        return bool(self.expires_at and self.expires_at <= timezone.now())

    @property
    def is_effective(self) -> bool:
        return self.is_active and not self.is_expired

    @property
    def network(self):
        try:
            return ipaddress.ip_network(self.value.strip(), strict=False)
        except ValueError:
            return None

    def clean(self):
        value = (self.value or "").strip()
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise ValidationError({"value": "Enter a valid IP address or CIDR range."})

        if self.rule_type == self.RULE_WHITELIST and self.is_permanent:
            # Whitelists are always effectively permanent; keep the flag honest.
            self.is_permanent = True

        if self.source == self.SOURCE_AUTO:
            if self.is_permanent:
                raise ValidationError(
                    {"is_permanent": "Automatic rules can never be permanent."}
                )
            if not self.expires_at:
                raise ValidationError(
                    {"expires_at": "Automatic rules require an expiry date."}
                )

        if self.is_permanent and self.expires_at:
            raise ValidationError(
                {"expires_at": "A permanent rule cannot have an expiry date."}
            )
        if self.is_active and not self.is_permanent and not self.expires_at:
            raise ValidationError(
                {"expires_at": "Temporary rules require an expiry date."}
            )

    def save(self, *args, **kwargs):
        self.value = (self.value or "").strip()
        if self.source == self.SOURCE_AUTO:
            self.is_permanent = False
        super().save(*args, **kwargs)


class SecurityEvent(models.Model):
    """Structured log entry for one security relevant request."""

    # Detection families
    CAT_UA = "ua"
    CAT_RATE_LIMIT = "rate_limit"
    CAT_BURST = "burst"
    CAT_PATH_SCAN = "path_scan"
    CAT_NOT_FOUND = "not_found"
    CAT_REPEAT = "repeat"
    CAT_CRAWLER = "crawler"
    CAT_BLOCKLIST = "blocklist"
    CAT_CONCURRENCY = "concurrency"
    CAT_CHALLENGE = "challenge"
    CAT_METHOD = "method"
    CAT_HEADER = "header"
    CAT_MANUAL = "manual"
    CATEGORY_CHOICES = [
        (CAT_UA, "User-Agent analysis"),
        (CAT_RATE_LIMIT, "Rate limit"),
        (CAT_BURST, "Request burst"),
        (CAT_PATH_SCAN, "Suspicious URL"),
        (CAT_NOT_FOUND, "404 scanning"),
        (CAT_REPEAT, "Repeated page requests"),
        (CAT_CRAWLER, "Crawler verification"),
        (CAT_BLOCKLIST, "Known malicious source"),
        (CAT_CONCURRENCY, "Concurrent requests"),
        (CAT_CHALLENGE, "Challenge / verification"),
        (CAT_METHOD, "Unusual HTTP method"),
        (CAT_HEADER, "Header anomaly"),
        (CAT_MANUAL, "Manual action"),
    ]

    ACTION_ALLOWED = "allowed"
    ACTION_LOGGED = "logged"
    ACTION_CHALLENGED = "challenged"
    ACTION_BLOCKED = "blocked"
    ACTION_RATE_LIMITED = "rate_limited"
    ACTION_VERIFIED = "verified"
    ACTION_CHOICES = [
        (ACTION_ALLOWED, "Allowed"),
        (ACTION_LOGGED, "Logged only"),
        (ACTION_CHALLENGED, "Challenge served"),
        (ACTION_BLOCKED, "Blocked"),
        (ACTION_RATE_LIMITED, "Rate limited"),
        (ACTION_VERIFIED, "Verified / allowed"),
    ]

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    ip = models.GenericIPAddressField(db_index=True)
    method = models.CharField(max_length=10, default="GET")
    path = models.CharField(max_length=500)
    query_string = models.CharField(max_length=500, blank=True)
    status_code = models.PositiveSmallIntegerField(null=True, blank=True)
    user_agent = models.CharField(max_length=500, blank=True)
    referer = models.CharField(max_length=500, blank=True)

    category = models.CharField(max_length=32, choices=CATEGORY_CHOICES, db_index=True)
    action = models.CharField(max_length=16, choices=ACTION_CHOICES, db_index=True)
    score = models.PositiveSmallIntegerField(default=0)
    reasons = models.TextField(blank=True, help_text="JSON list of detection reasons.")
    request_count = models.PositiveIntegerField(default=0)

    bot_name = models.CharField(max_length=64, blank=True)
    is_verified_bot = models.BooleanField(default=False)
    country = models.CharField(max_length=2, blank=True)
    request_id = models.CharField(max_length=32, blank=True, db_index=True)
    block_expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "Security event"
        verbose_name_plural = "Security events"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["created_at", "category"]),
            models.Index(fields=["ip", "created_at"]),
            models.Index(fields=["action", "created_at"]),
        ]

    def __str__(self):
        return f"{self.created_at:%Y-%m-%d %H:%M:%S} {self.ip} {self.action} {self.path}"

    # -- reason helpers -------------------------------------------------------
    def get_reasons(self):
        import json

        try:
            data = json.loads(self.reasons or "[]")
        except (TypeError, ValueError):
            return []
        return data if isinstance(data, list) else []

    def set_reasons(self, values):
        import json

        self.reasons = json.dumps(list(values or []), separators=(",", ":"))

    @property
    def reasons_display(self):
        return ", ".join(str(item) for item in self.get_reasons())


class TrafficStat(models.Model):
    """Hourly aggregated traffic counters (small, index friendly)."""

    bucket_start = models.DateTimeField(db_index=True, unique=True)
    requests = models.PositiveIntegerField(default=0)
    suspicious = models.PositiveIntegerField(default=0)
    blocked = models.PositiveIntegerField(default=0)
    rate_limited = models.PositiveIntegerField(default=0)
    challenges = models.PositiveIntegerField(default=0)
    unique_ips = models.PositiveIntegerField(default=0)

    class Meta:
        verbose_name = "Traffic statistic"
        verbose_name_plural = "Traffic statistics"
        ordering = ["-bucket_start"]

    def __str__(self):
        return f"{self.bucket_start:%Y-%m-%d %H:00} requests={self.requests}"
