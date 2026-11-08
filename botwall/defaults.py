"""Code-level defaults for the bot protection firewall.

These values are used:

* as ``default=`` for the :class:`botwall.models.BotWallSettings` fields,
* as the emergency configuration when the settings table cannot be read
  (missing migration, database outage, management command bootstrap).

Administrators tune the live values from the Django admin; the values below
are only the starting point.
"""

# NOTE: keep keys in sync with ``BotWallSettings`` fields (test_config_defaults
# enforces this).

DEFAULT_EXEMPT_PATHS = "\n".join(
    [
        "# Paths that never receive challenges or automatic blocks.",
        "/admin/",
        "/botwall/",
        "/static/",
        "/media/",
        "/robots.txt",
        "/sitemap",
        "/favicon.ico",
        "/ads.txt",
        "/.well-known/",
        # Google Search Console / Bing verification files at the site root.
        r"^/google[a-z0-9]+\.html$",
        r"^/BingSiteAuth\.xml$",
        r"^/yandex_[a-z0-9]+\.html$",
    ]
)

DEFAULT_SENSITIVE_PATHS = "\n".join(
    [
        "# Regular expressions. Requests matching these get the stricter limit.",
        r"^/admin/",
        r"^/search/",
        r"^/download/",
        r"^/ads/",
        r"^/accounts/",
        r"^/login",
        r"^/logout",
        r"^/comments?",
    ]
)

DEFAULTS = {
    # --- master switches -----------------------------------------------------
    "enabled": True,
    "auto_block": True,
    "challenge_enabled": True,
    "log_suspicious": True,
    "log_verified_crawlers": False,
    # --- rate limiting -------------------------------------------------------
    "window_seconds": 60,
    "browse_limit": 240,
    "burst_window_seconds": 10,
    "burst_limit": 60,
    "sensitive_limit": 30,
    "challenge_limit": 12,
    "crawler_limit": 300,
    "verified_multiplier": 2.0,
    "max_concurrent": 30,
    # --- detection thresholds ------------------------------------------------
    "log_threshold": 20,
    "challenge_threshold": 40,
    "block_threshold": 85,
    "require_multiple_signals": True,
    "repeat_path_limit": 30,
    "not_found_limit": 5,
    "not_found_ratio": 0.6,
    # --- blocking ------------------------------------------------------------
    "temp_ban_minutes": 30,
    "progressive_ban": True,
    "max_ban_hours": 168,
    "ban_escalation": 2.0,
    "violation_block_after": 2,
    # --- challenge / verification -------------------------------------------
    "challenge_difficulty": 16,
    "challenge_ttl": 900,
    "verification_ttl_hours": 24,
    "verification_ip_binding": "prefix",
    "verification_bind_ua": True,
    # --- crawler / SEO -------------------------------------------------------
    "crawler_verification": True,
    "crawler_dns_ttl": 21600,
    "crawler_fail_open": True,
    "challenge_unverified_crawler": True,
    "trusted_crawler_domains": "",
    "extra_trusted_crawlers": "",
    "blocked_agents": "",
    # --- path configuration --------------------------------------------------
    "exempt_paths": DEFAULT_EXEMPT_PATHS,
    "sensitive_paths": DEFAULT_SENSITIVE_PATHS,
    "blocked_networks": "",
    # --- logging / retention -------------------------------------------------
    "log_retention_days": 30,
    "stats_retention_days": 730,
    "cleanup_enabled": True,
    "cleanup_max_rows": 250,
    "cleanup_interval_hours": 6,
    "event_log_cap": 30,
    # --- traffic spike handling ---------------------------------------------
    "spike_enabled": True,
    "spike_multiplier": 5.0,
    "spike_min_requests": 120,
    "attack_limit_factor": 0.5,
    # --- stats / geolocation -------------------------------------------------
    "unique_tracking": True,
    "geo_enabled": False,
    "trust_cf_country": False,
}
