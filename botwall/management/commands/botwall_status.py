"""Print a deployment/health summary for the bot protection firewall."""

from django.conf import settings
from django.core.management.base import BaseCommand
from django.test import Client

from botwall import blocking, conf
from botwall.cache import get_cache
from botwall.models import BotWallSettings, IPRule, SecurityEvent, TrafficStat


class Command(BaseCommand):
    help = "Show firewall configuration, cache health, rule/event counts and checks."

    def add_arguments(self, parser):
        parser.add_argument(
            "--check-urls",
            action="store_true",
            help="Make internal requests to robots.txt, the sitemap and the challenge endpoint.",
        )

    def handle(self, *args, **options):
        config = conf.get_config()
        cache = get_cache()
        health = cache.health()

        self.stdout.write(self.style.MIGRATE_HEADING("Bot protection firewall status"))
        self.stdout.write(f"  settings switch (settings.BOTWALL_ENABLED): {getattr(settings, 'BOTWALL_ENABLED', True)}")
        self.stdout.write(f"  database switch (admin settings):           {config.enabled}")
        self.stdout.write(f"  auto block:                                 {config.auto_block}")
        self.stdout.write(f"  challenge enabled:                          {config.challenge_enabled}")
        self.stdout.write(f"  logging enabled:                            {config.log_suspicious}")
        self.stdout.write(f"  configuration source:                       {'database' if config.from_database else 'code defaults'}")
        self.stdout.write("")
        self.stdout.write(self.style.MIGRATE_HEADING("Cache"))
        self.stdout.write(f"  primary:   {health['primary_backend']} ({health['primary_alias']})")
        self.stdout.write(f"  fallback:  {health['fallback_backend']} ({health['fallback_alias']})")
        self.stdout.write(f"  reachable: {health['reachable']}   degraded: {health['degraded']}")
        if health["last_error"]:
            self.stdout.write(f"  last error: {health['last_error']}")
        if "DatabaseCache" in health["primary_backend"] or "DatabaseCache" in health["fallback_backend"]:
            self.stdout.write(
                "  note: run 'python manage.py createcachetable' once for the database cache table."
            )
        self.stdout.write("")
        self.stdout.write(self.style.MIGRATE_HEADING("Limits and thresholds"))
        self.stdout.write(
            f"  browse {config.browse_limit}/{config.window_seconds}s, "
            f"sensitive {config.sensitive_limit}, burst {config.burst_limit}/{config.burst_window_seconds}s, "
            f"crawler {config.crawler_limit}"
        )
        self.stdout.write(
            f"  log >= {config.log_threshold}, challenge >= {config.challenge_threshold}, "
            f"block >= {config.block_threshold}"
        )
        self.stdout.write(
            f"  temp ban {config.temp_ban_minutes} min, escalation x{config.ban_escalation}, "
            f"max {config.max_ban_hours}h, progressive {config.progressive_ban}"
        )
        self.stdout.write("")
        self.stdout.write(self.style.MIGRATE_HEADING("Data"))
        try:
            self.stdout.write(f"  settings rows:       {BotWallSettings.objects.count()}")
            self.stdout.write(f"  IP rules:            {IPRule.objects.count()}")
            self.stdout.write(
                f"  active blocks:       {IPRule.objects.filter(rule_type='block', is_active=True).count()}"
            )
            self.stdout.write(
                f"  whitelist entries:   {IPRule.objects.filter(rule_type='whitelist', is_active=True).count()}"
            )
            self.stdout.write(f"  security events:     {SecurityEvent.objects.count()}")
            self.stdout.write(f"  hourly stat rows:    {TrafficStat.objects.count()}")
        except Exception as exc:  # noqa: BLE001
            self.stdout.write(self.style.ERROR(f"  database not ready: {exc}"))
            self.stdout.write(
                "  run 'python manage.py migrate' (and 'createcachetable') first."
            )

        self.stdout.write("")
        self.stdout.write(self.style.MIGRATE_HEADING("Configuration checks"))
        middleware = list(getattr(settings, "MIDDLEWARE", []))
        marker = "botwall.middleware.BotWallMiddleware"
        if marker in middleware:
            index = middleware.index(marker)
            self.stdout.write(self.style.SUCCESS(f"  middleware installed at position {index}"))
            if index and "WhiteNoise" not in middleware[index - 1]:
                self.stdout.write(
                    "  warning: the middleware is not directly after WhiteNoiseMiddleware."
                )
        else:
            self.stdout.write(self.style.ERROR("  middleware is NOT installed"))
        if "botwall" in getattr(settings, "INSTALLED_APPS", []):
            self.stdout.write(self.style.SUCCESS("  'botwall' is in INSTALLED_APPS"))
        else:
            self.stdout.write(self.style.ERROR("  'botwall' is missing from INSTALLED_APPS"))

        if options["check_urls"]:
            self.stdout.write("")
            self.stdout.write(self.style.MIGRATE_HEADING("Endpoint checks"))
            client = Client()
            for path in ("/robots.txt", "/sitemap.xml", "/botwall/challenge/verify/"):
                try:
                    response = client.get(path)
                    self.stdout.write(f"  GET {path} -> {response.status_code}")
                except Exception as exc:  # noqa: BLE001
                    self.stdout.write(self.style.ERROR(f"  GET {path} failed: {exc}"))

        self.stdout.write("")
        self.stdout.write(self.style.MIGRATE_HEADING("Recent blocks"))
        for rule in IPRule.objects.filter(rule_type="block", is_active=True)[:10]:
            self.stdout.write(
                f"  {rule.value}  source={rule.source}  permanent={rule.is_permanent}  "
                f"expires={rule.expires_at or 'never'}  reason={rule.reason[:60]}"
            )
        self.stdout.write("")
        self.stdout.write(
            self.style.SUCCESS("Dashboard: /botwall/dashboard/  (staff login required)")
        )
