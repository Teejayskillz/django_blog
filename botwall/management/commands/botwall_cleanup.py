"""Delete old security events / traffic statistics / expired IP rules."""

from django.core.management.base import BaseCommand
from django.utils import timezone

from botwall import conf
from botwall.maintenance import cleanup_retention


class Command(BaseCommand):
    help = "Apply the bot protection log retention policy (safe to run from cron)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--max-rows",
            type=int,
            default=None,
            help="Maximum rows deleted per table in this run (default: from settings).",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Only report how many rows would be deleted.",
        )

    def handle(self, *args, **options):
        config = conf.get_config()
        max_rows = options["max_rows"]
        if options["dry_run"]:
            self._dry_run(config, max_rows)
            return

        result = cleanup_retention(config, max_rows=max_rows)
        self.stdout.write(
            self.style.SUCCESS(
                "Cleanup finished: {events} events, {stats} traffic rows, "
                "{rules} expired rules removed.".format(**result)
            )
        )

    def _dry_run(self, config, max_rows):
        from datetime import timedelta

        from botwall.models import IPRule, SecurityEvent, TrafficStat

        max_rows = max_rows or config.cleanup_max_rows
        event_cutoff = timezone.now() - timedelta(days=config.log_retention_days)
        stat_cutoff = timezone.now() - timedelta(days=config.stats_retention_days)
        events = SecurityEvent.objects.filter(created_at__lt=event_cutoff).count()
        stats = TrafficStat.objects.filter(bucket_start__lt=stat_cutoff).count()
        rules = IPRule.objects.filter(
            source=IPRule.SOURCE_AUTO,
            expires_at__lt=timezone.now() - timedelta(days=7),
        ).count()
        self.stdout.write(
            f"Dry run: {events} events older than {config.log_retention_days}d, "
            f"{stats} traffic rows older than {config.stats_retention_days}d, "
            f"{rules} expired automatic rules (max {max_rows} rows per table per run)."
        )
