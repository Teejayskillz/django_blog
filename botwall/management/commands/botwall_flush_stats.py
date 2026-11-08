"""Roll cache minute-buckets into hourly TrafficStat rows.

The middleware already does this every five minutes; running the command from
cron keeps the data flowing even on low-traffic sites or after a restart.
"""

from django.core.management.base import BaseCommand

from botwall import stats


class Command(BaseCommand):
    help = "Flush cached traffic counters into the hourly TrafficStat table."

    def add_arguments(self, parser):
        parser.add_argument(
            "--minutes",
            type=int,
            default=130,
            help="How many completed minutes to roll up (max 130, the cache TTL).",
        )

    def handle(self, *args, **options):
        minutes = max(1, min(int(options["minutes"]), 130))
        written = stats.flush_recent(minutes=minutes)
        self.stdout.write(
            self.style.SUCCESS(f"Flushed {written} hourly traffic row(s).")
        )
