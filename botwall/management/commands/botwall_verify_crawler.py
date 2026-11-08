"""Debug the reverse/forward DNS verification of a claimed crawler."""

from django.core.management.base import BaseCommand, CommandError

from botwall import conf, crawler


class Command(BaseCommand):
    help = "Verify whether an IP really belongs to the search engine it claims."

    def add_arguments(self, parser):
        parser.add_argument("ip", help="Client IP address to verify.")
        parser.add_argument(
            "bot",
            nargs="?",
            default="googlebot",
            help="Claimed crawler name (googlebot, bingbot, mediapartners-google, ...).",
        )
        parser.add_argument(
            "--clear-cache",
            action="store_true",
            help="Ignore cached DNS results.",
        )

    def handle(self, *args, **options):
        ip = options["ip"]
        bot = options["bot"].lower()
        if options["clear_cache"]:
            crawler.clear_cache_for(ip)
        config = conf.get_config()
        result = crawler.verify_claimed_crawler(ip, bot, config)
        self.stdout.write(f"ip:       {ip}")
        self.stdout.write(f"claimed:  {bot}")
        self.stdout.write(f"status:   {result.status}")
        self.stdout.write(f"verified: {result.verified}")
        self.stdout.write(f"hostname: {result.hostname or '-'}")
        self.stdout.write(f"detail:   {result.detail or '-'}")
        self.stdout.write(f"cached:   {result.from_cache}")
        if result.verified:
            self.stdout.write(self.style.SUCCESS("This client is a verified crawler."))
        elif result.status == crawler.STATUS_ERROR:
            self.stdout.write(
                self.style.WARNING(
                    "DNS failure (not a spoofing proof). With crawler_fail_open enabled "
                    "the client is allowed."
                )
            )
        else:
            self.stdout.write(
                self.style.WARNING("The claim could not be verified (likely spoofed).")
            )
