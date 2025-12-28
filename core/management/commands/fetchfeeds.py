from django.core.management.base import BaseCommand
from core.utils import fetch_feeds


class Command(BaseCommand):
    help = "Fetch external posts into blog"

    def handle(self, *args, **kwargs):
        fetch_feeds()
        self.stdout.write(self.style.SUCCESS("Feeds imported"))
