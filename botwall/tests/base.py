"""Shared helpers for the bot protection test suite."""

from __future__ import annotations

from django.core.cache import caches
from django.test import TestCase

from botwall import blocking, conf, stats
from botwall.models import BotWallSettings

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
FIREFOX_UA = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"
)
SCRAPER_UA = "python-requests/2.31.0"
SCANNER_UA = "sqlmap/1.7.2#stable (https://sqlmap.org)"
GOOGLEBOT_UA = (
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
)
BINGBOT_UA = "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
ADSENSE_UA = "Mediapartners-Google"
PUBLIC_IP = "66.249.66.1"
CLIENT_IP = "203.0.113.10"


def clear_caches():
    for alias in ("botwall", "botwall_fallback"):
        caches[alias].clear()


class BotWallTestCase(TestCase):
    """Base class that isolates cache/config state between tests."""

    def setUp(self):
        super().setUp()
        clear_caches()
        conf.reset_caches()
        blocking.invalidate_rules()
        stats.reset_attack_state()
        self.config_obj = BotWallSettings.load()

    def tearDown(self):
        clear_caches()
        conf.reset_caches()
        blocking.invalidate_rules()
        stats.reset_attack_state()
        super().tearDown()

    # -- configuration --------------------------------------------------------
    def configure(self, **values):
        obj = BotWallSettings.load()
        for key, value in values.items():
            setattr(obj, key, value)
        obj.save()
        conf.invalidate_config()
        blocking.invalidate_rules()
        self.config_obj = obj
        return obj

    def config(self):
        return conf.get_config(force=True)

    # -- requests -------------------------------------------------------------
    def request(self, path="/", *, ip=CLIENT_IP, ua=BROWSER_UA, method="get", **extra):
        headers = {
            "REMOTE_ADDR": ip,
            "HTTP_USER_AGENT": ua,
            "HTTP_ACCEPT": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "HTTP_ACCEPT_LANGUAGE": "en-US,en;q=0.9",
        }
        headers.update(extra)
        return getattr(self.client, method)(path, **headers)

    # -- assertions -----------------------------------------------------------
    def assertAllowed(self, response):
        self.assertNotEqual(response.status_code, 403, "request was unexpectedly blocked")
        self.assertNotEqual(response.status_code, 429, "request was unexpectedly rate limited")
        if response.get("X-Robots-Tag", ""):
            self.assertNotIn("noindex", response["X-Robots-Tag"])

    def assertBlocked(self, response):
        self.assertEqual(response.status_code, 403)
        self.assertIn("noindex", response.get("X-Robots-Tag", ""))

    def assertChallenged(self, response):
        self.assertEqual(response.status_code, 200)
        self.assertIn("Confirming your browser", response.content.decode())
        self.assertIn("noindex", response.get("X-Robots-Tag", ""))
        self.assertIn("no-store", response.get("Cache-Control", ""))
