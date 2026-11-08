"""User-Agent classification."""

from django.test import SimpleTestCase

from botwall import ua
from botwall.tests.base import (
    BROWSER_UA,
    FIREFOX_UA,
    GOOGLEBOT_UA,
    SCANNER_UA,
    SCRAPER_UA,
)


class UserAgentTests(SimpleTestCase):
    def test_normal_browsers_are_clean(self):
        for agent in (BROWSER_UA, FIREFOX_UA):
            info = ua.analyze(agent)
            self.assertEqual(info.category, "browser")
            self.assertTrue(info.is_browser)
            self.assertEqual(info.score, 0)
            self.assertEqual(info.reasons, ())
            self.assertFalse(info.claims_crawler)

    def test_empty_agent_is_suspicious(self):
        info = ua.analyze("")
        self.assertEqual(info.category, "empty")
        self.assertIn("ua:empty", info.reasons)
        self.assertGreater(info.score, 0)

    def test_scripted_client(self):
        info = ua.analyze(SCRAPER_UA)
        self.assertEqual(info.category, "scripted")
        self.assertEqual(info.scripted_client, "python-requests")
        self.assertIn("ua:scripted:python-requests", info.reasons)

    def test_headless_browser(self):
        info = ua.analyze(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) HeadlessChrome/124.0.0.0 Safari/537.36"
        )
        self.assertEqual(info.category, "headless")
        self.assertEqual(info.headless, "headless-chrome")
        self.assertFalse(info.is_browser)

    def test_vulnerability_scanner(self):
        info = ua.analyze(SCANNER_UA)
        self.assertEqual(info.category, "vuln_scanner")
        self.assertEqual(info.scanner, "sqlmap")

    def test_googlebot_claim_is_recorded_not_trusted(self):
        info = ua.analyze(GOOGLEBOT_UA)
        self.assertEqual(info.claimed_bot, "googlebot")
        self.assertEqual(info.claimed_kind, "search_engine")
        self.assertTrue(info.claims_crawler)

    def test_adsense_crawler_is_a_crawler_claim(self):
        info = ua.analyze("Mediapartners-Google")
        self.assertEqual(info.claimed_bot, "mediapartners-google")
        self.assertEqual(info.claimed_kind, "ads_crawler")

    def test_ai_and_seo_crawlers_are_classified(self):
        self.assertEqual(ua.analyze("GPTBot/1.0").claimed_kind, "ai_crawler")
        self.assertEqual(ua.analyze("AhrefsBot/7.0").claimed_kind, "seo_tool")

    def test_social_previews_are_not_punished(self):
        info = ua.analyze("facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)")
        self.assertEqual(info.claimed_kind, "social_preview")
        self.assertEqual(info.score, 0)

    def test_custom_unknown_agent_is_low_risk(self):
        info = ua.analyze("MyCustomClient/1.0")
        self.assertEqual(info.category, "unknown")
        self.assertLessEqual(info.score, 10)

    def test_analysis_is_cached(self):
        first = ua.analyze(BROWSER_UA)
        second = ua.analyze(BROWSER_UA)
        self.assertIs(first, second)

    def test_crawler_domain_lookup(self):
        self.assertIn("googlebot.com", ua.crawler_domains("googlebot"))
        self.assertIn("search.msn.com", ua.crawler_domains("bingbot"))
        self.assertEqual(ua.crawler_domains("does-not-exist"), ())
        self.assertEqual(
            ua.crawler_domains("googlebot", {"googlebot": ("example.com",)}),
            ("example.com",),
        )
