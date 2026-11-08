"""Reverse/forward DNS crawler verification."""

import socket
from unittest import mock

from django.test import override_settings

from botwall import crawler
from botwall.tests.base import PUBLIC_IP, BotWallTestCase


class CrawlerVerificationTests(BotWallTestCase):
    def setUp(self):
        super().setUp()
        self.configure(crawler_verification=True, crawler_fail_open=True)

    def _patch_dns(self, ptr=None, addresses=None, ptr_error=None, forward_error=None):
        reverse = mock.patch(
            "botwall.crawler.reverse_dns",
            side_effect=ptr_error if ptr_error else None,
            return_value=None if ptr_error else ptr,
        )
        forward = mock.patch(
            "botwall.crawler.forward_dns",
            side_effect=forward_error if forward_error else None,
            return_value=() if forward_error else tuple(addresses or ()),
        )
        return reverse, forward

    def test_verified_googlebot(self):
        reverse, forward = self._patch_dns(
            ptr="crawl-66-249-66-1.googlebot.com", addresses=[PUBLIC_IP]
        )
        with reverse, forward:
            result = crawler.verify_claimed_crawler(
                PUBLIC_IP, "googlebot", self.config()
            )
        self.assertTrue(result.verified)
        self.assertEqual(result.status, crawler.STATUS_VERIFIED)
        self.assertEqual(result.hostname, "crawl-66-249-66-1.googlebot.com")

    def test_domain_mismatch_is_spoofing(self):
        reverse, forward = self._patch_dns(
            ptr="crawl-66-249-66-1.evil-example.com", addresses=[PUBLIC_IP]
        )
        with reverse, forward:
            result = crawler.verify_claimed_crawler(
                PUBLIC_IP, "googlebot", self.config()
            )
        self.assertFalse(result.verified)
        self.assertEqual(result.status, crawler.STATUS_SPOOFED)

    def test_forward_lookup_mismatch_is_spoofing(self):
        reverse, forward = self._patch_dns(
            ptr="crawl-66-249-66-1.googlebot.com", addresses=["203.0.113.9"]
        )
        with reverse, forward:
            result = crawler.verify_claimed_crawler(
                PUBLIC_IP, "googlebot", self.config()
            )
        self.assertFalse(result.verified)
        self.assertEqual(result.status, crawler.STATUS_SPOOFED)

    def test_missing_ptr_is_spoofing(self):
        reverse, forward = self._patch_dns(ptr_error=socket.herror("no ptr"))
        with reverse, forward:
            result = crawler.verify_claimed_crawler(
                PUBLIC_IP, "googlebot", self.config()
            )
        self.assertFalse(result.verified)
        self.assertEqual(result.status, crawler.STATUS_NO_PTR)

    def test_resolver_error_is_not_spoofing(self):
        reverse, forward = self._patch_dns(ptr_error=socket.gaierror("temporary"))
        with reverse, forward:
            result = crawler.verify_claimed_crawler(
                PUBLIC_IP, "googlebot", self.config()
            )
        self.assertFalse(result.verified)
        self.assertEqual(result.status, crawler.STATUS_ERROR)

    def test_private_ip_can_never_be_a_crawler(self):
        result = crawler.verify_claimed_crawler("10.0.0.5", "googlebot", self.config())
        self.assertFalse(result.verified)

    def test_results_are_cached(self):
        reverse, forward = self._patch_dns(
            ptr="crawl-66-249-66-1.googlebot.com", addresses=[PUBLIC_IP]
        )
        with reverse as reverse_mock, forward:
            crawler.verify_claimed_crawler(PUBLIC_IP, "googlebot", self.config())
            second = crawler.verify_claimed_crawler(PUBLIC_IP, "googlebot", self.config())
        self.assertTrue(second.verified)
        self.assertTrue(second.from_cache)
        self.assertEqual(reverse_mock.call_count, 1)

    def test_disabled_verification_reports_disabled(self):
        self.configure(crawler_verification=False)
        result = crawler.verify_claimed_crawler(PUBLIC_IP, "googlebot", self.config())
        self.assertEqual(result.status, crawler.STATUS_DISABLED)
        self.assertFalse(result.verified)

    def test_unknown_bot_is_reported(self):
        result = crawler.verify_claimed_crawler(PUBLIC_IP, "not-a-bot", self.config())
        self.assertEqual(result.status, crawler.STATUS_UNKNOWN_BOT)

    @override_settings(BOTWALL_CONFIG_CACHE_SECONDS=0)
    def test_bingbot_domains(self):
        reverse, forward = self._patch_dns(
            ptr="msnbot-40-77-167-1.search.msn.com", addresses=[PUBLIC_IP]
        )
        with reverse, forward:
            result = crawler.verify_claimed_crawler(PUBLIC_IP, "bingbot", self.config())
        self.assertTrue(result.verified)

    def test_adsense_crawler_verification(self):
        reverse, forward = self._patch_dns(
            ptr="crawl-66-249-66-1.googlebot.com", addresses=[PUBLIC_IP]
        )
        with reverse, forward:
            result = crawler.verify_claimed_crawler(
                PUBLIC_IP, "mediapartners-google", self.config()
            )
        self.assertTrue(result.verified)

    def test_clear_cache_for_ip(self):
        reverse, forward = self._patch_dns(
            ptr="crawl-66-249-66-1.googlebot.com", addresses=[PUBLIC_IP]
        )
        with reverse, forward:
            crawler.verify_claimed_crawler(PUBLIC_IP, "googlebot", self.config())

        crawler.clear_cache_for(PUBLIC_IP)
        fresh_reverse, fresh_forward = self._patch_dns(
            ptr="crawl-66-249-66-1.googlebot.com", addresses=[PUBLIC_IP]
        )
        with fresh_reverse as reverse_mock, fresh_forward:
            crawler.verify_claimed_crawler(PUBLIC_IP, "googlebot", self.config())
        self.assertEqual(reverse_mock.call_count, 1)
