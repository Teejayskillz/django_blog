"""Configuration defaults, parsing and database overrides."""

from django.test import TestCase

from botwall import conf
from botwall.defaults import DEFAULTS
from botwall.models import BotWallSettings
from botwall.tests.base import BotWallTestCase


class DefaultsSyncTests(TestCase):
    def test_every_default_maps_to_a_model_field(self):
        model_fields = {
            field.name
            for field in BotWallSettings._meta.fields
            if field.name not in {"id", "created_at", "updated_at"}
        }
        self.assertTrue(model_fields)
        self.assertEqual(
            set(DEFAULTS),
            model_fields,
            "botwall.defaults.DEFAULTS and BotWallSettings fields are out of sync",
        )

    def test_code_defaults_are_used_before_migration(self):
        # An empty database still returns a usable config object.
        config = conf.build_config({})
        self.assertTrue(config.enabled)
        self.assertGreater(config.browse_limit, 0)
        self.assertTrue(config.exempt_prefixes)
        self.assertTrue(config.sensitive_regexes)


class ConfigParsingTests(BotWallTestCase):
    def test_defaults_exempt_robots_and_sitemaps(self):
        config = self.config()
        for path in (
            "/robots.txt",
            "/sitemap.xml",
            "/sitemap-blog.xml",
            "/favicon.ico",
            "/ads.txt",
            "/.well-known/acme-challenge/x",
            "/admin/login/",
            "/botwall/challenge/verify/",
        ):
            self.assertTrue(config.is_exempt_path(path), path)
        self.assertFalse(config.is_exempt_path("/some-post/"))
        self.assertTrue(
            config.is_exempt_path("/google850bdbab435ea6f5.html"),
            "Google Search Console verification file must stay reachable",
        )

    def test_sensitive_paths(self):
        config = self.config()
        for path in ("/search/", "/download/quality/1/", "/ads/click/1/", "/admin/"):
            self.assertTrue(config.is_sensitive_path(path), path)
        self.assertFalse(config.is_sensitive_path("/category/action/"))

    def test_database_values_override_defaults(self):
        self.configure(browse_limit=7, log_threshold=3, exempt_paths="/robots.txt\n/custom/")
        config = self.config()
        self.assertEqual(config.browse_limit, 7)
        self.assertEqual(config.log_threshold, 3)
        self.assertTrue(config.is_exempt_path("/custom/thing"))
        self.assertTrue(config.from_database)

    def test_invalid_regex_is_ignored(self):
        self.configure(sensitive_paths="/ok/\n([unclosed")
        config = self.config()
        self.assertTrue(config.is_sensitive_path("/ok/"))

    def test_crawler_domain_overrides(self):
        self.configure(trusted_crawler_domains="mybot: mybot.example.com, example.net")
        config = self.config()
        self.assertEqual(
            config.crawler_domain_overrides["mybot"],
            ("mybot.example.com", "example.net"),
        )

    def test_blocked_agents_and_networks(self):
        self.configure(blocked_agents="BadBot\nEvilCrawler", blocked_networks="198.51.100.0/24")
        config = self.config()
        self.assertIn("badbot", config.blocked_agent_tokens)
        self.assertTrue(any("198.51.100.0/24" == str(net) for net in config.blocked_networks))

    def test_database_failure_falls_back_to_defaults(self):
        from unittest import mock

        with mock.patch.object(
            conf, "build_config", side_effect=RuntimeError("boom")
        ):
            conf.invalidate_config()
            config = conf.get_config()
        self.assertTrue(config.enabled)
        self.assertFalse(config.from_database)
