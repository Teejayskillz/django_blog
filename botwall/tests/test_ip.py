"""Client IP resolution, proxy trust and CIDR helpers."""

import ipaddress

from django.test import RequestFactory, SimpleTestCase, override_settings

from botwall.ip import (
    get_client_ip,
    ip_in_networks,
    is_private_or_reserved,
    limit_key,
    mask_ip,
    normalize_ip,
    parse_network_list,
)


class NormalizeIPsTests(SimpleTestCase):
    def test_accepts_plain_ipv4_and_ipv6(self):
        self.assertEqual(normalize_ip("203.0.113.7"), "203.0.113.7")
        self.assertEqual(normalize_ip("2001:DB8::1"), "2001:db8::1")

    def test_strips_port_and_brackets(self):
        self.assertEqual(normalize_ip("203.0.113.7:51234"), "203.0.113.7")
        self.assertEqual(normalize_ip("[2001:db8::1]:443"), "2001:db8::1")

    def test_unwraps_ipv4_mapped_addresses(self):
        self.assertEqual(normalize_ip("::ffff:203.0.113.7"), "203.0.113.7")

    def test_rejects_garbage_and_unspecified(self):
        for value in ("", None, "not-an-ip", "0.0.0.0", "::", "1.2.3.4.5", "evil" * 30):
            self.assertIsNone(normalize_ip(value), value)


class LimitKeyTests(SimpleTestCase):
    def test_ipv4_key_is_exact(self):
        self.assertEqual(limit_key("203.0.113.7"), "203.0.113.7")

    def test_ipv6_key_is_masked_to_64(self):
        self.assertEqual(limit_key("2001:db8:1:2:3:4:5:6"), "2001:db8:1:2::")

    def test_invalid_key_is_stable(self):
        self.assertEqual(limit_key("nope"), "invalid")


class MaskTests(SimpleTestCase):
    def test_prefix_binding(self):
        self.assertEqual(mask_ip("203.0.113.77", "prefix"), "203.0.113.0/24")
        self.assertEqual(mask_ip("2001:db8:1:2:3:4:5:6", "prefix"), "2001:db8:1:2::/64")

    def test_exact_binding(self):
        self.assertEqual(mask_ip("203.0.113.77", "exact"), "203.0.113.77")

    def test_none_binding(self):
        self.assertEqual(mask_ip("203.0.113.77", "none"), "")


class NetworkListTests(SimpleTestCase):
    def test_parses_comments_and_invalid_entries(self):
        networks = parse_network_list(
            "# comment\n\n203.0.113.0/24\nnonsense\n2001:db8::/32\n"
        )
        self.assertEqual(len(networks), 2)
        self.assertTrue(ip_in_networks("203.0.113.5", networks))
        self.assertTrue(ip_in_networks("2001:db8::5", networks))
        self.assertFalse(ip_in_networks("198.51.100.5", networks))
        self.assertFalse(ip_in_networks("bad", networks))

    def test_private_detection(self):
        self.assertTrue(is_private_or_reserved("10.1.2.3"))
        self.assertTrue(is_private_or_reserved("127.0.0.1"))
        self.assertFalse(is_private_or_reserved("66.249.66.1"))


class ClientIPTests(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def _request(self, remote, forwarded=None, cf=None):
        extra = {}
        if forwarded is not None:
            extra["HTTP_X_FORWARDED_FOR"] = forwarded
        if cf is not None:
            extra["HTTP_CF_CONNECTING_IP"] = cf
        return self.factory.get("/", REMOTE_ADDR=remote, **extra)

    def test_uses_remote_addr_by_default(self):
        client = get_client_ip(self._request("203.0.113.7", "1.2.3.4"))
        self.assertEqual(client.address, "203.0.113.7")
        self.assertEqual(client.source, "remote_addr")
        self.assertFalse(client.trusted_proxy)
        self.assertFalse(client.spoof_suspect)

    @override_settings(BOTWALL_TRUSTED_PROXIES=["10.0.0.0/8"], BOTWALL_TRUSTED_PROXY_HOPS=1)
    def test_trusted_proxy_honours_forwarded_for(self):
        # One proxy appends exactly one address: the real client.
        client = get_client_ip(self._request("10.0.0.5", "203.0.113.7"))
        self.assertEqual(client.address, "203.0.113.7")
        self.assertEqual(client.source, "x_forwarded_for")
        self.assertTrue(client.trusted_proxy)

    @override_settings(BOTWALL_TRUSTED_PROXIES=["10.0.0.0/8"], BOTWALL_TRUSTED_PROXY_HOPS=2)
    def test_two_trusted_hops_walk_from_the_right(self):
        # XFF = client, proxy1, proxy2 with two trusted proxies in front of us.
        client = get_client_ip(
            self._request("10.0.0.5", "203.0.113.7, 10.0.0.9, 10.0.0.5")
        )
        self.assertEqual(client.address, "203.0.113.7")
        self.assertEqual(client.source, "x_forwarded_for")

    @override_settings(BOTWALL_TRUSTED_PROXIES=["10.0.0.0/8"], BOTWALL_TRUSTED_PROXY_HOPS=1)
    def test_too_short_forwarded_for_is_not_used(self):
        client = get_client_ip(self._request("10.0.0.5", ""))
        self.assertEqual(client.address, "10.0.0.5")
        self.assertFalse(client.spoof_suspect)

    @override_settings(BOTWALL_TRUSTED_PROXIES=["10.0.0.0/8"], BOTWALL_TRUSTED_PROXY_HOPS=1)
    def test_malformed_forwarded_for_falls_back_and_flags_spoofing(self):
        client = get_client_ip(self._request("10.0.0.5", "not-an-ip"))
        self.assertEqual(client.address, "10.0.0.5")
        self.assertTrue(client.spoof_suspect)

    @override_settings(BOTWALL_TRUSTED_PROXIES=["10.0.0.0/8"], BOTWALL_TRUSTED_PROXY_HOPS=1)
    def test_private_hop_is_flagged(self):
        client = get_client_ip(self._request("10.0.0.5", "192.168.1.5"))
        self.assertTrue(client.spoof_suspect)

    def test_untrusted_forwarded_for_is_ignored(self):
        client = get_client_ip(self._request("198.51.100.9", "1.2.3.4"))
        self.assertEqual(client.address, "198.51.100.9")
        self.assertFalse(client.spoof_suspect)

    @override_settings(
        BOTWALL_TRUSTED_PROXIES=["103.21.244.0/22"],
        BOTWALL_TRUST_CF_HEADERS=True,
    )
    def test_cloudflare_header_only_from_cloudflare_peer(self):
        client = get_client_ip(
            self._request("103.21.244.5", "203.0.113.7", cf="203.0.113.7")
        )
        self.assertEqual(client.address, "203.0.113.7")
        self.assertEqual(client.source, "cf_connecting_ip")

        spoofed = get_client_ip(
            self._request("198.51.100.9", "203.0.113.7", cf="203.0.113.7")
        )
        self.assertEqual(spoofed.address, "198.51.100.9")
        self.assertEqual(spoofed.source, "remote_addr")

    def test_invalid_remote_addr_is_replaced(self):
        client = get_client_ip(self._request("garbage"))
        self.assertEqual(client.address, "0.0.0.0")


class CidrTests(SimpleTestCase):
    def test_cidr_membership(self):
        networks = parse_network_list("203.0.113.0/24")
        self.assertTrue(ip_in_networks("203.0.113.200", networks))
        self.assertFalse(ip_in_networks("203.0.114.1", networks))

    def test_network_is_strict_false(self):
        network = ipaddress.ip_network("203.0.113.7/24", strict=False)
        self.assertEqual(str(network), "203.0.113.0/24")
