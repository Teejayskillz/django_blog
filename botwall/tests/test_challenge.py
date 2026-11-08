"""Signed, time limited, replay protected verification challenge."""

import time
from unittest import mock

from django.core import signing
from django.test import RequestFactory, SimpleTestCase

from botwall import challenge
from botwall.conf import build_config
from botwall.tests.base import (
    BROWSER_UA,
    CLIENT_IP,
    BotWallTestCase,
)


class ProofOfWorkTests(SimpleTestCase):
    def test_hash_is_deterministic_ascii(self):
        self.assertEqual(challenge.pow_hash("abc", 1), challenge.pow_hash("abc", 1))
        self.assertNotEqual(challenge.pow_hash("abc", 1), challenge.pow_hash("abc", 2))
        self.assertTrue(0 <= challenge.pow_hash("abc", 1) < 2**32)

    def test_leading_zero_bits(self):
        self.assertEqual(challenge.leading_zero_bits(0), 32)
        self.assertEqual(challenge.leading_zero_bits(1), 31)
        self.assertEqual(challenge.leading_zero_bits(1 << 31), 0)
        self.assertEqual(challenge.leading_zero_bits(0b0001), 28)

    def test_solver_produces_valid_proofs(self):
        for bits in (4, 8, 12):
            proof = challenge.solve("nonce-value", bits)
            self.assertIsNotNone(proof)
            self.assertTrue(challenge.proof_is_valid("nonce-value", proof, bits))
            self.assertFalse(
                challenge.proof_is_valid("different-nonce", proof, bits),
                "a proof must not validate for another nonce",
            )

    def test_invalid_proofs(self):
        for proof in (None, "abc", -1, 2**53 + 1):
            self.assertFalse(challenge.proof_is_valid("n", proof, 1))


class ChallengeLifecycleTests(BotWallTestCase):
    def setUp(self):
        super().setUp()
        self.config_obj = self.configure(challenge_difficulty=8)

    def _solve(self, issued):
        proof = challenge.solve(issued.nonce, issued.difficulty)
        self.assertIsNotNone(proof)
        return proof

    def test_issue_and_verify(self):
        issued = challenge.issue(CLIENT_IP, BROWSER_UA, self.config())
        self.assertEqual(issued.difficulty, 8)
        result = challenge.verify_submission(
            issued.token, self._solve(issued), CLIENT_IP, BROWSER_UA, self.config()
        )
        self.assertTrue(result.ok, result.reason)

    def test_token_is_single_use(self):
        issued = challenge.issue(CLIENT_IP, BROWSER_UA, self.config())
        proof = self._solve(issued)
        first = challenge.verify_submission(
            issued.token, proof, CLIENT_IP, BROWSER_UA, self.config()
        )
        second = challenge.verify_submission(
            issued.token, proof, CLIENT_IP, BROWSER_UA, self.config()
        )
        self.assertTrue(first.ok)
        self.assertFalse(second.ok)
        self.assertEqual(second.reason, "expired_or_used")

    def test_tampered_token_is_rejected(self):
        issued = challenge.issue(CLIENT_IP, BROWSER_UA, self.config())
        result = challenge.verify_submission(
            issued.token + "x", 0, CLIENT_IP, BROWSER_UA, self.config()
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "invalid_signature")

    def test_expired_token_is_rejected(self):
        issued = challenge.issue(CLIENT_IP, BROWSER_UA, self.config())
        future = time.time() + self.config().challenge_ttl + 60
        with mock.patch("time.time", return_value=future):
            result = challenge.verify_submission(
                issued.token, 0, CLIENT_IP, BROWSER_UA, self.config()
            )
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "expired")

    def test_wrong_proof_is_rejected(self):
        issued = challenge.issue(CLIENT_IP, BROWSER_UA, self.config())
        bad_proof = next(
            value
            for value in range(500)
            if not challenge.proof_is_valid(issued.nonce, value, issued.difficulty)
        )
        result = challenge.verify_submission(
            issued.token, bad_proof, CLIENT_IP, BROWSER_UA, self.config()
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "bad_proof")

    def test_too_many_attempts_consumes_nonce(self):
        issued = challenge.issue(CLIENT_IP, BROWSER_UA, self.config())
        bad_proof = next(
            value
            for value in range(500)
            if not challenge.proof_is_valid(issued.nonce, value, issued.difficulty)
        )
        result = None
        for _ in range(challenge.MAX_ATTEMPTS + 1):
            result = challenge.verify_submission(
                issued.token, bad_proof, CLIENT_IP, BROWSER_UA, self.config()
            )
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "too_many_attempts")

    def test_ip_binding_exact(self):
        self.configure(challenge_difficulty=8, verification_ip_binding="exact")
        issued = challenge.issue(CLIENT_IP, BROWSER_UA, self.config())
        result = challenge.verify_submission(
            issued.token, self._solve(issued), "203.0.113.99", BROWSER_UA, self.config()
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "ip_mismatch")

    def test_ip_binding_prefix_allows_same_network(self):
        self.configure(challenge_difficulty=8, verification_ip_binding="prefix")
        issued = challenge.issue(CLIENT_IP, BROWSER_UA, self.config())
        result = challenge.verify_submission(
            issued.token, self._solve(issued), "203.0.113.99", BROWSER_UA, self.config()
        )
        self.assertTrue(result.ok, result.reason)

    def test_user_agent_binding(self):
        issued = challenge.issue(CLIENT_IP, BROWSER_UA, self.config())
        result = challenge.verify_submission(
            issued.token,
            self._solve(issued),
            CLIENT_IP,
            "Mozilla/5.0 (different browser)",
            self.config(),
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "user_agent_mismatch")

    def test_difficulty_is_clamped(self):
        config = build_config({"challenge_difficulty": 99})
        self.assertEqual(challenge.difficulty_for(config), challenge.MAX_DIFFICULTY)
        config = build_config({"challenge_difficulty": 0})
        self.assertEqual(challenge.difficulty_for(config), challenge.MIN_DIFFICULTY)


class VerifiedCookieTests(BotWallTestCase):
    def setUp(self):
        super().setUp()
        self.configure(verification_ttl_hours=2)

    def _request(self, cookies):
        request = RequestFactory().get("/")
        request.COOKIES = cookies
        return request

    def test_cookie_round_trip(self):
        name, value, max_age = challenge.issue_cookie(
            CLIENT_IP, BROWSER_UA, self.config()
        )
        self.assertEqual(name, challenge.COOKIE_NAME)
        self.assertEqual(max_age, 7200)
        request = self._request({name: value})
        self.assertTrue(
            challenge.read_verified(request, CLIENT_IP, BROWSER_UA, self.config())
        )

    def test_cookie_rejects_wrong_ua(self):
        name, value, _ = challenge.issue_cookie(CLIENT_IP, BROWSER_UA, self.config())
        request = self._request({name: value})
        self.assertFalse(
            challenge.read_verified(request, CLIENT_IP, "other-agent", self.config())
        )

    def test_cookie_rejects_wrong_ip_when_bound(self):
        self.configure(verification_ip_binding="exact")
        name, value, _ = challenge.issue_cookie(CLIENT_IP, BROWSER_UA, self.config())
        request = self._request({name: value})
        self.assertFalse(
            challenge.read_verified(request, "198.51.100.55", BROWSER_UA, self.config())
        )

    def test_cookie_rejects_tampering(self):
        name, value, _ = challenge.issue_cookie(CLIENT_IP, BROWSER_UA, self.config())
        request = self._request({name: value[:-2] + "xx"})
        self.assertFalse(
            challenge.read_verified(request, CLIENT_IP, BROWSER_UA, self.config())
        )

    def test_cookie_expires(self):
        name, value, max_age = challenge.issue_cookie(
            CLIENT_IP, BROWSER_UA, self.config()
        )
        request = self._request({name: value})
        future = time.time() + max_age + 120
        with mock.patch("time.time", return_value=future):
            self.assertFalse(
                challenge.read_verified(request, CLIENT_IP, BROWSER_UA, self.config())
            )

    def test_missing_cookie(self):
        request = self._request({})
        self.assertFalse(
            challenge.read_verified(request, CLIENT_IP, BROWSER_UA, self.config())
        )

    def test_bad_signature_raises_are_handled(self):
        forged = signing.dumps({"i": "", "u": "", "e": 1}, salt="wrong-salt")
        request = self._request({challenge.COOKIE_NAME: forged})
        self.assertFalse(
            challenge.read_verified(request, CLIENT_IP, BROWSER_UA, self.config())
        )
