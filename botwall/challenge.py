"""Browser verification challenge (signed, time limited, replay protected).

A suspicious visitor receives a small self-contained page that must compute a
proof of work derived from a server-generated nonce. The nonce is stored in the
cache and consumed on success, so a token cannot be replayed. Tokens and the
resulting cookie are signed with Django's ``SECRET_KEY`` (tamper proof) and are
bound to the IP network prefix and User-Agent.

No external CAPTCHA service, cookie sync or third-party request is involved,
which keeps AdSense/Analytics isolation intact.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time
from dataclasses import dataclass
from datetime import datetime

from django.conf import settings
from django.core import signing
from django.utils import timezone

from .cache import get_cache
from .ip import mask_ip

logger = logging.getLogger("botwall.challenge")

CHALLENGE_SALT = "botwall.challenge.v1"
VERIFY_SALT = "botwall.verified.v1"
COOKIE_NAME = "bwv"
MAX_ATTEMPTS = 6
MIN_DIFFICULTY = 1
MAX_DIFFICULTY = 28


@dataclass(frozen=True)
class Challenge:
    nonce: str
    token: str
    difficulty: int
    expires_in: int


@dataclass(frozen=True)
class Verification:
    ok: bool
    reason: str = ""
    binding: str = ""


# ---------------------------------------------------------------------------
# proof of work
# ---------------------------------------------------------------------------
def pow_hash(nonce: str, proof: int) -> int:
    """32-bit FNV-1a + avalanche hash, mirrored exactly in the challenge JS.

    Input is ASCII by construction (hex nonce + decimal counter), so JavaScript
    ``charCodeAt`` and Python byte iteration agree byte for byte.
    """
    data = f"{nonce}:{int(proof)}".encode("ascii", "ignore")
    value = 0x811C9DC5
    for byte in data:
        value ^= byte
        value = (value * 0x01000193) & 0xFFFFFFFF
    value ^= value >> 16
    value = (value * 0x85EBCA6B) & 0xFFFFFFFF
    value ^= value >> 13
    value = (value * 0xC2B2AE35) & 0xFFFFFFFF
    value ^= value >> 16
    return value & 0xFFFFFFFF


def leading_zero_bits(value: int, width: int = 32) -> int:
    count = 0
    for bit in range(width - 1, -1, -1):
        if value & (1 << bit):
            break
        count += 1
    return count


def proof_is_valid(nonce: str, proof, difficulty: int) -> bool:
    try:
        proof = int(proof)
    except (TypeError, ValueError):
        return False
    if proof < 0 or proof > 2**53:
        return False
    return leading_zero_bits(pow_hash(nonce, proof)) >= int(difficulty)


def solve(nonce: str, difficulty: int, max_iterations: int = 2**24):
    """Server-side solver (tests, support tooling). Returns proof or None."""
    for proof in range(max_iterations):
        if proof_is_valid(nonce, proof, difficulty):
            return proof
    return None


# ---------------------------------------------------------------------------
# binding helpers
# ---------------------------------------------------------------------------
def _secret() -> bytes:
    return str(getattr(settings, "SECRET_KEY", "") or "insecure-botwall").encode()


def ua_fingerprint(user_agent: str) -> str:
    return hmac.new(_secret(), (user_agent or "").encode(), hashlib.sha256).hexdigest()[:16]


def binding_value(ip: str, config) -> str:
    return mask_ip(ip, getattr(config, "verification_ip_binding", "prefix"))


def difficulty_for(config) -> int:
    try:
        value = int(getattr(config, "challenge_difficulty", 16) or 16)
    except (TypeError, ValueError):
        value = 16
    return max(MIN_DIFFICULTY, min(value, MAX_DIFFICULTY))


def _ttl(config) -> int:
    try:
        return max(int(getattr(config, "challenge_ttl", 900) or 900), 30)
    except (TypeError, ValueError):
        return 900


# ---------------------------------------------------------------------------
# challenge lifecycle
# ---------------------------------------------------------------------------
def issue(ip: str, user_agent: str, config) -> Challenge:
    nonce = secrets.token_urlsafe(12).replace("-", "a").replace("_", "b")
    difficulty = difficulty_for(config)
    ttl = _ttl(config)
    binding = binding_value(ip, config)
    fingerprint = ua_fingerprint(user_agent)
    expires_at = int(time.time()) + ttl

    payload = {
        "n": nonce,
        "b": difficulty,
        "e": expires_at,
        "i": binding,
        "u": fingerprint,
    }
    token = signing.dumps(payload, salt=CHALLENGE_SALT, compress=True)
    get_cache().set(
        f"bw:chal:{nonce}",
        {"i": binding, "u": fingerprint, "b": difficulty, "issued": int(time.time())},
        ttl,
    )
    return Challenge(nonce=nonce, token=token, difficulty=difficulty, expires_in=ttl)


def verify_token(token: str, ip: str, user_agent: str, config):
    """Return ``(payload, reason)``; ``payload`` is ``None`` on failure."""
    ttl = _ttl(config)
    try:
        payload = signing.loads(
            token,
            salt=CHALLENGE_SALT,
            max_age=ttl,
            clock=time.time,
        )
    except signing.SignatureExpired:
        return None, "expired"
    except signing.BadSignature:
        return None, "invalid_signature"
    if not isinstance(payload, dict):
        return None, "invalid_payload"

    nonce = payload.get("n") or ""
    stored = get_cache().get(f"bw:chal:{nonce}")
    if not isinstance(stored, dict):
        return None, "expired_or_used"

    binding = binding_value(ip, config)
    if payload.get("i") != binding or stored.get("i") != binding:
        return None, "ip_mismatch"
    fingerprint = ua_fingerprint(user_agent)
    if payload.get("u") != fingerprint or stored.get("u") != fingerprint:
        return None, "user_agent_mismatch"
    if int(payload.get("b") or 0) != int(stored.get("b") or 0):
        return None, "difficulty_mismatch"
    if int(payload.get("b") or 0) < MIN_DIFFICULTY:
        return None, "difficulty_too_low"
    return payload, ""


def verify_submission(token: str, proof, ip: str, user_agent: str, config):
    """Validate token + proof and consume the nonce exactly once."""
    payload, reason = verify_token(token, ip, user_agent, config)
    if payload is None:
        return Verification(ok=False, reason=reason)

    nonce = payload["n"]
    difficulty = int(payload.get("b") or 0)
    attempts_key = f"bw:chal:att:{nonce}"
    attempts = int(get_cache().incr(attempts_key, 1, _ttl(config)))
    if attempts > MAX_ATTEMPTS:
        get_cache().delete(f"bw:chal:{nonce}")
        return Verification(ok=False, reason="too_many_attempts")

    if not proof_is_valid(nonce, proof, difficulty):
        return Verification(ok=False, reason="bad_proof")

    # Single-use nonce: deleting it here makes replay impossible.
    get_cache().delete(f"bw:chal:{nonce}")
    get_cache().delete(attempts_key)
    return Verification(ok=True, binding=binding_value(ip, config))


# ---------------------------------------------------------------------------
# verified visitor cookie
# ---------------------------------------------------------------------------
def issue_cookie(ip: str, user_agent: str, config) -> tuple[str, str, int]:
    hours = max(int(getattr(config, "verification_ttl_hours", 24) or 24), 1)
    max_age = hours * 3600
    payload = {
        "i": binding_value(ip, config),
        "u": ua_fingerprint(user_agent),
        "e": int(time.time()) + max_age,
    }
    value = signing.dumps(payload, salt=VERIFY_SALT, compress=True)
    return COOKIE_NAME, value, max_age


def read_verified(request, ip: str, user_agent: str, config) -> bool:
    """Check the signed verification cookie without touching the cache."""
    value = request.COOKIES.get(COOKIE_NAME)
    if not value:
        return False
    max_age = max(int(getattr(config, "verification_ttl_hours", 24) or 24), 1) * 3600
    try:
        payload = signing.loads(value, salt=VERIFY_SALT, max_age=max_age, clock=time.time)
    except (signing.SignatureExpired, signing.BadSignature):
        return False
    if not isinstance(payload, dict):
        return False
    if int(payload.get("e") or 0) < int(time.time()):
        return False
    if getattr(config, "verification_bind_ua", True):
        if payload.get("u") != ua_fingerprint(user_agent):
            return False
    binding = binding_value(ip, config)
    if binding and payload.get("i") != binding:
        return False
    return True
