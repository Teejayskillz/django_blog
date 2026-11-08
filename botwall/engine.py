"""Detection engine: turns request features into a risk score and an action.

Signals are grouped into *families* (user-agent, path, 404 scanning, repeated
paths, headers, crawler verification, bursts). Automatic blocks additionally
require ``require_multiple_signals`` to be satisfied, so a single request can
never trigger a permanent or even a temporary ban on its own.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from . import crawler, ua
from .conf import get_weights

logger = logging.getLogger("botwall.engine")

ACTION_ALLOW = "allow"
ACTION_LOG = "log"
ACTION_CHALLENGE = "challenge"
ACTION_BLOCK = "block"
ACTION_RATE_LIMIT = "ratelimit"

MAX_SCORE = 100

BAD_EXTENSIONS = {
    ".php",
    ".php3",
    ".php4",
    ".php5",
    ".phtml",
    ".asp",
    ".aspx",
    ".ashx",
    ".jsp",
    ".jspx",
    ".cgi",
    ".pl",
    ".env",
    ".git",
    ".svn",
    ".hg",
    ".sql",
    ".bak",
    ".old",
    ".orig",
    ".swp",
    ".ini",
    ".conf",
    ".config",
    ".yml",
    ".yaml",
    ".json",
    ".xml.bak",
    ".zip",
    ".tar",
    ".tgz",
    ".gz",
    ".rar",
    ".7z",
    ".log",
}

PROBE_TOKENS = (
    "wp-login",
    "wp-admin",
    "wp-content",
    "wp-json",
    "xmlrpc",
    "phpmyadmin",
    "pma/",
    "cgi-bin",
    "actuator",
    "phpunit",
    "/solr",
    "jenkins",
    "telescope",
    "_ignition",
    "credentials",
    ".aws",
    ".ssh",
    "config.json",
    "settings.py",
    "manage.py",
    "server-status",
    "boaform",
    "hnap1",
    "gponform",
    "shell.php",
    "manager/html",
    "geoserver",
    "weblogic",
    "struts",
    "jndi:",
    "${jndi",
    "log4j",
    "eval(",
    "base64_",
    "etc/passwd",
    "proc/self",
    "union select",
    "information_schema",
    "onerror=",
    "<script",
    "%00",
    "cmd=",
    "downloadfile",
    "setup.php",
)

# Tokens that are only suspicious in the query string (avoid false positives on
# ordinary article slugs that may legitimately contain a word like "admin").
QUERY_PROBE_TOKENS = (
    "union select",
    "information_schema",
    "sleep(",
    "benchmark(",
    "etc/passwd",
    "<script",
    "onerror=",
    "' or ",
    "\" or ",
    "1=1",
    "../../",
    "%2e%2e",
)


@dataclass
class Input:
    """Everything the engine needs; keeps the engine trivially testable."""

    ua: str = ""
    path: str = "/"
    method: str = "GET"
    query: str = ""
    accept: str = ""
    accept_language: str = ""
    ip: str = ""
    spoof_suspect: bool = False
    verified_visitor: bool = False
    frequency: int = 0
    path_count: int = 0
    not_found_count: int = 0
    not_found_ratio: float = 0.0
    attack: bool = False


@dataclass
class Decision:
    action: str = ACTION_ALLOW
    score: int = 0
    reasons: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    category: str = "ua"
    frequency: int = 0
    block_minutes: int = 0
    retry_after: int = 0
    verified_crawler: bool = False
    verified_visitor: bool = False
    crawler_status: str = ""
    crawler_bot: str = ""
    crawler_host: str = ""
    crawler_error: bool = False
    attack: bool = False

    @property
    def families(self):
        return set(self.categories)

    @property
    def suspicious(self) -> bool:
        return self.action in (ACTION_CHALLENGE, ACTION_BLOCK, ACTION_LOG)


class _Signals:
    def __init__(self):
        self.items: list[tuple[str, str, int]] = []

    def add(self, category: str, reason: str, score: int):
        if score:
            self.items.append((category, reason, int(score)))

    @property
    def score(self) -> int:
        return min(sum(item[2] for item in self.items), MAX_SCORE)

    @property
    def families(self):
        return {item[0] for item in self.items}

    @property
    def reasons(self):
        return [item[1] for item in self.items]

    def dominant_category(self, fallback: str = "ua") -> str:
        if not self.items:
            return fallback
        return max(self.items, key=lambda item: item[2])[0]


def _path_signals(input_: Input, signals: _Signals, weights):
    path = (input_.path or "/")[:2000]
    lowered = path.lower()
    query = (input_.query or "").lower()

    extension = ""
    last_segment = lowered.rstrip("/").rsplit("/", 1)[-1]
    if "." in last_segment:
        extension = "." + last_segment.rsplit(".", 1)[-1]
    if extension in BAD_EXTENSIONS:
        signals.add("path", f"path:bad_extension:{extension}", weights["path_bad_extension"])

    traversal = ".." in lowered or "%2e%2e" in lowered or "%252e" in lowered
    if traversal:
        signals.add("path", "path:traversal", weights["path_traversal"])

    for token in PROBE_TOKENS:
        if token in lowered:
            signals.add("path", f"path:probe:{token}", weights["path_probe"])
            break

    for token in QUERY_PROBE_TOKENS:
        if token in query:
            signals.add("path", f"query:probe:{token}", weights["path_probe"])
            break

    if len(path) > 1500 or path.count("/") > 14:
        signals.add("path", "path:abnormal_length", weights["path_long"])

    if query.count("&") > 30:
        signals.add("path", "path:many_parameters", weights["path_many_params"])


def _header_signals(input_: Input, signals: _Signals, weights):
    method = (input_.method or "GET").upper()
    if method not in {"GET", "HEAD", "OPTIONS", "POST"}:
        signals.add("method", f"method:unusual:{method}", weights["method_unusual"])

    if input_.spoof_suspect:
        signals.add("header", "header:forwarded_for_spoof", weights["header_spoof"])

    if method in {"GET", "HEAD"} and not (input_.accept or "").strip():
        # Every real browser sends an Accept header; most scrapers do not.
        signals.add("header", "header:missing_accept", weights.get("header_missing_accept", 10))

    if (
        (input_.accept_language or "").strip() == ""
        and "mozilla/" in (input_.ua or "").lower()
    ):
        signals.add("header", "header:missing_accept_language", weights["ua_missing_language"])


def _custom_crawler_claim(input_: Input, config):
    lowered = (input_.ua or "").lower()
    for token, domains in config.extra_crawlers:
        if token and token in lowered:
            return token, domains
    return None


def evaluate(input_: Input, config, weights=None) -> Decision:
    weights = weights or get_weights()
    signals = _Signals()
    decision = Decision(frequency=input_.frequency, verified_visitor=input_.verified_visitor)
    ua_info = ua.analyze(input_.ua)

    # -- crawler claims -----------------------------------------------------
    claimed_bot = ua_info.claimed_bot
    claim_kind = ua_info.claimed_kind
    custom = _custom_crawler_claim(input_, config)
    if custom is not None and custom[0]:
        claimed_bot, claim_kind = custom[0], "search_engine"

    if claimed_bot and claim_kind in ("search_engine", "ads_crawler"):
        if not config.crawler_verification:
            # Verification disabled by the administrator: trust the claim but
            # still apply the crawler rate limit.
            decision.action = ACTION_ALLOW
            decision.reasons = [f"crawler:claim_unverified:{claimed_bot}"]
            decision.crawler_bot = claimed_bot
            decision.crawler_status = crawler.STATUS_DISABLED
            decision.category = "crawler"
            return decision

        result = crawler.verify_claimed_crawler(input_.ip, claimed_bot, config)
        decision.crawler_bot = claimed_bot
        decision.crawler_status = result.status
        decision.crawler_host = result.hostname
        if result.verified:
            decision.action = ACTION_ALLOW
            decision.verified_crawler = True
            decision.crawler_error = False
            decision.reasons = [f"crawler:verified:{claimed_bot}"]
            decision.category = "crawler"
            return decision

        if result.status == crawler.STATUS_ERROR:
            decision.crawler_error = True
            if config.crawler_fail_open:
                # Never punish Googlebot/Bingbot for a resolver hiccup.
                decision.action = ACTION_ALLOW
                decision.reasons = [f"crawler:dns_error:{claimed_bot}"]
                decision.category = "crawler"
                return decision
            signals.add(
                "crawler",
                f"crawler:dns_error:{claimed_bot}",
                weights["crawler_unverified"],
            )
        elif result.status == crawler.STATUS_UNKNOWN_BOT:
            signals.add(
                "crawler",
                f"crawler:unknown_bot:{claimed_bot}",
                weights["crawler_unverified"],
            )
        else:  # spoofed / no PTR
            if config.challenge_unverified_crawler:
                weight = (
                    weights["crawler_no_ptr"]
                    if result.status == crawler.STATUS_NO_PTR
                    else weights["crawler_spoofed"]
                )
                signals.add(
                    "crawler",
                    f"crawler:{result.status}:{claimed_bot}",
                    weight,
                )
            else:
                decision.reasons = [f"crawler:{result.status}:{claimed_bot}"]
                decision.category = "crawler"

        if signals.items:
            return _finalize(decision, signals, config)

    # -- generic user-agent signals ----------------------------------------
    if ua_info.score:
        weight_key = {
            "empty": "ua_empty",
            "scripted": "ua_scripted",
            "headless": "ua_headless",
            "vuln_scanner": "ua_vuln_scanner",
            "unknown": "ua_unknown",
            "seo_tool": "ua_seo_tool",
            "ai_crawler": "ua_ai_crawler",
        }.get(ua_info.category)
        if weight_key:
            signals.add("ua", ua_info.reasons[0] if ua_info.reasons else "ua:suspicious", weights[weight_key])

    for token in config.blocked_agent_tokens:
        if token and token in (input_.ua or "").lower():
            signals.add("ua", f"ua:blocked_agent:{token}", weights["ua_custom_blocked"])
            break

    # -- path / query scanning ---------------------------------------------
    _path_signals(input_, signals, weights)
    _header_signals(input_, signals, weights)

    # -- behavioural signals ------------------------------------------------
    if input_.not_found_count >= int(config.not_found_limit or 0) and (
        input_.not_found_ratio >= float(config.not_found_ratio or 0)
    ):
        signals.add(
            "not_found",
            f"not_found:scanning:{input_.not_found_count}",
            weights["not_found_ratio"],
        )

    if input_.path_count >= int(config.repeat_path_limit or 0):
        signals.add(
            "repeat",
            f"repeat:same_path:{input_.path_count}",
            weights["repeated_path"],
        )

    if input_.attack:
        signals.add("burst", "burst:traffic_spike", weights["attack_mode"])
        decision.attack = True

    return _finalize(decision, signals, config)


def _finalize(decision: Decision, signals: _Signals, config) -> Decision:
    decision.score = signals.score
    decision.reasons = list(signals.reasons)
    decision.categories = sorted(signals.families)
    decision.category = signals.dominant_category()

    if decision.score < int(config.log_threshold or 0):
        decision.action = ACTION_ALLOW
        return decision

    if decision.verified_visitor:
        # Verified humans browse normally but are still logged if extreme.
        decision.action = ACTION_LOG
        return decision

    block_allowed = bool(config.auto_block)
    if block_allowed and bool(config.require_multiple_signals):
        if len(signals.families) < 2:
            block_allowed = False

    if block_allowed and decision.score >= int(config.block_threshold or 0):
        decision.action = ACTION_BLOCK
        return decision

    if config.challenge_enabled and decision.score >= int(config.challenge_threshold or 0):
        decision.action = ACTION_CHALLENGE
        return decision

    decision.action = ACTION_LOG
    return decision
