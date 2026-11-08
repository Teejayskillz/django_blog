"""Search engine crawler verification (reverse + forward DNS).

The verification rules follow Google's and Bing's published guidance:

1. reverse-resolve the client IP,
2. require the hostname to belong to the crawler's official domain,
3. forward-resolve that hostname and require it to contain the original IP.

Results are cached for ``crawler_dns_ttl`` seconds to keep the request path
cheap. Failures are classified so that a transient resolver problem never
causes a real crawler to be challenged (SEO safety), while a missing PTR or a
domain mismatch is treated as spoofing (fake Googlebot).
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from dataclasses import dataclass

from . import ua
from .cache import get_cache

logger = logging.getLogger("botwall.crawler")

STATUS_VERIFIED = "verified"
STATUS_SPOOFED = "spoofed"
STATUS_ERROR = "error"
STATUS_DISABLED = "disabled"
STATUS_UNKNOWN_BOT = "unknown_bot"
STATUS_NO_PTR = "no_ptr"


@dataclass(frozen=True)
class CrawlerResult:
    bot: str
    verified: bool
    status: str
    hostname: str = ""
    detail: str = ""
    from_cache: bool = False

    @property
    def trusted(self) -> bool:
        return self.verified


def _cache_key(bot: str, ip: str) -> str:
    return f"bw:cv:v2:{bot}:{ip}"


# ---------------------------------------------------------------------------
# DNS primitives (module level so tests can patch them safely)
# ---------------------------------------------------------------------------
def reverse_dns(ip: str) -> str:
    """Return the PTR hostname for ``ip`` or raise ``socket.herror``."""
    hostname, _aliases, _addresses = socket.gethostbyaddr(ip)
    return hostname.rstrip(".").lower()


def forward_dns(hostname: str) -> tuple[str, ...]:
    """Return every address ``hostname`` resolves to."""
    addresses = set()
    for family, _type, _proto, _canon, sockaddr in socket.getaddrinfo(
        hostname, None, 0, socket.SOCK_STREAM
    ):
        if family == socket.AF_INET:
            addresses.add(sockaddr[0])
        elif family == socket.AF_INET6:
            addresses.add(sockaddr[0].split("%")[0])
    return tuple(sorted(addresses))


def _same_ip(candidate: str, ip: str) -> bool:
    try:
        left = ipaddress.ip_address(candidate)
        right = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if left.version != right.version:
        left = getattr(left, "ipv4_mapped", None) or left
        right = getattr(right, "ipv4_mapped", None) or right
    return str(left) == str(right)


def _domain_matches(hostname: str, domains) -> bool:
    for domain in domains:
        domain = domain.lower().strip()
        if not domain:
            continue
        if hostname == domain or hostname.endswith("." + domain):
            return True
    return False


def verify_claimed_crawler(ip, bot_name, config):
    """Verify a client that *claims* to be ``bot_name``.

    Returns ``CrawlerResult``; ``status`` is one of ``verified``,
    ``spoofed``, ``no_ptr``, ``error``, ``disabled``, ``unknown_bot``.
    """
    bot = (bot_name or "").lower()
    if not config.crawler_verification:
        return CrawlerResult(bot=bot, verified=False, status=STATUS_DISABLED)
    if not ip:
        return CrawlerResult(bot=bot, verified=False, status=STATUS_ERROR, detail="no-ip")
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return CrawlerResult(bot=bot, verified=False, status=STATUS_ERROR, detail="bad-ip")
    if not address.is_global:
        # Private / reserved / CGNAT space can never host a search engine.
        return CrawlerResult(
            bot=bot, verified=False, status=STATUS_NO_PTR, detail="non-public-ip"
        )

    domains = ua.crawler_domains(bot, config.crawler_domain_overrides)
    if not domains:
        return CrawlerResult(bot=bot, verified=False, status=STATUS_UNKNOWN_BOT)

    cache = get_cache()
    key = _cache_key(bot, ip)
    cached = cache.get(key)
    if isinstance(cached, dict) and cached.get("status"):
        return CrawlerResult(
            bot=bot,
            verified=bool(cached.get("verified")),
            status=cached["status"],
            hostname=cached.get("hostname", ""),
            detail=cached.get("detail", ""),
            from_cache=True,
        )

    result = _resolve_and_verify(ip, bot, domains)
    ttl = int(config.crawler_dns_ttl or 21600)
    if result.status == STATUS_VERIFIED:
        timeout = max(ttl, 3600)
    elif result.status == STATUS_ERROR:
        timeout = 600  # retry a resolver hiccup soon
    else:
        timeout = min(max(ttl // 4, 900), 7200)
    cache.set(
        key,
        {
            "verified": result.verified,
            "status": result.status,
            "hostname": result.hostname,
            "detail": result.detail,
        },
        timeout,
    )

    if result.status == STATUS_VERIFIED:
        logger.info("botwall: verified crawler %s from %s (%s)", bot, ip, result.hostname)
    else:
        logger.warning(
            "botwall: crawler check failed for %s from %s: %s (%s)",
            bot,
            ip,
            result.status,
            result.detail,
        )
    return result


def _resolve_and_verify(ip: str, bot: str, domains) -> CrawlerResult:
    try:
        hostname = reverse_dns(ip)
    except socket.herror as exc:  # definitive: no PTR record
        return CrawlerResult(
            bot=bot,
            verified=False,
            status=STATUS_NO_PTR,
            detail=f"no-ptr:{exc}",
        )
    except (socket.gaierror, OSError) as exc:  # resolver problem: do not punish
        return CrawlerResult(
            bot=bot,
            verified=False,
            status=STATUS_ERROR,
            detail=f"reverse-dns-error:{exc}",
        )

    if not _domain_matches(hostname, domains):
        return CrawlerResult(
            bot=bot,
            verified=False,
            status=STATUS_SPOOFED,
            hostname=hostname,
            detail="ptr-domain-mismatch",
        )

    try:
        addresses = forward_dns(hostname)
    except (socket.gaierror, OSError) as exc:
        return CrawlerResult(
            bot=bot,
            verified=False,
            status=STATUS_ERROR,
            hostname=hostname,
            detail=f"forward-dns-error:{exc}",
        )

    if not any(_same_ip(candidate, ip) for candidate in addresses):
        return CrawlerResult(
            bot=bot,
            verified=False,
            status=STATUS_SPOOFED,
            hostname=hostname,
            detail="forward-dns-mismatch",
        )

    return CrawlerResult(
        bot=bot,
        verified=True,
        status=STATUS_VERIFIED,
        hostname=hostname,
    )


def clear_cache_for(ip: str):
    """Drop cached DNS verdicts for an IP (used by the admin 'recheck' action)."""
    cache = get_cache()
    for bot in ua.CRAWLER_BOTS:
        cache.delete(_cache_key(bot.name, ip))
