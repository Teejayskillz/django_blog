"""User-Agent analysis.

User-Agent strings are a *signal*, never an identity: the engine combines this
module with DNS verification (``botwall.crawler``) before trusting a client
that claims to be Googlebot/Bingbot.

Results are cached in-process because the same handful of UA strings repeat
for every visitor and the parsing runs for every request.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import NamedTuple

logger = logging.getLogger("botwall.ua")

MAX_UA_LENGTH = 1024
_CACHE_LIMIT = 2048
_cache: dict[str, "UAInfo"] = {}


class CrawlerBot(NamedTuple):
    name: str
    tokens: tuple[str, ...]
    domains: tuple[str, ...]
    kind: str  # search_engine | ads_crawler | social_preview | ai_crawler | seo_tool


# Ordered: more specific tokens first. ``googlebot`` must come before
# ``googleother`` and ``adsbot`` before ``googlebot``-like fallbacks.
CRAWLER_BOTS: tuple[CrawlerBot, ...] = (
    # --- search engines / their inspection tools --------------------------
    CrawlerBot("adsbot-google-mobile", ("adsbot-google-mobile",), ("google.com", "googlebot.com"), "ads_crawler"),
    CrawlerBot("adsbot-google", ("adsbot-google",), ("google.com", "googlebot.com"), "ads_crawler"),
    CrawlerBot("mediapartners-google", ("mediapartners-google",), ("google.com", "googlebot.com"), "ads_crawler"),
    CrawlerBot("google-inspectiontool", ("google-inspectiontool",), ("googlebot.com", "google.com"), "search_engine"),
    CrawlerBot("storebot-google", ("storebot-google",), ("googlebot.com", "google.com"), "search_engine"),
    CrawlerBot("googleother", ("googleother",), ("googlebot.com", "google.com"), "search_engine"),
    CrawlerBot("googlebot", ("googlebot",), ("googlebot.com", "google.com"), "search_engine"),
    CrawlerBot("bingpreview", ("bingpreview",), ("search.msn.com", "bing.com"), "search_engine"),
    CrawlerBot("bingbot", ("bingbot",), ("search.msn.com", "cn.bing.com", "bing.com"), "search_engine"),
    CrawlerBot("duckduckbot", ("duckduckbot", "duckduckgo"), ("duckduckgo.com",), "search_engine"),
    CrawlerBot("baiduspider", ("baiduspider",), ("baidu.com", "baidu.jp"), "search_engine"),
    CrawlerBot("yandexbot", ("yandexbot",), ("yandex.com", "yandex.ru", "yandex.net"), "search_engine"),
    CrawlerBot("applebot", ("applebot",), ("applebot.apple.com", "apple.com"), "search_engine"),
    CrawlerBot("slurp", ("slurp",), ("crawl.yahoo.net", "yahoo.com"), "search_engine"),
    CrawlerBot("sogou", ("sogou",), ("sogou.com",), "search_engine"),
    CrawlerBot("seznambot", ("seznambot",), ("seznam.cz",), "search_engine"),
    # --- social / link previews -------------------------------------------
    CrawlerBot("facebookexternalhit", ("facebookexternalhit",), ("facebook.com", "fbs1-1.fbs1.com"), "social_preview"),
    CrawlerBot("facebookbot", ("facebookbot",), ("facebook.com",), "social_preview"),
    CrawlerBot("twitterbot", ("twitterbot",), ("twitter.com", "x.com"), "social_preview"),
    CrawlerBot("linkedinbot", ("linkedinbot",), ("linkedin.com",), "social_preview"),
    CrawlerBot("whatsapp", ("whatsapp/",), ("whatsapp.com",), "social_preview"),
    CrawlerBot("telegrambot", ("telegrambot",), ("telegram.org",), "social_preview"),
    CrawlerBot("slackbot", ("slackbot",), ("slack.com",), "social_preview"),
    CrawlerBot("discordbot", ("discordbot",), ("discordapp.com", "discord.com"), "social_preview"),
    CrawlerBot("pinterestbot", ("pinterestbot", "pinterest/"), ("pinterest.com",), "social_preview"),
    CrawlerBot("embedly", ("embedly",), ("embedly.com",), "social_preview"),
    # --- AI crawlers -------------------------------------------------------
    CrawlerBot("gptbot", ("gptbot",), ("openai.com",), "ai_crawler"),
    CrawlerBot("oai-searchbot", ("oai-searchbot",), ("openai.com",), "ai_crawler"),
    CrawlerBot("chatgpt-user", ("chatgpt-user",), ("openai.com",), "ai_crawler"),
    CrawlerBot("claudebot", ("claudebot", "claude-web", "anthropic-ai"), ("anthropic.com",), "ai_crawler"),
    CrawlerBot("ccbot", ("ccbot",), ("commoncrawl.org",), "ai_crawler"),
    CrawlerBot("bytespider", ("bytespider",), ("bytedance.com",), "ai_crawler"),
    CrawlerBot("perplexitybot", ("perplexitybot",), ("perplexity.ai",), "ai_crawler"),
    CrawlerBot("meta-externalagent", ("meta-externalagent",), ("meta.com", "facebook.com"), "ai_crawler"),
    CrawlerBot("cohere-ai", ("cohere-ai",), ("cohere.com",), "ai_crawler"),
    CrawlerBot("diffbot", ("diffbot",), ("diffbot.com",), "ai_crawler"),
    CrawlerBot("youbot", ("youbot",), ("you.com",), "ai_crawler"),
    # --- aggressive commercial SEO crawlers --------------------------------
    CrawlerBot("ahrefsbot", ("ahrefsbot",), ("ahrefs.com",), "seo_tool"),
    CrawlerBot("semrushbot", ("semrushbot",), ("semrush.com",), "seo_tool"),
    CrawlerBot("mj12bot", ("mj12bot",), ("majestic12.co.uk",), "seo_tool"),
    CrawlerBot("dotbot", ("dotbot",), ("moz.com",), "seo_tool"),
    CrawlerBot("blexbot", ("blexbot",), ("webmeup.com",), "seo_tool"),
    CrawlerBot("dataforseobot", ("dataforseobot",), ("dataforseo.com",), "seo_tool"),
    CrawlerBot("serpstatbot", ("serpstatbot",), ("serpstat.com",), "seo_tool"),
    CrawlerBot("screaming frog", ("screaming frog",), ("screamingfrog.co.uk",), "seo_tool"),
    CrawlerBot("petalbot", ("petalbot",), ("petalbot",), "seo_tool"),
    CrawlerBot("barkrowler", ("barkrowler",), ("babbar.tech",), "seo_tool"),
    CrawlerBot("megalodon", ("megalodon",), ("megalodon.jp",), "seo_tool"),
    CrawlerBot("siteauditbot", ("siteauditbot",), ("siteauditbot.com",), "seo_tool"),
)

_BOT_BY_NAME = {bot.name: bot for bot in CRAWLER_BOTS}

# Tokens that indicate an automated HTTP client rather than a browser.
SCRIPTED_CLIENTS: tuple[tuple[str, str], ...] = (
    ("python-requests", "python-requests"),
    ("python-urllib", "python-urllib"),
    ("python-httpx", "httpx"),
    ("httpx/", "httpx"),
    ("aiohttp", "aiohttp"),
    ("curl/", "curl"),
    ("wget/", "wget"),
    ("libwww-perl", "libwww-perl"),
    ("httpclient", "apache-httpclient"),
    ("okhttp", "okhttp"),
    ("go-http-client", "go-http-client"),
    ("go-resty", "go-resty"),
    ("java/", "java"),
    ("postmanruntime", "postman"),
    ("insomnia/", "insomnia"),
    ("axios/", "axios"),
    ("node-fetch", "node-fetch"),
    ("undici", "undici"),
    ("scrapy/", "scrapy"),
    ("mechanize", "mechanize"),
    ("php/", "php"),
    ("guzzlehttp", "guzzle"),
    ("restsharp", "restsharp"),
    ("winhttp", "winhttp"),
    ("powershell", "powershell"),
    ("dart/", "dart"),
    ("reqwest", "reqwest"),
    ("faraday", "faraday"),
    ("ruby", "ruby"),
    ("http.rb", "http.rb"),
    ("perl", "perl"),
)

HEADLESS_TOKENS: tuple[tuple[str, str], ...] = (
    ("headlesschrome", "headless-chrome"),
    ("phantomjs", "phantomjs"),
    ("slimerjs", "slimerjs"),
    ("puppeteer", "puppeteer"),
    ("playwright", "playwright"),
    ("selenium", "selenium"),
    ("htmlunit", "htmlunit"),
    ("nightmare", "nightmare"),
    ("jsdom", "jsdom"),
    ("electron/", "electron"),
)

SCANNER_TOKENS: tuple[tuple[str, str], ...] = (
    ("sqlmap", "sqlmap"),
    ("nikto", "nikto"),
    ("nmap", "nmap"),
    ("masscan", "masscan"),
    ("zgrab", "zgrab"),
    ("nuclei", "nuclei"),
    ("wpscan", "wpscan"),
    ("dirbuster", "dirbuster"),
    ("gobuster", "gobuster"),
    ("ffuf", "ffuf"),
    ("feroxbuster", "feroxbuster"),
    ("acunetix", "acunetix"),
    ("netsparker", "netsparker"),
    ("burpsuite", "burpsuite"),
    ("burp collaborator", "burp"),
    ("zaproxy", "owasp-zap"),
    ("w3af", "w3af"),
    ("whatweb", "whatweb"),
    ("joomscan", "joomscan"),
    ("openvas", "openvas"),
    ("crawlergo", "crawlergo"),
    ("jorgee", "jorgee"),
    ("xray/", "xray"),
)

BROWSER_TOKENS = ("chrome/", "firefox/", "safari/", "edg/", "opr/", "opera/", "msie ")


@dataclass(frozen=True)
class UAInfo:
    raw: str
    category: str
    label: str
    is_browser: bool = False
    claimed_bot: str | None = None
    claimed_kind: str | None = None
    scripted_client: str | None = None
    headless: str | None = None
    scanner: str | None = None
    score: int = 0
    reasons: tuple[str, ...] = ()

    @property
    def claims_crawler(self) -> bool:
        return self.claimed_bot is not None


def _match_tokens(lowered: str, catalog):
    for token, label in catalog:
        if token in lowered:
            return token, label
    return None, None


def analyze(user_agent: str) -> UAInfo:
    """Classify a User-Agent string (never trust the claim, just record it)."""
    raw = (user_agent or "").strip()
    key = raw[:MAX_UA_LENGTH]
    cached = _cache.get(key)
    if cached is not None:
        return cached

    info = _analyze_uncached(key)
    if len(_cache) > _CACHE_LIMIT:
        _cache.clear()
    _cache[key] = info
    return info


def _analyze_uncached(ua: str) -> UAInfo:
    if not ua:
        return UAInfo(
            raw=ua,
            category="empty",
            label="empty user-agent",
            score=15,
            reasons=("ua:empty",),
        )

    lowered = ua.lower()

    # Attack tools usually keep their name in the UA; check those first so a
    # "Mozilla/5.0 sqlmap" string is not mistaken for a browser.
    _, scanner = _match_tokens(lowered, SCANNER_TOKENS)
    if scanner:
        return UAInfo(
            raw=ua,
            category="vuln_scanner",
            label=scanner,
            scanner=scanner,
            score=65,
            reasons=(f"ua:vuln_scanner:{scanner}",),
        )

    _, scripted = _match_tokens(lowered, SCRIPTED_CLIENTS)
    _, headless = _match_tokens(lowered, HEADLESS_TOKENS)

    # Claimed crawler identity (verified later via DNS by the engine).
    for bot in CRAWLER_BOTS:
        if any(token in lowered for token in bot.tokens):
            score = {
                "search_engine": 0,
                "ads_crawler": 0,
                "social_preview": 0,
                "ai_crawler": 5,
                "seo_tool": 20,
            }.get(bot.kind, 10)
            reasons = ()
            if bot.kind == "ai_crawler":
                reasons = ("ua:ai_crawler",)
            elif bot.kind == "seo_tool":
                reasons = ("ua:seo_tool",)
            return UAInfo(
                raw=ua,
                category=bot.kind,
                label=bot.name,
                claimed_bot=bot.name,
                claimed_kind=bot.kind,
                score=score,
                reasons=reasons,
            )

    if scripted or headless:
        score = 0
        reasons = []
        if scripted:
            score += 40
            reasons.append(f"ua:scripted:{scripted}")
        if headless:
            score += 35
            reasons.append(f"ua:headless:{headless}")
        return UAInfo(
            raw=ua,
            category="headless" if headless else "scripted",
            label=headless or scripted or "automated client",
            scripted_client=scripted,
            headless=headless,
            score=min(score, 75),
            reasons=tuple(reasons),
        )

    if "mozilla/" in lowered and any(token in lowered for token in BROWSER_TOKENS):
        return UAInfo(raw=ua, category="browser", label="browser", is_browser=True)

    # Something custom: not a browser, not a known bot.
    return UAInfo(
        raw=ua,
        category="unknown",
        label="unknown client",
        score=10,
        reasons=("ua:unknown",),
    )


def crawler_bot(name: str):
    return _BOT_BY_NAME.get((name or "").lower())


def crawler_domains(name: str, overrides: dict | None = None) -> tuple[str, ...]:
    if overrides:
        custom = overrides.get((name or "").lower())
        if custom:
            return tuple(custom)
    bot = crawler_bot(name)
    if bot is None:
        return ()
    return bot.domains


def reset_cache():
    """Used by tests and by long-running processes after config changes."""
    _cache.clear()
