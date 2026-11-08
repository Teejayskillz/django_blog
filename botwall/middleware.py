"""Request inspection middleware.

Placement: directly after ``SecurityMiddleware``/``WhiteNoiseMiddleware`` and
before session/authentication middleware, so blocked or challenged requests
never touch the session store and static files are served without any extra
work. Admin paths and the firewall's own endpoints are exempt from blocking so
the site owner can never lock themselves out.

The middleware never raises into Django's request/response cycle: any failure
inside the firewall fails open and the request continues.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from dataclasses import dataclass, field
from datetime import timedelta

from django.conf import settings
from django.http import HttpResponse
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone

from . import blocking, challenge, conf, crawler, engine, geo, ratelimit, stats, ua
from .cache import get_cache
from .conf import Config
from .ip import get_client_ip

logger = logging.getLogger("botwall.middleware")

STATIC_PREFIXES = ("/static/", "/media/")
NO_INDEX_HEADERS = {
    "X-Robots-Tag": "noindex, nofollow, noarchive, nosnippet",
    "Cache-Control": "no-store, no-cache, must-revalidate, private",
    "Pragma": "no-cache",
    "Referrer-Policy": "no-referrer",
}
CHALLENGE_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
    "connect-src 'self'; form-action 'self'; base-uri 'none'"
)


@dataclass
class RequestContext:
    config: Config
    path: str = "/"
    method: str = "GET"
    ua: str = ""
    ip: str = ""
    limit_key: str = ""
    spoof: bool = False
    request_id: str = ""
    bypass: str = ""
    whitelisted: bool = False
    verified_visitor: bool = False
    verified_crawler: bool = False
    crawler_bot: str = ""
    crawler_status: str = ""
    crawler_host: str = ""
    attack: bool = False
    count: int = 0
    not_found_count: int = 0
    not_found_key: str = ""
    window: int = 60
    path_count: int = 0
    decision: engine.Decision | None = None
    concurrency: ratelimit.ConcurrencyVerdict | None = None
    counted: bool = False
    country: str = ""
    immediate: HttpResponse | None = None
    events: dict = field(default_factory=dict)


class BotWallMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    # -- Django entry point ---------------------------------------------------
    def __call__(self, request):
        try:
            ctx = self._inspect(request)
        except Exception:  # noqa: BLE001 - never break the site
            logger.exception("botwall: inspection failed, allowing request")
            return self.get_response(request)

        if ctx.immediate is not None:
            return ctx.immediate

        try:
            response = self.get_response(request)
        finally:
            self._release(ctx)

        try:
            self._post(request, response, ctx)
        except Exception:  # noqa: BLE001
            logger.exception("botwall: response processing failed")

        return response

    # -- helpers --------------------------------------------------------------
    @staticmethod
    def _release(ctx: RequestContext):
        if ctx.concurrency is not None:
            ctx.concurrency.release()
            ctx.concurrency = None

    @staticmethod
    def _should_count(path: str) -> bool:
        return not path.startswith(STATIC_PREFIXES)

    @staticmethod
    def _normalize_path(raw_path: str) -> str:
        path = (raw_path or "/").split("?")[0][:500]
        while "//" in path:
            path = path.replace("//", "/")
        return path or "/"

    def _inspect(self, request) -> RequestContext:
        config = conf.get_config()
        ctx = RequestContext(
            config=config,
            path=self._normalize_path(request.path),
            method=(request.method or "GET").upper(),
            ua=(request.META.get("HTTP_USER_AGENT") or "")[:1024],
            request_id=secrets.token_hex(8),
        )

        if not getattr(settings, "BOTWALL_ENABLED", True) or not config.enabled:
            ctx.bypass = "disabled"
            return ctx

        if not self._should_count(ctx.path):
            ctx.bypass = "static"
            return ctx

        client = get_client_ip(request)
        ctx.ip = client.address
        ctx.limit_key = client.limit_key
        ctx.spoof = client.spoof_suspect

        # One atomic counter per request; no database writes for normal views.
        stats.record_request(ctx.ip, bool(config.unique_tracking))
        ctx.counted = True

        if config.is_exempt_path(ctx.path):
            ctx.bypass = "exempt"
            return ctx

        rule_check = blocking.evaluate_ip(ctx.ip, config)
        if rule_check.whitelisted:
            ctx.whitelisted = True
            ctx.bypass = "whitelist"
            return ctx
        if rule_check.block is not None:
            if self._crawler_can_bypass(request, ctx, rule_check.block):
                return ctx
            self._apply_block_response(request, ctx, rule_check.block)
            return ctx

        ctx.verified_visitor = challenge.read_verified(request, ctx.ip, ctx.ua, config)
        ctx.country = geo.resolve_country(request, ctx.ip, config)

        window = max(int(config.window_seconds or 60), 1)
        ctx.window = window
        window_id = ratelimit.window_id(window)
        ctx.not_found_key = f"bw:nf:{ctx.limit_key}:{window_id}"
        browse_key = ratelimit.counter_key("browse", ctx.limit_key, window_id)
        values = get_cache().get_many([browse_key, ctx.not_found_key])
        previous_total = int(values.get(browse_key) or 0)
        ctx.not_found_count = int(values.get(ctx.not_found_key) or 0)
        ctx.count = previous_total + 1
        ratio = ctx.not_found_count / max(ctx.count, 1)

        ctx.path_count = int(
            get_cache().incr(
                f"bw:path:{ctx.limit_key}:{self._path_hash(ctx.path)}:{window_id}",
                1,
                max(window * 2, 60),
            )
        )

        ctx.attack = stats.attack_mode(config)

        decision = engine.evaluate(
            engine.Input(
                ua=ctx.ua,
                path=ctx.path,
                method=ctx.method,
                query=(request.META.get("QUERY_STRING") or "")[:1000],
                accept=request.META.get("HTTP_ACCEPT", ""),
                accept_language=request.META.get("HTTP_ACCEPT_LANGUAGE", ""),
                ip=ctx.ip,
                spoof_suspect=ctx.spoof,
                verified_visitor=ctx.verified_visitor,
                frequency=ctx.count,
                path_count=ctx.path_count,
                not_found_count=ctx.not_found_count,
                not_found_ratio=ratio,
                attack=ctx.attack,
            ),
            config,
        )
        ctx.decision = decision
        ctx.verified_crawler = decision.verified_crawler
        ctx.crawler_bot = decision.crawler_bot
        ctx.crawler_status = decision.crawler_status
        ctx.crawler_host = decision.crawler_host

        # --- rate limiting ---------------------------------------------------
        profile, limit = self._profile(ctx, config)
        factor = float(config.attack_limit_factor or 1.0) if ctx.attack else 1.0
        if ctx.verified_visitor:
            factor *= max(float(config.verified_multiplier or 1.0), 1.0)
        verdict = ratelimit.check(ctx.limit_key, profile, limit, window, factor=factor)
        burst = ratelimit.RateVerdict(True, "burst", 0, 0, 0)
        if profile != "crawler":
            burst = ratelimit.check(
                ctx.limit_key,
                "burst",
                int(config.burst_limit or 0),
                int(config.burst_window_seconds or 10),
                factor=factor,
            )

        # --- concurrency -----------------------------------------------------
        concurrency_limit = int(config.max_concurrent or 0)
        if ctx.verified_crawler:
            concurrency_limit *= 2
        ctx.concurrency = ratelimit.acquire_concurrency(ctx.limit_key, concurrency_limit)
        if not ctx.concurrency.allowed:
            ctx.concurrency.release()
            ctx.concurrency = None

        ctx.events = {
            "rate": verdict,
            "burst": burst,
            "profile": profile,
        }

        if verdict.exceeded or burst.exceeded:
            self._handle_rate_limit(request, ctx, verdict, burst)
            return ctx

        if ctx.verified_crawler:
            # Verified search engines are never challenged or banned.
            return ctx

        if ctx.concurrency is None and concurrency_limit > 0:
            self._handle_concurrency(request, ctx)
            return ctx

        if decision.action == engine.ACTION_BLOCK:
            reason = "; ".join(decision.reasons) or "suspicious request"
            self._auto_block(request, ctx, decision, reason, decision.category, status=403)
            return ctx

        if decision.action == engine.ACTION_CHALLENGE:
            self._serve_challenge(request, ctx)
            return ctx

        if decision.suspicious:
            self._log_decision(ctx, request, action="logged", status_code=None)
        return ctx

    # -- decisions ------------------------------------------------------------
    def _profile(self, ctx: RequestContext, config) -> tuple[str, int]:
        if ctx.verified_crawler:
            return "crawler", int(config.crawler_limit or 0)
        if ctx.method not in ("GET", "HEAD", "OPTIONS"):
            return "sensitive", int(config.sensitive_limit or 0)
        if config.is_sensitive_path(ctx.path.lower()):
            return "sensitive", int(config.sensitive_limit or 0)
        return "browse", int(config.browse_limit or 0)

    @staticmethod
    def _path_hash(path: str) -> str:
        return hashlib.blake2b(path.encode("utf-8", "ignore"), digest_size=8).hexdigest()

    def _crawler_can_bypass(self, request, ctx: RequestContext, block) -> bool:
        """Verified crawlers override automatic bans, never manual ones."""
        info = ua.analyze(ctx.ua)
        if info.claimed_kind not in ("search_engine", "ads_crawler") or not info.claimed_bot:
            return False
        if block.permanent and block.source == "manual":
            return False
        result = crawler.verify_claimed_crawler(ctx.ip, info.claimed_bot, ctx.config)
        if not result.verified:
            return False
        ctx.verified_crawler = True
        ctx.crawler_bot = info.claimed_bot
        ctx.crawler_status = result.status
        ctx.crawler_host = result.hostname
        ctx.bypass = "verified_crawler"
        if ctx.config.log_verified_crawlers:
            self._log_decision(
                ctx,
                request,
                action="allowed",
                override_category="crawler",
                reasons=[f"crawler:verified:{info.claimed_bot}", "crawler:auto_block_bypassed"],
                status_code=None,
            )
        logger.warning(
            "botwall: verified crawler %s (%s) bypassed an automatic block",
            info.claimed_bot,
            ctx.ip,
        )
        return True

    def _handle_rate_limit(self, request, ctx: RequestContext, verdict, burst):
        config = ctx.config
        stats.record_rate_limited()
        violations = ratelimit.note_violation(ctx.limit_key)
        exceeded = burst if burst.exceeded else verdict
        reason = (
            f"rate_limit:{exceeded.profile}:{exceeded.count}/{exceeded.limit} "
            f"in {exceeded.window}s"
        )
        ctx.events["violations"] = violations

        if ctx.verified_crawler:
            self._log_decision(
                ctx,
                request,
                action="rate_limited",
                override_category="rate_limit",
                reasons=[reason, f"crawler:verified:{ctx.crawler_bot}"],
                status_code=429,
            )
            ctx.immediate = self._too_many(request, ctx, exceeded.retry_after)
            return

        if config.challenge_enabled and violations <= int(config.violation_block_after or 0):
            # Progressive restriction: first violations get a challenge, not a ban.
            self._serve_challenge(request, ctx, reason=[reason])
            return

        if config.auto_block:
            decision = ctx.decision or engine.Decision()
            decision.action = engine.ACTION_RATE_LIMIT
            decision.reasons = list(decision.reasons) + [reason]
            decision.category = "rate_limit"
            decision.score = max(decision.score, 50)
            self._auto_block(
                request,
                ctx,
                decision,
                reason,
                "rate_limit",
                status=429,
                retry_after=exceeded.retry_after,
            )
            return

        self._log_decision(
            ctx,
            request,
            action="rate_limited",
            override_category="rate_limit",
            reasons=[reason],
            status_code=429,
        )
        ctx.immediate = self._too_many(request, ctx, exceeded.retry_after)

    def _handle_concurrency(self, request, ctx: RequestContext):
        stats.record_rate_limited()
        violations = ratelimit.note_violation(ctx.limit_key)
        reason = f"concurrency:{ctx.config.max_concurrent}"
        if ctx.config.challenge_enabled and violations <= int(ctx.config.violation_block_after or 0):
            self._serve_challenge(request, ctx, reason=[reason])
            return
        if ctx.config.auto_block:
            decision = ctx.decision or engine.Decision()
            decision.action = engine.ACTION_RATE_LIMIT
            decision.reasons = list(decision.reasons) + [reason]
            decision.category = "concurrency"
            self._auto_block(
                request, ctx, decision, reason, "concurrency", status=429, retry_after=5
            )
            return
        self._log_decision(
            ctx,
            request,
            action="rate_limited",
            override_category="concurrency",
            reasons=[reason],
            status_code=429,
        )
        ctx.immediate = self._too_many(request, ctx, 5)

    def _auto_block(self, request, ctx, decision, reason, category, status=403, retry_after=0):
        strikes = blocking.note_strike(ctx.ip)
        minutes = blocking.ban_minutes(strikes, ctx.config)
        rule = blocking.block_ip(
            ctx.ip,
            reason,
            minutes=minutes,
            source="auto",
            strike_level=strikes,
        )
        stats.record_blocked()
        expires_at = None
        if rule is not None:
            expires_at = rule.expires_at
        elif ctx.config.temp_ban_minutes:
            expires_at = timezone.now() + timedelta(minutes=minutes)
        self._log_decision(
            ctx,
            request,
            action="blocked",
            override_category=category,
            reasons=[reason],
            status_code=status,
            block_expires_at=expires_at,
        )
        if status == 429:
            ctx.immediate = self._too_many(request, ctx, minutes * 60, blocked=True)
        else:
            ctx.immediate = self._block_page(request, ctx, minutes * 60)

    # -- logging --------------------------------------------------------------
    def _log_decision(
        self,
        ctx: RequestContext,
        request,
        action: str,
        override_category=None,
        reasons=None,
        status_code=None,
        block_expires_at=None,
    ):
        config = ctx.config
        if not config.log_suspicious:
            return None
        decision = ctx.decision or engine.Decision()
        reasons = list(reasons or decision.reasons)
        category = override_category or decision.category or "ua"
        minute = stats.current_minute()
        cap = int(config.event_log_cap or 0)
        if cap > 0:
            count = int(get_cache().incr(f"bw:lg:{ctx.ip}:{minute}", 1, 180))
            if count > cap:
                return None

        from .models import SecurityEvent

        event = SecurityEvent(
            ip=ctx.ip or "0.0.0.0",
            method=ctx.method[:10],
            path=(ctx.path or "/")[:500],
            query_string=(request.META.get("QUERY_STRING") or "")[:500],
            status_code=status_code,
            user_agent=(ctx.ua or "")[:500],
            referer=(request.META.get("HTTP_REFERER") or "")[:500],
            category=category,
            action=action,
            score=min(int(decision.score or 0), 255),
            request_count=int(ctx.count or 0),
            bot_name=(ctx.crawler_bot or "")[:64],
            is_verified_bot=bool(ctx.verified_crawler),
            country=(ctx.country or "")[:2],
            request_id=ctx.request_id[:32],
            block_expires_at=block_expires_at,
        )
        event.set_reasons(reasons)
        try:
            event.save()
        except Exception as exc:  # noqa: BLE001 - logging must never break a request
            logger.warning("botwall: could not store security event: %s", exc)
            return None
        return event

    def _post(self, request, response, ctx: RequestContext):
        if not ctx.counted or ctx.bypass in ("disabled", "static"):
            return
        if response is not None and response.status_code == 404 and ctx.not_found_key:
            get_cache().incr(ctx.not_found_key, 1, max(ctx.window * 2, 60))
        if ctx.bypass == "verified_crawler" and ctx.config.log_verified_crawlers:
            self._log_decision(
                ctx,
                request,
                action="allowed",
                override_category="crawler",
                reasons=[f"crawler:verified:{ctx.crawler_bot}"],
                status_code=getattr(response, "status_code", None),
            )
        self._maybe_maintenance()

    def _maybe_maintenance(self):
        cache = get_cache()
        try:
            if cache.add("bw:lock:flush", 1, 300):
                stats.flush_recent()
        except Exception:  # noqa: BLE001
            logger.debug("botwall: stats flush skipped", exc_info=True)
        try:
            config = conf.get_config()
            if config.cleanup_enabled:
                interval = max(int(config.cleanup_interval_hours or 6), 1) * 3600
                if cache.add("bw:lock:cleanup", 1, interval):
                    from .maintenance import cleanup_retention

                    cleanup_retention(config)
        except Exception:  # noqa: BLE001
            logger.debug("botwall: cleanup skipped", exc_info=True)

    # -- responses ------------------------------------------------------------
    def _next_url(self, request) -> str:
        full_path = request.get_full_path()[:500]
        if full_path.startswith("/") and not full_path.startswith("//"):
            return full_path
        return "/"

    def _serve_challenge(self, request, ctx: RequestContext, reason=None):
        config = ctx.config
        limit = ratelimit.check(
            ctx.limit_key, "challenge", int(config.challenge_limit or 0), ctx.window
        )
        if limit.exceeded:
            self._log_decision(
                ctx,
                request,
                action="rate_limited",
                override_category="challenge",
                reasons=list(reason or []) + [f"challenge:{limit.count}/{limit.limit}"],
                status_code=429,
            )
            stats.record_rate_limited()
            ctx.immediate = self._too_many(request, ctx, limit.retry_after)
            return

        reasons = list(reason or [])
        if ctx.decision is not None:
            reasons = reasons + list(ctx.decision.reasons)
        try:
            issued = challenge.issue(ctx.ip, ctx.ua, config)
        except Exception:  # noqa: BLE001 - cannot sign: fail safe with 429
            logger.exception("botwall: cannot issue challenge")
            ctx.immediate = self._too_many(request, ctx, 60)
            return

        stats.record_challenge()
        self._log_decision(
            ctx,
            request,
            action="challenged",
            override_category="challenge",
            reasons=reasons or ["challenge:requested"],
            status_code=200,
        )
        context = {
            "token": issued.token,
            "difficulty": issued.difficulty,
            "expires_in": issued.expires_in,
            "verify_url": reverse("botwall:challenge_verify"),
            "next_url": self._next_url(request),
            "brand": getattr(settings, "BOTWALL_CHALLENGE_BRAND", "") or request.get_host(),
            "reason_code": (reasons[0] if reasons else "suspicious_traffic"),
        }
        html = render_to_string("botwall/challenge.html", context)
        response = HttpResponse(html, status=200, content_type="text/html; charset=utf-8")
        for header, value in NO_INDEX_HEADERS.items():
            response[header] = value
        response["Content-Security-Policy"] = CHALLENGE_CSP
        response["Vary"] = "User-Agent, Cookie"
        ctx.immediate = response

    def _too_many(self, request, ctx: RequestContext, retry_after: int = 60, blocked=False):
        template = "botwall/blocked.html" if blocked else "botwall/too_many.html"
        context = {
            "brand": getattr(settings, "BOTWALL_CHALLENGE_BRAND", "") or request.get_host(),
            "retry_after": int(max(retry_after, 1)),
            "blocked_until": (timezone.now() + timedelta(seconds=max(retry_after, 1)))
            if blocked
            else None,
            "contact": getattr(settings, "BOTWALL_CONTACT_EMAIL", ""),
        }
        html = render_to_string(template, context)
        response = HttpResponse(html, status=429, content_type="text/html; charset=utf-8")
        for header, value in NO_INDEX_HEADERS.items():
            response[header] = value
        response["Retry-After"] = str(int(max(retry_after, 1)))
        response["Vary"] = "User-Agent"
        return response

    def _block_page(self, request, ctx: RequestContext, retry_after: int = 0):
        context = {
            "brand": getattr(settings, "BOTWALL_CHALLENGE_BRAND", "") or request.get_host(),
            "blocked_until": (timezone.now() + timedelta(seconds=retry_after))
            if retry_after
            else None,
            "retry_after": int(max(retry_after, 0)),
            "contact": getattr(settings, "BOTWALL_CONTACT_EMAIL", ""),
            "ip": ctx.ip,
        }
        html = render_to_string("botwall/blocked.html", context)
        response = HttpResponse(html, status=403, content_type="text/html; charset=utf-8")
        for header, value in NO_INDEX_HEADERS.items():
            response[header] = value
        if retry_after:
            response["Retry-After"] = str(int(retry_after))
        response["Vary"] = "User-Agent"
        return response

    def _apply_block_response(self, request, ctx: RequestContext, block):
        stats.record_blocked()
        blocking.note_hit(block)
        self._log_decision(
            ctx,
            request,
            action="blocked",
            override_category="blocklist",
            reasons=[f"blocklist:{block.source}", block.reason or "blocked"],
            status_code=403,
            block_expires_at=block.expires_at,
        )
        ctx.immediate = self._block_page(request, ctx, block.retry_after)
