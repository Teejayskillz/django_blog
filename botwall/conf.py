"""Runtime configuration: database values with safe code defaults.

The configuration is cached in-process for ``BOTWALL_CONFIG_CACHE_SECONDS``
(default 20s). Admin changes are visible to the process that made them
immediately (the settings signal invalidates the cache) and to other worker
processes within a few seconds.

If the database cannot be read (missing migration, outage) the code defaults
from :mod:`botwall.defaults` are used and the error is logged once, so the
website keeps serving.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Mapping

from django.conf import settings

from . import ua
from .defaults import DEFAULTS
from .ip import parse_network_list

logger = logging.getLogger("botwall.conf")

CACHE_SECONDS = float(getattr(settings, "BOTWALL_CONFIG_CACHE_SECONDS", 20))
DEFAULTS_TTL = float(getattr(settings, "BOTWALL_DEFAULTS_CACHE_SECONDS", 30))


@dataclass(frozen=True)
class Config:
    """Immutable, parsed view of the settings table."""

    values: Mapping[str, Any] = field(default_factory=dict)
    exempt_prefixes: tuple[str, ...] = ()
    exempt_regexes: tuple[Any, ...] = ()
    sensitive_regexes: tuple[Any, ...] = ()
    blocked_networks: tuple[Any, ...] = ()
    blocked_agent_tokens: tuple[str, ...] = ()
    crawler_domain_overrides: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    extra_crawlers: tuple[tuple[str, tuple[str, ...]], ...] = ()
    from_database: bool = False

    def __getattr__(self, item):
        # Attribute access proxies the raw settings (config.browse_limit, ...).
        try:
            return self.values[item]
        except KeyError:
            raise AttributeError(item) from None

    # -- convenience helpers --------------------------------------------------
    def get(self, name, default=None):
        return self.values.get(name, default)

    @property
    def challenge_enabled_effective(self):
        return bool(self.values.get("enabled")) and bool(self.values.get("challenge_enabled"))

    def is_exempt_path(self, path: str) -> bool:
        if not path:
            return False
        for prefix in self.exempt_prefixes:
            if path.startswith(prefix):
                return True
        for regex in self.exempt_regexes:
            if regex.match(path):
                return True
        return False

    def is_sensitive_path(self, path: str) -> bool:
        for regex in self.sensitive_regexes:
            if regex.search(path):
                return True
        return False


def _lines(text: str) -> list[str]:
    result = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        result.append(line)
    return result


def parse_exempt_paths(text: str):
    prefixes: list[str] = []
    regexes: list[Any] = []
    for line in _lines(text):
        if line.startswith("^") or line.startswith(r"\^"):
            try:
                regexes.append(re.compile(line))
            except re.error:
                logger.warning("botwall: invalid exempt-path regex %r", line)
            continue
        if line.startswith("/"):
            prefixes.append(line)
            continue
        try:
            regexes.append(re.compile(line))
        except re.error:
            logger.warning("botwall: invalid exempt path %r", line)
    return tuple(prefixes), tuple(regexes)


def compile_patterns(text: str):
    patterns = []
    for line in _lines(text):
        try:
            patterns.append(re.compile(line))
        except re.error:
            logger.warning("botwall: invalid regular expression %r", line)
    return tuple(patterns)


def parse_crawler_overrides(text: str):
    """Parse ``ua-token: domain1, domain2`` lines."""
    result: dict[str, tuple[str, ...]] = {}
    for line in _lines(text):
        if ":" not in line:
            logger.warning("botwall: invalid crawler override %r", line)
            continue
        name, _, rest = line.partition(":")
        name = name.strip().lower()
        domains = tuple(part.strip().lower() for part in rest.split(",") if part.strip())
        if name and domains:
            result[name] = domains
    return result


def parse_extra_crawlers(text: str):
    """Parse additional trusted crawler UA tokens (``token: domains``)."""
    result = []
    for token, domains in parse_crawler_overrides(text).items():
        result.append((token, domains))
    return tuple(result)


def build_config(values: Mapping[str, Any], from_database: bool = False) -> Config:
    merged = dict(DEFAULTS)
    merged.update({key: value for key, value in values.items() if key in DEFAULTS})
    prefixes, regexes = parse_exempt_paths(merged["exempt_paths"])
    overrides = parse_crawler_overrides(merged["trusted_crawler_domains"])
    return Config(
        values=merged,
        exempt_prefixes=prefixes,
        exempt_regexes=regexes,
        sensitive_regexes=compile_patterns(merged["sensitive_paths"]),
        blocked_networks=parse_network_list(merged["blocked_networks"]),
        blocked_agent_tokens=tuple(
            line.lower() for line in _lines(merged["blocked_agents"])
        ),
        crawler_domain_overrides=overrides,
        extra_crawlers=parse_extra_crawlers(merged["extra_trusted_crawlers"]),
        from_database=from_database,
    )


DEFAULT_CONFIG = build_config({})


_state: dict[str, Any] = {"config": None, "expires": 0.0}


def get_config(force: bool = False) -> Config:
    now = time.monotonic()
    cached = _state.get("config")
    if not force and cached is not None and now < _state.get("expires", 0.0):
        return cached

    values: dict[str, Any] = {}
    try:
        from .models import BotWallSettings

        obj = BotWallSettings.load()
        for name in DEFAULTS:
            values[name] = getattr(obj, name)
        config = build_config(values, from_database=True)
        ttl = CACHE_SECONDS
    except Exception as exc:  # noqa: BLE001 - migrations may not have run yet
        logger.debug("botwall: using code defaults (%s: %s)", type(exc).__name__, exc)
        config = DEFAULT_CONFIG
        ttl = DEFAULTS_TTL

    _state["config"] = config
    _state["expires"] = time.monotonic() + ttl
    return config


def invalidate_config():
    _state["config"] = None
    _state["expires"] = 0.0


def get_weights() -> dict[str, int]:
    weights = dict(DEFAULT_WEIGHTS)
    overrides = getattr(settings, "BOTWALL_WEIGHTS", None)
    if isinstance(overrides, dict):
        for key, value in overrides.items():
            if key in weights:
                try:
                    weights[key] = int(value)
                except (TypeError, ValueError):
                    logger.warning("botwall: ignoring invalid weight %r=%r", key, value)
    return weights


# Detection signal weights. Tunable through ``settings.BOTWALL_WEIGHTS`` but not
# through the admin (thresholds are in the admin, weights are an advanced knob).
DEFAULT_WEIGHTS = {
    "ua_empty": 15,
    "ua_scripted": 40,
    "ua_headless": 35,
    "ua_vuln_scanner": 65,
    "ua_unknown": 10,
    "ua_seo_tool": 20,
    "ua_ai_crawler": 5,
    "ua_custom_blocked": 65,
    "ua_missing_language": 5,
    "crawler_spoofed": 70,
    "crawler_unverified": 25,
    "crawler_no_ptr": 70,
    "path_bad_extension": 30,
    "path_traversal": 45,
    "path_probe": 35,
    "path_long": 15,
    "path_many_params": 15,
    "not_found_ratio": 40,
    "not_found_count": 15,
    "repeated_path": 35,
    "method_unusual": 25,
    "header_spoof": 30,
    "attack_mode": 15,
}


def crawler_domains_for(config: Config, bot_name: str) -> tuple[str, ...]:
    """Domains used for DNS verification, including admin overrides."""
    return ua.crawler_domains(bot_name, config.crawler_domain_overrides)


def reset_caches():
    """Test helper: drop every in-process cache owned by this module."""
    invalidate_config()
    ua.reset_cache()
