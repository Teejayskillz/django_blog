"""Optional, privacy friendly country resolution.

Two reliable sources are supported:

1. ``CF-IPCountry`` sent by Cloudflare - only honoured when the TCP peer is a
   configured trusted proxy (otherwise the header is spoofable).
2. A local MaxMind GeoLite2 database when the optional ``geoip2`` package and
   the ``BOTWALL_GEOIP2_DB`` setting are present.

No outbound HTTP lookups are made: visitor IPs are never sent to a third party.
"""

from __future__ import annotations

import logging
import re
from functools import lru_cache

from django.conf import settings

from .cache import get_cache
from .ip import is_trusted_proxy

logger = logging.getLogger("botwall.geo")

_COUNTRY_RE = re.compile(r"^[A-Z]{2}$")
_reader = None
_reader_path = ""


def _mmdb_reader():
    global _reader, _reader_path
    path = str(getattr(settings, "BOTWALL_GEOIP2_DB", "") or "")
    if not path:
        return None
    if _reader is not None and _reader_path == path:
        return _reader
    try:
        import geoip2.database  # type: ignore

        _reader = geoip2.database.Reader(path)
        _reader_path = path
        return _reader
    except Exception as exc:  # noqa: BLE001 - optional dependency
        logger.warning("botwall: cannot open GeoIP database %s: %s", path, exc)
        return None


@lru_cache(maxsize=1)
def _cloudflare_header_allowed() -> bool:  # pragma: no cover - settings driven
    return bool(getattr(settings, "BOTWALL_TRUST_CF_HEADERS", False))


def resolve_country(request, ip: str, config) -> str:
    if not getattr(config, "geo_enabled", False):
        return ""

    cache = get_cache()
    cache_key = f"bw:geo:{ip}"
    cached = cache.get(cache_key)
    if isinstance(cached, str):
        return cached

    country = ""

    if getattr(config, "trust_cf_country", False) and _cloudflare_header_allowed():
        remote = request.META.get("REMOTE_ADDR", "")
        if is_trusted_proxy(remote):
            header = (request.META.get("HTTP_CF_IPCOUNTRY") or "").upper()
            if _COUNTRY_RE.match(header):
                country = header
    else:
        header = (request.META.get("HTTP_CF_IPCOUNTRY") or "").upper()
        if _COUNTRY_RE.match(header):
            logger.debug(
                "botwall: ignoring untrusted CF-IPCountry header from %s", ip
            )

    if not country:
        reader = _mmdb_reader()
        if reader is not None:
            try:
                country = reader.country(ip).country.iso_code or ""
            except Exception:  # noqa: BLE001 - address not in database
                country = ""

    country = (country or "").upper()[:2]
    if not _COUNTRY_RE.match(country):
        country = ""
    cache.set(cache_key, country, 86400)
    return country
