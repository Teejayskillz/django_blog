"""Fault tolerant cache access.

The firewall keeps all hot-path counters in a cache. On cPanel shared hosting
Redis is frequently unavailable, so this module:

1. uses the ``botwall`` cache alias (Redis when configured, file cache
   otherwise),
2. automatically fails over to the ``botwall_fallback`` alias when the primary
   backend raises (Redis down, permission problem, ...),
3. never raises into the request/response cycle - if every backend fails the
   calls return harmless defaults so traffic is *allowed* (fail open).

No Django models are imported here on purpose: this module is usable during
``manage.py migrate`` and in management commands.
"""

from __future__ import annotations

import logging
import time

from django.conf import settings
from django.core.cache import InvalidCacheBackendError, caches

logger = logging.getLogger("botwall.cache")

DEFAULT_TIMEOUT = 300


class ResilientCache:
    """Tiny wrapper around Django's cache API with automatic failover."""

    def __init__(self):
        self.primary_alias = getattr(settings, "BOTWALL_CACHE_ALIAS", "botwall")
        self.fallback_alias = getattr(
            settings, "BOTWALL_FALLBACK_CACHE_ALIAS", "botwall_fallback"
        )
        self.cooldown = float(getattr(settings, "BOTWALL_CACHE_FAILURE_COOLDOWN", 30))
        self._down_until = 0.0
        self.last_error = ""
        self.fallback_active = False

    # -- backend resolution ---------------------------------------------------
    @staticmethod
    def _backend(alias):
        try:
            return caches[alias]
        except (InvalidCacheBackendError, KeyError, Exception):  # pragma: no cover
            return None

    @staticmethod
    def backend_label(alias):
        try:
            backend = caches[alias]
        except Exception:
            return "unavailable"
        return f"{backend.__class__.__module__}.{backend.__class__.__name__}"

    def _primary_available(self):
        return time.monotonic() >= self._down_until

    def _mark_down(self, exc):
        self._down_until = time.monotonic() + self.cooldown
        self.fallback_active = True
        message = f"{type(exc).__name__}: {exc}"
        if message != self.last_error:
            logger.warning(
                "botwall: primary cache (%s) unavailable, failing over to %s: %s",
                self.primary_alias,
                self.fallback_alias,
                message,
            )
            self.last_error = message

    # -- generic call helper --------------------------------------------------
    def _call(self, method, *args, **kwargs):
        if self._primary_available():
            primary = self._backend(self.primary_alias)
            if primary is not None:
                try:
                    return getattr(primary, method)(*args, **kwargs)
                except ValueError:
                    raise
                except Exception as exc:  # noqa: BLE001 - backend errors vary
                    self._mark_down(exc)
        fallback = self._backend(self.fallback_alias)
        if fallback is not None:
            try:
                return getattr(fallback, method)(*args, **kwargs)
            except ValueError:
                raise
            except Exception as exc:  # noqa: BLE001
                logger.error("botwall: fallback cache failed: %s", exc)
                self.last_error = f"{type(exc).__name__}: {exc}"
        return None

    # -- read API -------------------------------------------------------------
    def get(self, key, default=None):
        value = self._call("get", key, None)
        return default if value is None else value

    def get_many(self, keys):
        result = self._call("get_many", list(keys))
        return result if isinstance(result, dict) else {}

    def has_key(self, key):
        return self.get(key, None) is not None

    def add(self, key, value, timeout=DEFAULT_TIMEOUT):
        result = self._call("add", key, value, timeout)
        return bool(result)

    # -- write API ------------------------------------------------------------
    def set(self, key, value, timeout=DEFAULT_TIMEOUT):
        return self._call("set", key, value, timeout)

    def set_many(self, mapping, timeout=DEFAULT_TIMEOUT):
        return self._call("set_many", mapping, timeout)

    def delete(self, key):
        return self._call("delete", key)

    def delete_many(self, keys):
        return self._call("delete_many", list(keys))

    def incr(self, key, delta=1, timeout=DEFAULT_TIMEOUT):
        """Increment a missing-or-existing counter without racing on creation."""
        backend_method = "incr"

        def attempt(backend):
            try:
                return backend.incr(key, delta)
            except ValueError:
                if backend.add(key, delta, timeout):
                    return delta
                return backend.incr(key, delta)

        if self._primary_available():
            primary = self._backend(self.primary_alias)
            if primary is not None:
                try:
                    return attempt(primary)
                except ValueError:
                    raise
                except Exception as exc:  # noqa: BLE001
                    self._mark_down(exc)
        fallback = self._backend(self.fallback_alias)
        if fallback is not None:
            try:
                return attempt(fallback)
            except ValueError:
                raise
            except Exception as exc:  # noqa: BLE001
                logger.error("botwall: fallback cache incr failed: %s", exc)
                self.last_error = f"{type(exc).__name__}: {exc}"
        # Total cache outage: pretend the counter was incremented but keep no
        # state, which means limits never trip while the cache is down.
        return delta

    def clear(self):
        for alias in (self.primary_alias, self.fallback_alias):
            backend = self._backend(alias)
            if backend is not None:
                try:
                    backend.clear()
                except Exception as exc:  # noqa: BLE001
                    logger.warning("botwall: cannot clear cache %s: %s", alias, exc)

    # -- diagnostics ----------------------------------------------------------
    def health(self):
        ok = None
        probe_key = f"bw:probe:{time.time():.0f}"
        try:
            self.set(probe_key, "1", 5)
            ok = self.get(probe_key) == "1"
            self.delete(probe_key)
        except Exception:  # noqa: BLE001 - health check must never raise
            ok = False
        return {
            "primary_alias": self.primary_alias,
            "primary_backend": self.backend_label(self.primary_alias),
            "fallback_alias": self.fallback_alias,
            "fallback_backend": self.backend_label(self.fallback_alias),
            "reachable": bool(ok),
            "degraded": self.fallback_active or not self._primary_available(),
            "last_error": self.last_error,
        }


cache = ResilientCache()


def get_cache():
    return cache
