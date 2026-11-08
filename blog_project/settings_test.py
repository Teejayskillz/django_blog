"""Settings used by the automated test suite (SQLite + local memory cache).

Run the suite with::

    python manage.py test botwall core --settings=blog_project.settings_test

Never deploy with these settings.
"""

from .settings import *  # noqa: F401,F403

DEBUG = False
SECRET_KEY = SECRET_KEY or "botwall-test-secret-key-not-for-production"
ALLOWED_HOSTS = ["testserver", "localhost", "127.0.0.1"]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

# Isolate every test from the real file/database cache.
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "botwall-test-default",
    },
    "botwall": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "botwall-test-primary",
    },
    "botwall_fallback": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "botwall-test-fallback",
    },
}

BOTWALL_ENABLED = True
BOTWALL_CONFIG_CACHE_SECONDS = 0
BOTWALL_RULES_REFRESH_SECONDS = 0
BOTWALL_WEIGHTS = {}
BOTWALL_CHALLENGE_BRAND = "Test Site"
BOTWALL_CONTACT_EMAIL = ""

# Fast hashing keeps the admin/staff tests snappy.
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]

# The Telegram signal must never attempt network access during tests.
TELEGRAM_BOT_TOKEN = ""
TELEGRAM_CHANNEL_IDS = []

LOGGING["root"]["level"] = "CRITICAL"  # noqa: F405
LOGGING["loggers"]["botwall"] = {  # noqa: F405
    "handlers": ["console"],
    "level": "CRITICAL",
    "propagate": False,
}
