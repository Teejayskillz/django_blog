"""Intelligent bot protection firewall for the Django site.

The package is deliberately self-contained: it never imports ``core``/``ads``
models and it degrades to safe defaults when its own database table has not
been migrated yet.
"""

__version__ = "1.0.0"

default_app_config = "botwall.apps.BotWallConfig"
