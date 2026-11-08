from django.apps import AppConfig


class BotWallConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "botwall"
    verbose_name = "Bot Protection Firewall"

    def ready(self):
        # Cache invalidation hooks (safe during migrations: signals are lazy).
        from . import signals  # noqa: F401
