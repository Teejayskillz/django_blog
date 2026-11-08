"""Cache invalidation hooks so admin changes take effect immediately."""

from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from . import blocking, conf
from .models import BotWallSettings, IPRule


@receiver(post_save, sender=BotWallSettings)
@receiver(post_delete, sender=BotWallSettings)
def _settings_changed(sender, instance, **kwargs):
    conf.invalidate_config()
    blocking.invalidate_rules()


@receiver(post_save, sender=IPRule)
@receiver(post_delete, sender=IPRule)
def _rules_changed(sender, instance, **kwargs):
    blocking.invalidate_rules()
