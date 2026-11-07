from django.apps import AppConfig


class FrontConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'front'

    def ready(self):
        from . import checks  # Register checks before commands and requests run.
