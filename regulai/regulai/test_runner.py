"""Django isolates the test DB, but its process-local cache also needs isolation."""
import unittest
from django.core.cache import caches
from django.test.runner import DiscoverRunner


class IsolatedCacheResult(unittest.TextTestResult):
    def startTest(self, test):
        for cache in caches.all():
            cache.clear()
        super().startTest(test)


class IsolatedCacheRunner(DiscoverRunner):
    def get_test_runner_kwargs(self):
        return {**super().get_test_runner_kwargs(), 'resultclass': IsolatedCacheResult}
