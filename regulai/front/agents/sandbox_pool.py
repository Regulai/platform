"""Executor-only one-slot allocation on demand. Used slots are always killed."""
import ipaddress
from pathlib import Path
import threading
import time
import logging
from urllib.parse import urlsplit

from e2b import Sandbox


def e2b_options(config):
    for name in ('api_url', 'sandbox_url'):
        parsed = urlsplit(config[name])
        address = ipaddress.ip_address(parsed.hostname)
        if (parsed.scheme not in ('http', 'https') or not address.is_private
                or address.is_link_local or parsed.username or parsed.password):
            raise ValueError('Explicit private E2B endpoint required')
    return {key: config[key] for key in ('api_url', 'sandbox_url')} | {
        'api_key': Path(config['api_key_file']).read_text().strip(),
        'domain': 'task48.internal', 'debug': False, 'retries': 0, 'request_timeout': 15}


def create_clean(config):
    sandbox = Sandbox.create(template=config['template'], timeout=180,
        allow_internet_access=False,
        network={'deny_out': ['0.0.0.0/0'], 'allow_public_traffic': False}, **e2b_options(config))
    try:
        sandbox.commands.run('printf 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6 && '
            'printf 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6 && '
            'find / -xdev -type f -perm /6000 -exec chmod a-s {} + && '
            # E2B deny_out does not cover its link-local metadata endpoint.
            # The pinned microVM kernel lacks xt_owner. A kernel prohibit route
            # covers link-local metadata for every UID without touching envd.
            'ip route replace prohibit 169.254.0.0/16 && '
            'ip route show type prohibit | grep -q 169.254.0.0/16 && '
            'mount --bind /skills /skills && mount -o remount,bind,ro /skills', user='root', timeout=10)
        sandbox.commands.run('test "$(id -u)" = 1000 && '
            'test -z "$(ls -A /workspace/input)" && test -z "$(ls -A /workspace/work)" && '
            'test -z "$(ls -A /workspace/output)" && '
            'test "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)" = 1 && '
            'test "$(cat /proc/sys/net/ipv6/conf/default/disable_ipv6)" = 1', timeout=10)
        return sandbox
    except BaseException:
        sandbox.kill()
        raise


class CleanPool:
    """One demand-created slot; an uncertain destruction never frees capacity."""
    def __init__(self, factory):
        self.factory, self.ready, self.closed = factory, None, False
        self.leased = False
        self.lock = threading.Lock()
        self.metrics = []

    def take(self):
        with self.lock:
            if self.closed or self.leased:
                return None
            self.leased = True
        started = time.monotonic()
        # The caller first reserves global server capacity. Do not retry an
        # uncertain create: its server reservation remains occupied as well.
        sandbox = self.factory()
        with self.lock:
            self.ready = sandbox
            closed = self.closed
            self.metrics.append({'preparation_seconds': time.monotonic() - started,
                                 'sandbox_id': sandbox.sandbox_id})
        if closed:
            self.release(sandbox)
            raise RuntimeError('Sandbox pool closed during acquisition')
        return sandbox

    def release(self, sandbox):
        # Never return a used environment to the queue, even on error/cancel.
        with self.lock:
            if self.ready is not sandbox:
                return False
        try:
            sandbox.kill()
        except Exception:
            logging.getLogger(__name__).warning('Sandbox destruction uncertain; capacity remains occupied')
            return False
        with self.lock:
            if self.ready is sandbox:
                self.ready = None
                self.leased = False
        return True

    def return_unassigned(self, sandbox):
        # Compatibility for v1 callers. There is deliberately no warm slot.
        return self.release(sandbox)

    def close(self):
        with self.lock:
            self.closed = True
            ready = self.ready
        if ready:
            self.release(ready)
