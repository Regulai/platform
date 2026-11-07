"""Executor subprocess for the live application acceptance test.

Uses the real SDK, worker, HTTP gateway and Linux runner. E2B control transport
is replaced by a local namespace fixture; the provider is simulated by Django.
"""
import json
from pathlib import Path
import sys
from types import SimpleNamespace
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'regulai'))
from ops.agent_chat.test_professional_runtime import RealWorkspaceTests
from front.agents.adapter import InternalClient
from front.agents.sandbox_pool import CleanPool
from front.agents.worker import WorkerResource, run_job

config = json.loads(sys.stdin.read())
fixture = RealWorkspaceTests()
sandbox_allocations = 0
def create_namespace():
    global sandbox_allocations
    sandbox_allocations += 1
    if sandbox_allocations != 1:
        raise AssertionError('The lazy worker allocated more than one namespace')
    fixture.setUp()
    transport = fixture.transport
    original = transport.run
    def run(command, **kwargs):
        if kwargs.get('user') == 'root':
            # Each generated command gets a separate unshared namespace. This
            # substitute does not validate E2B creation or microVM tmpfs mounts.
            if not command.startswith(('mount -t tmpfs ', 'chmod -R a-w /workspace/input')):
                raise AssertionError('Unexpected administrative command')
            return SimpleNamespace(stdout='', stderr='', exit_code=0)
        return original(command, **kwargs)
    def destroy():
        if not fixture.doCleanups():
            raise RuntimeError('Namespace fixture cleanup failed')
    transport.run = run
    transport.set_timeout = lambda *_: None
    transport.kill = destroy
    return transport

internal = InternalClient(config['endpoint'], config['token'], config['attempt'])
pool = CleanPool(create_namespace)
resource = WorkerResource(internal, pool, config['endpoint'].rstrip('/') + '/',
    config['worker_token'], config['worker_id'], config)
try:
    result = run_job(internal, acquire=resource.acquire)
    print(json.dumps({**result, 'sandbox_allocations': sandbox_allocations}))
finally:
    resource.close()
    pool.close()
    internal.close()
    fixture.doCleanups()
