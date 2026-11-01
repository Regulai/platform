"""One-slot exhaustion, destruction and replacement on actual E2B microVMs."""
import json
from pathlib import Path
import sys
import time
import uuid
from front.agents.sandbox_pool import CleanPool, create_clean

config = json.loads(Path('/run/task50/config.json').read_text())
pool = CleanPool(lambda: create_clean(config))
def take():
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        sandbox = pool.take()
        if sandbox: return sandbox
        time.sleep(.1)
    raise AssertionError('Real clean slot unavailable')
try:
    first = take()
    old_id = first.sandbox_id
    marker = uuid.uuid4().hex
    first.files.write('/workspace/work/private-marker', marker)
    assert pool.take() is None  # Capacity exhausted while leased; no sharing.
    pool.release(first)
    second = take()
    assert second.sandbox_id != old_id
    check = second.commands.run('test ! -e /workspace/work/private-marker && '
        'test -z "$(ls -A /workspace/input)" && test -z "$(ls -A /workspace/work)" && '
        'test -z "$(ls -A /workspace/output)"', timeout=10)
    assert check.exit_code == 0
    pool.release(second)
    report = {'passed':True,'exhausted_slot_returns_none':True,'released_sandbox_destroyed':True,
        'old_sandbox':old_id,'new_sandbox':second.sandbox_id,'private_marker_absent':True,'metrics':pool.metrics,
        'scope':'Actual E2B backend, SDK and private microVM files; no simulated sandbox'}
    print(json.dumps(report))
finally:
    pool.close()
