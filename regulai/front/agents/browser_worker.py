"""Executor bridge for browser I/O. No provider keys or direct public sockets."""
import base64
import json
import shlex
import uuid

from .adapter import InternalOperationError


def browse(internal, sandbox, lease, call, budget):
    nonce = uuid.uuid4().hex
    received, buffer = {}, ''
    def output(chunk):
        nonlocal buffer
        buffer += str(chunk)
        if len(buffer) > 1500000:
            raise InternalOperationError('Browser output limit')
        while '\n' in buffer:
            line, buffer = buffer.split('\n', 1)
            value = json.loads(line)
            lease.check()
            if 'request_id' in value:
                reply = internal.operation('run/browser-fetch', {'call': call, **value})
                sandbox.files.write('/tmp/regulay-browser-' + nonce + '/' + str(value['request_id']) + '.json', json.dumps(reply))
            elif 'result' in value:
                received.update(value['result'])
    payload = base64.b64encode(json.dumps({'nonce': nonce, 'url': call['args']['url'], 'seconds': budget['web_seconds']}).encode()).decode()
    try:
        sandbox.commands.run('python -I /skills/browser_runner.py ' + shlex.quote(payload),
            user='user', timeout=budget['web_seconds'] + 15, on_stdout=output)
    except BaseException:
        # SDK command timeouts do not themselves prove process termination.
        # Destroy this exclusive sandbox on an unhandled browser/IPC failure.
        try:
            sandbox.kill()
        except Exception:
            pass  # Lease revocation and the microVM TTL are the fallback.
        raise
    lease.check()
    if not received:
        raise InternalOperationError('Browser returned no rendered evidence')
    internal.operation('run/browser-result', {'call': call, **received})
