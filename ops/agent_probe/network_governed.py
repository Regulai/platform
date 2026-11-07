"""Task49 real socket proof in the task48 VM. The HTTP control is synthetic."""
import json
from pathlib import Path
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Control(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers['Content-Length']))
        if self.path != '/internal/agents/inference/':
            self.send_error(404)
            return
        body = json.dumps({'status': 'completed', 'content': 'Synthetic internal network control.',
                           'tool_calls': [], 'usage': {}}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def executor_probe(targets):
    sys.path.insert(0, '/app/regulai')
    sys.path.insert(0, '/app/ops/agent_probe')
    from front.agents.adapter import InternalClient, RegulayModel
    from langchain_core.messages import HumanMessage
    from runtime_checks import connect_probe
    import os
    if any(('KEY' in name and name != 'GPG_KEY') or 'DATABASE' in name or name.startswith('PG') for name in os.environ):
        raise AssertionError('Unexpected executor credentials')
    for module in ('records.py', 'service.py', 'aliases.py', 'data_views.py'):
        if Path('/app/regulai/front/agents', module).exists():
            raise AssertionError('Private application code copied into executor')
    internal = InternalClient('http://172.30.50.1:31049/internal/agents/', 'synthetic-network-control', 'synthetic')
    try:
        answer = RegulayModel(internal=internal, cache=False).invoke([HumanMessage(content='Network control')])
        assert answer.content == 'Synthetic internal network control.'
    finally:
        internal.close()
    denials = [connect_probe(t['address'], t['port'], denied=True) for t in targets]
    print(json.dumps({'allowed_internal_http': True, 'real_adapter': True, 'provider_keys': False,
        'database_access': False, 'private_registry_code': False, 'denials': denials,
        'scope': 'Network proof only; HTTP control is synthetic, application governance tested separately.'}))


if __name__ == '__main__':
    if sys.argv[1] == 'serve':
        server = ThreadingHTTPServer(('172.30.50.1', 31049), Control)
        print('ready', flush=True)
        server.serve_forever()
    else:
        executor_probe(json.loads(sys.argv[2]))
