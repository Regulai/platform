"""Explicitly synthetic HTTP transport in an egress-isolated Docker network."""
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
import time

ROOT = Path('/lab/provider')
ROOT.mkdir(parents=True, exist_ok=True)
LOCK = threading.Lock()
SENTINEL = 'synthetic.pilot@example.invalid'


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        if length > 1048576:
            self.send_error(413)
            return
        raw = self.rfile.read(length)
        data = json.loads(raw)
        purpose = 'mask' if self.path == '/api/mask' else 'generation'
        event = {'purpose': purpose, 'body_sha256': sha256(raw).hexdigest(),
                 'contains_original_sentinel': SENTINEL.encode() in raw}
        with LOCK:
            with (ROOT / 'events.jsonl').open('a', encoding='utf-8') as stream:
                stream.write(json.dumps(event) + '\n')
        if self.path == '/api/mask':
            texts = json.loads(data['text'])
            assert isinstance(texts, list) and all(isinstance(text, str) for text in texts)
            result = {'masked': json.dumps([text.replace(SENTINEL, '[MASKED]') for text in texts])}
        elif self.path == '/v1/chat/completions':
            assert not event['contains_original_sentinel'], 'Original reached generation transport'
            if 'lab_wait' in raw.decode():
                (ROOT / 'waiting').write_text('ready', encoding='utf-8')
                deadline = time.monotonic() + 20
                while not (ROOT / 'release').exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
            result = {'id': 'synthetic-response', 'object': 'chat.completion', 'created': 0,
                'model': 'synthetic-v1', 'choices': [{'index': 0, 'finish_reason': 'stop',
                    'message': {'role': 'assistant', 'content': 'Synthetic answer [MASKED]'}}],
                'usage': {'prompt_tokens': 20, 'completion_tokens': 5, 'total_tokens': 25}}
        else:
            self.send_error(404)
            return
        encoded = json.dumps(result).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(encoded)))
        self.end_headers()
        try:
            self.wfile.write(encoded)
        except (BrokenPipeError, ConnectionResetError):
            pass


ThreadingHTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
