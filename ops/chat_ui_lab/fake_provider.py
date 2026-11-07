"""Loopback-only simulated AI provider for the chat UI lab. No real model, account or network.

Speaks the wire formats used by the pinned SDKs:
- OpenAI-compatible  POST /v1/chat/completions  (stream and non-stream)
- Anthropic Messages  POST /v1/messages         (stream and non-stream)
- TypeSafe Jev        POST /jev                  (structured signals only, no prose)

The scenario is chosen from keywords in the last user message, so a browser session can
reproduce each state on demand. Streaming is real: chunks are flushed with delays, and
``pausa`` holds the stream until ``POST /control/release`` (or 20 s) so content is
visibly delivered before the generation ends.

Run: python ops/chat_ui_lab/fake_provider.py --port 8790
"""
import argparse
import json
import re
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RELEASE = threading.Event()

MARKDOWN = """Aquí tienes un resumen de la política de viajes **2026**.

## Puntos clave

1. Las reservas se hacen con al menos **15 días** de antelación.
2. El alojamiento máximo es de *120 €* por noche en capitales europeas.
3. Los gastos se justifican en un plazo de 30 días.

| Concepto | Límite | Justificante |
| --- | ---: | --- |
| Hotel | 120 € | Factura |
| Dietas | 45 € | Ticket |
| Taxi | 30 € | Recibo |

Para calcular el total de dietas puedes usar esta función:

```python
def dietas(dias, importe=45):
    return dias * importe
```

> Consulta siempre la versión vigente en la intranet.

Más información en [la guía oficial](https://example.com/politica-viajes)."""

SHORT = 'Hola. Puedo ayudarte a redactar, resumir o revisar textos dentro de la política de tu empresa. ¿Qué necesitas?'
EMAIL = ('Puedes escribir al responsable de compras. Su contacto es juan.perez@empresa-lab.com y su '
         'teléfono 612 345 678. Indícale el número de pedido y la fecha prevista de entrega.\n\n'
         'Si no responde en dos días, abre una incidencia desde el portal de compras.')
SECRET = ('Para configurar la integración, el servicio usa la variable de entorno estándar.\n\n'
          'La configuración que me has pedido sería:\n\napi_key = sk-proj-9f8E7d6C5b4A3z2Y1x0W\n\n'
          'Guárdala en el gestor de secretos y no la compartas.')
JSON_REPLY = '{"resumen": "Pedido confirmado", "importe": 1250, "moneda": "EUR"}'


def long_text():
    parts = ['# Informe de seguimiento\n']
    for index in range(1, 13):
        parts.append(f'## Sección {index}\n\nEsta sección resume el estado del área {index}. '
                     'El equipo ha completado las tareas planificadas y mantiene los riesgos bajo control. '
                     'Se recomienda revisar los indicadores en la próxima reunión mensual.\n\n'
                     f'- Indicador A: {80 + index} %\n- Indicador B: {index * 3} incidencias\n')
    return '\n'.join(parts)


def scenario(messages):
    text = ''
    for message in reversed(messages):
        if message.get('role') == 'user':
            content = message.get('content')
            text = content if isinstance(content, str) else json.dumps(content, ensure_ascii=False)
            break
    lowered = text.lower()
    system = ' '.join(m.get('content') for m in messages if m.get('role') == 'system' and isinstance(m.get('content'), str))
    if 'Return only JSON {"claims"' in system or 'Sources:' in text:
        return 'document', document_reply(text)
    for key in ('error', 'caída', 'caida', 'corta', 'json', 'secreto', 'correo', 'largo', 'pausa', 'lento', 'hola'):
        if key in lowered:
            return key, {'error': '', 'caída': '', 'caida': '', 'corta': MARKDOWN, 'json': JSON_REPLY,
                         'secreto': SECRET, 'correo': EMAIL, 'largo': long_text(), 'pausa': MARKDOWN,
                         'lento': MARKDOWN, 'hola': SHORT}[key]
    return 'default', MARKDOWN


def document_reply(text):
    match = re.search(r'Sources:\n(.*)$', text, re.S)
    try:
        sources = json.loads(match[1]) if match else []
    except ValueError:
        sources = []
    claims = []
    for source in sources[:2]:
        words = str(source.get('text', '')).split()
        if len(words) >= 4:
            quote = ' '.join(words[:min(8, len(words))])
            claims.append({'text': 'El documento indica: ' + quote + '.',
                           'citations': [{'id': source.get('id', 'S1'), 'quote': quote}]})
    if not claims:
        claims = [{'text': 'El documento no contiene texto suficiente.', 'citations': [{'id': 'S1', 'quote': 'sin texto'}]}]
    return json.dumps({'claims': claims}, ensure_ascii=False)


def tokens(text):
    """Split into word-ish chunks (keeps whitespace), so entities cross chunk boundaries."""
    return re.findall(r'\S{1,6}|\s+', text)


def jev_answers(questions):
    answers = {}
    for key, question in questions.items():
        if question.get('type') == 'noul':
            answers[key] = {'type': 'noul', 'noul': 0.04}
        elif question.get('type') == 'choice':
            options = list(question['criteria'])
            preferred = {'category': 'internal', 'task': 'general', 'difficulty': 'economy'}.get(key, options[0])
            choice = preferred if preferred in options else options[0]
            rest = (1 - 0.86) / max(1, len(options) - 1)
            probabilities = {option: (0.86 if option == choice else rest) for option in options}
            answers[key] = {'type': 'choice', 'choice': choice, 'probabilities': probabilities, 'confidence': 0.86}
    return answers


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, pattern, *args):
        print('[fake-provider] ' + pattern % args, flush=True)

    def body(self):
        length = int(self.headers.get('Content-Length') or 0)
        return json.loads(self.rfile.read(length) or b'{}')

    def send_json(self, value, status=200):
        raw = json.dumps(value, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('x-request-id', 'lab-' + uuid.uuid4().hex[:12])
        self.end_headers()
        self.wfile.write(raw)

    def start_stream(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Cache-Control', 'no-cache')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.close_connection = True

    def emit(self, payload, event=None):
        prefix = f'event: {event}\n' if event else ''
        self.wfile.write((prefix + 'data: ' + payload + '\n\n').encode('utf-8'))
        self.wfile.flush()

    def do_POST(self):
        if self.path == '/control/release':
            RELEASE.set()
            return self.send_json({'released': True})
        if self.path == '/jev':
            payload = self.body()
            time.sleep(0.6)
            return self.send_json({'model': payload.get('model'), 'answers': jev_answers(payload.get('questions', {})),
                                   'usage': {'input_tokens': 900, 'output_tokens': 40}})
        if self.path.endswith('/chat/completions'):
            return self.openai(self.body())
        if self.path.endswith('/messages'):
            return self.anthropic(self.body())
        self.send_json({'error': {'message': 'unknown lab route'}}, 404)

    def plan(self, payload):
        kind, text = scenario(payload.get('messages', []))
        delay = {'lento': 0.12, 'largo': 0.012, 'document': 0.0}.get(kind, 0.035)
        finish = 'length' if kind == 'corta' else 'stop'
        if kind == 'corta':
            text = text[: len(text) // 2]
        return kind, text, delay, finish

    def openai(self, payload):
        kind, text, delay, finish = self.plan(payload)
        model = payload.get('model', 'lab-model')
        time.sleep(0.5)  # simulated time to first token
        if kind == 'error':
            return self.send_json({'error': {'message': 'Simulated provider failure', 'type': 'server_error'}}, 500)
        usage = {'prompt_tokens': 420, 'completion_tokens': max(1, len(text) // 4), 'total_tokens': 420 + max(1, len(text) // 4)}
        if not payload.get('stream'):
            time.sleep(min(3.0, delay * len(tokens(text))))
            return self.send_json({'id': 'chatcmpl-lab', 'object': 'chat.completion', 'model': model,
                'choices': [{'index': 0, 'message': {'role': 'assistant', 'content': text}, 'finish_reason': finish}],
                'usage': usage})
        self.start_stream()
        ident = 'chatcmpl-lab-' + uuid.uuid4().hex[:8]
        base = {'id': ident, 'object': 'chat.completion.chunk', 'created': int(time.time()), 'model': model}
        try:
            self.emit(json.dumps({**base, 'choices': [{'index': 0, 'delta': {'role': 'assistant', 'content': ''}, 'finish_reason': None}]}))
            pieces = tokens(text)
            pause_at = len(pieces) // 3 if kind == 'pausa' else None
            for index, piece in enumerate(pieces):
                if kind in ('caída', 'caida') and index == len(pieces) // 2:
                    self.wfile.flush()
                    self.connection.shutdown(2)
                    return
                if index == pause_at:
                    RELEASE.clear()
                    RELEASE.wait(20)
                self.emit(json.dumps({**base, 'choices': [{'index': 0, 'delta': {'content': piece}, 'finish_reason': None}]}, ensure_ascii=False))
                time.sleep(delay)
            self.emit(json.dumps({**base, 'choices': [{'index': 0, 'delta': {}, 'finish_reason': finish}]}))
            if (payload.get('stream_options') or {}).get('include_usage'):
                self.emit(json.dumps({**base, 'choices': [], 'usage': usage}))
            self.emit('[DONE]')
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
            print('[fake-provider] client closed the stream', flush=True)

    def anthropic(self, payload):
        kind, text, delay, finish = self.plan(payload)
        stop = 'max_tokens' if finish == 'length' else 'end_turn'
        model = payload.get('model', 'lab-claude')
        time.sleep(0.4)
        if kind == 'error':
            return self.send_json({'type': 'error', 'error': {'type': 'api_error', 'message': 'Simulated failure'}}, 500)
        if not payload.get('stream'):
            return self.send_json({'id': 'msg_lab', 'type': 'message', 'role': 'assistant', 'model': model,
                'content': [{'type': 'text', 'text': text}], 'stop_reason': stop,
                'usage': {'input_tokens': 420, 'output_tokens': max(1, len(text) // 4)}})
        self.start_stream()
        try:
            self.emit(json.dumps({'type': 'message_start', 'message': {'id': 'msg_lab', 'type': 'message', 'role': 'assistant',
                'model': model, 'content': [], 'stop_reason': None, 'usage': {'input_tokens': 420, 'output_tokens': 1}}}), 'message_start')
            self.emit(json.dumps({'type': 'content_block_start', 'index': 0, 'content_block': {'type': 'text', 'text': ''}}), 'content_block_start')
            for piece in tokens(text):
                self.emit(json.dumps({'type': 'content_block_delta', 'index': 0, 'delta': {'type': 'text_delta', 'text': piece}}, ensure_ascii=False), 'content_block_delta')
                time.sleep(delay)
            self.emit(json.dumps({'type': 'content_block_stop', 'index': 0}), 'content_block_stop')
            self.emit(json.dumps({'type': 'message_delta', 'delta': {'stop_reason': stop, 'stop_sequence': None},
                'usage': {'output_tokens': max(1, len(text) // 4)}}), 'message_delta')
            self.emit(json.dumps({'type': 'message_stop'}), 'message_stop')
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
            print('[fake-provider] client closed the stream', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8790)
    arguments = parser.parse_args()
    server = ThreadingHTTPServer(('127.0.0.1', arguments.port), Handler)
    server.daemon_threads = True
    print(f'SIMULATED PROVIDER (loopback only): http://127.0.0.1:{arguments.port}', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
