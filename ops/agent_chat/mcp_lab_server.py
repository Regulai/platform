"""Task 53 fixture account only; no real Drive requests are possible here."""
import argparse
import base64
from datetime import timedelta
import json
from pathlib import Path
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab_server


def prepare(evidence=None):
    lab_server.prepare(evidence=evidence)
    import httpx
    from asgiref.sync import async_to_sync
    from django.conf import settings
    from django.contrib.auth.models import User
    from django.utils import timezone
    from front.models import AgentDocumentConnection, AgentModelProfile
    from front.agents import document_mcp as mcp
    from front.test_agent_exports import ExportDriveFixture
    actor = User.objects.get(username='agent-synthetic-ui')
    AgentDocumentConnection.objects.update_or_create(user=actor, company=actor.profile.company,
        defaults={'enabled': True, 'write_enabled': True, 'expires_at': timezone.now() + timedelta(hours=1),
            'private_config': json.dumps({'token': 'synthetic-private-token', 'identity': 'person-one', 'folders': ['folder-one'],
                'write_folder': 'export-folder', 'account_label': 'synthetic@example.invalid', 'folder_label': 'Informes de laboratorio'})})
    settings.REGULAY_AGENT_MCP_ENABLED = True
    settings.REGULAY_AGENT_MCP_WRITES_ENABLED = True
    agent = AgentModelProfile.objects.get(pk=settings.REGULAY_AGENT_DEV_ACCOUNTS[str(actor.pk)]['profile_id'])
    agent.tools = list(dict.fromkeys([*agent.tools, 'save_revision']))
    agent.save(update_fields=['tools'])
    state = Path(evidence).parent / 'task54-drive.json' if evidence else None
    controls = state.with_name('task54-controls.json') if state else None
    class DurableFixture(ExportDriveFixture):
        def __init__(self):
            super().__init__()
            self.lock = threading.RLock()
            if state and state.exists():
                previous = json.loads(state.read_text())
                self.uploads, self.reservations = previous['uploads'], previous['reservations']
                self.files = {key: (value['metadata'], base64.b64decode(value['base64']))
                    for key, value in previous['files'].items()}

        def __call__(self, request):
            with self.lock:
                options = json.loads(controls.read_text()) if controls and controls.exists() else {}
                self.revoked = options.get('revoked', False)
                self.timeout_after_write = options.get('timeout_after_write', False)
                self.ambiguous_missing = options.get('ambiguous_missing', False)
                try:
                    return super().__call__(request)
                finally:
                    if state:
                        temporary = state.with_suffix('.tmp')
                        temporary.write_text(json.dumps({'uploads': self.uploads, 'reservations': self.reservations,
                            'files': {key: {'metadata': value[0], 'base64': base64.b64encode(value[1]).decode()}
                                for key, value in self.files.items()}}))
                        temporary.replace(state)
    remote = DurableFixture()
    mcp.call = lambda private, operation, args: async_to_sync(mcp._call)(private, operation, args,
        transport=httpx.MockTransport(remote))
    if controls:
        def flags():
            while True:
                try:
                    options = json.loads(controls.read_text()) if controls.exists() else {}
                    settings.REGULAY_AGENT_ENABLED = not options.get('mode_disabled', False)
                except (OSError, ValueError):
                    settings.REGULAY_AGENT_ENABLED = False
                time.sleep(.1)
        threading.Thread(target=flags, daemon=True).start()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8501)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--evidence')
    args = parser.parse_args()
    prepare(args.evidence)
    import uvicorn
    from django.core.asgi import get_asgi_application
    from django.contrib.staticfiles.handlers import ASGIStaticFilesHandler
    uvicorn.run(ASGIStaticFilesHandler(get_asgi_application()), host=args.host, port=args.port, access_log=False)
