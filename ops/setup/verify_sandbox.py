"""Real E2B/LibreOffice readiness, no LLM inference or example chat records."""
import json
from pathlib import Path
from types import SimpleNamespace
from front.agents.sandbox_pool import create_clean
from front.agents.workspace_backend import WorkspaceSandbox

config = json.loads(Path('/run/task50/config.json').read_text())
sandbox = create_clean(config)
try:
    # Exercise the same namespace/resource boundary as every professional tool.
    backend = WorkspaceSandbox(sandbox=sandbox, lease=SimpleNamespace(check=lambda: None),
        limits={'command_seconds': 120, 'memory_mb': 1024, 'processes': 64,
                'file_bytes': 20000000, 'output_bytes': 1048576})
    result = backend.execute('python -c "from docx import Document; d=Document(); '
        'd.add_paragraph(\'Installation readiness\'); d.save(\'/workspace/work/readiness.docx\')" && '
        'libreoffice -env:UserInstallation=file:///workspace/work/lo-ready --headless '
        '--convert-to pdf --outdir /workspace/output /workspace/work/readiness.docx && '
        'test -s /workspace/output/readiness.pdf && test ! -e /run && test "$(id -u)" = 1000', timeout=90)
    if result.exit_code:
        raise RuntimeError('LibreOffice readiness failed in the real microVM.')
    result = backend.execute("python -c \"import socket; s=socket.socket(); s.settimeout(2); "
                                  "assert s.connect_ex(('1.1.1.1',443)) != 0\"", timeout=10)
    if result.exit_code:
        raise RuntimeError('Sandbox network isolation failed.')
    print('Real microVM: DOCX/PDF rendering and outbound isolation passed. No model calls.')
finally:
    sandbox.kill()
