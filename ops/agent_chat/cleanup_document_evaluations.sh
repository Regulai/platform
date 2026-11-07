set -euo pipefail
test "$(hostname)" = task48-e2b-vm
# These directories were created for 51/52, outside the preserved task50/E2B tree.
python3 - <<'PY'
from pathlib import Path
import shutil
root = Path('/home/probe').resolve()
for name in ('task51-eval', 'task52-eval', 'task51-evaluation.tar', 'task52-evaluation.tar'):
    path = root / name
    if path.resolve() != path or path.parent != root:
        raise RuntimeError('Unexpected cleanup path')
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()
    print('Removed owned evaluation resource:', path)
PY
docker image rm regulay-task52-pptx-evaluation:local regulay-task51-docx-evaluation:local
# Keep the reviewed final document image/template and the pre-existing E2B stack.
test -z "$(docker ps --filter label=regulay.task=51 --format '{{.Names}}')"
test -z "$(docker ps --filter label=regulay.task=52 --format '{{.Names}}')"
