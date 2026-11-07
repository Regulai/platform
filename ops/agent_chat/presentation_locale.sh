set -euo pipefail
test "$(hostname)" = task48-e2b-vm
docker run -i --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
 --tmpfs /tmp:rw,size=128m,uid=1000,gid=1000 --mount type=bind,src=/home/probe/task52-eval/evidence,dst=/evidence \
 regulay-task52-pptx-evaluation:local python - <<'PY'
from pathlib import Path
import subprocess
from pypdf import PdfReader
output = Path('/evidence/locale-probe')
output.mkdir(exist_ok=False)
profile = output/'lo/user'
profile.mkdir(parents=True)
(profile/'registrymodifications.xcu').write_text('''<?xml version="1.0" encoding="UTF-8"?><oor:items xmlns:oor="http://openoffice.org/2001/registry"><item oor:path="/org.openoffice.Setup/L10N"><prop oor:name="ooLocale" oor:op="fuse"><value>es-ES</value></prop></item><item oor:path="/org.openoffice.System/L10N"><prop oor:name="Locale" oor:op="fuse"><value>es-ES</value></prop></item></oor:items>''')
subprocess.run(['libreoffice','-env:UserInstallation=file://'+str(output/'lo'),'--headless','--convert-to','pdf:impress_pdf_Export','--outdir',str(output),'/evidence/design-v2/new/final.pptx'],check=True,capture_output=True)
print(PdfReader(output/'final.pdf').pages[2].extract_text())
PY
