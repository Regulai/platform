"""Allowlisted synthetic task-54 evidence only; never runtime keys or settings."""
import argparse
import io
from pathlib import Path, PurePosixPath
import subprocess
import tarfile

parser=argparse.ArgumentParser()
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
args.output.mkdir(parents=True,exist_ok=False)
command=['rtk','proxy','docker','exec','regulay-task48-e2bvm','ssh','-i','/vm/id_ed25519',
    '-o','BatchMode=yes','-o','UserKnownHostsFile=/vm/known_hosts','-p','2222','probe@127.0.0.1','sudo',
    'tar','-cf','-','-C','/home/probe/task50/evidence-live']
data=subprocess.run(command+['task54-live','task54-ops','task54-corpus2','task54-model.json',
    'task54-worker-before-kill.log','task54-worker.log','task54-drive.json',
    'task54-ui-before','task54-ui-final'],capture_output=True,check=True).stdout
count=0
with tarfile.open(fileobj=io.BytesIO(data)) as archive:
    for member in archive:
        path=PurePosixPath(member.name)
        if not member.isfile() or '..' in path.parts or path.is_absolute(): continue
        if any(part.startswith('lo') or part == 'recalc' for part in path.parts): continue
        if path.suffix not in ('.json','.log','.docx','.xlsx','.pptx','.pdf','.png','.csv','.zip'): continue
        target=args.output.joinpath(*path.parts)
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(archive.extractfile(member).read())
        count+=1
print(f'Collected {count} synthetic evidence files')
