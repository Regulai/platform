"""Read only allowlisted synthetic evidence, never runtime keys/configuration."""
import argparse
import json
from pathlib import Path
import re
import subprocess

parser=argparse.ArgumentParser()
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
args.output.mkdir(parents=True,exist_ok=False)
command=['rtk','proxy','docker','exec','regulay-task48-e2bvm','ssh','-i','/vm/id_ed25519',
    '-o','BatchMode=yes','-o','UserKnownHostsFile=/vm/known_hosts','-p','2222','probe@127.0.0.1','sudo']
directory='/home/probe/task50/evidence-live'
listed=subprocess.run(command+['ls','-1',directory],capture_output=True,check=True)
names=listed.stdout.decode().splitlines()
for name in names:
    if not re.fullmatch(r'(?:model-requests|audit|live-cases|network(?:-[0-9a-f]+)?)\.json|live-[a-z-]+\.xlsx|worker(?:-before-kill)?\.log',name):
        continue
    data=subprocess.run(command+['cat',directory+'/'+name],capture_output=True,check=True).stdout
    (args.output/name).write_bytes(data)
print(json.dumps({'output':str(args.output),'files':[p.name for p in args.output.iterdir()]}))
