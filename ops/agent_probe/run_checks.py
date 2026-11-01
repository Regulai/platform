"""Capture commands and exits without PowerShell stream encoding/redirection."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time

parser = argparse.ArgumentParser()
parser.add_argument('--log', type=Path, required=True)
parser.add_argument('command', nargs=argparse.REMAINDER)
args = parser.parse_args()
args.log.parent.mkdir(parents=True, exist_ok=True)
started = time.monotonic()
with args.log.open('wb') as stream:
    result = subprocess.run(['rtk', 'proxy', *args.command], stdout=stream, stderr=subprocess.STDOUT)
report = {'command': ['rtk', 'proxy', *args.command], 'exit_code': result.returncode,
          'seconds': round(time.monotonic() - started, 3)}
args.log.with_suffix('.result.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
print(json.dumps(report))
print(args.log.read_text(encoding='utf-8', errors='replace')[-4500:])
sys.exit(result.returncode)
