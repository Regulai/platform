"""Run a local task-50 check without overwriting previous evidence."""
import argparse
import json
from pathlib import Path
import subprocess
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir', type=Path)
    parser.add_argument('name')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    output = args.output_dir or root / 'evals/reports/task50-chat-excel-20261007'
    output.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    with (output / (args.name + '.log')).open('xb') as log:
        result = subprocess.run(args.command, cwd=root, stdout=log, stderr=subprocess.STDOUT)
    record = {'command': args.command, 'exit_code': result.returncode,
              'seconds': round(time.monotonic() - started, 3)}
    (output / (args.name + '.result.json')).write_text(json.dumps(record, indent=2))
    print(json.dumps(record))
    return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())
