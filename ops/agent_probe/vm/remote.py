"""Send a reviewed script to our disposable VM, saving output outside the VM."""
import argparse
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("script", type=Path)
    parser.add_argument("--log", type=Path, required=True)
    args = parser.parse_args()
    command = ["rtk", "proxy", "docker", "exec", "-i", "regulay-task48-e2bvm",
               "ssh", "-i", "/vm/id_ed25519", "-o", "BatchMode=yes",
               "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=/vm/known_hosts",
               "-o", "ConnectTimeout=10", "-p", "2222", "probe@127.0.0.1", "sudo", "bash", "-se"]
    with args.log.open("xb") as log:
        result = subprocess.run(command, input=args.script.read_text(encoding="utf-8").encode(),
                                stdout=log, stderr=subprocess.STDOUT, timeout=1800)
    print(f"Exit {result.returncode}; log: {args.log}")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
