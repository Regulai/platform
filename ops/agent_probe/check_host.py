"""Read-only upstream E2B preflight and OpenSandbox runtime inventory."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import urllib.request

COMMIT = "79098f5667b695c9fa8d087305068e1950dccc54"
URL = f"https://raw.githubusercontent.com/e2b-dev/runtime/{COMMIT}/embed/compose/scripts/preflight.sh"
SHA256 = "db87fe2668c3104459f0e462d5dd6c46b0a6ad42efdca632d5407492d571f2b9"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--wsl-distribution", default="Ubuntu")
    args = parser.parse_args()
    if args.report.exists():
        parser.error("Choose a new report path")
    data = urllib.request.urlopen(URL, timeout=30).read()
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise RuntimeError("Upstream preflight checksum mismatch")
    # Reviewed upstream script: uname/getconf/ldd/df, filesystem existence,
    # command lookup and modprobe -n only. Never runs host-setup or changes sysctl.
    command = ["rtk", "proxy"]
    if platform.system() == "Windows":
        command += ["wsl", "-d", args.wsl_distribution, "--"]
    command += ["bash", "-s"]
    # Binary stdin preserves LF across Windows -> WSL (text mode would add CR).
    result = subprocess.run(command, input=data, capture_output=True, timeout=30)
    docker = subprocess.run(["rtk", "proxy", "docker", "info", "--format",
        "{{range $name, $runtime := .Runtimes}}{{$name}} {{end}}"], capture_output=True,
        text=True, encoding="utf-8", timeout=30)
    runtimes = docker.stdout.strip().split() if docker.returncode == 0 else []
    report = {"source": URL, "sha256": SHA256, "command": command,
              "e2b_preflight_exit_code": result.returncode,
              "e2b_preflight": (result.stdout + result.stderr).decode("utf-8", errors="replace"),
              "docker_runtimes": runtimes,
              "opensandbox_secure_runtime_available": bool(set(runtimes) & {"runsc", "kata", "kata-runtime"}),
              "e2b_infrastructure_validated": False}
    args.report.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"e2b_preflight_exit_code": result.returncode, "docker_runtimes": runtimes}))
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
