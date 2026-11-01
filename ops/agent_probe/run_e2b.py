"""Run the SAME task 48 probe against an explicitly configured self-hosted E2B.

No cloud defaults, provider clients, host code execution, or production data.
No config means PENDING (exit 2), never a successful infrastructure check.
"""
import argparse
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import shlex
import sys
import time
from urllib.parse import urlsplit

os.environ["LANGSMITH_TRACING"] = "false"
os.environ["LANGCHAIN_TRACING_V2"] = "false"
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "regulai"))

from e2b import Sandbox, Template
from langchain_e2b import E2BSandbox
from front.agents.integration_probe import EXPECTED, run_probe
from runtime_checks import connect_probe

BASE_IMAGE = "python:3.12.11-slim@sha256:47ae396f09c1303b8653019811a8498470603d7ffefc29cb07c88f1f8cb3d19f"


def private_endpoint(url):
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Expected an explicit private E2B HTTP(S) endpoint without URL credentials")
    host = parsed.hostname
    try:
        ip = ipaddress.ip_address(host)
        allowed = ip.is_private and not ip.is_link_local and not ip.is_unspecified
    except ValueError:
        allowed = host == "localhost" or "." not in host or host.endswith(".internal")
    if not allowed:
        raise ValueError("Public/cloud E2B endpoints are disabled in the task 48 probe")
    return url


def options(config):
    key = Path(config["api_key_file"]).read_text().strip()
    if not key:
        raise ValueError("An explicit self-hosted E2B key is required; environment fallback is forbidden")
    return {"api_url": private_endpoint(config["api_url"]),
            "sandbox_url": private_endpoint(config["sandbox_url"]),
            "api_key": key,
            "domain": "task48.internal", "debug": False, "retries": 0,
            "request_timeout": 15}


def create_sandbox(config):
    # `secure` is a deprecated no-op in this E2B version; do not rely on it.
    return Sandbox.create(template=config["template"], timeout=120,
        allow_internet_access=False,
        # The pinned real E2B server rejects IPv6 CIDRs. IPv6 is disabled in the
        # microVM by trusted preparation below, before any agent/tool runs.
        network={"deny_out": ["0.0.0.0/0"], "allow_public_traffic": False},
        **options(config))


def build_template(config):
    # Only the synthetic fixture directory is eligible for template uploads.
    root = Path(__file__).parent
    template = (Template(file_context_path=root / "input").from_image(BASE_IMAGE)
        .run_cmd("if ! id -u user >/dev/null 2>&1; then useradd --uid 1000 --create-home user; fi && "
                 "test \"$(id -u user)\" = 1000 && "
                 "mkdir -p /workspace/input /workspace/work /workspace/output /conversation_history /large_tool_results && "
                 "chown user:user /workspace/work /workspace/output /conversation_history /large_tool_results", user="root")
        .copy("numbers.csv", "/workspace/input/numbers.csv", user="root", mode=0o444)
        .run_cmd("chmod 0555 /workspace/input && find / -xdev -type f -perm /6000 -exec chmod a-s {} +", user="root")
        .set_user("user").set_workdir("/workspace/work"))
    # Construction uses verified public SDK methods. Actual build remains pending
    # until a compatible host is explicitly provided.
    return Template.build(template, alias=config["template"], cpu_count=1,
                          memory_mb=256, **options(config))


def prepare(sandbox):
    # Trusted preparation before agent execution, inside the microVM, never host.
    sandbox.commands.run("mount --bind /workspace/input /workspace/input && "
                         "mount -o remount,bind,ro /workspace/input && "
                         "printf 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6 && "
                         "printf 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6", user="root", timeout=10)
    source = Path(__file__).with_name("runtime_checks.py").read_text()
    check = source.split('if __name__ == "__main__":')[0] + (
        "\ncontract = filesystem_contract()\n"
        "contract['ipv6_disabled'] = all(Path('/proc/sys/net/ipv6/conf/' + name + '/disable_ipv6').read_text().strip() == '1' for name in ('all', 'default'))\n"
        "if not contract['ipv6_disabled']: raise RuntimeError('IPv6 is not disabled')\n"
        "print(json.dumps(contract))\n")
    result = sandbox.commands.run("python -I -c " + shlex.quote(check), timeout=10)
    contract = json.loads(result.stdout)
    sandbox.commands.run("test -z \"$(ls -A /workspace/work)\" && test -z \"$(ls -A /workspace/output)\"", timeout=10)
    return contract


def live_probe(config):
    targets = config["controlled_targets"]
    if {ipaddress.ip_address(t["address"]).version for t in targets} != {4, 6}:
        raise ValueError("Supply live controlled IPv4 AND IPv6 receiver addresses")
    # Positive controls MUST have been run immediately before this command from
    # a control host on the receiver network, and repeated afterwards. The report
    # remains incomplete without that separate evidence.
    executor_denials = [connect_probe(t["address"], t["port"], denied=True) for t in targets]
    report = {"scope": "self-hosted-e2b", "started_utc": datetime.now(timezone.utc).isoformat(),
              "executor_denials": executor_denials, "positive_controls": "require separate control-host evidence",
              "trials": [], "paid_calls": 0}
    seen = set()
    for mode in ("cold", "prepared"):
        started = time.perf_counter()
        sandbox = create_sandbox(config)
        try:
            if sandbox.sandbox_id in seen:
                raise RuntimeError("Backend reused an already assigned sandbox")
            seen.add(sandbox.sandbox_id)
            contract = prepare(sandbox)
            preparation_seconds = time.perf_counter() - started
            # One prepared clean environment, assigned once. No reusable dirty
            # pool and no second agent loop. Includes a real readiness roundtrip.
            assignment = time.perf_counter()
            backend = E2BSandbox(sandbox=sandbox, workdir="/workspace/work", timeout=10)
            if backend.execute("test -z \"$(ls -A /workspace/output)\"").exit_code != 0:
                raise RuntimeError("Prepared sandbox is dirty")
            assignment_seconds = time.perf_counter() - assignment
            source = Path(__file__).with_name("runtime_checks.py").read_text().split('if __name__ == "__main__":')[0]
            source += "\nprint(json.dumps([connect_probe(t['address'], t['port'], denied=True) for t in " + repr(targets) + "]))\n"
            raw = backend.execute("python -I -c " + shlex.quote(source), timeout=10)
            if raw.exit_code != 0:
                raise RuntimeError("Sandbox socket denial failed; diagnostic withheld")
            proof = run_probe(backend)
            downloaded = backend.download_files(["/workspace/output/totals.json"])[0]
            if downloaded.error or json.loads(downloaded.content) != EXPECTED:
                raise RuntimeError("Sandbox output artifact differs from the model result")
            report["trials"].append({"mode": mode, "sandbox_id": sandbox.sandbox_id,
                "preparation_seconds": preparation_seconds, "assignment_seconds": assignment_seconds,
                "contract": contract, "sandbox_denials": json.loads(raw.output), "sdk": proof})
        finally:
            sandbox.kill()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--build-template", action="store_true")
    args = parser.parse_args()
    if args.report.exists():
        parser.error("Choose a new report path; existing evidence will not be overwritten")
    if not args.config:
        args.report.write_text(json.dumps({"status": "pending", "backend": "e2b-self-hosted",
            "reason": "No compatible host configuration supplied", "real_sandbox_execution": False,
            "sandbox_network_isolation": "pending", "cold_seconds": None, "prepared_seconds": None}, indent=2))
        return 2
    config = json.loads(args.config.read_text())
    if args.build_template:
        build_template(config)
    report = live_probe(config)
    args.report.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
