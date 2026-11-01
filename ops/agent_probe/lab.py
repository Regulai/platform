"""Reproduce SDK + container template + real socket evidence without paid calls.

This lab deliberately DOES NOT label Docker/runc as a verified E2B sandbox.
Only named resources created in this invocation are removed, even on failure.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    tag = "regulay-task48-" + uuid.uuid4().hex[:8]
    networks, containers = [], []
    report = {"started_utc": datetime.now(timezone.utc).isoformat(), "scope": "SDK and local Docker template ONLY",
              "e2b_firecracker": "pending: compatible host required", "e2b_cold_seconds": None,
              "e2b_prepared_seconds": None, "commands": [], "paid_calls": 0}

    def docker(*cmd, check=True):
        result = subprocess.run(["rtk", "proxy", "docker", *cmd], cwd=ROOT,
            text=True, encoding="utf-8", errors="replace", capture_output=True, timeout=600)
        report["commands"].append({"command": ["rtk", "proxy", "docker", *cmd], "exit_code": result.returncode})
        with (output / "commands.log").open("a", encoding="utf-8") as log:
            log.write("\n$ " + " ".join(cmd) + "\n" + result.stdout + result.stderr)
        if check and result.returncode:
            raise RuntimeError(f"Docker {cmd[0]} failed; see {output / 'commands.log'}")
        return result.stdout.strip()

    def run(name, image, network, command, *, detached=False):
        if detached:
            containers.append(name)
        flags = ["-d"] if detached else ["--rm"]
        return docker("run", *flags, "--name", name, "--label", "regulay.task=48",
            "--network", network, "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--user", "1000:1000",
            "--memory", "512m", "--cpus", "1", "--pids-limit", "64",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m,uid=1000,gid=1000",
            "--tmpfs", "/workspace/work:rw,nosuid,nodev,size=32m,uid=1000,gid=1000",
            "--tmpfs", "/workspace/output:rw,nosuid,nodev,size=32m,uid=1000,gid=1000",
            image, *command)

    try:
        info = json.loads(docker("info", "--format",
            '{"OSType":{{json .OSType}},"Architecture":{{json .Architecture}},'
            '"KernelVersion":{{json .KernelVersion}},"ServerVersion":{{json .ServerVersion}},'
            '"Runtimes":"{{range $name, $runtime := .Runtimes}}{{$name}} {{end}}"}'))
        info["Runtimes"] = sorted(info["Runtimes"].split())
        report["host"] = info
        for role in ("executor", "sandbox"):
            print("Building task 48 " + role, flush=True)
            docker("build", "--build-context", f"agents={ROOT / 'regulai/front/agents'}",
                   "-t", "regulay-task48-" + role + ":local", "-f", str(HERE / ("Dockerfile." + role)), str(HERE))
        report["images"] = {role: docker("image", "inspect", "regulay-task48-" + role + ":local", "--format", "{{.Id}}")
                            for role in ("executor", "sandbox")}
        for suffix in ("executor", "receiver"):
            name = tag + "-" + suffix
            docker("network", "create", "--internal", "--ipv6", "--label", "regulay.task=48", name)
            networks.append(name)
        receiver_net, executor_net = networks[1], networks[0]
        fixture = "regulay-task48-sandbox:local"
        executor = "regulay-task48-executor:local"
        run(tag + "-receiver", fixture, receiver_net, ["python", "-I", "/probe/runtime_checks.py", "serve"], detached=True)
        network_info = json.loads(docker("inspect", tag + "-receiver", "--format", "{{json .NetworkSettings.Networks}}"))[receiver_net]
        addresses = [network_info["IPAddress"], network_info["GlobalIPv6Address"]]
        if not all(addresses):
            raise RuntimeError("The controlled receiver needs both IPv4 and IPv6")
        report["network"] = []
        for address in addresses:
            positive = json.loads(run(tag + "-control", fixture, receiver_net,
                ["python", "-I", "/probe/runtime_checks.py", "allow", address, "8080"]))
            denials = {}
            for role, image, script in (("executor", executor, "/app/ops/agent_probe/runtime_checks.py"),
                                        ("template_fixture", fixture, "/probe/runtime_checks.py")):
                denials[role] = json.loads(run(tag + "-deny", image, executor_net,
                    ["python", "-I", script, "deny", address, "8080"]))
            after = json.loads(run(tag + "-control", fixture, receiver_net,
                ["python", "-I", "/probe/runtime_checks.py", "allow", address, "8080"]))
            report["network"].append({"before": positive, "denials": denials, "after": after})
        report["template_contract"] = json.loads(run(tag + "-contract", fixture, executor_net,
            ["python", "-I", "/probe/runtime_checks.py", "contract"]))
        report["template_csv_result"] = json.loads(run(tag + "-csv", fixture, executor_net,
            ["python", "-I", "/probe/probe_csv.py"]))
        if report["template_csv_result"] != {"rows": 3, "total_cents": 750}:
            raise RuntimeError("Local template calculation mismatch")
        # Tests run with no host mounts, secrets, database or public route.
        run(tag + "-sdk", executor, executor_net, ["python", "/app/ops/agent_probe/test_probe.py"])
        report["sdk_tests"] = "passed (E2B operations simulated)"
        report["passed_independent_checks"] = True
    finally:
        for container in reversed(containers):
            docker("rm", "-f", container, check=False)
        for network in reversed(networks):
            docker("network", "rm", network, check=False)
        report["finished_utc"] = datetime.now(timezone.utc).isoformat()
        (output / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"report": str(output / "report.json"),
                      "independent_checks": "passed", "e2b_infrastructure": "pending"}))


if __name__ == "__main__":
    main()
