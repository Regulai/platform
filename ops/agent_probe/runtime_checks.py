"""Synthetic socket and filesystem checks, shared by local and live probes."""
import errno
import ipaddress
import json
import os
from pathlib import Path
import socket
import socketserver
import sys

MARKER = b"task48-synthetic-only"


def ipv6_disabled_by_kernel():
    try:
        return all(Path('/proc/sys/net/ipv6/conf/' + name + '/disable_ipv6').read_text().strip() == '1'
                   for name in ('all', 'default'))
    except OSError:
        return False


def connect_probe(address, port, *, denied):
    ip = ipaddress.ip_address(address)  # No DNS failure can masquerade as denial.
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        try:
            sock.connect((address, port))
        except OSError as exc:
            # Refused connections, DNS errors, missing services etc. aren't proof
            # of firewall denial. The harness also requires a positive control.
            # A Linux guest with IPv6 disabled returns EADDRNOTAVAIL rather
            # than ENETUNREACH. Accept ONLY when both kernel controls prove it;
            # the same errno for IPv4 or an enabled IPv6 stack must fail.
            disabled_ipv6 = (ip.version == 6 and exc.errno == errno.EADDRNOTAVAIL
                             and ipv6_disabled_by_kernel())
            if not denied or (not disabled_ipv6 and exc.errno not in {None, errno.EACCES, errno.EPERM,
                                               errno.ENETUNREACH, errno.EHOSTUNREACH,
                                               errno.ETIMEDOUT}):
                raise
            return {"address": str(ip), "port": port, "denied": True,
                    "error": type(exc).__name__, "errno": exc.errno,
                    "ipv6_disabled_by_kernel": disabled_ipv6}
        if denied:
            raise RuntimeError("Unapproved synthetic destination was reachable")
        sock.sendall(MARKER)
        if sock.recv(128) != MARKER:
            raise RuntimeError("Synthetic receiver returned an unexpected response")
        return {"address": str(ip), "port": port, "denied": False, "control": "echo-confirmed"}


def filesystem_contract():
    if os.geteuid() == 0:
        raise RuntimeError("Sandbox code is running as root")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    if int(status["CapEff"].strip(), 16) != 0:
        raise RuntimeError("Sandbox code has effective Linux capabilities")
    forbidden = ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "AWS_SECRET_ACCESS_KEY",
                 "DATABASE_URL", "DJANGO_SECRET_KEY", "LANGSMITH_API_KEY")
    if any(os.environ.get(name) for name in forbidden):
        raise RuntimeError("Forbidden host/provider credential in workload environment")
    if Path("/var/run/docker.sock").exists():
        raise RuntimeError("Docker control socket visible to workload")
    path = Path("/workspace/input/numbers.csv")
    original = path.read_bytes()
    try:
        with path.open("wb"):
            pass
    except OSError as exc:
        if exc.errno not in {errno.EACCES, errno.EROFS, errno.EPERM}:
            raise
    else:
        raise RuntimeError("Input is writable")
    if path.read_bytes() != original:
        raise RuntimeError("Synthetic input changed")
    for directory in ("work", "output"):
        marker = Path("/workspace") / directory / "task48-write-probe"
        marker.write_text("synthetic")
        marker.unlink()
    return {"uid": os.geteuid(), "effective_capabilities": 0, "input_readonly": True,
            "work_writable": True, "output_writable": True, "docker_socket": False,
            "provider_credentials": False, "no_new_privs": status["NoNewPrivs"].strip()}


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        data = self.request.recv(128)
        if data == MARKER:
            self.request.sendall(MARKER)


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "serve":
        class Server(socketserver.ThreadingTCPServer):
            address_family = socket.AF_INET6
            allow_reuse_address = True

            def server_bind(self):
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                super().server_bind()
        with Server(("::", 8080), Echo) as server:
            server.serve_forever()
    elif mode in {"deny", "allow"}:
        print(json.dumps(connect_probe(sys.argv[2], int(sys.argv[3]), denied=mode == "deny")))
    elif mode == "contract":
        print(json.dumps(filesystem_contract()))
    else:
        raise SystemExit("Expected serve, deny, allow or contract")
