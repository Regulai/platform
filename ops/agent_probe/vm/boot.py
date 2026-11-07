"""Disposable Ubuntu/KVM host inside Docker; no host mounts or credentials.

This is infrastructure for the one E2B backend, not another sandbox adapter.
Only its named Docker volume is written. SSH is reachable inside this container.
"""
import hashlib
import os
from pathlib import Path
import subprocess
import urllib.request

URL = "https://cloud-images.ubuntu.com/releases/noble/release-20260926/ubuntu-24.04-server-cloudimg-amd64.img"
SHA256 = "6a81c37564db9b1ee84e141922625e1d7c5b389b99bb3c572e0243607d5bb4d2"
ROOT = Path("/vm")


def run(*args):
    subprocess.run(args, check=True)


def main():
    base = ROOT / "base.img"
    if not base.exists():
        print("Downloading pinned Ubuntu image", flush=True)
        partial = ROOT / "base.img.part"
        with urllib.request.urlopen(URL, timeout=60) as source, partial.open("wb") as target:
            while chunk := source.read(1024 * 1024):
                target.write(chunk)
        with partial.open("rb") as source:
            if hashlib.file_digest(source, "sha256").hexdigest() != SHA256:
                raise RuntimeError("Ubuntu download checksum mismatch; restart to retry the partial download")
        partial.replace(base)
    with base.open("rb") as source:
        if hashlib.file_digest(source, "sha256").hexdigest() != SHA256:
            raise RuntimeError("Ubuntu image checksum mismatch")
    if not (ROOT / "disk.qcow2").exists():
        run("qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(base), "/vm/disk.qcow2", os.environ.get('REGULAI_DISK_SIZE', '48G'))
        run("ssh-keygen", "-t", "ed25519", "-N", "", "-f", "/vm/id_ed25519", "-q")
        public_key = (ROOT / "id_ed25519.pub").read_text().strip()
        (ROOT / "user-data").write_text(
            "#cloud-config\nhostname: task48-e2b-vm\nssh_pwauth: false\n"
            "users:\n  - name: probe\n    lock_passwd: true\n    shell: /bin/bash\n"
            "    sudo: ALL=(ALL) NOPASSWD:ALL\n    ssh_authorized_keys:\n      - " + public_key + "\n")
        (ROOT / "meta-data").write_text("instance-id: regulay-task48-disposable\nlocal-hostname: task48-e2b-vm\n")
        run("cloud-localds", "/vm/seed.img", "/vm/user-data", "/vm/meta-data")
    print("Starting disposable VM; SSH only on container loopback:2222", flush=True)
    args = ["qemu-system-x86_64", "-accel", "kvm", "-cpu", "host", "-machine", "q35",
            "-m", "8192", "-smp", "4", "-display", "none", "-serial", "mon:stdio", "-no-reboot",
            "-drive", "file=/vm/disk.qcow2,if=virtio,format=qcow2",
            "-drive", "file=/vm/seed.img,if=virtio,format=raw,readonly=on",
            "-device", "virtio-net-pci,netdev=net0",
            "-netdev", "user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22"]
    os.execvp(args[0], args)


if __name__ == "__main__":
    main()
