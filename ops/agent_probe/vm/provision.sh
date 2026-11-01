#!/bin/bash
# Runs as administrator INSIDE the disposable VM, never on Windows/WSL.
set -euo pipefail
test "$(hostname)" = task48-e2b-vm
cloud-init status --wait
uname -r
python3 - <<'PY'
import fcntl, json, os
fd = os.open('/dev/kvm', os.O_RDWR)
vm = fcntl.ioctl(fd, 0xAE01, 0)  # KVM_CREATE_VM, real nested virtualization check
print(json.dumps({'nested_kvm_create_vm': True}))
os.close(vm)
os.close(fd)
PY
export DEBIAN_FRONTEND=noninteractive
sed -i 's|http://|https://|g' /etc/apt/sources.list.d/ubuntu.sources
apt-get -o Acquire::Retries=1 -o Acquire::https::Timeout=20 update -qq
apt-get -o Acquire::Retries=1 -o Acquire::https::Timeout=20 install -y -qq docker.io docker-compose-v2 docker-buildx iptables rsync e2fsprogs iproute2 python3-venv curl
systemctl enable --now docker
mkdir -p /home/probe/e2b
cd /home/probe/e2b
for file in compose.yaml .env; do
    curl --fail --silent --show-error --location \
      "https://raw.githubusercontent.com/e2b-dev/runtime/79098f5667b695c9fa8d087305068e1950dccc54/embed/compose/$file" --output "$file"
done
# Official small-host knob; one 256 MiB sandbox at a time, reserve 1 GiB.
printf '\nHUGEPAGES=512\n' >> .env
sha256sum compose.yaml
docker version --format '{{.Server.Version}}'
docker compose version
docker compose up -d --wait --wait-timeout 600
docker compose ps --format json
# Never print `ready` logs or sdk.env: they include the generated backend key.
