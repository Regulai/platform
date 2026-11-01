#!/bin/bash
# Run as root only in the dedicated installer VM.
set -euo pipefail
test "$(hostname)" = task48-e2b-vm
cloud-init status --wait
python3 - <<'PY'
import fcntl, os
fd = os.open('/dev/kvm', os.O_RDWR)
vm = fcntl.ioctl(fd, 0xAE01, 0)
os.close(vm)
os.close(fd)
print('Nested KVM verified.')
PY
export DEBIAN_FRONTEND=noninteractive
if ! command -v docker >/dev/null; then
    sed -i 's|http://|https://|g' /etc/apt/sources.list.d/ubuntu.sources
    apt-get -o Acquire::Retries=2 update -qq
    apt-get install -y -qq docker.io docker-compose-v2 docker-buildx iptables rsync e2fsprogs iproute2 curl
fi
systemctl enable --now docker
mkdir -p /home/probe/e2b /opt/regulai
cd /home/probe/e2b
if [ ! -f compose.yaml ]; then
    for file in compose.yaml .env; do
        curl --fail --silent --show-error --location --retry 2 \
          "https://raw.githubusercontent.com/e2b-dev/runtime/79098f5667b695c9fa8d087305068e1950dccc54/embed/compose/$file" --output "$file"
    done
    printf '\nHUGEPAGES=1536\n' >> .env
fi
printf 'vm.nr_hugepages=1536\n' > /etc/sysctl.d/90-regulai.conf
sysctl -w vm.nr_hugepages=1536
if [ -f .regulai-initialized ]; then
    docker compose run --rm --no-deps host-setup
    docker compose up -d --no-deps --wait --wait-timeout 600 postgres redis clickhouse vector orchestrator api dashboard-api client-proxy dashboard ready
else
    docker compose up -d --wait --wait-timeout 600
    touch .regulai-initialized
fi
echo 'Private E2B is running.'
