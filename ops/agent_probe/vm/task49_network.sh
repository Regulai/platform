#!/bin/bash
set -euo pipefail
test "$(hostname)" = task48-e2b-vm
mkdir -p /home/probe/task49
cd /home/probe/task49
tar -xf /home/probe/task49-source.tar
python3 -u ops/agent_probe/vm/task49_network.py
