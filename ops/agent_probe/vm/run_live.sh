#!/bin/bash
set -euo pipefail
test "$(hostname)" = task48-e2b-vm
mkdir -p /home/probe/task48
cd /home/probe/task48
tar -xf /home/probe/task48-source.tar
python3 -u ops/agent_probe/vm/live_lab.py --output "/home/probe/task48/evidence-$(date -u +%Y%m%dT%H%M%S)"
