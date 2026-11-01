#!/bin/bash
# Restore the private executor's host boundary after the disposable VM reboots.
set -euo pipefail
test "$(hostname)" = task48-e2b-vm
iptables -nL REGULAI_REAL_EXEC >/dev/null 2>&1 || iptables -N REGULAI_REAL_EXEC
iptables -C REGULAI_REAL_EXEC -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A REGULAI_REAL_EXEC -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -C REGULAI_REAL_EXEC -p tcp -m multiport --dports 3000,3002,31049 -j ACCEPT 2>/dev/null || iptables -A REGULAI_REAL_EXEC -p tcp -m multiport --dports 3000,3002,31049 -j ACCEPT
iptables -C REGULAI_REAL_EXEC -j REJECT --reject-with icmp-admin-prohibited 2>/dev/null || iptables -A REGULAI_REAL_EXEC -j REJECT --reject-with icmp-admin-prohibited
iptables -C INPUT -i br-task50 -j REGULAI_REAL_EXEC 2>/dev/null || iptables -I INPUT 1 -i br-task50 -j REGULAI_REAL_EXEC
ip6tables -C INPUT -i br-task50 -j REJECT 2>/dev/null || ip6tables -I INPUT 1 -i br-task50 -j REJECT
