#!/bin/bash
set -euo pipefail
iptables -nL REGULAI_V2_EXEC >/dev/null 2>&1 || iptables -N REGULAI_V2_EXEC
iptables -C REGULAI_V2_EXEC -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A REGULAI_V2_EXEC -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -C REGULAI_V2_EXEC -p tcp -m multiport --dports 3000,3002,31058 -j ACCEPT 2>/dev/null || iptables -A REGULAI_V2_EXEC -p tcp -m multiport --dports 3000,3002,31058 -j ACCEPT
iptables -C REGULAI_V2_EXEC -j REJECT --reject-with icmp-admin-prohibited 2>/dev/null || iptables -A REGULAI_V2_EXEC -j REJECT --reject-with icmp-admin-prohibited
iptables -C INPUT -i br-regulai-v2 -j REGULAI_V2_EXEC 2>/dev/null || iptables -I INPUT 1 -i br-regulai-v2 -j REGULAI_V2_EXEC
ip6tables -C INPUT -i br-regulai-v2 -j REJECT 2>/dev/null || ip6tables -I INPUT 1 -i br-regulai-v2 -j REJECT
