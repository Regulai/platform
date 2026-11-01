set -euo pipefail
test "$(hostname)" = task48-e2b-vm
for name in task50-worker task50-web task50-postgres; do
  if docker ps -a --format '{{.Names}}' | grep -qx "$name"; then
    test "$(docker inspect "$name" --format '{{index .Config.Labels "regulay.task"}}')" = 50
    docker stop -t 30 "$name"
    for iteration in $(seq 1 60); do
      if ! docker inspect "$name" >/dev/null 2>&1; then break; fi
      sleep 1
    done
  fi
done
iptables -D INPUT -i br-task50 -j TASK50_EXEC
iptables -F TASK50_EXEC
iptables -X TASK50_EXEC
ip6tables -D INPUT -i br-task50 -j REJECT
docker network rm task50-exec
test -z "$(docker ps -a --filter label=regulay.task=50 --format '{{.Names}}')"
test -z "$(docker network ls --filter label=regulay.task=50 --format '{{.Name}}')"
echo 'Task50 containers, network and firewall rules removed; evidence and 48 volumes preserved.'
