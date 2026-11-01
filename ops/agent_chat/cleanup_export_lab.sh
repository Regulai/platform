set -euo pipefail
test "$(hostname)" = task48-e2b-vm
for name in task50-worker task50-web task50-postgres; do
  if docker inspect "$name" >/dev/null 2>&1; then
    test "$(docker inspect "$name" --format '{{index .Config.Labels "regulay.task"}}')" = 50
    automatic="$(docker inspect "$name" --format '{{.HostConfig.AutoRemove}}')"
    docker stop -t 30 "$name"
    if test "$automatic" = true; then
      for iteration in $(seq 1 30); do
        if ! docker inspect "$name" >/dev/null 2>&1; then break; fi
        sleep 1
      done
      ! docker inspect "$name" >/dev/null 2>&1
    else
      docker rm "$name"
    fi
  fi
done
if iptables -C INPUT -i br-task50 -j TASK50_EXEC 2>/dev/null; then
  iptables -D INPUT -i br-task50 -j TASK50_EXEC
  iptables -F TASK50_EXEC
  iptables -X TASK50_EXEC
fi
if ip6tables -C INPUT -i br-task50 -j REJECT 2>/dev/null; then
  ip6tables -D INPUT -i br-task50 -j REJECT
fi
if docker network inspect task50-exec >/dev/null 2>&1; then
  test "$(docker network inspect task50-exec --format '{{index .Labels "regulay.task"}}')" = 50
  docker network rm task50-exec
fi
test -z "$(docker ps -a --filter label=regulay.task=50 --format '{{.Names}}')"
echo 'Isolated task50 containers, network and firewall removed; evidence, checkpoint files and task48 volumes preserved.'
