#!/usr/bin/env bash
# Throwaway PostgreSQL for the chat UI lab (task 81) when no container runtime is
# available: a cluster in RAM from a local PostgreSQL install (for example inside
# WSL), synthetic credentials, the lab marker and 127.0.0.1:55478 only.
#   init  create the cluster        run   serve it in the foreground
#   drop  remove it once stopped
set -euo pipefail
BIN=${PG_BIN:-$(ls -d /usr/lib/postgresql/*/bin | sort -V | tail -1)}
DIR=${LAB_PG_DIR:-/dev/shm/regulai-chat-ui-20261017}
case "${1:-}" in
  init)
    [ ! -e "$DIR" ] || { echo "exists: $DIR" >&2; exit 1; }
    mkdir -m 700 "$DIR"
    printf synthetic-ci-only > "$DIR/pw"
    "$BIN/initdb" -D "$DIR/data" -U task58 --pwfile="$DIR/pw" --auth=scram-sha-256 \
      -E UTF8 --locale=C.UTF-8 > "$DIR/initdb.log"
    rm "$DIR/pw" ;;
  run)
    exec "$BIN/postgres" -D "$DIR/data" -p 55478 -k "$DIR" -c listen_addresses=127.0.0.1 \
      -c regulai.chat_ui=20261017 -c fsync=off -c synchronous_commit=off -c full_page_writes=off ;;
  drop)
    [ -f "$DIR/data/PG_VERSION" ] || { echo "not a lab cluster: $DIR" >&2; exit 1; }
    if "$BIN/pg_ctl" -D "$DIR/data" status > /dev/null; then echo "still running" >&2; exit 1; fi
    rm -rf -- "$DIR" ;;
  *) echo "usage: $0 init|run|drop" >&2; exit 2 ;;
esac
