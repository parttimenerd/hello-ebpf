#!/bin/sh
# Watch local repo and rsync changes to thinkstation.
# Uses fswatch if installed, else polls every 1s.
# Usage: scripts/sync-watch.sh        (foreground)
#        scripts/sync-watch.sh &      (background; logs to scripts/.sync-watch.log)

set -e

cd "$(dirname "$0")/.."

PIDFILE="scripts/.sync-watch.pid"
LOGFILE="scripts/.sync-watch.log"

if [ -f "$PIDFILE" ]; then
    OLD=$(cat "$PIDFILE" 2>/dev/null || true)
    if [ -n "$OLD" ] && kill -0 "$OLD" 2>/dev/null; then
        echo "sync-watch already running (pid $OLD); exiting" >&2
        exit 0
    fi
    rm -f "$PIDFILE"
fi

echo $$ > "$PIDFILE"
trap 'rm -f "$PIDFILE"' EXIT INT TERM

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }

do_sync() {
    if ! ./scripts/sync.sh 2>&1; then
        log "sync failed (exit $?)"
    fi
}

log "initial sync"
do_sync

if command -v fswatch >/dev/null 2>&1; then
    log "watching with fswatch"
    fswatch -o \
        --exclude '\.git/' \
        --exclude 'target/' \
        --exclude '\.idea/' \
        --exclude '\.bpf\.compile\.cache/' \
        --exclude 'scripts/\.sync-watch\.(pid|log)' \
        . | while read -r _; do
            log "change detected"
            do_sync
        done
else
    log "fswatch not found; polling every 1s (brew install fswatch for instant sync)"
    while true; do
        sleep 1
        if ./scripts/sync.sh --dry-run 2>/dev/null | grep -q '^[<>cdh*.]'; then
            log "change detected"
            do_sync
        fi
    done
fi
