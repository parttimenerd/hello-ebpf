#!/bin/sh
# Run a command on thinkstation in the synced repo.
# Usage: scripts/ts.sh ./mvnw -pl annotations compile
#        scripts/ts.sh --no-tty 'find bpf-runtime/src -type f | wc -l'
#
# Multi-statement commands or pipes should be passed as a single quoted arg
# so the remote shell sees them intact:
#   scripts/ts.sh 'cmd1 && cmd2 | grep foo'
#
# Sources ~/.sdkman/bin/sdkman-init.sh and runs `sdk env` so the JDK pinned
# in .sdkmanrc takes effect for every command. If sdkman isn't installed,
# the prelude is a no-op.

set -e

REMOTE_DIR="/home/i560383/code/experiments/hello-ebpf"
TTY="-t"

if [ "$1" = "--no-tty" ]; then
    TTY=""
    shift
fi

if [ $# -eq 0 ]; then
    echo "usage: $0 [--no-tty] <command...>" >&2
    exit 2
fi

PRELUDE='export PATH="$HOME/.local/bin:$PATH"; [ -f ~/.sdkman/bin/sdkman-init.sh ] && . ~/.sdkman/bin/sdkman-init.sh > /dev/null 2>&1; [ -f .sdkmanrc ] && sdk env > /dev/null 2>&1; true'

exec ssh $TTY thinkstation "cd $REMOTE_DIR && $PRELUDE && $*"
