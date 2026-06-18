#!/bin/sh
# One-shot rsync from local mac to thinkstation.
# Usage: scripts/sync.sh [--dry-run|-n] [-v]
#
# Filter rules are inline (not a merge file) because openrsync's merge
# directive has been observed to silently drop protect rules unless at least
# one --exclude is also passed on the command line. Inline is portable across
# openrsync and GNU rsync.

set -e

cd "$(dirname "$0")/.."

REMOTE="thinkstation:/home/i560383/code/experiments/hello-ebpf/"

EXTRA=""
for arg in "$@"; do
    case "$arg" in
        --dry-run|-n) EXTRA="$EXTRA -n --itemize-changes" ;;
        -v) EXTRA="$EXTRA -v" ;;
        *) EXTRA="$EXTRA $arg" ;;
    esac
done

# Generator output and remote-only artifacts: protect from --delete.
# Order matters: protect (P) rules must precede the delete pass.
exec rsync -az --delete $EXTRA \
    --filter='P bpf-runtime/src/**' \
    --filter='P bpf-runtime/target/**' \
    --filter='P rawbpf/bin/**' \
    --filter='R rawbpf/src/main/java/me/bechberger/ebpf/bpf/raw/LibraryLoader.java' \
    --filter='P rawbpf/src/main/java/me/bechberger/ebpf/bpf/raw/*.java' \
    --filter='P .mvn/wrapper/maven-wrapper.jar' \
    --filter='P bpf-gen/src/test/resources/snapshots/**' \
    --filter='P target/**' \
    --filter='P */target/**' \
    --filter='P **/target/**' \
    --filter='P .bpf.compile.cache/**' \
    --exclude='target/' \
    --exclude='.bpf.compile.cache/' \
    --exclude='bpf-runtime/src/' \
    --exclude='rawbpf/bin/' \
    --exclude='.git/' \
    --exclude='.idea/' \
    --exclude='.DS_Store' \
    --exclude='*.swp' \
    --exclude='*.class' \
    --exclude='IMPLEMENTATION_PLAN.md' \
    --exclude='TODO.md' \
    --exclude='SYNC_WORKFLOW.md' \
    --exclude='.plans/' \
    --exclude='scripts/.sync-watch.pid' \
    --exclude='scripts/.sync-watch.log' \
    ./ "$REMOTE"
