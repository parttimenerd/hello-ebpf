#!/bin/zsh
# Run a sample program from the bpf-samples module
# Usage: ./run.sh <sample> [args]
#        ./run.sh doctor       -- check prerequisites

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ---------------------------------------------------------------------------
# doctor subcommand
# ---------------------------------------------------------------------------
if [ "$1" = "doctor" ]; then
    PASS="[OK]"
    FAIL="[FAIL]"
    WARN="[WARN]"
    ok=0; fail=0

    _check() {
        local label="$1"; shift
        if "$@" >/dev/null 2>&1; then
            printf "  %s  %s\n" "$PASS" "$label"
            ok=$((ok+1))
        else
            printf "  %s  %s\n" "$FAIL" "$label"
            fail=$((fail+1))
        fi
    }

    _check_cmd() {
        local label="$1"; local cmd="$2"
        if command -v "$cmd" >/dev/null 2>&1; then
            local ver
            ver=$("$cmd" --version 2>&1 | head -1)
            printf "  %s  %s  (%s)\n" "$PASS" "$label" "$ver"
            ok=$((ok+1))
        else
            printf "  %s  %s  (not found — try: apt install %s)\n" "$FAIL" "$label" "$cmd"
            fail=$((fail+1))
        fi
    }

    echo "hello-ebpf doctor"
    echo "================="

    # Detect darwin (editor host) vs Linux (build/runtime host)
    if [ "$(uname)" = "Darwin" ]; then
        echo ""
        echo "  ${WARN}  This is a darwin machine."
        echo "       Build and test commands run on the Linux build host via ./scripts/ts.sh"
        echo "       See SYNC_WORKFLOW.md for the setup guide."
        echo ""
        echo "  Run './run.sh doctor' on the build host (thinkstation) to check prerequisites."
        exit 0
    fi

    echo ""
    echo "OS / kernel:"
    _check "Linux kernel >= 5.8 (BPF ring buffer)" \
        sh -c 'ver=$(uname -r | cut -d. -f1-2); major=${ver%%.*}; minor=${ver##*.}; [ "$major" -gt 5 ] || ( [ "$major" -eq 5 ] && [ "$minor" -ge 8 ] )'
    _check "kernel >= 6.14 (sched_ext / scx_bpf_dsq_insert)" \
        sh -c 'ver=$(uname -r | cut -d. -f1-2); major=${ver%%.*}; minor=${ver##*.}; [ "$major" -gt 6 ] || ( [ "$major" -eq 6 ] && [ "$minor" -ge 14 ] )'
    _check "BTF available (/sys/kernel/btf/vmlinux)" test -r /sys/kernel/btf/vmlinux

    echo ""
    echo "Toolchain:"
    _check_cmd "clang (need >= 19)" clang
    clang_ver=$(clang --version 2>&1 | grep -oE '[0-9]+\.[0-9]+' | head -1 | cut -d. -f1)
    if [ -n "$clang_ver" ] && [ "$clang_ver" -lt 19 ]; then
        printf "  %s  clang version %s < 19 (upgrade: apt install clang-19)\n" "$FAIL" "$clang_ver"
        fail=$((fail+1)); ok=$((ok-1))
    fi
    _check_cmd "bpftool" bpftool
    _check "llvm-strip (llvm-strip or llvm-strip-*)" \
        sh -c 'command -v llvm-strip >/dev/null 2>&1 || ls /usr/bin/llvm-strip-* 2>/dev/null | grep -q llvm-strip'

    echo ""
    echo "Libraries:"
    _check "libbpf-dev installed" sh -c 'ldconfig -p 2>/dev/null | grep -q libbpf || pkg-config --exists libbpf 2>/dev/null'
    _check "linux-headers / /usr/include/asm present" \
        sh -c 'ls /usr/include/x86_64-linux-gnu/asm/unistd.h /usr/include/aarch64-linux-gnu/asm/unistd.h 2>/dev/null | grep -q asm || ls /usr/include/asm/unistd.h 2>/dev/null | grep -q asm'

    echo ""
    echo "Java:"
    _check_cmd "java (need >= 22)" java
    jver=$(java -version 2>&1 | grep -oE '"[0-9]+' | tr -d '"' | head -1)
    if [ -n "$jver" ] && [ "$jver" -lt 22 ]; then
        printf "  %s  Java version %s < 22 (upgrade via sdkman: sdk install java 25-sapmchn)\n" "$FAIL" "$jver"
        fail=$((fail+1)); ok=$((ok-1))
    fi

    echo ""
    echo "Permissions:"
    if [ "$(id -u)" -eq 0 ]; then
        printf "  %s  running as root\n" "$PASS"
        ok=$((ok+1))
    else
        _check "CAP_BPF capability" sh -c 'capsh --print 2>/dev/null | grep -q cap_bpf || grep -q CapEff /proc/self/status'
        if [ "$?" -ne 0 ]; then
            printf "       (most BPF programs require root or CAP_BPF — run with sudo)\n"
        fi
    fi

    echo ""
    if [ "$fail" -eq 0 ]; then
        echo "All $ok checks passed. You're ready to run hello-ebpf programs."
    else
        echo "$fail check(s) failed, $ok passed."
        echo "Fix the items marked [FAIL] above before running BPF programs."
        exit 1
    fi
    exit 0
fi

# ---------------------------------------------------------------------------
# trace subcommand
# ---------------------------------------------------------------------------
if [ "$1" = "trace" ]; then
    TRACE_PIPE="/sys/kernel/debug/tracing/trace_pipe"
    if [ ! -r "$TRACE_PIPE" ]; then
        echo "Cannot read $TRACE_PIPE — try running as root."
        exit 1
    fi
    FILTER="${2:-}"
    echo "Tailing $TRACE_PIPE (Ctrl-C to stop)${FILTER:+, filtering for: $FILTER}"
    if [ -n "$FILTER" ]; then
        exec cat "$TRACE_PIPE" | grep --line-buffered "$FILTER"
    else
        exec cat "$TRACE_PIPE"
    fi
fi

# ---------------------------------------------------------------------------
# Navigate to samples module
# ---------------------------------------------------------------------------
cd "$SCRIPT_DIR/bpf-samples" || exit

# if empty arguments or help flag, print help
if [ $# -eq 0 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    echo "Usage: $0 <sample>"
    echo "       $0 doctor           -- check prerequisites"
    echo "       $0 trace [filter]   -- tail bpf_trace_printk output"
    echo "Available samples:"
    (cd src/main/java/me/bechberger/ebpf/samples && (
      find . -name "*.java" | while read file; do
        f=$(echo "$file" | sed 's/\//\./g')
        f=${f:2}
        printf "%-35s - " "${f%.java}"
        awk '/\/\*\*/{getline; sub(/^ \* /, ""); print; exit}' "$file"
      done
    ))
    exit 0
fi

CLASS=$1

# Run the program
shift
java -cp target/bpf-samples.jar --enable-native-access=ALL-UNNAMED $JAVA_OPTS me.bechberger.ebpf.samples.$CLASS $@
