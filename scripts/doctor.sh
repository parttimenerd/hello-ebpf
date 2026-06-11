#!/bin/bash
# Walk hello-ebpf prerequisites and print apt-line fixes for anything missing.
# Usage: ./scripts/doctor.sh
#
# On darwin (the editor host), prints the split-workflow note and exits 0
# rather than reporting a wall of bogus "missing kernel headers" errors.
# On Linux, runs the full check and exits non-zero if any required item
# is missing.

set -u

# ANSI helpers (auto-disable when stdout isn't a tty)
if [ -t 1 ]; then
    OK="\033[32m✓\033[0m"
    WARN="\033[33m!\033[0m"
    BAD="\033[31m✗\033[0m"
    DIM="\033[2m"
    RST="\033[0m"
else
    OK="OK"
    WARN="!"
    BAD="X"
    DIM=""
    RST=""
fi

FAIL=0
WARNED=0

note()  { printf "  ${DIM}%s${RST}\n" "$*"; }
ok()    { printf "${OK} %s\n" "$*"; }
warn()  { printf "${WARN} %s\n" "$*"; WARNED=$((WARNED+1)); }
bad()   { printf "${BAD} %s\n" "$*"; FAIL=$((FAIL+1)); }

# --- darwin short-circuit ----------------------------------------------------
if [ "$(uname -s)" = "Darwin" ]; then
    cat <<'EOF'
This is the editor host (darwin). hello-ebpf builds and tests run only on
Linux with a recent kernel. From here, drive the build host via:

    ./scripts/sync.sh                                         # mac → build host
    ./scripts/ts.sh ./mvnw -pl annotations,bpf-processor test # non-root tests
    ./scripts/ts.sh --no-tty 'bash scripts/run-tests-vng.sh'  # bpf-module tests

See SYNC_WORKFLOW.md for the full split-host workflow and HOW_TO_RUN_TESTS.md
for the test runner. To run doctor on the build host:

    ./scripts/ts.sh ./scripts/doctor.sh
EOF
    exit 0
fi

# --- Linux checks ------------------------------------------------------------
echo "hello-ebpf doctor — checking prerequisites on $(uname -srm)"
echo

# kernel version
KVER=$(uname -r)
KMAJ=${KVER%%.*}
KMIN=${KVER#*.}; KMIN=${KMIN%%.*}
if [ "$KMAJ" -gt 6 ] || { [ "$KMAJ" -eq 6 ] && [ "$KMIN" -ge 1 ]; }; then
    ok "kernel $KVER (>=6.1)"
else
    bad "kernel $KVER is too old (need >=6.1; sched_ext needs >=6.12)"
fi

# BTF
if [ -r /sys/kernel/btf/vmlinux ]; then
    ok "BTF available at /sys/kernel/btf/vmlinux"
else
    bad "BTF not readable at /sys/kernel/btf/vmlinux"
    note "kernel must be built with CONFIG_DEBUG_INFO_BTF=y"
fi

# clang
if command -v clang >/dev/null 2>&1; then
    CLANG_VER=$(clang --version | head -1 | grep -oE '[0-9]+(\.[0-9]+)+' | head -1)
    CLANG_MAJ=${CLANG_VER%%.*}
    if [ -n "${CLANG_MAJ:-}" ] && [ "$CLANG_MAJ" -ge 19 ]; then
        ok "clang $CLANG_VER"
    else
        bad "clang $CLANG_VER is too old (need >=19)"
        note "sudo apt install clang-19  # or newer"
    fi
else
    bad "clang not found"
    note "sudo apt install clang-19 lld-19 libbpf-dev"
fi

# libbpf
if dpkg -s libbpf-dev >/dev/null 2>&1; then
    LIBBPF_VER=$(dpkg -s libbpf-dev | awk '/^Version:/{print $2}')
    ok "libbpf-dev $LIBBPF_VER"
elif [ -r /usr/include/bpf/libbpf.h ]; then
    ok "libbpf headers present (non-dpkg)"
else
    bad "libbpf-dev not installed"
    note "sudo apt install libbpf-dev"
fi

# bpftool
if command -v bpftool >/dev/null 2>&1; then
    ok "bpftool $(bpftool --version 2>&1 | head -1)"
else
    warn "bpftool not found (optional for runtime, required to dump BTF)"
    note "sudo apt install bpftool   # or linux-tools-$(uname -r)"
fi

# JDK
if command -v javac >/dev/null 2>&1; then
    JDK_VER=$(javac -version 2>&1 | grep -oE '[0-9]+' | head -1)
    if [ -n "${JDK_VER:-}" ] && [ "$JDK_VER" -ge 22 ]; then
        ok "JDK $JDK_VER (javac on PATH)"
    else
        bad "JDK $JDK_VER is too old (need >=22)"
        note "use sdkman: sdk install java 25-sapmchn && sdk use java 25-sapmchn"
    fi
else
    bad "javac not on PATH"
    note "use sdkman: curl -s https://get.sdkman.io | bash; sdk install java 25-sapmchn"
fi

# multiarch include dir (mirrors Processor.findIncludePath)
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)    TRIPLET="x86_64-linux-gnu" ;;
    aarch64|arm64)   TRIPLET="aarch64-linux-gnu" ;;
    arm*)            TRIPLET="arm-linux-gnueabihf" ;;
    ppc64le)         TRIPLET="powerpc64le-linux-gnu" ;;
    s390x)           TRIPLET="s390x-linux-gnu" ;;
    riscv64)         TRIPLET="riscv64-linux-gnu" ;;
    *)               TRIPLET="$ARCH-linux-gnu" ;;
esac
if [ -d "/usr/include/$TRIPLET" ]; then
    ok "multiarch include dir /usr/include/$TRIPLET"
elif [ -d /usr/include/linux ] && [ -d /usr/include/asm-generic ]; then
    warn "multiarch dir /usr/include/$TRIPLET missing; falling back to /usr/include/linux"
    note "sudo apt install linux-libc-dev libc6-dev"
else
    bad "no usable kernel/libc include path (tried /usr/include/$TRIPLET and /usr/include/linux)"
    note "sudo apt install libc6-dev linux-libc-dev"
fi

# bpf privilege
UNPRIV=$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo "?")
if [ "$(id -u)" = "0" ]; then
    ok "running as root (CAP_SYS_ADMIN granted)"
elif command -v capsh >/dev/null 2>&1 && capsh --print 2>/dev/null | grep -q cap_bpf; then
    ok "process has CAP_BPF"
elif [ "$UNPRIV" = "0" ]; then
    ok "kernel allows unprivileged bpf() (unprivileged_bpf_disabled=0)"
else
    warn "bpf() will need root: not running as root, no CAP_BPF, unprivileged_bpf_disabled=$UNPRIV"
    note "for tests: ./scripts/ts.sh --no-tty 'bash scripts/run-tests-vng.sh' (uses virtme-ng)"
    note "for samples: sudo ./run.sh <SampleClass>"
fi

# virtme-ng (the test path used by run-tests-vng.sh)
if command -v vng >/dev/null 2>&1; then
    ok "virtme-ng (vng) on PATH — $(vng --version 2>&1 | head -1)"
else
    warn "virtme-ng (vng) not on PATH — bpf-module tests can't run via scripts/run-tests-vng.sh"
    note "pipx install virtme-ng  # then ensure ~/.local/bin is on PATH"
fi

echo
if [ "$FAIL" -eq 0 ] && [ "$WARNED" -eq 0 ]; then
    echo "All checks passed."
    exit 0
elif [ "$FAIL" -eq 0 ]; then
    echo "$WARNED warning(s); no hard failures. You can probably build, but read the notes above."
    exit 0
else
    echo "$FAIL hard failure(s), $WARNED warning(s). Fix the items marked ${BAD} above."
    exit 1
fi
