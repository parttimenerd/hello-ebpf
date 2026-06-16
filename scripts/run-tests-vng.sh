#!/bin/bash
# Run each bpf-module test class in its own virtme-ng VM (root inside the VM,
# host kernel + host rootfs as copy-on-write). Aggregates surefire output into
# one summary table.
#
# Run on thinkstation: this script lives on the mac but is intended to be
# invoked via `./scripts/ts.sh ./scripts/run-tests-vng.sh`.
#
# Why per-class VMs: Phase 0.4 found 19 tests that need root (CAP_SYS_ADMIN
# for bpf(2)). thinkstation has no NOPASSWD; running each class in its own
# vng gives root + isolation (a stuck/leaky bpf program can't poison the next
# class). Pre-built artifacts are shared via the host rootfs (CoW).

set -u

KERNEL=/boot/vmlinuz-6.17.0-35-generic
JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn
MVN=/home/i560383/.m2/wrapper/dists/apache-maven-3.8.7-bin/678cc9d4/apache-maven-3.8.7/bin/mvn
HOST_HOME=/home/i560383

TESTS=(
    ArrayMapTest
    AttachAnnotationTest
    AutoPtrTest
    BasePacketParserTest
    BloomFilterMapTest
    BPFArenaSmokeTest
    BpfAtomicOpsTest
    BpfContextHelpersTest
    BPFInlineTest
    BpfLoopCallsBpfFunctionTest
    BpfLoopEarlyBreakTest
    BpfLoopLocalStructTest
    BpfLoopMultiAccumulatorTest
    BpfLoopNestedTest
    BpfLoopNestedTypedCtxTest
    BpfLoopPrimitiveCtxTest
    BpfLoopStructCtxTest
    BpfLoopTest
    BpfMapBpfSideHelpersTest
    BpfMapDeleteTest
    BpfSnprintfAdvancedTest
    BpfSnprintfTest
    BpfStackTest
    BpfTimerTest
    BPFProgramExtensionTest
    BPFTypedArenaTest
    ChainedBpfFunctionTest
    CoReFieldExistsTest
    CoReInExpressionTest
    CoReInLambdaTest
    CoReMethodCallRootTest
    CoReMixedChainTest
    CoReMultiLevelTest
    CoReTest
    DataTypeTest
    FEntryExitAutoAttachTest
    FexitAnnotationTest
    GetCurrentCommTest
    GlobalVariableStructTest
    GlobalVariableTest
    HashMapBpfOperationsTest
    HashMapTest
    HelloWorldTest
    KretprobeAttachTest
    KsyscallAttachTest
    LRUHashMapBpfSideTest
    MapForEachLruTest
    MapForEachTest
    MapForEachTypedCtxTest
    PerCpuArrayMultiKeyTest
    PerCpuArrayTest
    PerCpuVarTest
    PrefixIncrementTest
    QueueMapTest
    RawTracepointAnnotationTest
    RealVerifierClassificationTest
    RingBufferMultiEventTest
    RingBufferTypedEventTest
    SchedulerSmokeTest
    SchedulerTimeoutTest
    SetFieldTest
    SyscallProgramTest
    TailCallTest
    TCHookTest
    TimerCallbackTest
    TracepointAnnotationTest
    TracepointAttachTest
    TracePrintkTest
    TypeLayoutTest
    TypeProcessingTest
    XDPContextTest
    VerifierLogCaptureSuccessTest
    VerifierLogCaptureTest
    VerifierLogCaptureUnitTest
)

# Allow caller to override the test list:
#   run-tests-vng.sh                       → all classes above
#   run-tests-vng.sh HelloWorldTest        → just one
#   run-tests-vng.sh HelloWorldTest ArrayMapTest
# Class names are matched against the bpf module's surefire `-Dtest=` arg, so
# anything surefire accepts (globs like `Hello*`) works too.
if [ $# -gt 0 ]; then
    TESTS=("$@")
fi

REPO="$(cd "$(dirname "$0")/.." && pwd)"
# vng overlays / with a CoW snapshot, so writes inside the repo dir get rolled
# back when the VM exits — even host-side writes that happen *while* vng is
# running. /tmp is outside that overlay on this host. Logs land there; we
# symlink the dir back into the repo for convenience.
LOGDIR="/tmp/vng-test-logs"
mkdir -p "$LOGDIR"
ln -sfn "$LOGDIR" "$REPO/.vng-test-logs"

declare -A COUNTS

# Pre-compile both test modules on the host so that VNG (2G RAM) never has to
# run the annotation processor + javac for all source files — that triggers
# a JVM JIT crash inside virtme-ng.  The "Nothing to compile" fast-path inside
# VNG takes <1 s.
echo "--- Pre-compiling bpf and bpf-samples test classes on host ---"
"$MVN" -ntp -pl bpf,bpf-samples test-compile -q 2>/dev/null || true
echo "--- Done pre-compiling ---"

for cls in "${TESTS[@]}"; do
    log="$LOGDIR/$cls.log"
    echo "=== $cls ==="

    # Determine which Maven module hosts the test class.
    # Tests in bpf-samples reside under bpf-samples/src/test; all others use bpf.
    if find "$REPO/bpf-samples/src/test" -name "${cls}.java" 2>/dev/null | grep -q .; then
        MODULE="bpf-samples"
    else
        MODULE="bpf"
    fi

    # Build the in-VM command: pin JDK and mvn, override HOME so ~/.m2 is the
    # host's, scope the reactor to the module that owns this test, require
    # offline-only resolution from the host m2 cache.
    inner="export HOME=$HOST_HOME JAVA_HOME=$JAVA_HOME PATH=$JAVA_HOME/bin:\$PATH && cd $REPO && $MVN -ntp -pl $MODULE test -Dtest=$cls -Dmaven.test.skip=false -DskipTests=false -Dmaven.repo.local=$HOST_HOME/.m2/repository"

    vng --network user --memory 2G --run "$KERNEL" --user root --cwd "$REPO" -- "$inner" \
        > "$log" 2>&1 < /dev/null

    # Surefire summary line, e.g. "[INFO] Tests run: 5, Failures: 0, Errors: 0, Skipped: 0"
    line=$(grep -E 'Tests run: [0-9]+, Failures: [0-9]+, Errors: [0-9]+, Skipped: [0-9]+' "$log" | tail -1)
    if [ -z "$line" ]; then
        if grep -q 'BUILD SUCCESS' "$log"; then
            COUNTS[$cls]="-/-/-/-"  # built but no tests ran (test method not found?)
        else
            COUNTS[$cls]="VM_OR_BUILD_FAILED"
        fi
    else
        COUNTS[$cls]=$(echo "$line" | sed -E 's/.*Tests run: ([0-9]+), Failures: ([0-9]+), Errors: ([0-9]+), Skipped: ([0-9]+).*/\1\/\2\/\3\/\4/')
    fi
    echo "  → ${COUNTS[$cls]}"
done

echo
echo "================ SUMMARY (run/fail/err/skip) ================"
total_run=0; total_fail=0; total_err=0; total_skip=0
for cls in "${TESTS[@]}"; do
    printf "  %-30s  %s\n" "$cls" "${COUNTS[$cls]}"
    if [[ "${COUNTS[$cls]}" =~ ^([0-9]+)/([0-9]+)/([0-9]+)/([0-9]+)$ ]]; then
        total_run=$((total_run + ${BASH_REMATCH[1]}))
        total_fail=$((total_fail + ${BASH_REMATCH[2]}))
        total_err=$((total_err + ${BASH_REMATCH[3]}))
        total_skip=$((total_skip + ${BASH_REMATCH[4]}))
    fi
done
echo "------------------------------------------------------------"
printf "  %-30s  %d/%d/%d/%d\n" "TOTAL" "$total_run" "$total_fail" "$total_err" "$total_skip"
echo
echo "Per-class logs in: $LOGDIR/<ClassName>.log"
