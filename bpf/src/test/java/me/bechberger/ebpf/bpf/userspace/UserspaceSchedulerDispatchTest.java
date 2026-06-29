// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

import me.bechberger.ebpf.bpf.QueuedTask;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JVM-only unit tests for {@link UserspaceScheduler} dispatch logic.
 *
 * <p>Does NOT load a BPF program or require a sched_ext kernel.
 *
 * <h2>Design</h2>
 * <p>These tests exercise {@link UserspaceScheduler#pickIdleCpu()} and
 * {@link UserspaceScheduler#dispatchInternal(QueuedTask, int)} directly
 * by overriding the two protected seam methods:
 * <ul>
 *   <li>{@link UserspaceScheduler#idleMaskView()} — returns a heap-allocated
 *       {@link MemorySegment} whose bits we control, no BPF fd needed.</li>
 *   <li>{@link UserspaceScheduler#submitDispatch(int, int, long, long, long)} —
 *       records calls without touching a real ring buffer.</li>
 * </ul>
 *
 * <h2>Drain-loop integration</h2>
 * <p>The full drain-loop path ({@code drainBatchOnce} → {@code consumeRaw} →
 * {@code fillFromSegment} → {@code policy} → {@code dispatchInternal}) requires
 * a live {@code BPFRingBuffer} and is covered by Task 18
 * (RustlandFifoSampleSmokeTest) which runs on a sched_ext kernel.
 *
 * <h2>Lifecycle tests</h2>
 * <p>Run-loop lifecycle (requestExit, kernel-detach, tick) lives in
 * {@link UserspaceSchedulerLifecycleTest}.
 */
public class UserspaceSchedulerDispatchTest {

    // ── Controllable test subclass ────────────────────────────────────────────

    /**
     * Test-only subclass that overrides BPF seams so tests run without a kernel.
     *
     * <ul>
     *   <li>{@link #idleMaskView()} returns {@link #stubMask} — a heap segment.</li>
     *   <li>{@link #submitDispatch} records calls in {@link #submitted} and
     *       returns {@link #submitResult}.</li>
     * </ul>
     */
    static class TestSched extends UserspaceScheduler implements AutoCloseable {

        // ── idle-mask seam ──────────────────────────────────────────────────
        final Arena maskArena = Arena.ofConfined();
        /** 128-byte heap segment; word i covers CPUs [64i .. 64i+63]. */
        final MemorySegment stubMask = maskArena.allocate(16 * 8L, 8);

        /** Set CPU bit in the stub idle mask. */
        void setIdle(int cpu) {
            long off = (long)(cpu / 64) * 8L;
            long cur = stubMask.get(ValueLayout.JAVA_LONG, off);
            stubMask.set(ValueLayout.JAVA_LONG, off, cur | (1L << (cpu & 63)));
        }

        /** Clear CPU bit in the stub idle mask. */
        void clearIdle(int cpu) {
            long off = (long)(cpu / 64) * 8L;
            long cur = stubMask.get(ValueLayout.JAVA_LONG, off);
            stubMask.set(ValueLayout.JAVA_LONG, off, cur & ~(1L << (cpu & 63)));
        }

        @Override
        protected MemorySegment idleMaskView() { return stubMask; }

        // ── submit seam ─────────────────────────────────────────────────────
        /** Records {targetCpu, pid, enqCnt} per submitDispatch call. */
        final List<int[]> submitted = new ArrayList<>();
        int submitResult = 0;

        @Override
        protected int submitDispatch(int targetCpu, int pid, long enqCnt, long sliceNs, long vtime) {
            submitted.add(new int[]{targetCpu, pid, (int) enqCnt});
            return submitResult;
        }

        // ── lifecycle seams ─────────────────────────────────────────────────
        @Override protected void loadAndAttachBpf() { /* no-op */ }
        @Override protected void cleanupBpf()       { /* no-op — maskArena closed in close() */ }
        @Override protected boolean isAttached()    { return false; }

        @Override
        public void close() {
            maskArena.close();
        }
    }

    // ── pickIdleCpu tests ─────────────────────────────────────────────────────

    @Test
    @Timeout(5)
    void pickIdleCpuReturnsCpuWhenBitIsSet() {
        try (var sched = new TestSched()) {
            // Set exactly CPU 0 as idle — always in range regardless of nrCpus.
            sched.setIdle(0);
            int cpu = sched.pickIdleCpu();
            assertEquals(0, cpu, "pickIdleCpu should return the single idle CPU (0)");
        }
    }

    @Test
    @Timeout(5)
    void pickIdleCpuReturnsAnyCpuWhenMaskIsEmpty() {
        try (var sched = new TestSched()) {
            // All bits zero.
            assertEquals(UserspaceScheduler.ANY_CPU, sched.pickIdleCpu(),
                    "pickIdleCpu must return ANY_CPU when idle mask is empty");
        }
    }

    @Test
    @Timeout(5)
    void pickIdleCpuReturnsAnyCpuWhenViewIsNull() {
        var sched = new UserspaceScheduler() {
            @Override protected MemorySegment idleMaskView() { return null; }
            @Override protected void loadAndAttachBpf() {}
            @Override protected void cleanupBpf() {}
            @Override protected boolean isAttached() { return false; }
        };
        assertEquals(UserspaceScheduler.ANY_CPU, sched.pickIdleCpu(),
                "pickIdleCpu must return ANY_CPU when idleMaskView returns null");
    }

    @Test
    @Timeout(5)
    void pickIdleCpuRoundRobinAdvancesCursorPastPreviousCpu() {
        int nrCpus = Runtime.getRuntime().availableProcessors();
        if (nrCpus < 2) return; // need at least CPUs 0 and 1

        try (var sched = new TestSched()) {
            // Set CPUs 0 and 1 as idle. The cursor starts at 0.
            sched.setIdle(0);
            sched.setIdle(1);

            // First call: cursor starts at 0, should return CPU 0 (first set bit at/after 0).
            int first = sched.pickIdleCpu();
            assertEquals(0, first,
                    "first pickIdleCpu with cursor=0 and CPUs 0,1 idle should return CPU 0");

            // Second call: cursor is now 1, should return CPU 1.
            int second = sched.pickIdleCpu();
            assertEquals(1, second,
                    "second pickIdleCpu with cursor=1 and CPUs 0,1 idle should return CPU 1");

            // Round-robin guarantee: the two calls must not return the same CPU.
            assertNotEquals(first, second,
                    "round-robin cursor must advance past the previously found CPU");
        }
    }

    // ── dispatchInternal tests ────────────────────────────────────────────────

    @Test
    @Timeout(5)
    void dispatchInternalForwardsExactCpuToSubmit() {
        try (var sched = new TestSched()) {
            QueuedTask t = new QueuedTask();
            t.pid = 1234; t.enqCnt = 7L; t.vtime = 9999L;

            sched.dispatchInternal(t, 3);

            assertEquals(1, sched.submitted.size(), "submitDispatch must be called once");
            int[] rec = sched.submitted.get(0);
            assertEquals(3,    rec[0], "targetCpu must match");
            assertEquals(1234, rec[1], "pid must match");
            assertEquals(7,    rec[2], "enqCnt must match");
        }
    }

    @Test
    @Timeout(5)
    void dispatchInternalCountsSuccessInStats() {
        try (var sched = new TestSched()) {
            QueuedTask t = new QueuedTask();
            t.pid = 42;
            sched.dispatchInternal(t, 1);
            assertEquals(1L, sched.stats().dispatched(),
                    "sDispatched must be 1 after a successful submitDispatch");
            assertEquals(0L, sched.stats().dispatchFailed(),
                    "sDispatchFailed must be 0 on success");
        }
    }

    @Test
    @Timeout(5)
    void dispatchInternalCountsFailureInStats() {
        try (var sched = new TestSched()) {
            sched.submitResult = -1;
            QueuedTask t = new QueuedTask();
            t.pid = 99;
            sched.dispatchInternal(t, 0);
            assertEquals(0L, sched.stats().dispatched(),
                    "sDispatched must remain 0 on submitDispatch failure");
            assertEquals(1L, sched.stats().dispatchFailed(),
                    "sDispatchFailed must be 1 when submitDispatch returns non-zero");
        }
    }

    @Test
    @Timeout(5)
    void dispatchInternalCallsPickIdleCpuWhenAnyCpuPassed() {
        try (var sched = new TestSched()) {
            // CPU 0 is always in range.
            sched.setIdle(0);
            QueuedTask t = new QueuedTask();
            t.pid = 77;

            sched.dispatchInternal(t, UserspaceScheduler.ANY_CPU);

            assertEquals(1, sched.submitted.size());
            assertEquals(0, sched.submitted.get(0)[0],
                    "dispatchInternal(ANY_CPU) must use the idle CPU found by pickIdleCpu");
        }
    }

    // ── stats before run ──────────────────────────────────────────────────────

    @Test
    @Timeout(5)
    void exitedIsFalseBeforeRun() {
        try (var sched = new TestSched()) {
            assertFalse(sched.exited(), "exited() must be false before runUntilExit");
        }
    }

    @Test
    @Timeout(5)
    void statsReturnZeroBeforeRun() {
        try (var sched = new TestSched()) {
            assertEquals(SchedStatsSnapshot.ZERO, sched.stats(),
                    "stats() must return ZERO before runUntilExit (no bpfHandle)");
        }
    }

    // ── Integration-grade tests (require sched_ext kernel) ────────────────────

    /**
     * Full drain-loop integration: BPF enqueues real tasks into the kernel→user
     * ringbuf, Java drains and dispatches them, and {@code stats().dispatched() > 0}.
     * Requires {@code CONFIG_SCHED_CLASS_EXT} and a loaded {@code UserspaceSchedulerBase}.
     * Covered end-to-end by Task 18 (RustlandFifoSampleSmokeTest).
     */
    @Disabled("requires sched_ext kernel — covered in Task 18 (RustlandFifoSampleSmokeTest)")
    @Test
    void fullDrainLoopIntegration() {
        // Placeholder — implementation in Task 18.
    }
}
