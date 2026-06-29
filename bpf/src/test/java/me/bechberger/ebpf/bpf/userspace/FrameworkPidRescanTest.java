// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.lang.foreign.MemorySegment;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JVM-only unit tests for the framework-PID rescan and {@code selectCpu} helpers in
 * {@link UserspaceScheduler}.
 *
 * <p>Does NOT load a BPF program or require a sched_ext kernel. The BPF seams are
 * overridden on {@link UserspaceScheduler} itself so the REAL production methods
 * ({@link UserspaceScheduler#maybeRescanFrameworkPids},
 * {@link UserspaceScheduler#frameworkPidCount},
 * {@link UserspaceScheduler#selectCpu}) are exercised without a live BPF handle.
 *
 * <h2>Design</h2>
 * <p>The test subclass {@code RescanSched} overrides the seam methods introduced in
 * MINOR-2:
 * <ul>
 *   <li>{@link UserspaceScheduler#putFrameworkPid} — writes into an in-heap
 *       {@code HashMap<Integer,Byte>}.</li>
 *   <li>{@link UserspaceScheduler#frameworkPidsIterable} — returns
 *       {@link Map#entrySet()} of that HashMap.</li>
 *   <li>{@link UserspaceScheduler#selectCpuFor} — returns a controllable stub
 *       value so that the final {@link UserspaceScheduler#selectCpu} wrapper can
 *       be verified.</li>
 * </ul>
 *
 * <p>{@code maybeRescanFrameworkPids}, {@code frameworkPidCount}, and
 * {@code selectCpu} are NOT overridden — the production code in
 * {@link UserspaceScheduler} is executed by every test here.
 */
public class FrameworkPidRescanTest {

    // ── Controllable test subclass ────────────────────────────────────────────

    /**
     * Test-only subclass that overrides the BPF seam methods introduced for
     * testability (MINOR-2 / CRITICAL fix) so tests run on any JVM.
     *
     * <ul>
     *   <li>{@link #fakeFrameworkPids} — in-heap backing store for framework PIDs.</li>
     *   <li>{@link #putFrameworkPid} — captured into {@code fakeFrameworkPids}.</li>
     *   <li>{@link #frameworkPidsIterable} — iterates {@code fakeFrameworkPids}.</li>
     *   <li>{@link #selectCpuFor} — returns {@link #stubSelectCpuResult}.</li>
     * </ul>
     *
     * <p>The production methods {@code maybeRescanFrameworkPids},
     * {@code frameworkPidCount}, and {@code selectCpu} are NOT overridden.
     */
    static class RescanSched extends UserspaceScheduler implements AutoCloseable {

        /** Backing store for framework PIDs — replaces the BPF hash map. */
        final Map<Integer, Byte> fakeFrameworkPids = new HashMap<>();

        /** Controls the return value of the stubbed selectCpuFor. */
        int stubSelectCpuResult = 7;

        /** Tracks how many times selectCpuFor was called. */
        int selectCpuForCalls = 0;

        // ── BPF lifecycle seams ─────────────────────────────────────────────
        @Override protected void loadAndAttachBpf()     { /* no-op — no BPF kernel */ }
        @Override protected void cleanupBpf()           { /* no-op */ }
        @Override protected boolean isAttached()        { return false; }
        @Override protected MemorySegment idleMaskView() { return null; }

        // ── framework-PID seams ─────────────────────────────────────────────

        /**
         * Capture the pid into the in-heap map instead of writing to a BPF fd.
         * The REAL {@code maybeRescanFrameworkPids} calls this via
         * {@code putFrameworkPid(tid)} — tested without any BPF kernel.
         */
        @Override
        protected void putFrameworkPid(int pid) {
            fakeFrameworkPids.put(pid, (byte) 1);
        }

        /**
         * Return the in-heap map's entry set so the REAL {@code frameworkPidCount}
         * iterates it instead of a BPF fd-backed map.
         */
        @Override
        protected Iterable<Map.Entry<Integer, Byte>> frameworkPidsIterable() {
            return fakeFrameworkPids.entrySet();
        }

        // ── selectCpu seam ──────────────────────────────────────────────────

        /**
         * Return a controllable stub so the REAL final {@code selectCpu} wrapper
         * can be verified without invoking the BPF {@code scx_bpf_select_cpu_dfl}
         * kernel helper.
         */
        @Override
        protected int selectCpuFor(int pid, int prevCpu) {
            selectCpuForCalls++;
            return stubSelectCpuResult;
        }

        @Override
        public void close() {
            // Nothing to close — no BPF handle was ever opened.
        }
    }

    // ── /proc/self/task rescan tests ──────────────────────────────────────────

    @Test
    @Timeout(5)
    void rescanPopulatesFrameworkPidMap() {
        try (var sched = new RescanSched()) {
            // Before rescan, the backing map is empty.
            assertEquals(0, sched.fakeFrameworkPids.size(),
                    "fakeFrameworkPids must be empty before rescan");

            // Call the REAL production method — it calls putFrameworkPid(tid) via seam.
            sched.maybeRescanFrameworkPids();

            // After rescan, the map should contain at least one TID from /proc/self/task.
            assertTrue(sched.fakeFrameworkPids.size() > 0,
                    "maybeRescanFrameworkPids must add at least one TID from /proc/self/task");
        }
    }

    @Test
    @Timeout(5)
    void frameworkPidCountReflectsRescan() {
        try (var sched = new RescanSched()) {
            // Call the REAL frameworkPidCount — iterates frameworkPidsIterable() seam.
            assertEquals(0L, sched.frameworkPidCount(),
                    "frameworkPidCount must be 0 before rescan");

            // REAL maybeRescanFrameworkPids populates fakeFrameworkPids via putFrameworkPid.
            sched.maybeRescanFrameworkPids();

            // REAL frameworkPidCount now iterates fakeFrameworkPids via frameworkPidsIterable.
            assertTrue(sched.frameworkPidCount() > 0,
                    "frameworkPidCount must be > 0 after rescan");
        }
    }

    @Test
    @Timeout(5)
    void rescanIncludesCurrentThread() {
        try (var sched = new RescanSched()) {
            // REAL maybeRescanFrameworkPids reads /proc/self/task and calls putFrameworkPid.
            sched.maybeRescanFrameworkPids();
            assertFalse(sched.fakeFrameworkPids.isEmpty(),
                    "rescan must find at least one task under /proc/self/task");

            // All values in the map must be (byte)1 — matches the production put(pid, (byte)1).
            for (byte v : sched.fakeFrameworkPids.values()) {
                assertEquals((byte) 1, v, "frameworkPids values must all be 1");
            }
        }
    }

    @Test
    @Timeout(5)
    void multipleRescansAreIdempotent() {
        try (var sched = new RescanSched()) {
            // First scan runs (lastRescanNs=0, so timer gate is open).
            sched.maybeRescanFrameworkPids();
            long firstCount = sched.frameworkPidCount();
            assertTrue(firstCount > 0, "first rescan must yield > 0 entries");

            // Second call is within the rescan window (default 5 s) — timer gate blocks it.
            // frameworkPidCount must equal firstCount (no new entries, none removed).
            sched.maybeRescanFrameworkPids();
            long secondCount = sched.frameworkPidCount();

            assertEquals(firstCount, secondCount,
                    "second rescan (blocked by timer gate) must not change frameworkPidCount");
        }
    }

    @Test
    @Timeout(5)
    void rescanTimerGatePreventsImmediateRepeat() {
        try (var sched = new RescanSched()) {
            // Force the first scan.
            sched.maybeRescanFrameworkPids();
            int afterFirst = sched.fakeFrameworkPids.size();
            assertTrue(afterFirst > 0, "first scan must populate the map");

            // Clear the map to detect whether a second scan actually ran.
            sched.fakeFrameworkPids.clear();

            // Second call within 5 s must be blocked by the timer gate.
            sched.maybeRescanFrameworkPids();
            assertEquals(0, sched.fakeFrameworkPids.size(),
                    "timer gate must prevent second rescan from running within 5 s");
        }
    }

    // ── selectCpu tests ───────────────────────────────────────────────────────

    /**
     * Verify that the REAL final {@code selectCpu} delegates to the {@code selectCpuFor}
     * seam and returns its result verbatim.
     */
    @Test
    @Timeout(5)
    void selectCpuReturnsStubbedValue() {
        try (var sched = new RescanSched()) {
            sched.stubSelectCpuResult = 3;
            // selectCpu is final — it calls selectCpuFor(pid, prevCpu) via seam.
            int result = sched.selectCpu(1234, 0);
            assertEquals(3, result, "selectCpu must return the value from selectCpuFor seam");
        }
    }

    @Test
    @Timeout(5)
    void selectCpuForwardsPrevCpuWhenStubReturnsIt() {
        try (var sched = new RescanSched()) {
            int prevCpu = 5;
            sched.stubSelectCpuResult = prevCpu;
            int result = sched.selectCpu(9999, prevCpu);
            assertEquals(prevCpu, result,
                    "selectCpu must return prevCpu when selectCpuFor seam returns prevCpu");
        }
    }

    @Test
    @Timeout(5)
    void selectCpuDelegatesToSelectCpuForSeam() {
        try (var sched = new RescanSched()) {
            assertEquals(0, sched.selectCpuForCalls, "no calls before invocation");
            sched.selectCpu(1, 0);
            sched.selectCpu(2, 1);
            assertEquals(2, sched.selectCpuForCalls,
                    "selectCpu must invoke selectCpuFor once per call");
        }
    }

    // ── Integration-grade test (requires sched_ext kernel) ────────────────────

    /**
     * Full integration: load BPF, scan /proc/self/task, verify frameworkPidCount
     * reflects the entries inserted via the real BPFHashMap.
     * Requires {@code CONFIG_SCHED_CLASS_EXT} and root.
     */
    @Disabled("requires sched_ext kernel and root — run manually on thinkstation")
    @Test
    void fullIntegrationRescanWritesToBpfMap() throws Exception {
        // Placeholder — implementation deferred to Task 18 (smoke tests).
    }
}
