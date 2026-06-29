// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

import jdk.jfr.Recording;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;
import me.bechberger.ebpf.bpf.QueuedTask;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.lang.foreign.MemorySegment;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JVM-only tests for JFR event emission in {@link UserspaceScheduler}.
 *
 * <p>Does NOT load a BPF program or require a sched_ext kernel.
 * Uses a synchronous {@link Recording} with {@code withoutThreshold()} so events
 * fire regardless of their duration, and {@code RecordingFile.readAllEvents} for
 * deterministic event retrieval without async-stream timing races.
 *
 * <h2>Design</h2>
 * <p>Each test uses {@code JfrTestSched} which:
 * <ul>
 *   <li>Overrides all BPF lifecycle seams to no-ops.</li>
 *   <li>Overrides {@link UserspaceScheduler#drainRaw()} to fill the package-private
 *       {@code taskPool} with controllable {@link QueuedTask}s and return their count,
 *       so the production {@code drainBatchOnce} + BatchEvent / DispatchEvent logic
 *       runs unchanged.</li>
 *   <li>Overrides {@link UserspaceScheduler#submitDispatch} to record calls and
 *       return 0 (success) without touching a real ring buffer.</li>
 * </ul>
 */
public class JfrEmissionTest {

    @TempDir
    Path tempDir;

    // ── Shared test subclass ──────────────────────────────────────────────────

    /**
     * Test subclass: overrides BPF seams so tests run without a real kernel.
     *
     * <p>Set {@code fakeTasks} before calling {@code drainBatchOnce()} — it is
     * injected via the {@link UserspaceScheduler#drainRaw()} seam into the
     * real production dispatch + event-emission path.
     */
    static class JfrTestSched extends UserspaceScheduler {

        /** Tasks injected into drainRaw for the next drainBatchOnce call. */
        final List<QueuedTask> fakeTasks = new ArrayList<>();

        /** Return value for submitDispatch — 0 = success. */
        int submitResult = 0;

        /** Records pids passed to submitDispatch. */
        final List<Integer> submittedPids = new ArrayList<>();

        // ── BPF lifecycle seams ─────────────────────────────────────────────
        @Override protected void loadAndAttachBpf() { /* no-op */ }
        @Override protected void cleanupBpf()       { /* no-op */ }
        @Override protected boolean isAttached()    { return false; }
        @Override protected MemorySegment idleMaskView() { return null; }

        // ── framework-PID seam ──────────────────────────────────────────────
        @Override protected void putFrameworkPid(int pid) { /* no-op */ }
        @Override
        protected Iterable<Map.Entry<Integer, Byte>> frameworkPidsIterable() {
            return Collections.emptyList();
        }

        // ── submit seam ─────────────────────────────────────────────────────
        @Override
        protected int submitDispatch(int targetCpu, int pid, long enqCnt, long sliceNs, long vtime) {
            submittedPids.add(pid);
            return submitResult;
        }

        /**
         * Drain seam: fill the real {@code taskPool} with {@link #fakeTasks} and
         * return their count. The production {@code drainBatchOnce} then runs the
         * real BatchEvent + DispatchEvent emission path on those tasks.
         *
         * <p>Returns 0 when {@code fakeTasks} is empty so the early-return path
         * in {@code drainBatchOnce} is taken (no BatchEvent emitted).
         */
        @Override
        protected int drainRaw() {
            int n = fakeTasks.size();
            // Ensure taskPool is sized for the fake tasks (production code allocates
            // taskPool lazily in runUntilExit; tests must init it manually).
            ensureTaskPool(n);
            for (int i = 0; i < n; i++) {
                taskPool[i] = fakeTasks.get(i);
            }
            batchCtx.count = n;
            return n;
        }
    }

    // ── Test 1: BatchEvent emitted when tasks are drained ────────────────────

    @Test
    @Timeout(5)
    void batchEventEmittedWhenTasksDrained() throws Exception {
        int n = 3;
        var sched = new JfrTestSched();
        for (int i = 0; i < n; i++) {
            QueuedTask t = new QueuedTask();
            t.pid = 100 + i;
            t.enqCnt = 1;
            sched.fakeTasks.add(t);
        }

        Path dump = tempDir.resolve("batch.jfr");
        try (var r = new Recording()) {
            r.enable("hellobpf.userspace.Batch").withoutThreshold();
            r.setDestination(dump);
            r.start();
            sched.drainBatchOnce();
            r.stop();
        }

        List<RecordedEvent> events = RecordingFile.readAllEvents(dump);
        assertEquals(1, events.size(), "Exactly one BatchEvent must be emitted");
        RecordedEvent ev = events.get(0);
        assertEquals(n, ev.getInt("size"),
                "BatchEvent.size must equal the number of drained tasks");
        assertTrue(ev.getInt("dispatched") > 0,
                "BatchEvent.dispatched must be > 0 when all submits succeed");
    }

    // ── Test 2: DispatchEvent emitted per dispatch ────────────────────────────

    @Test
    @Timeout(5)
    void dispatchEventEmittedPerDispatch() throws Exception {
        int n = 4;
        var sched = new JfrTestSched();
        List<Integer> expectedPids = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            QueuedTask t = new QueuedTask();
            t.pid = 200 + i;
            t.enqCnt = 1;
            sched.fakeTasks.add(t);
            expectedPids.add(200 + i);
        }

        Path dump = tempDir.resolve("dispatch.jfr");
        try (var r = new Recording()) {
            r.enable("hellobpf.userspace.Dispatch").withoutThreshold();
            r.setDestination(dump);
            r.start();
            sched.drainBatchOnce();
            r.stop();
        }

        List<RecordedEvent> events = RecordingFile.readAllEvents(dump);
        assertEquals(n, events.size(),
                "DispatchEvent must be emitted exactly once per dispatched task");

        List<Integer> seenPids = new ArrayList<>();
        for (var ev : events) {
            seenPids.add(ev.getInt("pid"));
        }
        Collections.sort(seenPids);
        Collections.sort(expectedPids);
        assertEquals(expectedPids, seenPids,
                "DispatchEvent pids must exactly match the submitted task pids");
    }

    // ── Test 3: TickEvent emitted from emitTickEvent() ────────────────────────

    @Test
    @Timeout(5)
    void tickEventEmittedFromEmitTickEvent() throws Exception {
        var sched = new JfrTestSched();

        Path dump = tempDir.resolve("tick.jfr");
        try (var r = new Recording()) {
            r.enable("hellobpf.userspace.Tick").withoutThreshold();
            r.setDestination(dump);
            r.start();
            sched.emitTickEvent();
            r.stop();
        }

        List<RecordedEvent> events = RecordingFile.readAllEvents(dump);
        assertEquals(1, events.size(), "Exactly one TickEvent must be emitted");
        RecordedEvent ev = events.get(0);

        long heapUsedMb = ev.getLong("heapUsedMb");
        assertTrue(heapUsedMb > 0,
                "TickEvent.heapUsedMb must be > 0 (JVM always has some heap used)");
        assertTrue(heapUsedMb < Runtime.getRuntime().totalMemory() / (1024L * 1024L),
                "TickEvent.heapUsedMb must be less than totalMemory in MiB");
        assertEquals(0, ev.getInt("frameworkPids"),
                "TickEvent.frameworkPids must be 0 (empty iterable in test)");
    }

    // ── Test 4: No BatchEvent for empty drain ─────────────────────────────────

    @Test
    @Timeout(5)
    void batchEventNotEmittedForEmptyDrain() throws Exception {
        var sched = new JfrTestSched();
        // fakeTasks is empty — should NOT emit a BatchEvent.

        Path dump = tempDir.resolve("empty.jfr");
        try (var r = new Recording()) {
            r.enable("hellobpf.userspace.Batch").withoutThreshold();
            r.setDestination(dump);
            r.start();
            sched.drainBatchOnce();
            r.stop();
        }

        List<RecordedEvent> events = RecordingFile.readAllEvents(dump);
        assertEquals(0, events.size(),
                "BatchEvent must NOT be emitted when drain returns 0 tasks");
    }
}
