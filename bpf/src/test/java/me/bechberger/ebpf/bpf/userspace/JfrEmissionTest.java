// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

import jdk.jfr.Recording;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;
import me.bechberger.ebpf.bpf.QueuedTask;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

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
 * <p>Each test uses {@code JfrTestSched} which extends {@link FakeSchedulerBase}
 * (no-op BPF seams + {@code fakeTasks}-driven {@code drainRaw}) and additionally
 * records which pids were passed to {@code submitDispatch}.
 *
 * <h2>JFR epoch-flush tolerance</h2>
 * <p>JFR may occasionally flush thread-local event buffers from a prior recording
 * epoch when a new recording starts, producing a spurious event that lands in the
 * new recording window. Each test therefore filters or counts only events that match
 * the specific field values produced by that test's tasks, tolerating noise from
 * unrelated events. The real invariant is never "exactly N events" but "the events
 * attributable to this test's tasks look exactly right".
 */
public class JfrEmissionTest {

    @TempDir
    Path tempDir;

    // ── Shared test subclass ──────────────────────────────────────────────────

    /**
     * Extends {@link FakeSchedulerBase} to additionally capture pids passed to
     * {@code submitDispatch} — needed to verify the dispatch path was exercised.
     */
    static class JfrTestSched extends FakeSchedulerBase {

        /** Records pids passed to submitDispatch. */
        final List<Integer> submittedPids = new ArrayList<>();

        @Override
        protected int submitDispatch(int targetCpu, int pid, long enqCnt, long sliceNs, long vtime) {
            submittedPids.add(pid);
            return submitResult;
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
        // Filter to events whose size field matches this batch — tolerates spurious
        // BatchEvents from JFR epoch flushing (which would have a different size).
        List<RecordedEvent> matching = events.stream()
                .filter(ev -> ev.getInt("size") == n)
                .toList();
        assertEquals(1, matching.size(),
                "Exactly one BatchEvent with size=" + n + " must be emitted");
        RecordedEvent ev = matching.get(0);
        assertTrue(ev.getInt("dispatched") > 0,
                "BatchEvent.dispatched must be > 0 when all submits succeed");
    }

    // ── Test 2: DispatchEvent emitted per dispatch (success path) ─────────────

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
        // Filter to only events whose pid is in the expected set — tolerates spurious
        // DispatchEvents from JFR epoch flushing (which would have unrelated pids).
        List<Integer> seenPids = events.stream()
                .filter(ev -> ev.hasField("pid"))
                .map(ev -> ev.getInt("pid"))
                .filter(expectedPids::contains)
                .sorted()
                .toList();
        Collections.sort(expectedPids);
        assertEquals(expectedPids, seenPids,
                "DispatchEvent pids must exactly match the submitted task pids");

        // Verify field values on the matching events.
        for (RecordedEvent ev : events) {
            if (!ev.hasField("pid") || !expectedPids.contains(ev.getInt("pid"))) continue;
            assertEquals(0, ev.getInt("rc"),
                    "DispatchEvent.rc must be 0 on success (pid=" + ev.getInt("pid") + ")");
            assertEquals(UserspaceScheduler.ANY_CPU, ev.getInt("cpu"),
                    "DispatchEvent.cpu must be ANY_CPU when idle mask is null (pid=" + ev.getInt("pid") + ")");
        }
    }

    // ── Test 3: DispatchEvent rc != 0 on submitDispatch failure ──────────────

    @Test
    @Timeout(5)
    void dispatchEventRecordsFailureRc() throws Exception {
        var sched = new JfrTestSched();
        sched.submitResult = -1; // stub returns failure
        QueuedTask t = new QueuedTask();
        t.pid = 500;
        t.enqCnt = 1;
        sched.fakeTasks.add(t);

        Path dump = tempDir.resolve("dispatch-fail.jfr");
        try (var r = new Recording()) {
            r.enable("hellobpf.userspace.Dispatch").withoutThreshold();
            r.setDestination(dump);
            r.start();
            sched.drainBatchOnce();
            r.stop();
        }

        List<RecordedEvent> events = RecordingFile.readAllEvents(dump);
        List<RecordedEvent> matching = events.stream()
                .filter(ev -> ev.hasField("pid") && ev.getInt("pid") == 500)
                .toList();
        assertEquals(1, matching.size(),
                "Exactly one DispatchEvent for pid=500 must be emitted");
        assertNotEquals(0, matching.get(0).getInt("rc"),
                "DispatchEvent.rc must be non-zero when submitDispatch fails");
    }

    // ── Test 4: TickEvent emitted from emitTickEvent() ────────────────────────

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
        assertTrue(heapUsedMb < Runtime.getRuntime().maxMemory() / (1024L * 1024L),
                "TickEvent.heapUsedMb must be less than -Xmx (maxMemory) in MiB");
        assertEquals(0, ev.getInt("frameworkPids"),
                "TickEvent.frameworkPids must be 0 (empty iterable in test)");
    }

    // ── Test 5: No BatchEvent for empty drain ─────────────────────────────────

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
        // Filter to BatchEvents that could have been emitted by this test: size == 0.
        // Any bleed-in from a prior epoch would have size > 0 and is ignored.
        long zeroSizeBatches = events.stream().filter(ev -> ev.getInt("size") == 0).count();
        assertEquals(0, zeroSizeBatches,
                "BatchEvent must NOT be emitted when drain returns 0 tasks");
    }
}
