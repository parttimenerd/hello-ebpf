// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.bpf.QueuedTask;
import me.bechberger.ebpf.bpf.userspace.UserspaceScheduler;
import me.bechberger.femtocli.FemtoCli;
import me.bechberger.femtocli.annotations.Command;
import me.bechberger.femtocli.annotations.Option;

import java.util.ArrayDeque;

/**
 * <b>Experimental</b> — API may change without notice.
 *
 * <p>Two-queue FIFO scheduler with persistent cross-batch queues.
 *
 * <p>Demonstrates {@link QueuedTask#copy()} — tasks are copied out of the
 * flyweight pool and held in {@link ArrayDeque}s that survive across drain
 * cycles. Interactive tasks (low {@code execRuntime}) always drain before
 * batch tasks regardless of which drain cycle they arrived in.
 *
 * <h2>Why copy() is needed</h2>
 * <p>The framework reuses the same {@code QueuedTask[]} pool on every drain.
 * Holding a raw reference to a task after {@code schedule()} returns means
 * the fields will be overwritten by the next batch. {@link QueuedTask#copy()}
 * produces a heap-owned instance safe to enqueue, sort, or defer.
 *
 * <h2>The catch</h2>
 * <p>Every copied task must still be dispatched promptly — the kernel's 50 ms
 * stall watchdog fires if a task sits undispatched too long. This scheduler
 * dispatches everything that has accumulated across both queues on every
 * {@code schedule()} call, so nothing is truly deferred — only reordered
 * across batches.
 */
public final class TwoQueueFifoSample extends UserspaceScheduler {

    private static final long INTERACTIVE_THRESHOLD_NS = 10_000_000L; // 10 ms total CPU

    // Persistent across batches — safe because we store copies, not flyweights.
    private final ArrayDeque<QueuedTask> highPri = new ArrayDeque<>();
    private final ArrayDeque<QueuedTask> lowPri  = new ArrayDeque<>();

    @Override
    protected void schedule(QueuedTask[] tasks, int count) {
        // Copy incoming tasks into the appropriate persistent queue.
        for (int i = 0; i < count; i++) {
            QueuedTask t = tasks[i];
            if (t.execRuntime < INTERACTIVE_THRESHOLD_NS) {
                highPri.addLast(t.copy());
            } else {
                lowPri.addLast(t.copy());
            }
        }

        // Drain high-priority first, then low-priority.
        // dispatchTask() accepts copies just as well as flyweights.
        while (!highPri.isEmpty()) dispatchTask(highPri.pollFirst(), ANY_CPU);
        while (!lowPri.isEmpty())  dispatchTask(lowPri.pollFirst(),  ANY_CPU);
    }

    @Command(name = "TwoQueueFifoSample",
            description = {
                "Two-queue FIFO: interactive tasks (low execRuntime) dispatched before batch tasks.",
                "Uses QueuedTask.copy() to hold tasks in persistent ArrayDeques across batches.",
            },
            mixinStandardHelpOptions = true)
    static final class Cli implements Runnable {

        @Option(names = {"--stats-interval"},
                description = "Seconds between stats prints to stderr (0 = disable).",
                defaultValue = "5")
        int statsInterval;

        @Override
        public void run() {
            new TwoQueueFifoSample().runWithCli("TwoQueueFifoSample", statsInterval, null);
        }
    }

    public static void main(String[] args) {
        FemtoCli.run(new Cli(), args);
    }
}
