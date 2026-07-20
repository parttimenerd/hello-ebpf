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
 * <p>Pure FIFO scheduler backed by a userland {@link ArrayDeque}.
 *
 * <p>Every arriving task is copied out of the flyweight pool via
 * {@link QueuedTask#copy()} and appended to a persistent queue. On each
 * {@code schedule()} call the entire queue is drained in arrival order.
 *
 * <p>This is the simplest possible demonstration that userland queues work:
 * tasks from batch N may sit in the deque until batch N+1 triggers the drain.
 */
public final class FifoQueueSample extends UserspaceScheduler {

    private final ArrayDeque<QueuedTask> queue = new ArrayDeque<>();

    @Override
    protected void schedule(QueuedTask[] tasks, int count) {
        // Enqueue copies — raw references would be overwritten on next drain.
        for (int i = 0; i < count; i++) {
            queue.addLast(tasks[i].copy());
        }

        // Drain the whole queue in FIFO order.
        while (!queue.isEmpty()) {
            dispatchTask(queue.pollFirst(), ANY_CPU);
        }
    }

    @Command(name = "FifoQueueSample",
            description = {
                "Pure FIFO scheduler backed by a persistent userland ArrayDeque.",
                "Tasks are copied from the flyweight pool and dispatched in arrival order."
            },
            mixinStandardHelpOptions = true)
    static final class Cli implements Runnable {

        @Option(names = {"--stats-interval"},
                description = "Seconds between stats prints to stderr (0 = disable).",
                defaultValue = "5")
        int statsInterval;

        @Override
        public void run() {
            var sched = new FifoQueueSample();
            sched.runWithCli("FifoQueueSample", statsInterval,
                    () -> "queued=" + sched.queue.size());
        }
    }

    public static void main(String[] args) {
        FemtoCli.run(new Cli(), args);
    }
}
