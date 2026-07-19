// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.bpf.QueuedTask;
import me.bechberger.ebpf.bpf.userspace.Opts;
import me.bechberger.ebpf.bpf.userspace.UserspaceScheduler;
import me.bechberger.femtocli.FemtoCli;
import me.bechberger.femtocli.annotations.Command;
import me.bechberger.femtocli.annotations.Option;

import java.util.HashMap;
import java.util.Map;

/**
 * <b>Experimental</b> — API may change without notice.
 *
 * <p>Latency-aware interactive-boost scheduler. Classifies each task as
 * <em>interactive</em> or <em>batch</em> based on how much CPU it has been
 * burning recently, then favours interactive tasks so UI/latency-sensitive
 * work stays responsive under load from CPU hogs.
 *
 * <h2>Classification</h2>
 * <p>A task's recent CPU appetite is tracked as an exponentially-weighted moving
 * average of its {@code execRuntime} deltas between successive enqueues. A task
 * that repeatedly sleeps (short runs) stays "interactive"; a task that runs to
 * the end of its slice every time drifts "batch".
 *
 * <h2>Policy</h2>
 * <p>Interactive tasks are dispatched first, to a freshly-selected idle CPU, so
 * their wake-to-run latency is minimal. Batch tasks are dispatched after, to any
 * idle CPU.
 *
 * <p>The interesting case — and the one that motivates preemption — is when an
 * interactive task wakes while every CPU is busy running batch hogs. Placement
 * alone can't help it: the task will sit in a DSQ until a hog yields. What we
 * <em>want</em> is to preempt a hog on the interactive task's target CPU so it
 * runs now.
 */
public final class InteractiveBoostScheduler extends UserspaceScheduler {

    /** EWMA smoothing factor numerator/denominator (alpha = 1/4). */
    private static final long EWMA_SHIFT = 2;

    /** A task whose smoothed run-per-enqueue is below this (ns) is "interactive". */
    private static final long INTERACTIVE_THRESHOLD_NS = 2_000_000L; // 2 ms

    /** Per-pid smoothed execRuntime-per-enqueue, in ns. */
    private final Map<Integer, Long> avgRun = new HashMap<>();
    /** Per-pid last observed cumulative execRuntime, to compute deltas. */
    private final Map<Integer, Long> lastExec = new HashMap<>();

    private long interactiveDispatches;
    private long batchDispatches;
    private long preemptWanted;

    private boolean isInteractive(QueuedTask t) {
        long prevExec = lastExec.getOrDefault(t.pid, t.execRuntime);
        long delta = Math.max(0, t.execRuntime - prevExec);
        lastExec.put(t.pid, t.execRuntime);

        long prev = avgRun.getOrDefault(t.pid, delta);
        long next = prev + ((delta - prev) >> EWMA_SHIFT);
        avgRun.put(t.pid, next);

        return next < INTERACTIVE_THRESHOLD_NS;
    }

    @Override
    protected void schedule(QueuedTask[] tasks, int count) {
        // Two passes: interactive first (lowest latency), then batch.
        for (int i = 0; i < count; i++) {
            QueuedTask t = tasks[i];
            if (isInteractive(t)) {
                int cpu = selectCpu(t.pid, t.prevCpu);
                boolean cpuWasIdle = cpu != t.prevCpu; // selectCpu returns prevCpu when no idle CPU
                if (!cpuWasIdle) {
                    // No idle CPU: an interactive task is about to queue behind a hog.
                    // This is where we WANT to preempt a batch task on `cpu`.
                    preemptWanted++;
                    // preempt(t.pid);  // <-- NOT AVAILABLE in current framework
                }
                dispatchTask(t, cpu);
                interactiveDispatches++;
            }
        }
        for (int i = 0; i < count; i++) {
            QueuedTask t = tasks[i];
            if (!isInteractive(t)) {
                dispatchTask(t, ANY_CPU);
                batchDispatches++;
            }
        }
    }

    @Override
    protected void tick() {
        // Age out stale pids so the maps stay bounded.
        if (avgRun.size() > 8192) {
            avgRun.clear();
            lastExec.clear();
        }
    }

    public long interactiveDispatches() { return interactiveDispatches; }
    public long batchDispatches()       { return batchDispatches; }
    public long preemptWanted()         { return preemptWanted; }

    @Command(name = "InteractiveBoostScheduler",
            description = {
                "Latency-aware interactive-boost scheduler.",
                "Favours interactive (frequently-sleeping) tasks over CPU hogs,",
                "dispatching them first to a freshly-selected idle CPU."
            },
            mixinStandardHelpOptions = true)
    static final class Cli implements Runnable {

        @Option(names = {"--stats-interval"}, defaultValue = "5")
        int statsInterval;

        @Override
        public void run() {
            var sched = new InteractiveBoostScheduler();
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                sched.requestExit();
                while (!sched.exited()) {
                    try { Thread.sleep(10); } catch (InterruptedException ignored) {}
                }
                System.err.println();
                System.err.println("==== Final stats ====");
                System.err.printf("interactive=%d batch=%d preemptWanted=%d  %s%n",
                        sched.interactiveDispatches(), sched.batchDispatches(),
                        sched.preemptWanted(), sched.formatStats());
            }));
            if (statsInterval > 0) {
                long intervalNs = (long) statsInterval * 1_000_000_000L;
                var t = new Thread(() -> {
                    long deadline = System.nanoTime() + intervalNs;
                    try {
                        while (!sched.exited()) {
                            Thread.sleep(200);
                            if (System.nanoTime() >= deadline) {
                                System.err.printf("[stats] interactive=%d batch=%d preemptWanted=%d  %s%n",
                                        sched.interactiveDispatches(), sched.batchDispatches(),
                                        sched.preemptWanted(), sched.formatStats());
                                deadline += intervalNs;
                            }
                        }
                    } catch (InterruptedException ignored) {}
                }, "iboost-stats");
                t.setDaemon(true);
                t.start();
            }
            System.err.println("InteractiveBoostScheduler: attaching (Ctrl-C to detach)...");
            sched.runUntilExit(Opts.defaults());
        }
    }

    public static void main(String[] args) {
        FemtoCli.run(new Cli(), args);
    }
}
