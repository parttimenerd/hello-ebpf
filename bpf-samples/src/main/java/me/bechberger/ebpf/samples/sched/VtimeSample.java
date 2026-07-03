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
import java.util.TreeMap;

/**
 * <b>Experimental</b> — API may change without notice.
 *
 * <p>Weight-proportional vtime fair-share scheduler.
 *
 * <h2>Why this requires {@code schedule()} not {@code policy()}</h2>
 * <p>Fair-share scheduling requires dispatching the task with the <em>lowest
 * virtual time</em> first. With {@code policy(t)} you see one task at a time in
 * arrival order — you cannot pick the minimum-vtime task from the batch because
 * you don't see the others. {@code schedule(tasks, count)} gives you the whole
 * batch at once, so you can sort by vtime and dispatch in order.
 *
 * <p>This is exactly what {@code scx_rustland} does with a {@code BTreeSet}
 * ordered by deadline. Here we do the same with a Java {@code TreeMap}.
 *
 * <h2>Algorithm</h2>
 * <p>Each task has a virtual time {@code vtimes[pid]} maintained across batches.
 * On each batch:
 * <ol>
 *   <li>Insert all tasks into a {@code TreeMap<Long, QueuedTask>} keyed by vtime.
 *   <li>Dispatch them in vtime order (lowest first) to {@link #ANY_CPU}.
 *   <li>Advance each dispatched task's vtime by {@code slice / weight}, where
 *       {@code slice} is a fixed quantum. Higher-weight tasks advance more slowly,
 *       so they win more often — weight-proportional fair share.
 * </ol>
 *
 * <p>Vtime is initialised to the current minimum across all tracked tasks so that
 * newly woken tasks don't get a huge catch-up burst.
 */
public final class VtimeSample extends UserspaceScheduler {

    private static final long SLICE_NS = 5_000_000L;  // 5 ms base quantum

    /** Per-pid virtual time, in ns units scaled by weight. */
    private final Map<Integer, Long> vtimes = new HashMap<>();

    /** Minimum vtime seen this tick — used to initialise new tasks fairly. */
    private long minVtime = 0;

    @Override
    protected void schedule(QueuedTask[] tasks, int count) {
        // Build a vtime-ordered map for this batch.
        // TreeMap gives O(n log n) sort; a typical batch is 16–256 tasks.
        TreeMap<Long, QueuedTask> byVtime = new TreeMap<>();
        for (int i = 0; i < count; i++) {
            QueuedTask t = tasks[i];
            long vt = vtimes.computeIfAbsent(t.pid, p -> minVtime);
            // Break ties by pid to keep the map key unique.
            byVtime.put(vt << 20 | (t.pid & 0xFFFFF), t);
        }

        // Dispatch in vtime order and advance each task's vtime.
        long newMin = Long.MAX_VALUE;
        for (var entry : byVtime.entrySet()) {
            QueuedTask t = entry.getValue();
            long vt = vtimes.getOrDefault(t.pid, minVtime);
            long weight = Math.max(1, t.weight);
            // Advance vtime inversely proportional to weight:
            // high-weight tasks step less → they stay near the front.
            long step = SLICE_NS * 100 / weight;
            long nextVt = vt + step;
            vtimes.put(t.pid, nextVt);
            if (nextVt < newMin) newMin = nextVt;
            dispatchTask(t, ANY_CPU);
        }
        if (newMin != Long.MAX_VALUE) minVtime = newMin;
    }

    /** Evict vtimes for tasks not seen for a while to keep the map bounded. */
    @Override
    protected void tick() {
        // Simple age-out: if a pid hasn't appeared in a long time its vtime
        // entry can accumulate lag. Remove entries far ahead of minVtime —
        // they will be re-initialised at minVtime on next appearance anyway.
        long horizon = minVtime + SLICE_NS * 10_000L;
        vtimes.values().removeIf(vt -> vt > horizon);
    }

    @Command(name = "VtimeSample",
            description = {
                "Weight-proportional vtime fair-share scheduler.",
                "Uses schedule() to sort the whole batch by vtime before dispatching.",
                "Higher-weight tasks (lower nice) advance vtime more slowly and run more."
            },
            mixinStandardHelpOptions = true)
    static final class Cli implements Runnable {

        @Option(names = {"--stats-interval"}, defaultValue = "5")
        int statsInterval;

        @Override
        public void run() {
            var sched = new VtimeSample();
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                sched.requestExit();
                while (!sched.exited()) {
                    try { Thread.sleep(10); } catch (InterruptedException ignored) {}
                }
                System.err.println();
                System.err.println("==== Final stats ====");
                System.err.println(sched.formatStats());
                System.err.println("==== Histograms ====");
                sched.printHistograms(System.err);
            }));
            if (statsInterval > 0) {
                long intervalNs = (long) statsInterval * 1_000_000_000L;
                var t = new Thread(() -> {
                    long deadline = System.nanoTime() + intervalNs;
                    try {
                        while (!sched.exited()) {
                            Thread.sleep(200);
                            if (System.nanoTime() >= deadline) {
                                System.err.printf("[stats] %s  tracked=%d%n",
                                        sched.formatStats(), sched.vtimes.size());
                                deadline += intervalNs;
                            }
                        }
                    } catch (InterruptedException ignored) {}
                }, "vtime-stats");
                t.setDaemon(true);
                t.start();
            }
            System.err.println("VtimeSample: attaching vtime fair-share scheduler (Ctrl-C to detach)...");
            sched.runUntilExit(Opts.defaults());
        }
    }

    public static void main(String[] args) {
        FemtoCli.run(new Cli(), args);
    }
}
