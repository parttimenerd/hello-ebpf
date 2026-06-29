// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.bpf.QueuedTask;
import me.bechberger.ebpf.bpf.userspace.Opts;
import me.bechberger.ebpf.bpf.userspace.UserspaceScheduler;
import me.bechberger.femtocli.FemtoCli;
import me.bechberger.femtocli.annotations.Command;
import me.bechberger.femtocli.annotations.Option;

import java.util.concurrent.ThreadLocalRandom;

/**
 * Lottery scheduler demo — weight-proportional probabilistic CPU placement.
 *
 * <h2>Design rationale</h2>
 * <p>The classic lottery scheduling paper (Waldspurger &amp; Weihl, 1994) assigns
 * each task a number of "tickets" proportional to its priority, then selects the
 * next task to run by drawing a random ticket. In a traditional batch model this
 * would be expressed as: collect all runnable tasks, hold a lottery, dispatch the
 * winner first.
 *
 * <p>The hello-ebpf userspace scheduler framework no longer exposes a
 * {@code schedule(Batch)} callback; the {@code Batch} class was removed in
 * Task 11. The framework now calls {@link #policy(QueuedTask)} once per
 * dequeued task and expects a CPU number in return. This sample adapts the
 * lottery intent to the per-task model by making the <em>placement</em>
 * decision probabilistic:
 *
 * <ul>
 *   <li>Draw a uniform random ticket in [0, 10000).
 *   <li>If the ticket is less than {@code t.weight} (range [1, 10000], default 100),
 *       return {@link #ANY_CPU} — the fast path through SHARED_DSQ that lets
 *       sched_ext choose any idle CPU.
 *   <li>Otherwise return {@code t.prevCpu} (if valid) to keep the task on its
 *       last-used CPU, exploiting cache warmth. If {@code prevCpu} is negative
 *       (task has never run), fall back to {@link #ANY_CPU}.
 * </ul>
 *
 * <p>The net effect: a task with weight 10000 always wins (always gets ANY_CPU
 * load-balance), a task with weight 100 wins roughly 1% of the time (mostly
 * cache-pinned), and a task with weight 1 almost never wins. This makes
 * {@code t.weight} observable in the placement decision without requiring
 * per-CPU bookkeeping.
 *
 * <h2>Usage</h2>
 * <pre>{@code
 *   sudo java -jar bpf-samples.jar me.bechberger.ebpf.samples.sched.LotterySample \
 *       [--stats-interval <seconds>]
 * }</pre>
 */
public final class LotterySample extends UserspaceScheduler {

    /** Upper bound of {@code QueuedTask.weight}; ticket draw is uniform in [0, this). */
    private static final long WEIGHT_DENOMINATOR = 10_000L;

    // ── policy ───────────────────────────────────────────────────────────────

    /**
     * Weighted lottery placement: draw a random ticket in [0, WEIGHT_DENOMINATOR);
     * if the ticket is below {@code t.weight} the task wins and is sent to
     * {@link #ANY_CPU}, otherwise it is pinned to {@code t.prevCpu} (or
     * {@link #ANY_CPU} if prevCpu is invalid).
     */
    @Override
    protected int policy(QueuedTask t) {
        long weight = Math.max(1L, t.weight);
        long ticket = ThreadLocalRandom.current().nextLong(WEIGHT_DENOMINATOR);
        if (ticket < weight) {
            return ANY_CPU;
        }
        return t.prevCpu >= 0 ? t.prevCpu : ANY_CPU;
    }

    // ── CLI ──────────────────────────────────────────────────────────────────

    @Command(name = "LotterySample",
            description = {"Lottery scheduler demo: weight-proportional probabilistic CPU placement.",
                           "Higher-weight tasks are more likely to be load-balanced to any idle CPU."},
            mixinStandardHelpOptions = true)
    static final class Cli implements Runnable {

        @Option(names = {"--stats-interval"},
                description = "Seconds between stats prints to stderr (0 = disable).",
                defaultValue = "5")
        int statsInterval;

        @Override
        public void run() {
            var sched = new LotterySample();

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
                var statsThread = new Thread(() -> {
                    long deadline = System.nanoTime() + intervalNs;
                    try {
                        while (!sched.exited()) {
                            Thread.sleep(200);
                            if (System.nanoTime() >= deadline) {
                                System.err.println("[stats] " + sched.formatStats());
                                deadline += intervalNs;
                            }
                        }
                    } catch (InterruptedException ignored) {}
                }, "lottery-stats");
                statsThread.setDaemon(true);
                statsThread.start();
            }

            System.err.println("LotterySample: attaching scheduler (Ctrl-C to detach)...");
            sched.runUntilExit(Opts.defaults());
        }
    }

    public static void main(String[] args) {
        FemtoCli.run(new Cli(), args);
    }
}
