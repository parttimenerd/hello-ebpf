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
 * Weighted round-robin demo scheduler.
 *
 * <p>Tracks per-pid debt (cumulative weight minus elapsed ticks) and exposes the
 * value via {@code formatStats}. The actual CPU choice is delegated to the BPF
 * transport via {@link #ANY_CPU} — sched_ext does not expose a way to reorder
 * dispatch within a batch, so this sample demonstrates per-task state retention
 * and {@code t.weight} use, not pure WRR queueing.
 */
public final class WeightedRRSample extends UserspaceScheduler {

    private final Map<Integer, Long> debt = new HashMap<>();
    private final Map<Integer, Long> lastSeenTick = new HashMap<>();
    private long tickCount = 0;

    @Override
    protected int policy(QueuedTask t) {
        long last = lastSeenTick.getOrDefault(t.pid, tickCount);
        long elapsed = tickCount - last;
        long d = debt.getOrDefault(t.pid, 0L) + t.weight - elapsed;
        debt.put(t.pid, d);
        lastSeenTick.put(t.pid, tickCount);
        return ANY_CPU;
    }

    @Override
    protected void tick() {
        tickCount++;
        // Drop entries whose debt has drifted far from zero; prevents the map from growing
        // unbounded across pid churn. Threshold is in weight-units (QueuedTask.weight maxes at 10000).
        debt.entrySet().removeIf(e -> Math.abs(e.getValue()) > 1_000_000);
        lastSeenTick.keySet().retainAll(debt.keySet());
    }

    @Command(name = "WeightedRRSample",
            description = {"Weight-aware userspace scheduler demo.",
                           "Tracks per-pid debt = sum(weight) - elapsed ticks."},
            mixinStandardHelpOptions = true)
    static final class Cli implements Runnable {

        @Option(names = {"--stats-interval"},
                description = "Seconds between stats prints to stderr (0 = disable).",
                defaultValue = "5")
        int statsInterval;

        @Override
        public void run() {
            var sched = new WeightedRRSample();
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
                }, "weighted-rr-stats");
                statsThread.setDaemon(true);
                statsThread.start();
            }
            System.err.println("WeightedRRSample: attaching scheduler (Ctrl-C to detach)...");
            sched.runUntilExit(Opts.defaults());
        }
    }

    public static void main(String[] args) {
        FemtoCli.run(new Cli(), args);
    }
}
