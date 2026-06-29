// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.bpf.QueuedTask;
import me.bechberger.ebpf.bpf.userspace.Opts;
import me.bechberger.ebpf.bpf.userspace.UserspaceScheduler;
import me.bechberger.femtocli.FemtoCli;
import me.bechberger.femtocli.annotations.Command;
import me.bechberger.femtocli.annotations.Option;

/**
 * Minimal FIFO userspace scheduler — every task gets {@link UserspaceScheduler#ANY_CPU}.
 *
 * <p>Equivalent to the simplest Rustland/scx_rustland policy: drain the run queue in
 * arrival order and let the BPF transport pick a suitable idle CPU via the built-in
 * SHARED_DSQ round-robin path.
 *
 * <p>Useful as a baseline and as a live demonstration that the Java-side framework
 * can attach as a sched_ext scheduler with zero policy logic.
 *
 * <h2>Usage</h2>
 * <pre>{@code
 *   sudo java -jar bpf-samples.jar me.bechberger.ebpf.samples.sched.RustlandFifoSample \
 *       [--stats-interval <seconds>]
 * }</pre>
 */
public final class RustlandFifoSample extends UserspaceScheduler {

    // ── policy ───────────────────────────────────────────────────────────────

    /**
     * Pure FIFO: return {@link #ANY_CPU} for every task.
     * The BPF transport will place the task on the SHARED_DSQ and dispatch it
     * to any available idle CPU.
     */
    @Override
    protected int policy(QueuedTask t) {
        return ANY_CPU;
    }

    // ── CLI ──────────────────────────────────────────────────────────────────

    @Command(name = "RustlandFifoSample",
            description = {"Minimal FIFO sched_ext scheduler implemented in Java.",
                           "All tasks are dispatched to ANY_CPU (SHARED_DSQ round-robin)."},
            mixinStandardHelpOptions = true)
    static final class Cli implements Runnable {

        @Option(names = {"--stats-interval"},
                description = "Seconds between stats prints to stderr (0 = disable).",
                defaultValue = "5")
        int statsInterval;

        @Override
        public void run() {
            var sched = new RustlandFifoSample();

            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                sched.requestExit();
                // Wait for the run loop to return so cleanup has finished before
                // the JVM proceeds with shutdown.
                while (!sched.exited()) {
                    try { Thread.sleep(10); } catch (InterruptedException ignored) {}
                }
                System.err.println();
                System.err.println("==== Final stats ====");
                System.err.println(sched.formatStats());
                System.err.println("==== Histograms ====");
                sched.printHistograms(System.err);
            }));

                // Spawn a background thread to emit periodic stats while runUntilExit blocks.
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
                }, "rustland-fifo-stats");
                statsThread.setDaemon(true);
                statsThread.start();
            }

            System.err.println("RustlandFifoSample: attaching scheduler (Ctrl-C to detach)...");
            sched.runUntilExit(Opts.defaults());
        }
    }

    public static void main(String[] args) {
        FemtoCli.run(new Cli(), args);
    }
}
