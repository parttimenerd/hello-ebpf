// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

/**
 * One-call launcher: wires the shutdown hook, the periodic stats thread, and
 * {@code runUntilExit} so a sample's {@code main} shrinks to one line:
 *
 * <pre>{@code
 * public static void main(String[] args) {
 *     SchedulerRunner.run(new VtimeSample(), args);
 * }
 * }</pre>
 *
 * <p>Reads {@code --stats-interval <sec>} (default 5; 0 = off) from {@code args}.
 * (Metrics-port wiring is Sub-project D and layered on separately.)
 */
public final class SchedulerRunner {
    private SchedulerRunner() {}

    public static void run(UserspaceScheduler sched, String[] args) {
        int statsInterval = parseIntOpt(args, "--stats-interval", 5);

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            sched.requestExit();
            while (!sched.exited()) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); break; }
            }
            System.err.println();
            System.err.println("==== Final stats ====");
            System.err.println(sched.formatStats());
            System.err.println("==== Histograms ====");
            sched.printHistograms(System.err);
        }));

        if (statsInterval > 0) {
            long intervalNs = (long) statsInterval * 1_000_000_000L;
            Thread t = new Thread(() -> {
                long deadline = System.nanoTime() + intervalNs;
                try {
                    while (!sched.exited()) {
                        Thread.sleep(200);
                        if (System.nanoTime() >= deadline) {
                            System.err.printf("[stats] %s%n", sched.formatStats());
                            deadline += intervalNs;
                        }
                    }
                } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
            }, "sched-stats");
            t.setDaemon(true);
            t.start();
        }

        sched.runUntilExit(Opts.defaults());
    }

    private static int parseIntOpt(String[] args, String name, int dflt) {
        for (int i = 0; i < args.length - 1; i++) {
            if (args[i].equals(name)) {
                try { return Integer.parseInt(args[i + 1]); } catch (NumberFormatException e) { return dflt; }
            }
        }
        return dflt;
    }
}
