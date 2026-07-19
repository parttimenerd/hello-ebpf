// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.bpf.QueuedTask;
import me.bechberger.ebpf.bpf.userspace.Opts;
import me.bechberger.ebpf.bpf.userspace.UserspaceScheduler;
import me.bechberger.femtocli.FemtoCli;
import me.bechberger.femtocli.annotations.Command;
import me.bechberger.femtocli.annotations.Option;

/**
 * <b>Experimental</b> — API may change without notice.
 *
 * <p>Demonstrates the {@link UserspaceScheduler#preempt(int)} control API: a task
 * whose {@code comm} matches {@code --critical <name>} is preempted-in the moment
 * it enqueues, so its wake-to-run latency stays low even when every CPU is busy
 * running other work.
 *
 * <h2>Why preempt() is needed</h2>
 * <p>Placement alone ({@code selectCpu}) cannot help a latency-critical task that
 * wakes while all CPUs are busy: it will sit in a DSQ until a running task yields.
 * {@code preempt(pid)} writes a control record that makes the BPF side kick the
 * task's target CPU with {@code SCX_KICK_PREEMPT}, so the critical task runs now.
 *
 * <h2>Try it</h2>
 * <pre>
 *   # boost every task whose comm is "myapp"
 *   sudo java ... LatencyCriticalSample --critical myapp
 * </pre>
 */
public final class LatencyCriticalSample extends UserspaceScheduler {

    private final String criticalComm;
    private long preemptsRequested;

    public LatencyCriticalSample(String criticalComm) {
        this.criticalComm = criticalComm;
    }

    @Override
    protected int policy(QueuedTask t) {
        if (t.commEquals(criticalComm)) {
            preempt(t.pid);   // demo: force the critical task to run ASAP
            preemptsRequested++;
        }
        return ANY_CPU;
    }

    public long preemptsRequested() { return preemptsRequested; }

    @Command(name = "LatencyCriticalSample",
            description = {
                "Latency-critical preempt() demo.",
                "Preempts-in any task whose comm matches --critical <name>",
                "the moment it enqueues, minimising its wake-to-run latency."
            },
            mixinStandardHelpOptions = true)
    static final class Cli implements Runnable {

        @Option(names = {"--critical"},
                description = "comm (thread name, <=15 chars) of tasks to preempt-in.",
                required = true)
        String critical;

        @Option(names = {"--stats-interval"},
                description = "Seconds between stats prints (0 = disable).",
                defaultValue = "5")
        int statsInterval;

        @Override
        public void run() {
            var sched = new LatencyCriticalSample(critical);

            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                sched.requestExit();
                while (!sched.exited()) {
                    try { Thread.sleep(10); } catch (InterruptedException ignored) {}
                }
                System.err.println();
                System.err.println("==== Final stats ====");
                System.err.printf("preemptsRequested=%d  %s%n",
                        sched.preemptsRequested(), sched.formatStats());
            }));

            if (statsInterval > 0) {
                long intervalNs = (long) statsInterval * 1_000_000_000L;
                var t = new Thread(() -> {
                    long deadline = System.nanoTime() + intervalNs;
                    try {
                        while (!sched.exited()) {
                            Thread.sleep(200);
                            if (System.nanoTime() >= deadline) {
                                System.err.printf("[stats] preemptsRequested=%d  %s%n",
                                        sched.preemptsRequested(), sched.formatStats());
                                deadline += intervalNs;
                            }
                        }
                    } catch (InterruptedException ignored) {}
                }, "latcrit-stats");
                t.setDaemon(true);
                t.start();
            }

            System.err.printf("LatencyCriticalSample: preempting comm=\"%s\" (Ctrl-C to detach)...%n", critical);
            sched.runUntilExit(Opts.defaults());
        }
    }

    public static void main(String[] args) {
        FemtoCli.run(new Cli(), args);
    }
}
