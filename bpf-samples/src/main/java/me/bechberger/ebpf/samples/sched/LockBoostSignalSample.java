// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.bpf.QueuedTask;
import me.bechberger.ebpf.bpf.UserspaceSchedulerBase;
import me.bechberger.ebpf.bpf.userspace.Opts;
import me.bechberger.ebpf.bpf.userspace.Signal;
import me.bechberger.ebpf.bpf.userspace.UserspaceScheduler;
import me.bechberger.femtocli.FemtoCli;
import me.bechberger.femtocli.annotations.Command;
import me.bechberger.femtocli.annotations.Option;

/**
 * <b>Experimental</b> — API may change without notice.
 *
 * <p>Demonstrates the BPF&rarr;Java <em>signals</em> path end-to-end: a kernel-side
 * event is turned into a typed {@link Signal} that the Java scheduler reacts to by
 * {@link #preempt(int) preempting} the subject task in.
 *
 * <h2>How it works</h2>
 * <ol>
 *   <li>{@link LockBoostSchedBpf} (the {@code @BPF} transport subclass selected via
 *       {@link #bpfProgramClass()}) overrides the {@code runnable} struct_ops callback
 *       and, for tasks whose {@code comm} matches {@link LockBoostSchedBpf#WATCHED_COMM},
 *       calls {@code emitSignal(LOCK_ACQUIRED, pid, 0)}.</li>
 *   <li>The framework drains the signals ring in its run loop and delivers each record
 *       to {@link #onSignal(Signal)} on the policy thread.</li>
 *   <li>{@code onSignal} calls {@link #preempt(int)}, which writes a PREEMPT control
 *       record; the BPF side kicks the holder's CPU with {@code SCX_KICK_PREEMPT}.</li>
 * </ol>
 *
 * <p>This replaces the older shared-map + JVM-uprobe {@code LockHolderBoost} scheme:
 * the signal path needs no second BPF program and no live JVM target, so it is fully
 * kernel-smoke-testable.
 */
public final class LockBoostSignalSample extends UserspaceScheduler {

    private static final int LOCK_ACQUIRED = Signal.SignalKind.FIRST_USER_KIND;

    private volatile long signalsSeen;
    private volatile long boostsIssued;

    @Override
    protected Class<? extends UserspaceSchedulerBase> bpfProgramClass() {
        return LockBoostSchedBpf.class;
    }

    @Override
    protected int policy(QueuedTask t) {
        return ANY_CPU; // placement is not the point; the signal reaction is
    }

    @Override
    protected void onSignal(Signal s) {
        signalsSeen++;
        if (s.kind() == LOCK_ACQUIRED) {
            preempt(s.pid()); // boost the lock holder in
            boostsIssued++;
        }
    }

    /** Signals delivered to {@link #onSignal} on the policy thread. */
    public long signalsSeen() { return signalsSeen; }

    /** {@link #preempt} calls issued in response to LOCK_ACQUIRED signals. */
    public long boostsIssued() { return boostsIssued; }

    @Override
    public String formatStats() {
        return String.format("%s  signalsSeen=%d boostsIssued=%d",
                super.formatStats(), signalsSeen, boostsIssued);
    }

    @Command(name = "LockBoostSignalSample",
            description = {
                "BPF->Java signals demo.",
                "A BPF runnable callback emits LOCK_ACQUIRED for watched tasks;",
                "onSignal reacts by preempting the holder in via the control ring."
            },
            mixinStandardHelpOptions = true)
    static final class Cli implements Runnable {

        @Option(names = {"--stats-interval"},
                description = "Seconds between stats prints (0 = disable).",
                defaultValue = "5")
        int statsInterval;

        @Override
        public void run() {
            var sched = new LockBoostSignalSample();

            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                sched.requestExit();
                while (!sched.exited()) {
                    try { Thread.sleep(10); } catch (InterruptedException ignored) {}
                }
                System.err.println();
                System.err.println("==== Final stats ====");
                System.err.println(sched.formatStats());
            }));

            if (statsInterval > 0) {
                long intervalNs = (long) statsInterval * 1_000_000_000L;
                var t = new Thread(() -> {
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
                }, "lockboost-stats");
                t.setDaemon(true);
                t.start();
            }

            System.err.printf("LockBoostSignalSample: watching comm=\"%s\" (Ctrl-C to detach)...%n",
                    LockBoostSchedBpf.WATCHED_COMM);
            sched.runUntilExit(Opts.defaults());
        }
    }

    public static void main(String[] args) {
        FemtoCli.run(new Cli(), args);
    }
}
