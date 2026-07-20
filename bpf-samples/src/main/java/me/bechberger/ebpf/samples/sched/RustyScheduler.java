// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.bpf.QueuedTask;
import me.bechberger.ebpf.bpf.userspace.CpuTopology;
import me.bechberger.ebpf.bpf.userspace.Domain;
import me.bechberger.ebpf.bpf.userspace.DomainLoadBalancer;
import me.bechberger.ebpf.bpf.userspace.Opts;
import me.bechberger.ebpf.bpf.userspace.RustyLoadTracker;
import me.bechberger.ebpf.bpf.userspace.UserspaceScheduler;
import me.bechberger.femtocli.FemtoCli;
import me.bechberger.femtocli.annotations.Command;
import me.bechberger.femtocli.annotations.Option;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A Java port of scx_rusty's userspace domain load balancer (single-NUMA scope).
 *
 * <p>Each task is assigned a {@link Domain} (default: one per last-level cache). On enqueue the
 * task is dispatched to an idle CPU inside its domain; if none is idle it goes to {@code ANY_CPU}.
 * Every ~1s {@code tick()} reads each task's decayed load, buckets by domain, runs rusty's
 * push/pull balancer ({@link DomainLoadBalancer}) and re-assigns migrated tasks' {@code target_dom}
 * — faithful to rusty, which only sets {@code target_dom} and lets the next enqueue act on it.
 *
 * <p>See {@code docs/sched-ext/userspace.md} "Porting scx_rusty: domain load balancing".
 */
public class RustyScheduler extends UserspaceScheduler {

    private static final long DEFAULT_HALF_LIFE_NS = 1_000_000_000L; // 1s

    private final CpuTopology topo;
    private final RustyLoadTracker load;
    private final boolean skipKworkers;
    private final int stalePidTicks;

    /** pid -> assigned domain id. */
    private final Map<Integer, Integer> assignedDom = new HashMap<>();
    /** pid -> ticks since last seen (for pruning). */
    private final Map<Integer, Integer> idleTicks = new HashMap<>();
    private int nextRrDomain = 0;

    public RustyScheduler() { this(CpuTopology.detect(), DEFAULT_HALF_LIFE_NS, true, 10); }

    public RustyScheduler(CpuTopology topo, long halfLifeNs, boolean skipKworkers, int stalePidTicks) {
        this.topo = topo;
        this.load = new RustyLoadTracker(halfLifeNs);
        this.skipKworkers = skipKworkers;
        this.stalePidTicks = stalePidTicks;
        if (topo.nrDomains() < 1) {
            throw new IllegalStateException("CpuTopology reported " + topo.nrDomains()
                    + " domains; need >= 1");
        }
    }

    @Override
    protected void schedule(QueuedTask[] tasks, int count) {
        long now = nanoTime();
        for (int i = 0; i < count; i++) {
            QueuedTask t = tasks[i];
            int dom = assignedDom.computeIfAbsent(t.pid, pid -> {
                if (t.prevCpu >= 0) return topo.domainOfCpu(t.prevCpu);
                int d = nextRrDomain;
                nextRrDomain = (nextRrDomain + 1) % topo.nrDomains();
                return d;
            });
            if (dom < 0 || dom >= topo.nrDomains()) {
                throw new IllegalStateException("pid " + t.pid + " assigned to out-of-range domain "
                        + dom + " (nrDomains=" + topo.nrDomains() + ")");
            }
            load.onEnqueue(t.pid, t.execRuntime, now);
            idleTicks.put(t.pid, 0);

            int cpu = pickIdleCpuInDomain(topo.cpuMask(dom));
            dispatchTask(t, cpu >= 0 ? cpu : ANY_CPU);
        }
    }

    /** Scan the idle bitmap restricted to {@code domMask}; return an idle CPU or -1. */
    private int pickIdleCpuInDomain(long domMask) {
        int cpu = pickIdleCpu();               // framework's global idle pick
        if (cpu >= 0 && (domMask & (1L << cpu)) != 0) return cpu;
        // Fall back: scan the mask ourselves against the idle view.
        MemorySegment idle = idleMaskView();
        if (idle == null) return -1;
        long m = domMask;
        while (m != 0) {
            int c = Long.numberOfTrailingZeros(m);
            m &= (m - 1);
            if (c < cpuCount() && isIdle(idle, c)) return c;
        }
        return -1;
    }

    private static boolean isIdle(MemorySegment idle, int cpu) {
        // Matches UserspaceScheduler.pickIdleCpu(): byte-offset word addressing, 64 CPUs/word.
        long word = idle.get(ValueLayout.JAVA_LONG, (long) (cpu / 64) * 8L);
        return (word & (1L << (cpu & 63))) != 0;
    }

    @Override
    protected void tick() {
        long now = nanoTime();
        // Decay-at-read every tracked pid + prune stale ones.
        for (int pid : load.trackedPids()) {
            load.dutyCycle(pid, now);           // side-effects the decay
            int ticks = idleTicks.merge(pid, 1, Integer::sum);
            if (ticks > stalePidTicks) {
                load.forget(pid);
                idleTicks.remove(pid);
                assignedDom.remove(pid);
            }
        }
        // Balancing wired in Task 5.
    }

    // Exposed for the harness test to inspect assignment.
    Integer domainOf(int pid) { return assignedDom.get(pid); }
    CpuTopology topology() { return topo; }

    // ── CLI ──
    @Command(name = "RustyScheduler",
            description = {
                "scx_rusty-style domain load balancer (Java port, single-NUMA).",
                "Assigns tasks to LLC domains; balances load across domains every tick."
            },
            mixinStandardHelpOptions = true)
    static final class Cli implements Runnable {

        @Option(names = {"--half-life-ms"}, defaultValue = "1000")
        long halfLifeMs;

        @Option(names = {"--skip-kworkers"}, defaultValue = "true")
        boolean skipKworkers;

        @Override
        public void run() {
            var sched = new RustyScheduler(CpuTopology.detect(), halfLifeMs * 1_000_000L,
                    skipKworkers, 10);
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                sched.requestExit();
                while (!sched.exited()) {
                    try { Thread.sleep(10); } catch (InterruptedException ignored) {}
                }
                System.err.println();
                System.err.println("==== Final stats ==== " + sched.formatStats());
            }));
            System.err.println("RustyScheduler: attaching (Ctrl-C to detach)...");
            sched.runUntilExit(Opts.defaults());
        }
    }

    public static void main(String[] args) {
        FemtoCli.run(new Cli(), args);
    }
}
