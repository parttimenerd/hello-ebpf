// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Property;
import me.bechberger.ebpf.annotations.bpf.SharedFrom;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.BPFProgramGroup;
import me.bechberger.ebpf.bpf.GlobalVariable;
import me.bechberger.ebpf.bpf.Scheduler;
import me.bechberger.ebpf.bpf.SchedulerBase;
import me.bechberger.ebpf.bpf.SchedulerStats;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.bpf.map.BPFPerCpuArray;
import me.bechberger.ebpf.bpf.sched.DispatchQueue;
import me.bechberger.ebpf.bpf.sched.EnqFlags;
import me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;
import me.bechberger.ebpf.type.Ptr;
import me.bechberger.femtocli.FemtoCli;
import me.bechberger.femtocli.annotations.Command;
import me.bechberger.femtocli.annotations.Option;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.*;

/**
 * Lock-holder priority-inheritance scheduler for the JVM (consumer half).
 *
 * <p>Reads the per-tid {@link LockHolderBoostUprobes.BoostState} map written by
 * {@link LockHolderBoostUprobes} and routes boosted holders to a priority DSQ.
 * The split is required because uprobe context cannot call {@code bpf_task_from_pid}
 * on some kernels and the verifier rejects mixed uprobe + struct_ops sharing kfuncs.
 *
 * <p>Two DSQs:
 * <ul>
 *   <li>{@link #BOOSTED_DSQ}: boosted holders, vtime=0, 5 ms slice — should release fast.</li>
 *   <li>{@link #NORMAL_DSQ}: vtime weighted-fair queue for everything else.</li>
 * </ul>
 *
 * <p>Run with:
 * <pre>
 *   sudo java -cp bpf-samples.jar me.bechberger.ebpf.samples.sched.LockHolderBoostScheduler \
 *       --pid &lt;jvm-pid&gt; [--libjvm /path/to/libjvm.so]
 * </pre>
 */
@BPF(license = "GPL")
@Property(name = "sched_name", value = "lock_holder_boost")
@Property(name = "timeout_ms", value = "10000")
public abstract class LockHolderBoostScheduler extends SchedulerBase implements Scheduler {

    /** DSQ id for boosted (lock-holding) tasks; drained first. */
    static final long BOOSTED_DSQ = 1;
    /** DSQ id for normal (vtime-fair) tasks. */
    static final long NORMAL_DSQ  = 2;

    /** Slice given to a boosted holder (5 ms — enough to reach exit, not enough to hog). */
    static final long BOOSTED_SLICE_NS = 5_000_000L;

    /**
     * Inline watchdog threshold. A {@code BoostState.waiterCount > 0} that has
     * not been refreshed within this many nanoseconds is treated as stale and
     * reset to 0 in {@link #enqueue}.
     */
    static final long WATCHDOG_NS = 1_000_000_000L;

    /** Per-tid boost state — shared with the uprobe program via {@code @SharedFrom}. */
    @SharedFrom(LockHolderBoostUprobes.class)
    @BPFMapDefinition(maxEntries = LockHolderBoostUprobes.MAX_HOLDERS)
    BPFHashMap<@Unsigned Long, LockHolderBoostUprobes.BoostState> boostState;

    /** Per-CPU enqueue counters: index 0 = boosted DSQ, index 1 = normal DSQ. */
    @BPFMapDefinition(maxEntries = 2)
    BPFPerCpuArray<Long> enqueueCounters;

    /** Global vtime cursor for the normal queue (same logic as VTimeScheduler). */
    final GlobalVariable<@Unsigned Long> vtimeNow = new GlobalVariable<>(0L);

    /** Lifetime counter: number of stale boosts cleared by the watchdog. */
    final GlobalVariable<@Unsigned Long> watchdogResets = new GlobalVariable<>(0L);

    /** Aggregate ns spent on the boosted DSQ across all tasks. */
    final GlobalVariable<@Unsigned Long> totalBoostedNs = new GlobalVariable<>(0L);

    final DispatchQueue boosted = new DispatchQueue(BOOSTED_DSQ);
    final DispatchQueue normal  = new DispatchQueue(NORMAL_DSQ);
    final DispatchQueue shared  = DispatchQueue.attach(SHARED_DSQ_ID);

    @Override
    public int init() {
        return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
    }

    // ── sched_ext callbacks ───────────────────────────────────────────────────

    @Override
    public int selectCPU(Ptr<task_struct> p, int prev_cpu, long wake_flags) {
        return selectCpuDfl(p, prev_cpu, wake_flags);
    }

    /**
     * Routes tasks to the boosted or normal DSQ.
     *
     * <p>Inlines the watchdog: if a task's boost has gone stale
     * ({@code now - lastBoostNs > WATCHDOG_NS}), reset {@code waiterCount} to 0
     * and dispatch normally. Counts the reset for diagnostics.
     */
    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        EnqFlags f = EnqFlags.passThrough(enq_flags);
        @Unsigned long tid = (long) p.val().pid;
        Ptr<LockHolderBoostUprobes.BoostState> bs = boostState.bpf_get(tid);
        boolean boost = false;
        if (bs != null && bs.val().waiterCount > 0) {
            @Unsigned long age = bpf_ktime_get_ns() - bs.val().lastBoostNs;
            if (age > WATCHDOG_NS) {
                bs.val().waiterCount = 0;
                watchdogResets.set(watchdogResets.get() + 1);
            } else {
                boost = true;
            }
        }
        if (boost) {
            boosted.insertVtime(p, BOOSTED_SLICE_NS, 0, f);
            SchedulerStats.incrementEnqueuedAt(enqueueCounters, 0);
        } else {
            normal.insertVtimeClamped(p, vtimeNow.get(), f);
            SchedulerStats.incrementEnqueuedAt(enqueueCounters, 1);
        }
    }

    @Override
    public void dispatch(int cpu, Ptr<task_struct> prev) {
        if (boosted.nonEmpty()) {
            boosted.moveToLocal();
        } else {
            normal.moveToLocal();
        }
    }

    /**
     * Tracks vtime progression and, for boosted tasks, stamps the on-CPU start
     * time so {@link #stopping} can attribute boost time.
     */
    @Override
    public void running(Ptr<task_struct> p) {
        @Unsigned long vtime = p.val().scx.dsq_vtime;
        if (isSmaller(vtimeNow.get(), vtime)) {
            vtimeNow.set(vtime);
        }
        @Unsigned long tid = (long) p.val().pid;
        Ptr<LockHolderBoostUprobes.BoostState> bs = boostState.bpf_get(tid);
        if (bs != null && bs.val().waiterCount > 0) {
            bs.val().onCpuStartNs = bpf_ktime_get_ns();
        }
    }

    /**
     * Charges vtime and, if the task was running boosted, accumulates boost time
     * into {@link LockHolderBoostUprobes.BoostState#totalBoostedNs} and the global counter.
     */
    @Override
    public void stopping(Ptr<task_struct> p, boolean runnable) {
        vtimeCharge(p);
        @Unsigned long tid = (long) p.val().pid;
        Ptr<LockHolderBoostUprobes.BoostState> bs = boostState.bpf_get(tid);
        if (bs != null && bs.val().onCpuStartNs != 0) {
            @Unsigned long delta = bpf_ktime_get_ns() - bs.val().onCpuStartNs;
            bs.val().totalBoostedNs += delta;
            bs.val().onCpuStartNs = 0;
            totalBoostedNs.set(totalBoostedNs.get() + delta);
        }
    }

    @Override
    public void enable(Ptr<task_struct> p) {
        p.val().scx.dsq_vtime = vtimeNow.get();
    }

    // ── Java-side stats ──────────────────────────────────────────────────────

    public long getBoostedEnqueueCount() {
        return SchedulerStats.totalEnqueuedAt(enqueueCounters, 0);
    }

    public long getNormalEnqueueCount() {
        return SchedulerStats.totalEnqueuedAt(enqueueCounters, 1);
    }

    public long getWatchdogResets() {
        return watchdogResets.get();
    }

    public long getTotalBoostedNs() {
        return totalBoostedNs.get();
    }

    /** Snapshot of (monitor address, contention count) pairs. Reads producer state. */
    public record MonitorContention(long monitorAddr, long count) {}

    // ── libjvm.so + symbol resolution ────────────────────────────────────────

    static String findLibjvm(int pid) {
        try {
            for (var line : Files.readAllLines(Path.of("/proc/" + pid + "/maps"))) {
                var parts = line.split("\\s+");
                if (parts.length >= 6 && parts[5].endsWith("/libjvm.so")) return parts[5];
            }
        } catch (Exception e) {
            throw new RuntimeException("Cannot read /proc/" + pid + "/maps: " + e.getMessage());
        }
        throw new RuntimeException("libjvm.so not found in /proc/" + pid + "/maps — is pid " + pid + " a JVM?");
    }

    static boolean processAlive(int pid) {
        return Files.exists(Path.of("/proc/" + pid));
    }

    /**
     * Scrapes {@code nm} output of {@code libjvm.so} for a symbol whose mangled
     * name matches {@code regex}.
     */
    static String findMangledSymbol(String libjvm, String regex) {
        for (String[] cmd : new String[][]{
                {"nm", "--defined-only", libjvm},
                {"nm", "-D", "--defined-only", libjvm}
        }) {
            try {
                var p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
                try (var br = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                    String line;
                    var pat = java.util.regex.Pattern.compile(regex);
                    while ((line = br.readLine()) != null) {
                        var parts = line.trim().split("\\s+");
                        if (parts.length < 3) continue;
                        String sym = parts[parts.length - 1];
                        if (pat.matcher(sym).find()) {
                            p.destroy();
                            return sym;
                        }
                    }
                }
                p.waitFor();
            } catch (Exception ignored) {
                // Tool unavailable or libjvm stripped — try next variant.
            }
        }
        return null;
    }

    // ── CLI ──────────────────────────────────────────────────────────────────

    @Command(name = "LockHolderBoostScheduler",
            description = {"sched_ext scheduler that boosts JVM threads holding contended monitors."},
            mixinStandardHelpOptions = true)
    static final class Cli implements Runnable {

        @Option(names = {"--pid"}, description = "PID of the target JVM.", required = true)
        int pid;

        @Option(names = {"--libjvm"}, description = "Path to libjvm.so (auto-detected from /proc/pid/maps if omitted).", defaultValue = "")
        String libjvm;

        @Option(names = {"--enter-symbol"},
                description = "Mangled symbol for ObjectMonitor::enter (auto-detected via nm if blank).",
                defaultValue = "")
        String enterSymbol;

        @Option(names = {"--exit-symbol"},
                description = "Mangled symbol for ObjectMonitor::exit (auto-detected via nm if blank).",
                defaultValue = "")
        String exitSymbol;

        @Option(names = {"--stats-interval"},
                description = "Seconds between stats prints (0 = disable).",
                defaultValue = "5")
        int statsInterval;

        @Option(names = {"--top-n"},
                description = "Number of hottest monitors to print on shutdown.",
                defaultValue = "10")
        int topN;

        /**
         * HotSpot fallbacks (JDK 25 mangling).
         *
         * <p>We probe {@code ObjectMonitor::enter_internal(JavaThread*)}, not the public
         * {@code enter()}. On JDK 21+ HotSpot reaches the slow path via {@code try_enter}
         * → {@code enter_with_contention_mark} → {@code enter_internal} and the
         * public {@code enter()} symbol is effectively dead on contended workloads
         * (verified empirically with bpftrace). {@code enter_internal} runs exactly
         * when a thread is about to block — the moment a "waiter arrived" event
         * becomes true.
         */
        private static final String FALLBACK_ENTER = "_ZN13ObjectMonitor14enter_internalEP10JavaThread";
        private static final String FALLBACK_EXIT  = "_ZN13ObjectMonitor4exitEP10JavaThreadb";

        // Anchored to reject overloads (e.g. reenter_internal, exit's .part.0 clone).
        // The trailing `b?` on EXIT_REGEX accommodates JDK 21 (`exit(JavaThread*)`)
        // and JDK 25+ (`exit(JavaThread*, bool)`).
        private static final String ENTER_REGEX = "^_ZN13ObjectMonitor14enter_internalEP10JavaThread$";
        private static final String EXIT_REGEX  = "^_ZN13ObjectMonitor4exitEP10JavaThreadb?$";

        /** Gather (monitor, count) snapshot from the producer's contention map. */
        private static List<MonitorContention> topContendedMonitors(LockHolderBoostUprobes uprobes, int n) {
            var all = new ArrayList<MonitorContention>();
            for (var e : uprobes.contentionByMonitor) {
                all.add(new MonitorContention(e.getKey(), e.getValue()));
            }
            all.sort(Comparator.comparingLong(MonitorContention::count).reversed());
            return all.size() <= n ? all : all.subList(0, n);
        }

        @Override
        public void run() {
            String lib = libjvm.isEmpty() ? findLibjvm(pid) : libjvm;

            String enterSym = enterSymbol.isEmpty()
                    ? firstNonNull(findMangledSymbol(lib, ENTER_REGEX), FALLBACK_ENTER)
                    : enterSymbol;
            String exitSym = exitSymbol.isEmpty()
                    ? firstNonNull(findMangledSymbol(lib, EXIT_REGEX), FALLBACK_EXIT)
                    : exitSymbol;

            System.err.println("libjvm:        " + lib);
            System.err.println("enter symbol:  " + enterSym);
            System.err.println("exit symbol:   " + exitSym);

            try (var uprobes = BPFProgram.load(LockHolderBoostUprobes.class);
                 var sched   = BPFProgram.load(LockHolderBoostScheduler.class, uprobes)) {

                var enterHandle    = uprobes.getProgramByName("onMonitorEnter");
                var enterRetHandle = uprobes.getProgramByName("onMonitorEnterRet");
                var exitHandle     = uprobes.getProgramByName("onMonitorExit");

                try {
                    uprobes.attachUprobe(enterHandle,    false, pid, lib, enterSym);
                    uprobes.attachUprobe(enterRetHandle, true,  pid, lib, enterSym);
                    uprobes.attachUprobe(exitHandle,     false, pid, lib, exitSym);
                } catch (Exception e) {
                    throw new RuntimeException(
                            "Failed to attach uprobes — verify symbols with `nm " + lib + " | grep ObjectMonitor`. "
                            + "Underlying error: " + e.getMessage(), e);
                }

                sched.attachScheduler();
                System.err.println("Scheduler attached. Press Ctrl-C to detach.");

                Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                    System.err.println();
                    System.err.println("==== Top " + topN + " contended monitors ====");
                    int rank = 1;
                    for (var m : topContendedMonitors(uprobes, topN)) {
                        System.err.printf("  %2d. 0x%016x  %d events%n", rank++, m.monitorAddr(), m.count());
                    }
                }));

                long deadline = statsInterval > 0
                        ? System.nanoTime() + statsInterval * 1_000_000_000L
                        : Long.MAX_VALUE;

                while (processAlive(pid)) {
                    Thread.sleep(200);
                    if (statsInterval > 0 && System.nanoTime() >= deadline) {
                        System.err.printf("[stats] boostedEnq=%d normalEnq=%d boosts=%d watchdogResets=%d totalBoostedMs=%.1f%n",
                                sched.getBoostedEnqueueCount(),
                                sched.getNormalEnqueueCount(),
                                uprobes.boostActivations.get(),
                                sched.getWatchdogResets(),
                                sched.getTotalBoostedNs() / 1_000_000.0);
                        deadline = System.nanoTime() + statsInterval * 1_000_000_000L;
                    }
                }
                System.err.println("Target JVM " + pid + " exited; detaching.");
                sched.onSchedulerExit(sched.getExitCode());
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            }
        }

        private static <T> T firstNonNull(T a, T b) { return a != null ? a : b; }
    }

    public static void main(String[] args) {
        FemtoCli.run(new Cli(), args);
    }
}
