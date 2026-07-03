// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.bpf.QueuedTask;
import me.bechberger.ebpf.bpf.userspace.Opts;
import me.bechberger.ebpf.bpf.userspace.UserspaceScheduler;
import me.bechberger.femtocli.FemtoCli;
import me.bechberger.femtocli.annotations.Command;
import me.bechberger.femtocli.annotations.Option;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Java port of the scx_rustland algorithm.
 *
 * <h2>Algorithm</h2>
 * <p>Maintains per-task virtual time ({@code vtime}) and orders the whole batch by
 * <em>deadline = vtime + exec_runtime</em> before dispatching. This naturally favours
 * I/O-bound and interactive tasks: they sleep often, so their cumulative
 * {@code exec_runtime} stays small, giving them a lower deadline and therefore
 * priority over CPU-hungry batch tasks.
 *
 * <p>On each batch:
 * <ol>
 *   <li>Record the pre-advance minimum vtime across all tasks in the batch. Seed new
 *       or stale-returning tasks at this minimum (lag prevention).
 *   <li>Sort by {@code deadline = vtime + exec_runtime}, lowest first. Ties broken by pid.
 *   <li>Dispatch in that order. Advance each task's vtime by {@code SLICE_NS * 100 / weight}
 *       so higher-weight tasks step more slowly and stay near the front.
 *   <li>Try the task's previous CPU first (cache warmth); fall back to {@code ANY_CPU}.
 * </ol>
 *
 * <h2>Why schedule() is required</h2>
 * <p>Deadline ordering requires seeing the entire batch at once to find the minimum. The
 * per-task {@link #policy} callback cannot do this. {@link #schedule} receives the whole
 * drained batch, enabling the global sort that {@code scx_rustland} performs with a
 * {@code BTreeSet}.
 */
public final class RustlandJavaSample extends UserspaceScheduler {

    private static final long SLICE_NS       = 5_000_000L;  // 5 ms base quantum
    private static final long DEFAULT_WEIGHT = 100L;        // nice=0 weight
    private static final long EVICT_TICKS    = 10L;         // ~10 s absence → evict

    // ── Per-task state ───────────────────────────────────────────────────────

    private static final class TaskInfo {
        long vtime;
        long lastSeenTick;
    }

    private final Map<Integer, TaskInfo> table = new HashMap<>();
    private long minVtime  = 0;
    private long tickCount = 0;

    // ── Scratch arrays (grown lazily, never shrunk, reused every batch) ──────

    private long[]    scratchDeadlines = new long[64];
    private Integer[] scratchBoxed     = new Integer[64];

    // ── Counters (volatile so the stats thread can read without a race) ──────

    private volatile long batchesSeen;
    private volatile long tasksDispatched;
    private volatile long newTasksSeeded;
    private volatile long staleClamps;
    private volatile long prevCpuHits;
    private volatile long prevCpuMisses;
    private volatile long trackedTasks;  // mirror of table.size(), updated at end of schedule()

    // ── Core scheduling ──────────────────────────────────────────────────────

    @Override
    protected void schedule(QueuedTask[] tasks, int count) {
        if (count == 0) return;
        batchesSeen++;

        ensureScratchCapacity(count);

        long prevMin       = minVtime;
        long preAdvanceMin = Long.MAX_VALUE;

        // Pass 1: resolve/seed per-task state, compute deadlines, find pre-advance min.
        for (int i = 0; i < count; i++) {
            QueuedTask t = tasks[i];
            TaskInfo ti  = table.get(t.pid);
            if (ti == null) {
                ti = new TaskInfo();
                ti.vtime = prevMin;
                table.put(t.pid, ti);
                newTasksSeeded++;
            } else if (ti.vtime < prevMin) {
                // Stale returning task — clamp up so it doesn't hog the CPU.
                ti.vtime = prevMin;
                staleClamps++;
            }
            ti.lastSeenTick     = tickCount;
            long execRt         = Math.max(0L, t.execRuntime);
            scratchDeadlines[i] = ti.vtime + execRt;
            scratchBoxed[i]     = i;
            if (ti.vtime < preAdvanceMin) preAdvanceMin = ti.vtime;
        }

        // Publish pre-advance minimum BEFORE stepping anyone forward.
        // New tasks in the *next* batch join at this checkpoint, not after the advance.
        if (preAdvanceMin != Long.MAX_VALUE) minVtime = preAdvanceMin;

        // Pass 2: sort indices by (deadline, pid) — O(n log n), n ≤ batchSize (~256).
        Arrays.sort(scratchBoxed, 0, count, (i, j) -> {
            int c = Long.compare(scratchDeadlines[i], scratchDeadlines[j]);
            return c != 0 ? c : Integer.compare(tasks[i].pid, tasks[j].pid);
        });

        // Pass 3: dispatch in deadline order, advance vtime after each dispatch.
        for (int k = 0; k < count; k++) {
            int idx      = scratchBoxed[k];
            QueuedTask t = tasks[idx];
            TaskInfo  ti = table.get(t.pid);   // guaranteed present from Pass 1

            long weight = Math.max(1L, Math.min(10_000L, t.weight));
            ti.vtime += SLICE_NS * DEFAULT_WEIGHT / weight;

            int cpu = chooseCpu(t);
            dispatchTask(t, cpu);
            tasksDispatched++;
        }

        trackedTasks = table.size();
    }

    /** Try the task's previous CPU (cache warmth); fall back to ANY_CPU. */
    private int chooseCpu(QueuedTask t) {
        // Pinned tasks must stay on their allowed CPU.
        if (t.nrCpusAllowed == 1L && t.prevCpu >= 0) {
            return t.prevCpu;
        }
        if (isPrevCpuIdle(t.prevCpu)) {
            prevCpuHits++;
            return t.prevCpu;
        }
        prevCpuMisses++;
        return ANY_CPU;
    }

    /**
     * Returns true when {@code prevCpu} is currently idle according to the
     * mmap'd idle-CPU bitmap maintained by BPF.
     *
     * <p>Byte offset into the segment is {@code (cpu / 64) * 8} — one {@code long}
     * word per group of 64 CPUs; the bit index within the word is {@code cpu & 63}.
     */
    private boolean isPrevCpuIdle(int prevCpu) {
        if (prevCpu < 0) return false;
        MemorySegment view = idleMaskView();
        if (view == null) return false;
        long byteOffset = (long) (prevCpu / 64) * 8L;
        if (byteOffset + 8 > view.byteSize()) return false;
        long word = view.get(ValueLayout.JAVA_LONG, byteOffset);
        return (word & (1L << (prevCpu & 63))) != 0L;
    }

    // ── Housekeeping ─────────────────────────────────────────────────────────

    @Override
    protected void tick() {
        tickCount++;
        long cutoff = tickCount - EVICT_TICKS;
        table.entrySet().removeIf(e -> e.getValue().lastSeenTick < cutoff);
        trackedTasks = table.size();
    }

    // ── Observability ────────────────────────────────────────────────────────

    @Override
    public String formatStats() {
        return String.format(
                "%s  tracked=%d newTasks=%d clamps=%d prevCpu=%d/%d minVt=%d batches=%d",
                super.formatStats(), trackedTasks, newTasksSeeded, staleClamps,
                prevCpuHits, prevCpuMisses, minVtime, batchesSeen);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void ensureScratchCapacity(int n) {
        if (scratchDeadlines.length < n) {
            int cap = Integer.highestOneBit(n - 1) << 1;
            scratchDeadlines = new long[cap];
            scratchBoxed     = new Integer[cap];
        }
    }

    /** Package-private test seam: snapshot of the vtime table. */
    Map<Integer, Long> vtimeSnapshot() {
        var snap = new HashMap<Integer, Long>(table.size() * 2);
        table.forEach((pid, ti) -> snap.put(pid, ti.vtime));
        return snap;
    }

    // ── CLI ──────────────────────────────────────────────────────────────────

    @Command(name = "RustlandJavaSample",
            description = {
                "Java port of the scx_rustland deadline-based scheduler.",
                "Sorts each batch by deadline = vtime + exec_runtime before dispatching.",
                "I/O-bound tasks (low exec_runtime) are prioritised over CPU-hungry ones."
            },
            mixinStandardHelpOptions = true)
    static final class Cli implements Runnable {

        @Option(names = {"--stats-interval"},
                description = "Seconds between stats prints to stderr (0 = disable).",
                defaultValue = "5")
        int statsInterval;

        @Override
        public void run() {
            var sched = new RustlandJavaSample();

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
                                System.err.println("[stats] " + sched.formatStats());
                                deadline += intervalNs;
                            }
                        }
                    } catch (InterruptedException ignored) {}
                }, "rustland-java-stats");
                t.setDaemon(true);
                t.start();
            }

            System.err.println("RustlandJavaSample: attaching deadline scheduler (Ctrl-C to detach)...");
            sched.runUntilExit(Opts.defaults());
        }
    }

    public static void main(String[] args) {
        FemtoCli.run(new Cli(), args);
    }
}
