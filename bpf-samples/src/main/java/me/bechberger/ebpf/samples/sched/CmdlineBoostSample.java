// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.bpf.QueuedTask;
import me.bechberger.ebpf.bpf.userspace.Opts;
import me.bechberger.ebpf.bpf.userspace.UserspaceScheduler;
import me.bechberger.femtocli.FemtoCli;
import me.bechberger.femtocli.annotations.Command;
import me.bechberger.femtocli.annotations.Option;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Interactive-vs-batch CPU partitioner.
 *
 * <h2>Why this is only possible in a userspace scheduler</h2>
 * <p>BPF programs can read a task's {@code comm} (15-char kernel thread name),
 * but have no access to {@code /proc/<pid>/cmdline} — the full command line
 * with all arguments. Reading arbitrary files from BPF requires a helper that
 * does not exist; even {@code bpf_d_path} only works on open file descriptors
 * already known to the kernel.
 *
 * <p>This scheduler reads {@code /proc/<pid>/cmdline} once per new PID and
 * caches the result. The cache entry is the binary name (argv[0] basename),
 * which is richer than {@code comm}: a Java process whose comm is {@code java}
 * can be identified as {@code gradle}, {@code mvn}, or {@code kotlin} from
 * cmdline. The cache is purged in {@link #tick()} by checking whether
 * {@code /proc/<pid>} still exists, keeping memory bounded across PID churn.
 *
 * <h2>Policy</h2>
 * <ul>
 *   <li><b>Interactive tasks</b> (shells, editors, terminals, browsers) → {@link #ANY_CPU}:
 *       sched_ext picks any idle CPU for minimum latency.
 *   <li><b>Batch tasks</b> (compilers, build tools, test runners) → pinned to the
 *       upper half of available CPUs (ids ≥ {@code nCpus/2}), leaving the lower
 *       half free for interactive work. Round-robins across the batch partition.
 *   <li><b>Everything else</b> → {@link #ANY_CPU} (no opinion).
 * </ul>
 */
public final class CmdlineBoostSample extends UserspaceScheduler {

    // ── classification ───────────────────────────────────────────────────────

    private static final Set<String> INTERACTIVE = Set.of(
            "bash", "sh", "zsh", "fish",
            "vim", "nvim", "emacs", "nano", "helix",
            "alacritty", "kitty", "gnome-terminal", "konsole", "xterm",
            "firefox", "chromium", "chrome"
    );

    private static final Set<String> BATCH = Set.of(
            "gcc", "g++", "clang", "clang++", "cc1", "cc1plus", "as", "ld",
            "make", "ninja", "cmake",
            "gradle", "mvn", "ant", "bazel",
            "javac", "kotlinc", "scalac",
            "pytest", "go", "rustc", "cargo"
    );

    // ── state (policy thread only) ───────────────────────────────────────────

    /** pid → binary basename from /proc/<pid>/cmdline, or null if lookup failed. */
    private final Map<Integer, String> cmdlineCache = new ConcurrentHashMap<>();

    /** Tick count — used to timestamp cache entries so old ones can be purged. */
    private final Map<Integer, Long> lastSeen = new ConcurrentHashMap<>();

    private long tickCount = 0;
    private int batchCpuRobin = 0;

    // ── UserspaceScheduler overrides ─────────────────────────────────────────

    @Override
    protected int policy(QueuedTask t) {
        String bin = resolvebin(t.pid);
        lastSeen.put(t.pid, tickCount);

        if (bin != null && INTERACTIVE.contains(bin)) {
            return ANY_CPU;
        }
        if (bin != null && BATCH.contains(bin)) {
            return nextBatchCpu();
        }
        return ANY_CPU;
    }

    /** Called once per second. Ages out dead PIDs from the cache. */
    @Override
    protected void tick() {
        tickCount++;
        // Remove entries for PIDs that exited (proc dir gone) or not seen for >5 ticks.
        Iterator<Map.Entry<Integer, String>> it = cmdlineCache.entrySet().iterator();
        while (it.hasNext()) {
            int pid = it.next().getKey();
            long age = tickCount - lastSeen.getOrDefault(pid, tickCount);
            if (age > 5 || !Files.exists(Path.of("/proc/" + pid))) {
                it.remove();
                lastSeen.remove(pid);
            }
        }
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    /** Look up or cache the binary basename for {@code pid}. Returns null on any error. */
    private String resolvebin(int pid) {
        return cmdlineCache.computeIfAbsent(pid, p -> {
            try {
                byte[] raw = Files.readAllBytes(Path.of("/proc/" + p + "/cmdline"));
                if (raw.length == 0) return null;
                // cmdline is NUL-separated; argv[0] is everything up to the first NUL
                int end = 0;
                while (end < raw.length && raw[end] != 0) end++;
                String argv0 = new String(raw, 0, end);
                // take basename (strip path prefix)
                int slash = argv0.lastIndexOf('/');
                return slash >= 0 ? argv0.substring(slash + 1) : argv0;
            } catch (IOException e) {
                return null;
            }
        });
    }

    /** Round-robin over the upper half of CPUs reserved for batch work. */
    private synchronized int nextBatchCpu() {
        int n = Runtime.getRuntime().availableProcessors();
        int batchStart = Math.max(1, n / 2);  // lower CPUs left for interactive
        int batchCount = n - batchStart;
        int cpu = batchStart + (batchCpuRobin % batchCount);
        batchCpuRobin++;
        return cpu;
    }

    /** Test seam: snapshot of the current binary→classification map. */
    Map<Integer, String> cmdlineCacheSnapshot() {
        return Map.copyOf(cmdlineCache);
    }

    // ── CLI ──────────────────────────────────────────────────────────────────

    @Command(name = "CmdlineBoostSample",
            description = {
                "Interactive-vs-batch CPU partitioner.",
                "Reads /proc/<pid>/cmdline (unavailable to BPF) to classify tasks.",
                "Interactive tasks (shells, editors) get any idle CPU.",
                "Batch tasks (compilers, build tools) are pinned to the upper CPU half."
            },
            mixinStandardHelpOptions = true)
    static final class Cli implements Runnable {

        @Option(names = {"--stats-interval"},
                description = "Seconds between stats prints (0 = disable).",
                defaultValue = "5")
        int statsInterval;

        @Override
        public void run() {
            var sched = new CmdlineBoostSample();

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
                                int n = Runtime.getRuntime().availableProcessors();
                                System.err.printf("[cache] %d pids tracked, batch CPUs [%d, %d)%n",
                                        sched.cmdlineCache.size(), n / 2, n);
                                deadline += intervalNs;
                            }
                        }
                    } catch (InterruptedException ignored) {}
                }, "cmdline-stats");
                statsThread.setDaemon(true);
                statsThread.start();
            }

            int n = Runtime.getRuntime().availableProcessors();
            System.err.printf("CmdlineBoostSample: %d CPUs — interactive→[0,%d), batch→[%d,%d)%n",
                    n, n / 2, n / 2, n);
            System.err.println("Attaching scheduler (Ctrl-C to detach)...");
            sched.runUntilExit(Opts.defaults());
        }
    }

    public static void main(String[] args) {
        FemtoCli.run(new Cli(), args);
    }
}
