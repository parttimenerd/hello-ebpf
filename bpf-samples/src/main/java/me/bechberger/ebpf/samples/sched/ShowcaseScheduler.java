// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.bpf.QueuedTask;
import me.bechberger.ebpf.bpf.userspace.ClassMetrics;
import me.bechberger.ebpf.bpf.userspace.Opts;
import me.bechberger.ebpf.bpf.userspace.TaskClassifier;
import me.bechberger.ebpf.bpf.userspace.UserspaceScheduler;
import me.bechberger.femtocli.FemtoCli;
import me.bechberger.femtocli.annotations.Command;
import me.bechberger.femtocli.annotations.Option;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * <b>Experimental</b> — API may change without notice.
 *
 * <p>Showcase scheduler: demonstrates capabilities impossible in kernelspace BPF.
 *
 * <h2>What only userspace can do</h2>
 * <ul>
 *   <li><b>/proc/&lt;pid&gt;/cmdline</b> — full argv. BPF only sees {@code comm} (15 chars).
 *       A process whose comm is {@code java} could be {@code gradle}, {@code spring-boot},
 *       or {@code spark-submit} — indistinguishable from BPF.</li>
 *   <li><b>/proc/&lt;pid&gt;/cgroup</b> — container vs host. BPF has
 *       {@code bpf_get_current_cgroup_id()} (a number), not the path string with
 *       {@code docker}//{@code kubepods} in it.</li>
 *   <li><b>/proc/&lt;pid&gt;/io</b> — per-task I/O bytes. Lives in {@code task->ioac};
 *       no stable kfunc exposes it.</li>
 *   <li><b>Cross-batch history</b> — rolling {@code execRuntime} window per pid using an
 *       {@code ArrayDeque}. BPF maps have fixed-size values; no per-key deque exists.</li>
 * </ul>
 *
 * <h2>Dispatch priority</h2>
 * <ol>
 *   <li>Interactive tasks (shell/editor/terminal) that just woke up (low recent CPU)</li>
 *   <li>Interactive tasks running hot</li>
 *   <li>Host JVM services (Spring Boot, Elasticsearch, …)</li>
 *   <li>Container workloads — pinned to upper CPU partition</li>
 *   <li>Build/compiler tools — pinned to upper CPU partition</li>
 *   <li>Everything else</li>
 * </ol>
 * Within each tier, I/O-heavy tasks (high bytes/s) sort last — they're going to block
 * on I/O anyway, so CPU-bound peers should run first.
 */
public final class ShowcaseScheduler extends UserspaceScheduler {

    // ── Tiers ────────────────────────────────────────────────────────────────

    enum Tier {
        INTERACTIVE_FRESH,
        INTERACTIVE_HOT,
        HOST_JVM,
        CONTAINER,
        BUILDER,
        OTHER
    }

    // ── Classification tables ─────────────────────────────────────────────────

    private static final Set<String> INTERACTIVE_BINS = Set.of(
            "bash", "sh", "zsh", "fish", "dash",
            "vim", "nvim", "emacs", "nano", "helix", "micro",
            "alacritty", "kitty", "gnome-terminal", "konsole", "xterm", "tmux", "screen",
            "firefox", "chromium", "chrome", "brave", "code", "code-oss");

    private static final Set<String> BUILDER_BINS = Set.of(
            "gcc", "g++", "clang", "clang++", "cc1", "cc1plus", "as", "ld", "ar",
            "make", "ninja", "cmake", "meson", "bazel",
            "gradle", "mvn", "ant", "sbt",
            "javac", "kotlinc", "scalac", "ecj",
            "pytest", "tox",
            "go", "rustc", "cargo", "tsc", "webpack", "vite", "node", "npm", "pnpm", "yarn");

    // Substrings in the full cmdline that identify host JVM services
    private static final List<String> HOST_JVM_HINTS = List.of(
            "spring-boot", "tomcat", "jetty", "elasticsearch", "cassandra",
            "kafka", "zookeeper", "hadoop", "flink", "spark",
            "org.gradle.launcher.daemon", "-server");

    // Substrings in the cgroup path that indicate a container
    private static final List<String> CONTAINER_CGROUP_HINTS = List.of(
            "docker", "kubepods", "containerd", "podman", "lxc");

    // ── Tunables ─────────────────────────────────────────────────────────────

    private static final int  HISTORY_WINDOW    = 8;
    private static final long FRESH_RUNTIME_NS  = 5_000_000L;   // <5 ms recent CPU → fresh
    private static final long IO_HEAVY_BPS      = 5L << 20;     // >5 MB/s → I/O-heavy
    private static final long CACHE_STALE_TICKS = 30L;          // re-read /proc after 30 s
    private static final long DEAD_ENTRY_TICKS  = 60L;          // evict after 60 s absent

    // ── Per-pid state ─────────────────────────────────────────────────────────

    static final class PidInfo {
        Tier    tier            = Tier.OTHER;
        boolean container       = false;
        long    lastCmdlineTick = -CACHE_STALE_TICKS;  // force read on first access
        long    lastIoNs        = 0;
        long    lastReadBytes   = 0;
        long    lastWriteBytes  = 0;
        long    ioBps           = 0;
        boolean ioBlocked       = false;  // true if /proc/io is unreadable
        long    lastSeenTick    = 0;
        long    lastExecRuntime = 0;
        final ArrayDeque<Long> runtimeDeltas = new ArrayDeque<>(HISTORY_WINDOW + 1);
    }

    private final HashMap<Integer, PidInfo> pids = new HashMap<>();

    // ── CPU partitioning ──────────────────────────────────────────────────────

    private final int nCpus;
    private final int containerCpuStart;  // upper partition: [containerCpuStart, nCpus)
    private int containerRR = 0;
    private int builderRR   = 0;

    // ── Tick counter ──────────────────────────────────────────────────────────

    private long tickCount = 0;

    // ── Stats ─────────────────────────────────────────────────────────────────

    private final AtomicLong[] dispatchesByTier = new AtomicLong[Tier.values().length];

    // ── Constructor ───────────────────────────────────────────────────────────

    public ShowcaseScheduler(double containerCpuFrac) {
        this.nCpus = Runtime.getRuntime().availableProcessors();
        int start = (int) Math.round(nCpus * (1.0 - containerCpuFrac));
        this.containerCpuStart = Math.max(1, Math.min(nCpus - 1, start));
        for (int i = 0; i < dispatchesByTier.length; i++) {
            dispatchesByTier[i] = new AtomicLong();
        }

        // Per-class metrics: key the framework's per-class histograms by the tier we
        // cached during classify(). Placement stays in schedule() — the classifier's
        // policies are unused by the metrics path, so we only supply classify(...).
        setClassMetrics(TaskClassifier.<Tier>builder()
                .classify(t -> {
                    PidInfo info = pids.get(t.pid);
                    return info == null ? Tier.OTHER : info.tier;
                })
                .build());
    }

    // ── Core scheduling ───────────────────────────────────────────────────────

    @Override
    protected void schedule(QueuedTask[] tasks, int count) {
        long nowNs = System.nanoTime();

        // Six buckets — references into the original tasks[] array (not copies)
        List<QueuedTask> interactiveFresh = new ArrayList<>();
        List<QueuedTask> interactiveHot   = new ArrayList<>();
        List<QueuedTask> hostJvm          = new ArrayList<>();
        List<QueuedTask> container        = new ArrayList<>();
        List<QueuedTask> builder          = new ArrayList<>();
        List<QueuedTask> other            = new ArrayList<>();

        // Pass 1: classify each task and update /proc caches
        for (int i = 0; i < count; i++) {
            QueuedTask t = tasks[i];
            PidInfo info = pids.computeIfAbsent(t.pid, p -> new PidInfo());
            info.lastSeenTick = tickCount;

            // Refresh cmdline + cgroup classification when stale
            if (tickCount - info.lastCmdlineTick >= CACHE_STALE_TICKS) {
                classify(t.pid, t, info);
                info.lastCmdlineTick = tickCount;
            }

            // Sample I/O at most every ~1.5 s per pid (not every batch)
            if (!info.ioBlocked && nowNs - info.lastIoNs > 1_500_000_000L) {
                readIo(t.pid, info, nowNs);
            }

            // Rolling execRuntime delta → fresh/hot detection
            long delta = Math.max(0L, t.execRuntime - info.lastExecRuntime);
            info.lastExecRuntime = t.execRuntime;
            if (info.runtimeDeltas.size() == HISTORY_WINDOW) {
                info.runtimeDeltas.pollFirst();
            }
            info.runtimeDeltas.addLast(delta);
            long sumRecent = 0;
            for (Long d : info.runtimeDeltas) sumRecent += d;
            boolean fresh = sumRecent < FRESH_RUNTIME_NS;

            // Bucket the task
            switch (info.tier) {
                case INTERACTIVE_FRESH:
                case INTERACTIVE_HOT:
                    (fresh ? interactiveFresh : interactiveHot).add(t);
                    break;
                case HOST_JVM:   hostJvm.add(t);   break;
                case CONTAINER:  container.add(t); break;
                case BUILDER:    builder.add(t);   break;
                default:         other.add(t);     break;
            }
        }

        // Pass 2: within each bucket sort I/O-heavy tasks last
        Comparator<QueuedTask> cpuFirst = (a, b) -> {
            long aIo = pids.get(a.pid).ioBps;
            long bIo = pids.get(b.pid).ioBps;
            int aH = aIo > IO_HEAVY_BPS ? 1 : 0;
            int bH = bIo > IO_HEAVY_BPS ? 1 : 0;
            if (aH != bH) return aH - bH;
            return Integer.compare(a.pid, b.pid);
        };
        interactiveFresh.sort(cpuFirst);
        interactiveHot.sort(cpuFirst);
        hostJvm.sort(cpuFirst);
        container.sort(cpuFirst);
        builder.sort(cpuFirst);
        other.sort(cpuFirst);

        // Pass 3: dispatch in tier order
        for (QueuedTask t : interactiveFresh) dispatchAny(t, Tier.INTERACTIVE_FRESH);
        for (QueuedTask t : interactiveHot)   dispatchAny(t, Tier.INTERACTIVE_HOT);
        for (QueuedTask t : hostJvm)          dispatchAny(t, Tier.HOST_JVM);
        for (QueuedTask t : container)        dispatchPartition(t, Tier.CONTAINER, containerRR++);
        for (QueuedTask t : builder)          dispatchPartition(t, Tier.BUILDER,   builderRR++);
        for (QueuedTask t : other)            dispatchAny(t, Tier.OTHER);
    }

    // ── Dispatch helpers ──────────────────────────────────────────────────────

    private void dispatchAny(QueuedTask t, Tier tier) {
        dispatchTask(t, ANY_CPU);
        dispatchesByTier[tier.ordinal()].incrementAndGet();
    }

    private void dispatchPartition(QueuedTask t, Tier tier, int rr) {
        int span = nCpus - containerCpuStart;
        int cpu  = containerCpuStart + Math.floorMod(rr, span);
        dispatchTask(t, cpu);
        dispatchesByTier[tier.ordinal()].incrementAndGet();
    }

    // ── /proc helpers ─────────────────────────────────────────────────────────

    /** Read and classify a pid from /proc/cmdline + /proc/cgroup. */
    private void classify(int pid, QueuedTask t, PidInfo info) {
        String[] argv = readCmdline(pid);
        String   bin  = argv.length > 0 ? basename(argv[0]) : t.commStr();
        String   cgroup = readCgroup(pid);

        // Container detection via cgroup path
        info.container = false;
        for (String hint : CONTAINER_CGROUP_HINTS) {
            if (cgroup.contains(hint)) { info.container = true; break; }
        }

        if (info.container) {
            info.tier = Tier.CONTAINER;
        } else if (INTERACTIVE_BINS.contains(bin)) {
            info.tier = Tier.INTERACTIVE_FRESH;  // fresh/hot decided per-batch at dispatch time
        } else if (BUILDER_BINS.contains(bin)) {
            info.tier = Tier.BUILDER;
        } else if ("java".equals(bin) && matchesHostJvmHint(argv)) {
            info.tier = Tier.HOST_JVM;
        } else {
            info.tier = Tier.OTHER;
        }
    }

    private static String[] readCmdline(int pid) {
        try {
            byte[] raw = Files.readAllBytes(Path.of("/proc/" + pid + "/cmdline"));
            if (raw.length == 0) return new String[0];
            // Split on NUL bytes
            List<String> parts = new ArrayList<>();
            int start = 0;
            for (int i = 0; i <= raw.length; i++) {
                if (i == raw.length || raw[i] == 0) {
                    if (i > start) parts.add(new String(raw, start, i - start));
                    start = i + 1;
                }
            }
            return parts.toArray(new String[0]);
        } catch (IOException e) {
            return new String[0];
        }
    }

    private static String readCgroup(int pid) {
        try {
            // /proc/<pid>/cgroup lines: "hierarchyId:controllers:path"
            // cgroup v2 is always "0::/path"
            StringBuilder paths = new StringBuilder();
            for (String line : Files.readAllLines(Path.of("/proc/" + pid + "/cgroup"))) {
                int second = line.indexOf(':', line.indexOf(':') + 1);
                if (second >= 0) paths.append(line.substring(second + 1)).append('|');
            }
            return paths.toString();
        } catch (IOException e) {
            return "";
        }
    }

    private static void readIo(int pid, PidInfo info, long nowNs) {
        try {
            long rBytes = 0, wBytes = 0;
            for (String line : Files.readAllLines(Path.of("/proc/" + pid + "/io"))) {
                if (line.startsWith("read_bytes:")) {
                    rBytes = Long.parseLong(line.substring("read_bytes:".length()).trim());
                } else if (line.startsWith("write_bytes:")) {
                    wBytes = Long.parseLong(line.substring("write_bytes:".length()).trim());
                }
            }
            long dBytes = (rBytes - info.lastReadBytes) + (wBytes - info.lastWriteBytes);
            long dNs    = nowNs - info.lastIoNs;
            info.ioBps          = dNs > 0 ? dBytes * 1_000_000_000L / dNs : 0;
            info.lastReadBytes  = rBytes;
            info.lastWriteBytes = wBytes;
            info.lastIoNs       = nowNs;
        } catch (IOException e) {
            // Permission denied for other users' tasks — disable permanently
            info.ioBlocked = true;
        }
    }

    private static String basename(String path) {
        int slash = path.lastIndexOf('/');
        return slash >= 0 ? path.substring(slash + 1) : path;
    }

    private static boolean matchesHostJvmHint(String[] argv) {
        String joined = String.join(" ", argv);
        for (String hint : HOST_JVM_HINTS) {
            if (joined.contains(hint)) return true;
        }
        return false;
    }

    // ── Housekeeping ──────────────────────────────────────────────────────────

    @Override
    protected void tick() {
        tickCount++;
        long cutoff = tickCount - DEAD_ENTRY_TICKS;
        pids.entrySet().removeIf(e -> {
            if (e.getValue().lastSeenTick < cutoff) return true;
            return !Files.exists(Path.of("/proc/" + e.getKey()));
        });
    }

    // ── Stats ─────────────────────────────────────────────────────────────────

    @Override
    public String formatStats() {
        StringBuilder sb = new StringBuilder(super.formatStats())
                .append("  tracked=").append(pids.size()).append(" tiers=[");
        Tier[] tiers = Tier.values();
        for (int i = 0; i < tiers.length; i++) {
            if (i > 0) sb.append(' ');
            sb.append(tiers[i].name().toLowerCase(Locale.ROOT))
              .append('=').append(dispatchesByTier[i].get());
        }
        sb.append(']');

        // Per-class dispatch-count metrics from the framework (keyed by tier via
        // setClassMetrics). Only append tiers that have been dispatched at least once.
        StringBuilder perClass = new StringBuilder();
        for (Tier tier : tiers) {
            ClassMetrics m = perClass(tier);
            if (m == null || m.count() == 0) continue;
            if (perClass.length() > 0) perClass.append(' ');
            perClass.append(tier.name().toLowerCase(Locale.ROOT)).append('=').append(m.count());
        }
        if (perClass.length() > 0) {
            sb.append(" metrics=[").append(perClass).append(']');
        }
        return sb.toString();
    }

    // ── CLI ───────────────────────────────────────────────────────────────────

    @Command(name = "ShowcaseScheduler",
            description = {
                "Showcase of userspace-only scheduling capabilities.",
                "Reads /proc/<pid>/cmdline, /proc/<pid>/cgroup, /proc/<pid>/io.",
                "Interactive tasks dispatched first; containers/builders pinned to upper CPUs.",
                "None of this classification is possible in kernelspace BPF."
            },
            mixinStandardHelpOptions = true)
    static final class Cli implements Runnable {

        @Option(names = {"--stats-interval"},
                description = "Seconds between stats prints (0 = disable).",
                defaultValue = "5")
        int statsInterval;

        @Option(names = {"--container-cpu-frac"},
                description = "Fraction of CPUs reserved for containers+builders (upper partition).",
                defaultValue = "0.5")
        double containerCpuFrac;

        @Override
        public void run() {
            var sched = new ShowcaseScheduler(containerCpuFrac);

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
                }, "showcase-stats");
                t.setDaemon(true);
                t.start();
            }

            System.err.printf(
                "ShowcaseScheduler: attaching (cpus=%d, container/builder partition=[%d,%d)) — Ctrl-C to detach%n",
                sched.nCpus, sched.containerCpuStart, sched.nCpus);
            sched.runUntilExit(Opts.defaults());
        }
    }

    public static void main(String[] args) {
        FemtoCli.run(new Cli(), args);
    }
}
