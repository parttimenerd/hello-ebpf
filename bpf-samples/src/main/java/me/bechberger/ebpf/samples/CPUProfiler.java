package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.JavaOnly;
import me.bechberger.ebpf.bpf.BPFJ;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.bpf.map.BPFStackTraceMap;
import me.bechberger.ebpf.bpf.perf.PerfEvent;
import me.bechberger.ebpf.bpf.raw.Lib_2;
import me.bechberger.ebpf.shared.PanamaUtil.HandlerWithErrno;
import me.bechberger.ebpf.type.Ptr;

import me.bechberger.femtocli.FemtoCli;
import me.bechberger.femtocli.annotations.Command;
import me.bechberger.femtocli.annotations.Option;
import me.bechberger.util.json.PrettyPrinter;

import java.io.*;
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.file.*;
import java.util.*;
import static java.lang.foreign.ValueLayout.*;
import static me.bechberger.ebpf.runtime.BpfDefinitions.bpf_perf_event_data;
import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.*;

/**
 * CPU profiler that uses eBPF {@code perf_event} programs to sample call stacks
 * across all CPUs and renders the result as an interactive HTML flamegraph.
 *
 * <h2>How it works</h2>
 * <ol>
 *   <li>A {@code SEC("perf_event")} BPF program ({@link #onSample}) is attached to the
 *       Linux CPU-clock software event on every online CPU via
 *       <a href="https://man7.org/linux/man-pages/man2/perf_event_open.2.html">{@code perf_event_open(2)}</a>.
 *       The kernel fires the program at the requested sampling period.</li>
 *   <li>On each sample the BPF program captures the kernel and user-space call stacks
 *       using
 *       <a href="https://docs.kernel.org/bpf/map_stack_trace.html">{@code bpf_get_stackid}</a>
 *       and increments a per-{@link StackKey} hit counter in the {@link #counts} map.</li>
 *   <li>After the sampling window the Java side reads the two BPF maps, symbolizes every
 *       instruction pointer (kernel via {@code /proc/kallsyms}, user-space via ELF
 *       {@code .dynsym}/{@code .symtab}), and builds a call-tree.</li>
 *   <li>The call-tree is serialized as JSON and embedded into a self-contained HTML file
 *       powered by <a href="https://github.com/spiermar/d3-flame-graph">d3-flame-graph</a>.</li>
 * </ol>
 *
 * <h2>Usage</h2>
 * <pre>
 *   sudo java -cp bpf-samples.jar me.bechberger.ebpf.samples.CPUProfiler \
 *       [--duration=10] [--output=flame.html] [--period=1000000] [--pid=&lt;pid&gt;] [--no-table]
 * </pre>
 *
 * <p>The output file can be opened directly in any browser.
 */
@BPF(license = "GPL")
public abstract class CPUProfiler extends BPFProgram {

    /** Maximum number of distinct stack traces stored in {@link #stacks}. */
    static final int MAX_STACK_ENTRIES = 10_000;

    /** Maximum number of distinct (pid, kStackId, uStackId) tuples in {@link #counts}. */
    static final int MAX_COUNT_ENTRIES = 10_000;

    /**
     * BPF map key that uniquely identifies one observed call-stack combination.
     *
     * <p>The BPF program stores one entry per unique (process, kernel-stack, user-stack)
     * triple. The Java side uses {@code kStackId} and {@code uStackId} as keys into
     * {@link #stacks} to retrieve the actual instruction-pointer arrays.
     *
     * @param pid       lower 32 bits of {@code bpf_get_current_pid_tgid()} — the thread ID
     * @param kStackId  kernel stack ID returned by {@code bpf_get_stackid(..., 0)}; negative on error
     * @param uStackId  user-space stack ID returned by {@code bpf_get_stackid(..., BPF_F_USER_STACK)}; negative on error
     * @see <a href="https://docs.kernel.org/bpf/map_stack_trace.html">BPF_MAP_TYPE_STACK_TRACE</a>
     */
    @Type
    record StackKey(@Unsigned int pid, int kStackId, int uStackId) {}

    /**
     * Hit-count map: how many times each unique {@link StackKey} was sampled.
     *
     * <p>The BPF program atomically increments the counter for the current
     * (pid, kStackId, uStackId) on every CPU-clock tick. The Java side iterates
     * this map after profiling to build the flame-graph tree.
     */
    @BPFMapDefinition(maxEntries = MAX_COUNT_ENTRIES)
    BPFHashMap<StackKey, Long> counts;

    /**
     * Stack-trace map: stores raw instruction-pointer arrays keyed by integer stack ID.
     *
     * <p>Each entry holds up to {@value BPFStackTraceMap#PERF_MAX_STACK_DEPTH} 64-bit
     * instruction pointers, innermost frame first. The BPF program calls
     * {@code bpf_get_stackid} which hashes the current stack, stores it here, and
     * returns the integer key. The Java side calls {@link BPFStackTraceMap#get(int)}
     * to retrieve the frame list.
     *
     * @see <a href="https://docs.kernel.org/bpf/map_stack_trace.html">BPF_MAP_TYPE_STACK_TRACE</a>
     */
    @BPFMapDefinition(maxEntries = MAX_STACK_ENTRIES)
    BPFStackTraceMap stacks;

    /**
     * BPF sampling handler — fires on every CPU-clock perf event.
     *
     * <p>On each invocation the program:
     * <ol>
     *   <li>Captures the kernel call stack into {@link #stacks} (flags = {@code STACK_REUSE}).</li>
     *   <li>Captures the user-space call stack into {@link #stacks} (flags = {@code STACK_USER | STACK_REUSE}).</li>
     *   <li>Atomically increments the hit counter for the resulting {@link StackKey} in {@link #counts}.</li>
     * </ol>
     *
     * <p>{@code autoAttach = false} because attachment requires one fd per CPU opened via
     * {@link #perfEventOpen} — the generic libbpf auto-attach path does not handle this.
     *
     * @see <a href="https://docs.kernel.org/bpf/libbpf/program_types.html">BPF perf_event program type</a>
     */
    @BPFFunction(section = "perf_event", autoAttach = false)
    public void onSample(Ptr<bpf_perf_event_data> data) {
        PerfEvent pe = PerfEvent.of(data);

        @Unsigned int pid = (int) bpf_get_current_pid_tgid();

        int kStackId = (int) pe.getStackId(stacks, PerfEvent.STACK_REUSE);
        int uStackId = (int) pe.getStackId(stacks, PerfEvent.STACK_USER | PerfEvent.STACK_REUSE);

        StackKey key = new StackKey(pid, kStackId, uStackId);
        Ptr<Long> val = counts.bpf_get(key);
        if (val == null) {
            long one = 1L;
            counts.bpf_put(key, one);
        } else {
            BPFJ.sync_fetch_and_add(val, 1L);
        }
    }

    // ── perf_event_open ───────────────────────────────────────────────────────
    //
    // Constants mirror fields of struct perf_event_attr as documented in
    // https://man7.org/linux/man-pages/man2/perf_event_open.2.html

    /** {@code perf_event_attr.type} value for software events. */
    @JavaOnly private static final int  PERF_TYPE_SOFTWARE      = 1;
    /** {@code perf_event_attr.config} value for CPU-clock software event. */
    @JavaOnly private static final long PERF_COUNT_SW_CPU_CLOCK = 0L;
    /** Size of {@code struct perf_event_attr} as used here (128 bytes covers all needed fields). */
    @JavaOnly private static final int  PERF_EVENT_ATTR_SIZE    = 128;
    /**
     * x86-64 syscall number for {@code perf_event_open}.
     * glibc does not expose a wrapper, so we call the kernel directly.
     * @see <a href="https://man7.org/linux/man-pages/man2/perf_event_open.2.html">perf_event_open(2)</a>
     */
    @JavaOnly private static final long __NR_perf_event_open    = 298L;
    /** {@code perf_event_open} flag: close fd on {@code exec}. */
    @JavaOnly private static final long PERF_FLAG_FD_CLOEXEC    = 8L;

    /** Panama FFI handle for the libc {@code syscall(2)} variadic wrapper. */
    private static final HandlerWithErrno<Integer> SYSCALL_HANDLER =
            new HandlerWithErrno<>("syscall",
                    FunctionDescriptor.of(JAVA_INT,
                            JAVA_LONG, ADDRESS, JAVA_INT, JAVA_INT, JAVA_INT, JAVA_LONG));

    /** Panama FFI handle for {@code close(2)} used to clean up perf fds on attach failure. */
    private static final MethodHandle CLOSE_MH = Linker.nativeLinker().downcallHandle(
            Linker.nativeLinker().defaultLookup().find("close").orElseThrow(),
            FunctionDescriptor.of(JAVA_INT, JAVA_INT));

    private static void closeFd(int fd) {
        try { CLOSE_MH.invokeExact(fd); } catch (Throwable ignored) {}
    }

    /**
     * Opens a CPU-clock perf event for {@code cpu} (all processes, all threads).
     *
     * <p>Fills a minimal {@code struct perf_event_attr} in off-heap memory and calls
     * {@code perf_event_open(attr, pid=-1, cpu, groupFd=-1, PERF_FLAG_FD_CLOEXEC)}.
     * {@code pid = -1} means measure all processes on the given CPU.
     *
     * <p>Struct layout (offsets in bytes):
     * <pre>
     *   0   u32  type          = PERF_TYPE_SOFTWARE
     *   4   u32  size          = PERF_EVENT_ATTR_SIZE
     *   8   u64  config        = PERF_COUNT_SW_CPU_CLOCK
     *   16  u64  sample_period = samplePeriod
     * </pre>
     *
     * @param cpu          CPU index to profile
     * @param samplePeriod fire the event every {@code samplePeriod} CPU-clock ticks
     * @return the perf event file descriptor
     * @throws RuntimeException if the syscall fails (e.g. the CPU is offline)
     * @see <a href="https://man7.org/linux/man-pages/man2/perf_event_open.2.html">perf_event_open(2)</a>
     */
    private static int perfEventOpen(int cpu, long samplePeriod) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment attr = arena.allocate(PERF_EVENT_ATTR_SIZE);
            attr.set(JAVA_INT,  0, PERF_TYPE_SOFTWARE);
            attr.set(JAVA_INT,  4, PERF_EVENT_ATTR_SIZE);
            attr.set(JAVA_LONG, 8, PERF_COUNT_SW_CPU_CLOCK);
            attr.set(JAVA_LONG, 16, samplePeriod);
            var res = SYSCALL_HANDLER.call(__NR_perf_event_open, attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
            int fd = res.result();
            if (fd < 0) throw new RuntimeException("perf_event_open cpu=" + cpu + " errno=" + res.err());
            return fd;
        }
    }

    // ── main ──────────────────────────────────────────────────────────────────

    // ── CLI ───────────────────────────────────────────────────────────────────

    @Command(name = "CPUProfiler",
             description = {"CPU profiler: samples call stacks via eBPF perf_event and writes an HTML flamegraph."},
             mixinStandardHelpOptions = true)
    static final class Cli implements Runnable {

        @Option(names = {"--duration"}, description = "Sampling duration in seconds.", defaultValue = "10")
        int durationSec;

        @Option(names = {"--output"}, description = "Output HTML file.", defaultValue = "flame.html")
        Path output;

        @Option(names = {"--period"}, description = "Sampling period in CPU-clock ticks (~1000 samples/s/cpu at 1000000).", defaultValue = "1000000")
        long samplePeriod;

        @Option(names = {"--pid"}, description = "Filter to a single PID (-1 = all processes).", defaultValue = "-1")
        int pidFilter;

        @Option(names = {"--no-table"}, description = "Suppress the method-frequency table.", defaultValue = "false")
        boolean noTable;

        @Override
        public void run() {
            System.err.printf("Profiling for %ds (period=%d cycles, output=%s)%n", durationSec, samplePeriod, output);
            try {
                profile();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        private void profile() throws Exception {
            try (CPUProfiler program = BPFProgram.load(CPUProfiler.class)) {
                var progHandle = program.getProgramByName("onSample");
                int numCpus    = Lib_2.libbpf_num_possible_cpus();
                var perfFds    = new ArrayList<Integer>(numCpus);

                for (int cpu = 0; cpu < numCpus; cpu++) {
                    int pfd;
                    try { pfd = perfEventOpen(cpu, samplePeriod); }
                    catch (RuntimeException e) { continue; }   // CPU may be offline
                    perfFds.add(pfd);
                    try { program.attachPerfEvent(progHandle, pfd); }
                    catch (Exception e) {
                        System.err.println("Warning: attach failed on cpu " + cpu + ": " + e.getMessage());
                        closeFd(pfd);
                        perfFds.remove(perfFds.size() - 1);
                    }
                }
                System.err.println("Attached to " + perfFds.size() + " CPU(s). Sampling...");

                Thread.sleep(durationSec * 1000L);

                System.err.println("Collecting data...");
                var collector = new Collector(program, pidFilter);
                collector.collect();

                if (!noTable) collector.printMethodTable(System.err);
                collector.writeFlameGraph(output);
                System.err.println("Flamegraph written to " + output.toAbsolutePath());
            }
        }
    }

    public static void main(String[] args) {
        FemtoCli.run(new Cli(), args);
    }

    // ── Flame-graph call tree ─────────────────────────────────────────────────

    /**
     * One node in the call tree, corresponding to a single frame name.
     *
     * <p>The tree is built from symbolized stack traces (root → outermost caller →
     * … → innermost callee) and serialized to the JSON schema expected by
     * <a href="https://github.com/spiermar/d3-flame-graph">d3-flame-graph</a>:
     * <pre>
     *   { "name": "...", "value": &lt;hit-count&gt;, "children": [ ... ] }
     * </pre>
     * {@code value} counts how many times this node was on any sampled stack
     * (not just as a leaf), which is what d3-flame-graph uses to size the rectangles.
     */
    static class Node {
        final String name;
        /** Number of stack samples that passed through this node. */
        long value;
        /** Child nodes keyed by frame name, insertion-ordered for stable output. */
        final Map<String, Node> children = new LinkedHashMap<>();

        Node(String name) { this.name = name; }

        Node child(String n) { return children.computeIfAbsent(n, Node::new); }

        /**
         * Walks {@code frames} from {@code idx} onward, incrementing each node's
         * {@link #value} and creating child nodes as needed.
         *
         * @param frames ordered list of frame names, outermost first
         * @param idx    index of the frame this node represents (0 = root's child)
         */
        void addTrace(List<String> frames, int idx) {
            value++;
            if (idx < frames.size()) child(frames.get(idx)).addTrace(frames, idx + 1);
        }

        /** Converts this node and its subtree to the d3-flame-graph JSON schema. */
        Map<String, Object> toJsonObject() {
            var childList = new ArrayList<Object>(children.size());
            for (var c : children.values()) childList.add(c.toJsonObject());
            return Map.of("name", name, "value", value, "children", childList);
        }
    }

    // ── Collector ─────────────────────────────────────────────────────────────

    /**
     * Reads the BPF maps after sampling, symbolizes stacks, and produces both a
     * flat method-frequency table and the {@link Node} tree for the flame-graph.
     *
     * <p>Workflow:
     * <ol>
     *   <li>Iterate {@link #counts}: for each (pid, kStackId, uStackId) → hitCount entry…</li>
     *   <li>Retrieve the kernel frame IPs from {@link #stacks} and symbolize via
     *       {@link #symKernel}. BPF stores frames innermost-first so the list is
     *       reversed to get caller → callee order for the flame-graph.</li>
     *   <li>Do the same for user-space frames via {@link #symUser}, using
     *       {@code /proc/pid/maps} (cached per PID) for address-to-library mapping.</li>
     *   <li>Feed the combined frame list into the {@link Node} tree and the
     *       per-method counters {@code hitCount} times.</li>
     * </ol>
     */
    static class Collector {
        private final CPUProfiler program;
        /** If ≥ 0, only stacks from this PID are included. */
        private final int pidFilter;
        private final StackSymbolizer symbolizer = new StackSymbolizer();
        private final Node root = new Node("root");
        /** Per-method counters: {@code long[0]} = total appearances, {@code long[1]} = on-top count. */
        private final Map<String, long[]> methodCounts = new HashMap<>();
        private long totalSamples;

        Collector(CPUProfiler program, int pidFilter) {
            this.program   = program;
            this.pidFilter = pidFilter;
        }

        /** Reads and symbolizes all entries from the BPF maps. */
        void collect() {
            var mapsCache = new HashMap<Integer, List<StackSymbolizer.MapRange>>();
            for (var entry : program.counts.entrySet()) {
                StackKey key   = entry.getKey();
                long     count = entry.getValue();
                int      pid   = key.pid() & 0xFFFF_FFFF;
                if (pidFilter != -1 && pid != pidFilter) continue;

                var frames = new ArrayList<String>();

                // BPF stores frames innermost-first; reverse to get caller → callee.
                var kf = program.stacks.get(key.kStackId());
                for (int i = kf.size() - 1; i >= 0; i--) frames.add(symbolizer.symKernel(kf.get(i)));

                var uf = program.stacks.get(key.uStackId());
                var ranges = mapsCache.computeIfAbsent(pid, StackSymbolizer::readMaps);
                for (int i = uf.size() - 1; i >= 0; i--) frames.add(symbolizer.symUser(uf.get(i), ranges));

                if (frames.isEmpty()) continue;

                for (long c = 0; c < count; c++) root.addTrace(frames, 0);
                totalSamples += count;

                // Track per-method totals and on-top (leaf) counts for the table.
                var seen = new HashSet<String>();
                for (int i = 0; i < frames.size(); i++) {
                    String f = frames.get(i);
                    if (seen.add(f)) {
                        var mc = methodCounts.computeIfAbsent(f, k -> new long[2]);
                        mc[0] += count;
                        if (i == frames.size() - 1) mc[1] += count;
                    }
                }
            }
        }

        /**
         * Prints the top-40 methods by total sample count to {@code out}.
         *
         * <p>Columns: method name (truncated to 70 chars), total samples + %, on-top samples + %.
         * "On top" means the method was the innermost (currently executing) frame — a high
         * on-top % indicates the method itself is hot, not just on a hot call path.
         */
        void printMethodTable(PrintStream out) {
            out.printf("%n===== method table =====%n");
            out.printf("Total samples: %d%n", totalSamples);
            out.printf("%-70s %8s %7s %8s %7s%n", "Method", "Samples", "%", "OnTop", "%");
            methodCounts.entrySet().stream()
                    .sorted((a, b) -> Long.compare(b.getValue()[0], a.getValue()[0]))
                    .limit(40)
                    .forEach(e -> {
                        String m = e.getKey();
                        if (m.length() > 70) m = m.substring(0, 67) + "...";
                        long[] mc = e.getValue();
                        out.printf("%-70s %8d %6.1f%% %8d %6.1f%%%n",
                                m, mc[0], mc[0] * 100.0 / totalSamples,
                                mc[1], mc[1] * 100.0 / totalSamples);
                    });
        }

        /**
         * Serializes the call tree to JSON and writes a self-contained HTML file.
         *
         * <p>The JSON is injected into {@link #FLAME_HTML_TEMPLATE} at the
         * {@code __DATA__} placeholder. The resulting file has no external dependencies
         * beyond CDN-hosted scripts and can be opened directly in a browser.
         *
         * @param output destination path for the HTML file
         */
        void writeFlameGraph(Path output) throws IOException {
            String json = PrettyPrinter.compactPrint(root.toJsonObject());
            String html = FLAME_HTML_TEMPLATE.replace("__DATA__", json);
            Files.writeString(output, html);
        }
    }

    // ── HTML template ─────────────────────────────────────────────────────────

    /**
     * Self-contained HTML template for the flamegraph output.
     *
     * <p>Uses <a href="https://github.com/spiermar/d3-flame-graph">d3-flame-graph 4.1.3</a>
     * via CDN. The {@code __DATA__} placeholder is replaced with the JSON call tree by
     * {@link Collector#writeFlameGraph}. {@code .inverted(true)} renders an icicle chart
     * (root at top, callees below) which is the conventional orientation for CPU profiles.
     */
    @JavaOnly
    private static final String FLAME_HTML_TEMPLATE = """
            <!DOCTYPE html>
            <html>
            <head>
              <meta charset="utf-8">
              <title>CPU Flamegraph</title>
              <link rel="stylesheet" type="text/css"
                    href="https://cdn.jsdelivr.net/npm/d3-flame-graph@4.1.3/dist/d3-flamegraph.css">
              <style>
                body { font-family: monospace; margin: 0; padding: 8px; background: #fafafa; }
                h2 { margin: 4px 0 6px 0; font-size: 15px; font-family: sans-serif; }
                #details { font-size: 12px; margin-top: 6px; min-height: 16px; color: #333; }
                .d3-flame-graph rect:hover { stroke: #333; stroke-width: 0.5; }
              </style>
            </head>
            <body>
              <h2>CPU Flamegraph</h2>
              <div id="chart"></div>
              <div id="details"></div>
              <script type="text/javascript"
                      src="https://d3js.org/d3.v7.min.js"></script>
              <script type="text/javascript"
                      src="https://cdn.jsdelivr.net/npm/d3-flame-graph@4.1.3/dist/d3-flamegraph.min.js"></script>
              <script type="text/javascript">
                var data = __DATA__;
                var chart = flamegraph()
                    .width(window.innerWidth - 16)
                    .inverted(true)
                    .sort(true)
                    .tooltip(true)
                    .details(document.getElementById("details"));
                d3.select("#chart").datum(data).call(chart);
                window.onresize = function() {
                    chart.width(window.innerWidth - 16);
                    d3.select("#chart").call(chart);
                };
              </script>
            </body>
            </html>
            """;
}
