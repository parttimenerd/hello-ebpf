package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.BPFJ;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.bpf.map.BPFStackTraceMap;
import me.bechberger.ebpf.bpf.perf.PerfEvent;
import me.bechberger.ebpf.bpf.raw.Lib_2;
import me.bechberger.ebpf.shared.PanamaUtil.HandlerWithErrno;
import me.bechberger.ebpf.type.Ptr;

import java.io.*;
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.file.*;
import java.util.*;

import static java.lang.foreign.ValueLayout.*;
import static me.bechberger.ebpf.runtime.BpfDefinitions.bpf_perf_event_data;
import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.*;

/**
 * CPU profiler using perf_event + eBPF stack traces.
 *
 * <p>Attaches a BPF program to the CPU-clock software event on every online CPU.
 * Captures kernel + user stacks keyed by (pid, kStackId, uStackId).  After
 * collection the Java side symbolizes stacks and writes a self-contained HTML
 * flamegraph using <a href="https://github.com/spiermar/d3-flame-graph">d3-flame-graph</a>.
 *
 * <pre>
 *   sudo java -cp bpf-samples.jar me.bechberger.ebpf.samples.CPUProfiler \
 *       [--duration=10] [--output=flame.html] [--period=1000000] [--pid=&lt;pid&gt;]
 * </pre>
 *
 * <p>Output is a single {@code flame.html} that can be opened in any browser.
 */
@BPF(license = "GPL")
public abstract class CPUProfiler extends BPFProgram {

    static final int MAX_STACK_ENTRIES = 10_000;
    static final int MAX_COUNT_ENTRIES = 10_000;

    @Type
    record StackKey(@Unsigned int pid, int kStackId, int uStackId) {}

    @BPFMapDefinition(maxEntries = MAX_COUNT_ENTRIES)
    BPFHashMap<StackKey, Long> counts;

    @BPFMapDefinition(maxEntries = MAX_STACK_ENTRIES)
    BPFStackTraceMap stacks;

    @BPFFunction(
            section = "perf_event",
            headerTemplate = "int $name(struct bpf_perf_event_data *data)",
            lastStatement = "return 0;",
            autoAttach = false
    )
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

    private static final int  PERF_TYPE_SOFTWARE     = 1;
    private static final long PERF_COUNT_SW_CPU_CLOCK = 0L;
    private static final int  PERF_EVENT_ATTR_SIZE   = 128;
    private static final long __NR_perf_event_open   = 298L;   // x86-64
    private static final long PERF_FLAG_FD_CLOEXEC   = 8L;

    private static final HandlerWithErrno<Integer> SYSCALL_HANDLER =
            new HandlerWithErrno<>("syscall",
                    FunctionDescriptor.of(JAVA_INT,
                            JAVA_LONG, ADDRESS, JAVA_INT, JAVA_INT, JAVA_INT, JAVA_LONG));

    private static final MethodHandle CLOSE_MH = Linker.nativeLinker().downcallHandle(
            Linker.nativeLinker().defaultLookup().find("close").orElseThrow(),
            FunctionDescriptor.of(JAVA_INT, JAVA_INT));

    private static void closeFd(int fd) {
        try { CLOSE_MH.invokeExact(fd); } catch (Throwable ignored) {}
    }

    /** Open a CPU-clock perf event for the given CPU (all processes). */
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

    public static void main(String[] args) throws InterruptedException, IOException {
        // parse args
        int    durationSec   = 10;
        Path   output        = Path.of("flame.html");
        long   samplePeriod  = 1_000_000L;   // ~1000 samples/s/cpu
        int    pidFilter     = -1;            // -1 = all
        boolean showTable    = true;

        for (String arg : args) {
            if (arg.startsWith("--duration="))   durationSec  = Integer.parseInt(arg.substring(11));
            else if (arg.startsWith("--output=")) output       = Path.of(arg.substring(9));
            else if (arg.startsWith("--period=")) samplePeriod = Long.parseLong(arg.substring(9));
            else if (arg.startsWith("--pid="))    pidFilter    = Integer.parseInt(arg.substring(6));
            else if (arg.equals("--no-table"))    showTable    = false;
            else if (arg.equals("--help")) {
                System.err.println("Usage: CPUProfiler [--duration=10] [--output=flame.html] [--period=1000000] [--pid=<pid>] [--no-table]");
                return;
            }
        }

        System.err.printf("Profiling for %ds (period=%d cycles, output=%s)%n", durationSec, samplePeriod, output);

        try (CPUProfiler program = BPFProgram.load(CPUProfiler.class)) {
            var progHandle = program.getProgramByName("onSample");
            int numCpus    = Lib_2.libbpf_num_possible_cpus();
            var perfFds    = new ArrayList<Integer>(numCpus);

            for (int cpu = 0; cpu < numCpus; cpu++) {
                int pfd;
                try { pfd = perfEventOpen(cpu, samplePeriod); }
                catch (RuntimeException e) { continue; }
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
            // close() (try-with-resources) destroys all links before we read maps
            var collector = new Collector(program, pidFilter);
            collector.collect();

            if (showTable) collector.printMethodTable(System.err);
            collector.writeFlameGraph(output);
            System.err.println("Flamegraph written to " + output.toAbsolutePath());
        }
    }

    // ── Symbolization ─────────────────────────────────────────────────────────

    record MapRange(long start, long end, long fileOffset, String path) {}

    private static List<MapRange> readMaps(int pid) {
        try {
            var result = new ArrayList<MapRange>();
            for (var line : Files.readAllLines(Path.of("/proc/" + pid + "/maps"))) {
                var parts = line.split("\\s+", 6);
                if (parts.length < 5) continue;
                var addrs  = parts[0].split("-");
                long start = Long.parseUnsignedLong(addrs[0], 16);
                long end   = Long.parseUnsignedLong(addrs[1], 16);
                long off   = Long.parseUnsignedLong(parts[2], 16);
                String p   = parts.length == 6 ? parts[5].trim() : "[anon]";
                if (!p.isEmpty()) result.add(new MapRange(start, end, off, p));
            }
            return result;
        } catch (IOException e) { return List.of(); }
    }

    private static String symUser(long ip, List<MapRange> ranges) {
        for (var r : ranges) {
            if (ip >= r.start() && ip < r.end()) {
                String name = Path.of(r.path()).getFileName().toString();
                return name + "+0x" + Long.toHexString(ip - r.start() + r.fileOffset());
            }
        }
        return "[unknown]+0x" + Long.toHexString(ip);
    }

    // ── Kallsyms ──────────────────────────────────────────────────────────────

    /** Sorted array of kernel symbol addresses; parallel array of names. */
    private static long[]   kallsymsAddrs = null;
    private static String[] kallsymsNames = null;

    private static void loadKallsyms() {
        if (kallsymsAddrs != null) return;
        var addrs = new ArrayList<Long>();
        var names = new ArrayList<String>();
        try (var br = new BufferedReader(new FileReader("/proc/kallsyms"))) {
            String line;
            while ((line = br.readLine()) != null) {
                var parts = line.split("\\s+", 3);
                if (parts.length < 3) continue;
                // only function symbols: t, T, w, W
                char type = parts[1].charAt(0);
                if (type != 't' && type != 'T' && type != 'w' && type != 'W') continue;
                long addr = Long.parseUnsignedLong(parts[0], 16);
                if (addr == 0) continue;
                addrs.add(addr);
                names.add(parts[2].split("\\s")[0]); // strip optional module
            }
        } catch (IOException ignored) {}

        // sort by address
        int n = addrs.size();
        long[] a = new long[n];
        String[] s = new String[n];
        for (int i = 0; i < n; i++) { a[i] = addrs.get(i); s[i] = names.get(i); }
        // insertion-sort would be slow; use Arrays.sort on an index array
        Integer[] idx = new Integer[n];
        for (int i = 0; i < n; i++) idx[i] = i;
        Arrays.sort(idx, Comparator.comparingLong(i -> a[i]));
        long[] sa = new long[n]; String[] sn = new String[n];
        for (int i = 0; i < n; i++) { sa[i] = a[idx[i]]; sn[i] = s[idx[i]]; }
        kallsymsAddrs = sa;
        kallsymsNames = sn;
    }

    private static String symKernel(long ip) {
        loadKallsyms();
        if (kallsymsAddrs.length == 0) return "kernel+0x" + Long.toHexString(ip);
        // binary search: find largest addr <= ip
        int lo = 0, hi = kallsymsAddrs.length - 1, best = -1;
        while (lo <= hi) {
            int mid = (lo + hi) >>> 1;
            if (Long.compareUnsigned(kallsymsAddrs[mid], ip) <= 0) { best = mid; lo = mid + 1; }
            else hi = mid - 1;
        }
        if (best < 0) return "kernel+0x" + Long.toHexString(ip);
        long offset = ip - kallsymsAddrs[best];
        return kallsymsNames[best] + "+0x" + Long.toHexString(offset);
    }

    // ── Flame-graph tree (d3-flame-graph JSON) ────────────────────────────────

    static class Node {
        final String name;
        long value;
        final Map<String, Node> children = new LinkedHashMap<>();

        Node(String name) { this.name = name; }

        Node child(String n) { return children.computeIfAbsent(n, Node::new); }

        void addTrace(List<String> frames, int idx) {
            value++;
            if (idx < frames.size()) child(frames.get(idx)).addTrace(frames, idx + 1);
        }

        void toJson(StringBuilder sb) {
            sb.append("{\"name\":\"").append(jsonEscape(name))
              .append("\",\"value\":").append(value)
              .append(",\"children\":[");
            boolean first = true;
            for (var c : children.values()) {
                if (!first) sb.append(',');
                c.toJson(sb);
                first = false;
            }
            sb.append("]}");
        }

        private static String jsonEscape(String s) {
            return s.replace("\\", "\\\\").replace("\"", "\\\"");
        }
    }

    // ── Collector ─────────────────────────────────────────────────────────────

    static class Collector {
        private final CPUProfiler program;
        private final int pidFilter;
        private final Node root = new Node("root");
        private final Map<String, long[]> methodCounts = new HashMap<>(); // [total, onTop]
        private long totalSamples;

        Collector(CPUProfiler program, int pidFilter) {
            this.program   = program;
            this.pidFilter = pidFilter;
        }

        void collect() {
            var mapsCache = new HashMap<Integer, List<MapRange>>();
            for (var entry : program.counts.entrySet()) {
                StackKey key   = entry.getKey();
                long     count = entry.getValue();
                int      pid   = key.pid() & 0xFFFF_FFFF;
                if (pidFilter != -1 && pid != pidFilter) continue;

                var frames = new ArrayList<String>();

                // outermost (caller) → innermost (callee) for flame-graph
                var kf = program.stacks.get(key.kStackId());
                for (int i = kf.size() - 1; i >= 0; i--) frames.add(symKernel(kf.get(i)));

                var uf = program.stacks.get(key.uStackId());
                var ranges = mapsCache.computeIfAbsent(pid, CPUProfiler::readMaps);
                for (int i = uf.size() - 1; i >= 0; i--) frames.add(symUser(uf.get(i), ranges));

                if (frames.isEmpty()) continue;

                // add to tree (count times)
                for (long c = 0; c < count; c++) root.addTrace(frames, 0);
                totalSamples += count;

                // method table
                var seen = new HashSet<String>();
                for (int i = 0; i < frames.size(); i++) {
                    String f = frames.get(i);
                    if (seen.add(f)) {
                        var mc = methodCounts.computeIfAbsent(f, k -> new long[2]);
                        mc[0] += count;
                        if (i == frames.size() - 1) mc[1] += count; // on top = last (innermost)
                    }
                }
            }
        }

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

        void writeFlameGraph(Path output) throws IOException {
            var json = new StringBuilder(1 << 20);
            root.toJson(json);

            String html = FLAME_HTML_TEMPLATE.replace("__DATA__", json.toString());
            Files.writeString(output, html);
        }
    }

    // ── HTML template with inline d3-flame-graph ──────────────────────────────

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
