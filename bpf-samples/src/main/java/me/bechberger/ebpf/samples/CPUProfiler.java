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

import java.io.IOException;
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import static java.lang.foreign.ValueLayout.*;
import static me.bechberger.ebpf.runtime.BpfDefinitions.bpf_perf_event_data;
import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.*;

/**
 * Basic CPU profiler using perf_event + BPF stack traces.
 *
 * <p>Attaches a BPF program to the CPU-clock software event on every online CPU.
 * Each sample records the PID and kernel/user stack IDs. After the collection
 * window the Java side reads the stacks and prints folded-stack lines for
 * Brendan Gregg's {@code flamegraph.pl}:
 *
 * <pre>
 *   sudo java -jar ... me.bechberger.ebpf.samples.CPUProfiler [seconds]
 *   | flamegraph.pl > out.svg
 * </pre>
 */
@BPF(license = "GPL")
public abstract class CPUProfiler extends BPFProgram {

    static final int MAX_STACK_ENTRIES = 10_000;
    static final int MAX_COUNT_ENTRIES = 10_000;

    @Type
    record StackKey(@Unsigned int pid, int kStackId, int uStackId) {}

    /** Counts how many times each (pid, kStack, uStack) combination was sampled. */
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

    // ── perf_event_open via syscall ───────────────────────────────────────────

    // perf_event_attr offsets (struct size = 128, zero-filled)
    private static final int PERF_TYPE_SOFTWARE  = 1;
    private static final long PERF_COUNT_SW_CPU_CLOCK = 0L;
    private static final int PERF_EVENT_ATTR_SIZE = 128;
    // syscall number on x86-64
    private static final long __NR_perf_event_open = 298L;
    // perf_event_open(attr, pid=-1, cpu, group_fd=-1, flags=PERF_FLAG_FD_CLOEXEC=8)
    private static final long PERF_FLAG_FD_CLOEXEC = 8L;

    // syscall(long nr, ptr, int, int, int, long) → int
    private static final HandlerWithErrno<Integer> SYSCALL_HANDLER =
            new HandlerWithErrno<>("syscall",
                    FunctionDescriptor.of(JAVA_INT,
                            JAVA_LONG,  // syscall nr
                            ADDRESS,    // attr*
                            JAVA_INT,   // pid
                            JAVA_INT,   // cpu
                            JAVA_INT,   // group_fd
                            JAVA_LONG   // flags
                    ));

    private static final MethodHandle CLOSE_MH = Linker.nativeLinker().downcallHandle(
            Linker.nativeLinker().defaultLookup().find("close").orElseThrow(),
            FunctionDescriptor.of(JAVA_INT, JAVA_INT));

    private static void closeFd(int fd) {
        try { CLOSE_MH.invokeExact(fd); } catch (Throwable ignored) {}
    }

    /**
     * Open a CPU-clock software perf event for {@code cpu} (all processes).
     * Sampling period = 1 000 000 ns ≈ 1 000 samples/s/cpu.
     */
    private static int perfEventOpenCpuClock(int cpu) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment attr = arena.allocate(PERF_EVENT_ATTR_SIZE);
            attr.set(JAVA_INT,  0, PERF_TYPE_SOFTWARE);     // type
            attr.set(JAVA_INT,  4, PERF_EVENT_ATTR_SIZE);   // size
            attr.set(JAVA_LONG, 8, PERF_COUNT_SW_CPU_CLOCK);// config
            attr.set(JAVA_LONG, 16, 1_000_000L);             // sample_period
            // all other fields = 0 (already zero-filled by Arena)

            var res = SYSCALL_HANDLER.call(__NR_perf_event_open, attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
            int fd = res.result();
            if (fd < 0) {
                throw new RuntimeException(
                        "perf_event_open cpu=" + cpu + " failed, errno=" + res.err());
            }
            return fd;
        }
    }

    // ── main ──────────────────────────────────────────────────────────────────

    public static void main(String[] args) throws InterruptedException {
        int durationSec = args.length > 0 ? Integer.parseInt(args[0]) : 10;
        System.err.println("Profiling for " + durationSec + "s...");

        try (CPUProfiler program = BPFProgram.load(CPUProfiler.class)) {
            var progHandle = program.getProgramByName("onSample");

            int numCpus = Lib_2.libbpf_num_possible_cpus();
            var perfFds = new ArrayList<Integer>(numCpus);

            for (int cpu = 0; cpu < numCpus; cpu++) {
                int pfd;
                try {
                    pfd = perfEventOpenCpuClock(cpu);
                } catch (RuntimeException e) {
                    // CPU may be offline
                    continue;
                }
                perfFds.add(pfd);
                try {
                    program.attachPerfEvent(progHandle, pfd);
                } catch (Exception e) {
                    System.err.println("Warning: attach failed on cpu " + cpu + ": " + e.getMessage());
                    closeFd(pfd);
                    perfFds.remove(perfFds.size() - 1);
                }
            }
            System.err.println("Attached to " + perfFds.size() + " CPU(s)");

            Thread.sleep(durationSec * 1000L);
            // close() on the try-with-resources will destroy all attached links

            printFoldedStacks(program);
        }
    }

    // ── Symbolization ─────────────────────────────────────────────────────────

    record MapRange(long start, long end, long fileOffset, String path) {}

    private static void printFoldedStacks(CPUProfiler program) {
        var mapsCache = new HashMap<Integer, List<MapRange>>();

        for (var entry : program.counts.entrySet()) {
            StackKey key   = entry.getKey();
            long    count  = entry.getValue();

            var frames = new ArrayList<String>();

            // Kernel stack (reversed: outermost first for folded format)
            var kFrames = program.stacks.get(key.kStackId());
            for (int i = kFrames.size() - 1; i >= 0; i--) {
                frames.add(symKernel(kFrames.get(i)));
            }

            // User stack (reversed: outermost first)
            var uFrames = program.stacks.get(key.uStackId());
            var ranges  = mapsCache.computeIfAbsent(key.pid(), CPUProfiler::readMaps);
            for (int i = uFrames.size() - 1; i >= 0; i--) {
                frames.add(symUser(uFrames.get(i), ranges));
            }

            if (!frames.isEmpty()) {
                System.out.println(String.join(";", frames) + " " + count);
            }
        }
    }

    private static List<MapRange> readMaps(int pid) {
        try {
            var lines  = Files.readAllLines(Path.of("/proc/" + pid + "/maps"));
            var result = new ArrayList<MapRange>(lines.size());
            for (var line : lines) {
                // 7f1234560000-7f1234580000 r-xp 00000000 fd:01 12345 /usr/lib/libc.so.6
                var parts = line.split("\\s+", 6);
                if (parts.length < 5) continue;
                var addrs = parts[0].split("-");
                long start  = Long.parseUnsignedLong(addrs[0], 16);
                long end    = Long.parseUnsignedLong(addrs[1], 16);
                long offset = Long.parseUnsignedLong(parts[2], 16);
                String path = parts.length == 6 ? parts[5].trim() : "[anon]";
                result.add(new MapRange(start, end, offset, path));
            }
            return result;
        } catch (IOException e) {
            return List.of();
        }
    }

    private static String symUser(long ip, List<MapRange> ranges) {
        for (var r : ranges) {
            if (ip >= r.start() && ip < r.end()) {
                String lib = Path.of(r.path()).getFileName().toString();
                long   off = ip - r.start() + r.fileOffset();
                return lib + "+0x" + Long.toHexString(off);
            }
        }
        return "unknown_user+0x" + Long.toHexString(ip);
    }

    private static String symKernel(long ip) {
        // A full implementation would parse /proc/kallsyms; here we emit the hex addr.
        return "kernel+0x" + Long.toHexString(ip);
    }
}
