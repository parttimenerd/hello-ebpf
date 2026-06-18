package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.JavaOnly;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.bpf.map.BPFRingBuffer;
import me.bechberger.ebpf.runtime.PtDefinitions.pt_regs;
import me.bechberger.ebpf.type.Ptr;
import me.bechberger.femtocli.FemtoCli;
import me.bechberger.femtocli.annotations.Command;
import me.bechberger.femtocli.annotations.Option;

import java.nio.file.*;
import java.util.*;

import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.*;

/**
 * Traces JVM stop-the-world GC pauses by attaching uprobes to
 * {@code VM_GC_Operation::notify_gc_begin} and {@code VM_GC_Operation::notify_gc_end}
 * inside {@code libjvm.so}.
 *
 * <h2>How it works</h2>
 * <ol>
 *   <li>A uprobe on {@code notify_gc_begin(bool full)} records a start timestamp and
 *       whether the collection is a full GC.</li>
 *   <li>A uretprobe on {@code notify_gc_end()} computes the elapsed time and pushes
 *       a {@link GcEvent} to a ring buffer.</li>
 *   <li>The Java side prints each event and maintains per-GC-type histograms.</li>
 * </ol>
 *
 * <h2>Usage</h2>
 * <pre>
 *   sudo java -cp bpf-samples.jar me.bechberger.ebpf.samples.JvmGcPauseTracer \
 *       --pid=&lt;jvm-pid&gt; [--libjvm=/path/to/libjvm.so] [--histogram]
 * </pre>
 *
 * <p>The target JVM must be running; the tracer attaches to its {@code libjvm.so}
 * image. {@code --pid} is required to avoid spurious events from unrelated JVMs.
 */
@BPF(license = "GPL")
public abstract class JvmGcPauseTracer extends BPFProgram {

    /**
     * Per-CPU scratch storage: the nanosecond timestamp at which the current GC
     * pause began, and whether it is a full GC. Indexed by CPU id.
     *
     * <p>Using a per-CPU map avoids lock contention: each CPU handles at most one
     * STW pause at a time (the JVM suspends all threads before entering GC).
     */
    @BPFMapDefinition(maxEntries = 512)
    BPFHashMap<Integer, GcStart> startMap;

    /** Ring buffer for completed GC pause events sent to user space. */
    @BPFMapDefinition(maxEntries = 256 * 1024)
    BPFRingBuffer<GcEvent> events;

    /**
     * Scratch record stored on uprobe entry: the wall-clock nanosecond timestamp
     * and whether this is a full (major) GC.
     */
    @Type
    static class GcStart {
        /** {@code bpf_ktime_get_ns()} at the moment {@code notify_gc_begin} fires. */
        @Unsigned long startNs;
        /** 1 for full/major GC; 0 for young/minor. */
        @Unsigned int full;
    }

    /**
     * Completed GC pause event sent through the ring buffer to user space.
     */
    @Type
    static class GcEvent {
        /** Thread-group ID (Java PID) of the JVM thread that triggered GC. */
        @Unsigned int pid;
        /** Kernel thread ID. */
        @Unsigned int tid;
        /** Wall-clock pause duration in nanoseconds. */
        @Unsigned long durationNs;
        /** 1 for full/major GC; 0 for young/minor. */
        @Unsigned int full;
    }

    /**
     * Uprobe on {@code VM_GC_Operation::notify_gc_begin(bool full)}.
     *
     * <p>Records the start timestamp and the {@code full} flag (first argument, in
     * {@code rdi} on x86-64) into a per-CPU map entry keyed by CPU id.
     *
     * @param ctx raw {@code pt_regs} context from the uprobe
     */
    @BPFFunction(section = "uprobe/notify_gc_begin", autoAttach = false)
    public void onGcBegin(Ptr<pt_regs> ctx) {
        @Unsigned long now  = bpf_ktime_get_ns();
        @Unsigned int  cpu  = (int) bpf_get_smp_processor_id();
        // arg0 = bool full (x86-64 first argument register = di)
        @Unsigned int  full = (int) ctx.val().di;
        GcStart s = new GcStart();
        s.startNs = now;
        s.full = full;
        startMap.bpf_put(cpu, s);
    }

    /**
     * Uretprobe on {@code VM_GC_Operation::notify_gc_end()}.
     *
     * <p>Retrieves the start record for this CPU, computes the pause duration, and
     * emits a {@link GcEvent} to the ring buffer.
     *
     * @param ctx raw {@code pt_regs} context from the uretprobe
     */
    @BPFFunction(section = "uretprobe/notify_gc_end", autoAttach = false)
    public void onGcEnd(Ptr<pt_regs> ctx) {
        @Unsigned long now = bpf_ktime_get_ns();
        @Unsigned int  cpu = (int) bpf_get_smp_processor_id();

        Ptr<GcStart> sp = startMap.bpf_get(cpu);
        if (sp == null) return;

        @Unsigned long pidTid = bpf_get_current_pid_tgid();
        @Unsigned int  pid    = (int) (pidTid >> 32);
        @Unsigned int  tid    = (int) pidTid;
        @Unsigned long dur    = now - sp.val().startNs;
        @Unsigned int  full   = sp.val().full;

        startMap.bpf_delete(cpu);

        Ptr<GcEvent> evt = events.reserve();
        if (evt == null) return;
        evt.val().pid         = pid;
        evt.val().tid         = tid;
        evt.val().durationNs  = dur;
        evt.val().full        = full;
        events.submit(evt);
    }

    // ── libjvm.so path resolution ─────────────────────────────────────────────

    /** Default search pattern for libjvm.so inside a JVM home directory. */
    @JavaOnly
    private static final String LIBJVM_GLOB = "lib/server/libjvm.so";

    /** Returns {@code true} while {@code /proc/<pid>} exists (process is alive). */
    @JavaOnly
    static boolean processAlive(int pid) {
        return Files.exists(Path.of("/proc/" + pid));
    }

    /**
     * Resolves the path to {@code libjvm.so} for the given JVM process.
     *
     * <p>Scans {@code /proc/pid/maps} for a line ending in {@code libjvm.so} and
     * returns the mapped path. This handles cases where multiple JDKs are installed.
     *
     * @param pid target JVM process
     * @return absolute path to {@code libjvm.so}
     * @throws RuntimeException if the library cannot be found in the process's maps
     */
    static String findLibjvm(int pid) {
        try {
            for (var line : Files.readAllLines(Path.of("/proc/" + pid + "/maps"))) {
                var parts = line.split("\\s+");
                if (parts.length >= 6) {
                    String path = parts[5];
                    if (path.endsWith("/libjvm.so")) return path;
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("Cannot read /proc/" + pid + "/maps: " + e.getMessage());
        }
        throw new RuntimeException("libjvm.so not found in /proc/" + pid + "/maps — is pid " + pid + " a JVM?");
    }

    // ── CLI ───────────────────────────────────────────────────────────────────

    @Command(name = "JvmGcPauseTracer",
             description = {"Traces JVM stop-the-world GC pauses via uprobes on libjvm.so."},
             mixinStandardHelpOptions = true)
    static final class Cli implements Runnable {

        @Option(names = {"--pid"}, description = "PID of the target JVM process.", required = true)
        int pid;

        @Option(names = {"--libjvm"}, description = "Path to libjvm.so (auto-detected from /proc/pid/maps if omitted).", defaultValue = "")
        String libjvm;

        @Option(names = {"--histogram"}, description = "Print a pause-duration histogram on exit.", defaultValue = "false")
        boolean histogram;

        @Override
        public void run() {
            String lib = libjvm.isEmpty() ? findLibjvm(pid) : libjvm;
            System.err.println("Attaching to " + lib + " for pid " + pid);
            try {
                trace(lib);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        private void trace(String lib) throws Exception {
            // Pause-duration buckets in ms: <1, 1–5, 5–10, 10–50, 50–100, 100–500, ≥500
            long[] youngBuckets = new long[7];
            long[] fullBuckets  = new long[7];
            long[] totals = new long[2]; // [0]=young, [1]=full

            try (JvmGcPauseTracer program = BPFProgram.load(JvmGcPauseTracer.class)) {
                var beginHandle = program.getProgramByName("onGcBegin");
                var endHandle   = program.getProgramByName("onGcEnd");

                // Attach to the specific pid so we don't capture other JVMs.
                try {
                    program.attachUprobe(beginHandle,  false, pid, lib, "_ZN15VM_GC_Operation15notify_gc_beginEb");
                    program.attachUprobe(endHandle,    true,  pid, lib, "_ZN15VM_GC_Operation13notify_gc_endEv");
                } catch (Exception e) {
                    throw new RuntimeException(
                            "Failed to attach uprobes to " + lib + " — "
                            + "make sure the JVM was compiled with debug symbols "
                            + "and the target is a HotSpot JVM: " + e.getMessage(), e);
                }

                System.err.printf("%-6s  %-8s  %-8s  %s%n", "TYPE", "PID", "TID", "DURATION");

                program.events.setCallback((buf, evt) -> {
                    double ms = evt.durationNs / 1_000_000.0;
                    String type = evt.full != 0 ? "FULL" : "YOUNG";
                    System.out.printf("%-6s  %-8d  %-8d  %.3f ms%n",
                            type, evt.pid, evt.tid, ms);

                    long[] buckets = evt.full != 0 ? fullBuckets : youngBuckets;
                    buckets[bucketIndex(ms)]++;
                    if (evt.full != 0) totals[1]++; else totals[0]++;
                });

                Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                    if (histogram) printHistogram(youngBuckets, totals[0], fullBuckets, totals[1]);
                }));

                while (processAlive(pid)) {
                    program.consumeAndThrow();
                    Thread.sleep(10);
                }
                System.err.println("Target process " + pid + " exited; stopping tracer.");
            }
        }

        private static int bucketIndex(double ms) {
            if (ms < 1)    return 0;
            if (ms < 5)    return 1;
            if (ms < 10)   return 2;
            if (ms < 50)   return 3;
            if (ms < 100)  return 4;
            if (ms < 500)  return 5;
            return 6;
        }

        private static void printHistogram(long[] yb, long yt, long[] fb, long ft) {
            String[] labels = {"<1ms", "1–5ms", "5–10ms", "10–50ms", "50–100ms", "100–500ms", "≥500ms"};
            System.err.println("\n===== GC pause histogram =====");
            System.err.printf("%-12s  %8s  %8s%n", "Bucket", "Young", "Full");
            for (int i = 0; i < labels.length; i++) {
                System.err.printf("%-12s  %8d  %8d%n", labels[i], yb[i], fb[i]);
            }
            System.err.printf("%-12s  %8d  %8d%n", "TOTAL", yt, ft);
        }
    }

    public static void main(String[] args) {
        FemtoCli.run(new Cli(), args);
    }
}
