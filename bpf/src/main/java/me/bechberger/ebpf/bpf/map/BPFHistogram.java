package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.bpf.BPFMapClass;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;

import static me.bechberger.ebpf.type.BPFType.BPFIntType.INT32;
import static me.bechberger.ebpf.type.BPFType.BPFIntType.INT64;

import java.util.Arrays;

/**
 * A power-of-2 log2 histogram backed by a {@link BPFHashMap BPFHashMap&lt;Integer, Long&gt;}.
 *
 * <p>Keys are bucket indices 0..63 where bucket {@code i} counts values in the range
 * {@code [2^(i-1), 2^i)}.  Bucket 0 counts the value 0; bucket 1 counts value 1;
 * bucket 2 counts values 2–3; and so on.  This matches the BCC {@code log2_hist} layout.
 *
 * <h2>BPF-side usage</h2>
 * <pre>{@code
 * @BPFMapDefinition(maxEntries = 64)
 * BPFHistogram latency;
 *
 * // inside a BPF program:
 * latency.record(durationNs);
 * }</pre>
 *
 * <h2>Java-side usage</h2>
 * <pre>{@code
 * program.latency.printLog2Hist("latency (ns)");
 * }</pre>
 *
 * @see <a href="https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#2-log2_hist">BCC log2_hist</a>
 */
@BPFMapClass(
        cTemplate = """
        struct {
            __uint (type, BPF_MAP_TYPE_HASH);
            __uint (map_flags, BPF_F_NO_PREALLOC);
            __type (key, s32);
            __type (value, s64);
            __uint (max_entries, $maxEntries);
        } $field SEC(".maps");
        """,
        javaTemplate = """
        new $class<>($fd)
        """)
public class BPFHistogram extends BPFHashMap<Integer, Long> {

    public BPFHistogram(FileDescriptor fd) {
        super(fd, INT32, INT64);
    }

    /**
     * BPF-side: increment the log2 histogram bucket for {@code value}.
     *
     * <p>The bucket index is {@code value == 0 ? 0 : (64 - __builtin_clzll(value))},
     * which gives the floor-log2 position plus one (so bucket 0 = value 0,
     * bucket 1 = value 1, bucket 2 = values 2–3, bucket 3 = values 4–7, …).
     * This matches the BCC {@code log2_hist} convention.
     *
     * <p>The increment is atomic via {@code __sync_fetch_and_add} so concurrent
     * BPF programs on multiple CPUs update the same bucket safely.
     */
    @BuiltinBPFFunction("""
            ({
                s32 ___slot = (s64)($arg1) <= 0 ? 0 : (64 - __builtin_clzll((unsigned long long)($arg1)));
                s64 ___one = 1;
                s64 *___v = bpf_map_lookup_elem(&$this, &___slot);
                if (___v) {
                    __sync_fetch_and_add(___v, ___one);
                } else {
                    bpf_map_update_elem(&$this, &___slot, &___one, BPF_ANY);
                }
            })""")
    @NotUsableInJava
    public void record(long value) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Java-side: print a log2 histogram to stdout.
     *
     * <p>Reads all populated buckets from the kernel map and renders a bar chart
     * similar to BCC's {@code print_log2_hist}.  Empty leading/trailing buckets
     * are trimmed.
     *
     * @param header column header for the value axis (e.g. {@code "latency (ns)"})
     */
    public void printLog2Hist(String header) {
        long[] counts = new long[64];
        for (var entry : entrySet()) {
            int slot = entry.getKey();
            if (slot >= 0 && slot < 64) {
                counts[slot] = entry.getValue();
            }
        }

        int lo = 0, hi = 63;
        while (lo < 63 && counts[lo] == 0) lo++;
        while (hi > lo  && counts[hi] == 0) hi--;

        long maxVal = 0;
        for (int i = lo; i <= hi; i++) maxVal = Math.max(maxVal, counts[i]);

        int barWidth = 40;
        System.out.printf("%-19s  %10s  %s%n", header, "count", "distribution");
        for (int i = lo; i <= hi; i++) {
            String range = bucketRange(i);
            long cnt = counts[i];
            int bars = maxVal == 0 ? 0 : (int) (cnt * barWidth / maxVal);
            char[] bar = new char[barWidth];
            Arrays.fill(bar, 0, bars, '*');
            Arrays.fill(bar, bars, barWidth, ' ');
            System.out.printf("%-19s  %10d  |%s|%n", range, cnt, new String(bar));
        }
    }

    private static String bucketRange(int slot) {
        if (slot == 0) return "[0, 0]";
        if (slot == 1) return "[1, 1]";
        long lo = 1L << (slot - 1);
        long hi = (1L << slot) - 1;
        return String.format("[%d, %d]", lo, hi);
    }
}
