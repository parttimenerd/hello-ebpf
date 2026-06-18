package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPFMapClass;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.bpf.BPFError;
import me.bechberger.ebpf.bpf.raw.Lib;
import me.bechberger.ebpf.type.Ptr;

import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.util.ArrayList;
import java.util.List;

import static java.lang.foreign.ValueLayout.JAVA_LONG;

/**
 * Stack-trace map ({@code BPF_MAP_TYPE_STACK_TRACE}).
 *
 * <p>Used in conjunction with {@link me.bechberger.ebpf.runtime.helpers.BPFHelpers#bpf_get_stackid}
 * to capture kernel or user-space call stacks in BPF programs.  The BPF side
 * calls {@code bpf_get_stackid(ctx, &map, flags)} which stores the stack and
 * returns an integer {@code stackId}.  The Java side then calls {@link #get(int)}
 * to retrieve the stack frames.
 *
 * <h2>BPF-side usage</h2>
 * <pre>{@code
 * @BPFMapDefinition(maxEntries = 4096)
 * BPFStackTraceMap stacks;
 *
 * // In a kprobe:
 * long stackId = bpf_get_stackid(ctx, Ptr.of(stacks), BPFStackTraceMap.BPF_F_USER_STACK);
 * }</pre>
 *
 * <h2>Java-side retrieval</h2>
 * <pre>{@code
 * List<Long> frames = program.stacks.get((int) stackId);
 * for (long ip : frames) {
 *     System.out.printf("  0x%x%n", ip);
 * }
 * }</pre>
 *
 * <p>The maximum number of frames per stack is {@link #PERF_MAX_STACK_DEPTH} (127 by
 * default in upstream kernels).  Empty (zero) frames are trimmed from the result
 * by {@link #get(int)}.
 */
@BPFMapClass(
        cTemplate = """
        struct {
            __uint (type, BPF_MAP_TYPE_STACK_TRACE);
            __uint (key_size, sizeof(u32));
            __uint (value_size, 127 * sizeof(u64));
            __uint (max_entries, $maxEntries);
        } $field SEC(".maps");
        """,
        javaTemplate = """
        new $class($fd, 127)
        """)
public class BPFStackTraceMap extends BPFMap {

    // -----------------------------------------------------------------------
    // BPF flags for bpf_get_stackid
    // -----------------------------------------------------------------------

    /** Collect a user-space stack instead of a kernel stack. */
    public static final long BPF_F_USER_STACK = 1L << 8;

    /**
     * Reuse an existing stack-trace entry if one with the same hash exists,
     * rather than returning -EEXIST.
     */
    public static final long BPF_F_REUSE_STACKID = 1L << 10;

    /**
     * Default kernel-level depth; stack entries beyond this index are zero.
     * The actual kernel limit can be overridden via
     * {@code /proc/sys/kernel/perf_event_max_stack}.
     */
    public static final int PERF_MAX_STACK_DEPTH = 127;

    private final int maxFrames;

    public BPFStackTraceMap(FileDescriptor fd, int maxFrames) {
        super(MapTypeId.STACK_TRACE, fd);
        this.maxFrames = maxFrames;
    }

    /**
     * Retrieves the stack frames associated with {@code stackId}.
     *
     * <p>Returns a list of instruction-pointer values, innermost frame first,
     * with trailing zero entries removed.  Returns an empty list if the
     * {@code stackId} is not found in the map (e.g. it was evicted by LRU).
     *
     * @param stackId the stack ID returned by {@code bpf_get_stackid}
     */
    public List<Long> get(int stackId) {
        int n = Math.min(maxFrames, PERF_MAX_STACK_DEPTH);
        long stride = (long) n * Long.BYTES;
        try (var arena = Arena.ofConfined()) {
            var keySegment = arena.allocate(4);
            keySegment.set(java.lang.foreign.ValueLayout.JAVA_INT, 0, stackId);
            var valueSegment = arena.allocate(stride);
            var ret = Lib.bpf_map_lookup_elem(fd.fd(), keySegment, valueSegment);
            if (ret != 0) {
                return List.of();
            }
            List<Long> frames = new ArrayList<>(n);
            for (int i = 0; i < n; i++) {
                long ip = valueSegment.get(JAVA_LONG, (long) i * Long.BYTES);
                if (ip == 0L) break;
                frames.add(ip);
            }
            return frames;
        }
    }

    /**
     * Deletes the stack-trace entry with the given {@code stackId}.
     * Returns {@code true} if the entry existed and was removed.
     */
    public boolean delete(int stackId) {
        try (var arena = Arena.ofConfined()) {
            var keySegment = arena.allocate(4);
            keySegment.set(java.lang.foreign.ValueLayout.JAVA_INT, 0, stackId);
            return Lib.bpf_map_delete_elem(fd.fd(), keySegment) == 0;
        }
    }

    /**
     * In BPF programs: records the current call stack and returns an integer
     * stack-ID that can be used later (e.g. stored in a hash map keyed by PID).
     *
     * <p>Corresponds to {@code bpf_get_stackid(ctx, &this, flags)}.
     *
     * <p>Common flag values:
     * <ul>
     *   <li>{@code 0} — capture kernel stack
     *   <li>{@link #BPF_F_USER_STACK} — capture user-space stack
     *   <li>{@link #BPF_F_REUSE_STACKID} — allow hash collisions (reuse existing entry)
     * </ul>
     *
     * @param ctx   the BPF program context (e.g. {@code Ptr<pt_regs>})
     * @param flags combination of {@code BPF_F_*} constants
     * @return non-negative stack ID on success; negative errno on error
     *         ({@code -EEXIST} = hash collision without REUSE flag)
     */
    @BuiltinBPFFunction("bpf_get_stackid($arg1, &$this, $arg2)")
    @NotUsableInJava
    public long bpf_get_stackid(Ptr<?> ctx, @Unsigned long flags) {
        throw new MethodIsBPFRelatedFunction();
    }
}
