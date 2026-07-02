package me.bechberger.ebpf.bpf.features.probes;

import me.bechberger.ebpf.bpf.features.ProbeResult;
import me.bechberger.ebpf.bpf.map.MapTypeId;
import me.bechberger.ebpf.shared.LibC;
import me.bechberger.ebpf.shared.PanamaUtil;
import me.bechberger.ebpf.shared.PanamaUtil.HandlerWithErrno;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;

import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * Probe a {@link MapTypeId} by attempting {@code bpf_map_create} with
 * per-kind-appropriate key/value sizes and a single entry.
 */
public final class MapTypeProbe {

    private MapTypeProbe() {}

    static final HandlerWithErrno<Integer> BPF_MAP_CREATE =
            new HandlerWithErrno<>("bpf_map_create",
                    FunctionDescriptor.of(JAVA_INT,
                            JAVA_INT,
                            PanamaUtil.POINTER,
                            JAVA_INT,
                            JAVA_INT,
                            JAVA_INT,
                            PanamaUtil.POINTER));

    private static final int EINVAL = 22;
    private static final int EPERM  = 1;
    private static final int E2BIG  = 7;
    private static final int ENOTSUPP = 524;

    private record Shape(int keySize, int valueSize, int maxEntries) {}

    private static Shape shapeFor(MapTypeId t) {
        return switch (t) {
            case QUEUE, STACK             -> new Shape(0, 4, 1);
            case RINGBUF, USER_RINGBUF    -> new Shape(0, 0, 4096);
            case ARENA                    -> new Shape(0, 0, 1);
            case STACK_TRACE              -> new Shape(4, 8, 1);
            case LPM_TRIE                 -> new Shape(8, 4, 1);
            case ARRAY_OF_MAPS, HASH_OF_MAPS,
                 PROG_ARRAY, PERF_EVENT_ARRAY,
                 CGROUP_ARRAY, SOCKMAP,
                 SOCKHASH, DEVMAP, DEVMAP_HASH,
                 CPUMAP, XSKMAP,
                 REUSEPORT_SOCKARRAY,
                 SK_STORAGE, INODE_STORAGE,
                 TASK_STORAGE             -> new Shape(4, 4, 1);
            case PERCPU_HASH, PERCPU_ARRAY,
                 LRU_PERCPU_HASH, PERCPU_CGROUP_STORAGE
                                          -> new Shape(4, 8, 1);
            case BLOOM_FILTER             -> new Shape(0, 4, 1);
            case STRUCT_OPS               -> new Shape(4, 8, 1);
            default                       -> new Shape(4, 4, 1);
        };
    }

    public static ProbeResult probe(MapTypeId t) {
        Shape s = shapeFor(t);
        try (Arena arena = Arena.ofConfined()) {
            ProbeSyscallCounter.increment();
            PanamaUtil.ResultAndErr<Integer> r = BPF_MAP_CREATE.call(arena,
                    t.getId(),
                    MemorySegment.NULL,
                    s.keySize(),
                    s.valueSize(),
                    s.maxEntries(),
                    MemorySegment.NULL);

            int fd = r.result();
            if (fd >= 0) {
                LibC.close(fd);
                return new ProbeResult.Supported();
            }
            int err = r.err() != 0 ? r.err() : -fd;
            return switch (err) {
                case EINVAL   -> new ProbeResult.Unsupported("unknown map_type");
                case E2BIG    -> new ProbeResult.Supported();
                case ENOTSUPP -> new ProbeResult.Unsupported("not implemented (ENOTSUPP)");
                case EPERM    -> new ProbeResult.ProbeUnavailable(
                        "missing CAP_BPF or CAP_SYS_ADMIN");
                default -> new ProbeResult.Unsupported("errno=" + err);
            };
        } catch (Throwable t2) {
            return new ProbeResult.ProbeUnavailable(
                    "bpf_map_create threw: " + t2.getClass().getSimpleName()
                            + ": " + t2.getMessage());
        }
    }
}
