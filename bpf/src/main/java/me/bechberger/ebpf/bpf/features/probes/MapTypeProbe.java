package me.bechberger.ebpf.bpf.features.probes;

import me.bechberger.ebpf.bpf.features.ProbeResult;
import me.bechberger.ebpf.bpf.map.MapTypeId;
import me.bechberger.ebpf.bpf.raw.LibraryLoader;
import me.bechberger.ebpf.shared.PanamaUtil;
import me.bechberger.ebpf.shared.PanamaUtil.HandlerWithErrno;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;

import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * Probe a {@link MapTypeId} by delegating to {@code libbpf_probe_bpf_map_type}.
 * libbpf 1.6+ knows the per-kind shape constraints (arena needs
 * {@code BPF_F_MMAPABLE}, ringbuf needs key=value=0, etc.), so mirroring them
 * here is redundant and error-prone.
 *
 * <p>Return values: {@code 1 = supported}, {@code 0 = unsupported},
 * negative = -errno.
 */
public final class MapTypeProbe {

    static { LibraryLoader.load(); }

    private MapTypeProbe() {}

    static final HandlerWithErrno<Integer> LIBBPF_PROBE_BPF_MAP_TYPE =
            new HandlerWithErrno<>("libbpf_probe_bpf_map_type",
                    FunctionDescriptor.of(JAVA_INT, JAVA_INT, PanamaUtil.POINTER));

    private static final int EPERM = 1;

    public static ProbeResult probe(MapTypeId t) {
        try (Arena arena = Arena.ofConfined()) {
            ProbeSyscallCounter.increment();
            PanamaUtil.ResultAndErr<Integer> r =
                    LIBBPF_PROBE_BPF_MAP_TYPE.call(arena, t.getId(), MemorySegment.NULL);
            int ret = r.result();
            if (ret == 1) return new ProbeResult.Supported();
            if (ret == 0) return new ProbeResult.Unsupported("libbpf reports map_type not supported");
            int err = -ret;
            if (err == EPERM) {
                return new ProbeResult.ProbeUnavailable("missing CAP_BPF or CAP_SYS_ADMIN");
            }
            return new ProbeResult.ProbeUnavailable("libbpf_probe_bpf_map_type errno=" + err);
        } catch (Throwable ex) {
            return new ProbeResult.ProbeUnavailable(
                    "libbpf_probe_bpf_map_type threw: " + ex.getClass().getSimpleName()
                            + ": " + ex.getMessage());
        }
    }
}
