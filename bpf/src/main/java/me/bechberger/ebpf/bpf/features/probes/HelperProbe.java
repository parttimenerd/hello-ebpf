package me.bechberger.ebpf.bpf.features.probes;

import me.bechberger.ebpf.bpf.features.BPFHelper;
import me.bechberger.ebpf.bpf.features.ProbeResult;
import me.bechberger.ebpf.bpf.raw.LibraryLoader;
import me.bechberger.ebpf.shared.PanamaUtil;
import me.bechberger.ebpf.shared.PanamaUtil.HandlerWithErrno;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;

import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * Probe a {@link BPFHelper} by delegating to {@code libbpf_probe_bpf_helper}.
 * libbpf knows the correct three-insn stream and, more importantly, how to
 * distinguish "helper table lookup failed" (unknown) from "verifier rejected
 * placeholder args" (known but wrong args = still supported).
 *
 * <p>Return values: {@code 1 = supported}, {@code 0 = unsupported},
 * negative = -errno.
 */
public final class HelperProbe {

    static { LibraryLoader.load(); }

    private HelperProbe() {}

    static final HandlerWithErrno<Integer> LIBBPF_PROBE_BPF_HELPER =
            new HandlerWithErrno<>("libbpf_probe_bpf_helper",
                    FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT, PanamaUtil.POINTER));

    private static final int EPERM = 1;

    public static ProbeResult probe(BPFHelper h) {
        try (Arena arena = Arena.ofConfined()) {
            ProbeSyscallCounter.increment();
            PanamaUtil.ResultAndErr<Integer> r = LIBBPF_PROBE_BPF_HELPER.call(arena,
                    h.carrierProgramType().id(), h.id(), MemorySegment.NULL);
            int ret = r.result();
            if (ret == 1) return new ProbeResult.Supported();
            if (ret == 0) return new ProbeResult.Unsupported(
                    "libbpf reports helper not supported for " + h.carrierProgramType());
            int err = -ret;
            if (err == EPERM) {
                return new ProbeResult.ProbeUnavailable("missing CAP_BPF or CAP_SYS_ADMIN");
            }
            return new ProbeResult.ProbeUnavailable("libbpf_probe_bpf_helper errno=" + err);
        } catch (Throwable ex) {
            return new ProbeResult.ProbeUnavailable(
                    "libbpf_probe_bpf_helper threw: " + ex.getClass().getSimpleName()
                            + ": " + ex.getMessage());
        }
    }
}
