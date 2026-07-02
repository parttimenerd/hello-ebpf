package me.bechberger.ebpf.bpf.features.probes;

import me.bechberger.ebpf.bpf.features.BPFAttachType;
import me.bechberger.ebpf.bpf.features.ProbeResult;
import me.bechberger.ebpf.bpf.raw.LibraryLoader;
import me.bechberger.ebpf.shared.LibC;
import me.bechberger.ebpf.shared.PanamaUtil;
import me.bechberger.ebpf.shared.PanamaUtil.HandlerWithErrno;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;

import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * Probe a {@link BPFAttachType} via {@code bpf_link_create} with an invalid
 * target fd. If the kernel accepts the attach type it fails on the bogus fd
 * with EBADF; if the type is unknown it fails with EINVAL first.
 */
public final class AttachTypeProbe {

    static { LibraryLoader.load(); }

    private AttachTypeProbe() {}

    static final HandlerWithErrno<Integer> BPF_LINK_CREATE =
            new HandlerWithErrno<>("bpf_link_create",
                    FunctionDescriptor.of(JAVA_INT,
                            JAVA_INT,
                            JAVA_INT,
                            JAVA_INT,
                            PanamaUtil.POINTER));

    private static final int EBADF  = 9;
    private static final int EINVAL = 22;
    private static final int EPERM  = 1;

    public static ProbeResult probe(BPFAttachType t) {
        try (Arena arena = Arena.ofConfined()) {
            ProbeSyscallCounter.increment();
            PanamaUtil.ResultAndErr<Integer> r = BPF_LINK_CREATE.call(arena,
                    -1,
                    -1,
                    t.id(),
                    MemorySegment.NULL);

            int fd = r.result();
            if (fd >= 0) {
                LibC.close(fd);
                return new ProbeResult.Supported();
            }
            int err = r.err() != 0 ? r.err() : -fd;
            return switch (err) {
                case EBADF  -> new ProbeResult.Supported();
                case EINVAL -> new ProbeResult.Unsupported("unknown attach_type");
                case EPERM  -> new ProbeResult.ProbeUnavailable(
                        "missing CAP_BPF or CAP_SYS_ADMIN");
                default -> new ProbeResult.Unsupported("errno=" + err);
            };
        } catch (Throwable ex) {
            return new ProbeResult.ProbeUnavailable(
                    "bpf_link_create threw: " + ex.getClass().getSimpleName()
                            + ": " + ex.getMessage());
        }
    }
}
