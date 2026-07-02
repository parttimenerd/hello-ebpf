package me.bechberger.ebpf.bpf.features.probes;

import me.bechberger.ebpf.bpf.features.BPFProgramType;
import me.bechberger.ebpf.bpf.features.ProbeResult;
import me.bechberger.ebpf.bpf.raw.LibraryLoader;
import me.bechberger.ebpf.shared.LibC;
import me.bechberger.ebpf.shared.PanamaUtil;
import me.bechberger.ebpf.shared.PanamaUtil.HandlerWithErrno;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

/**
 * Probe a {@link BPFProgramType} by attempting to load a two-instruction
 * "return 0" program of that type via {@code bpf_prog_load}.
 *
 * <p>Errno mapping follows spec §6.1:
 * <ul>
 *   <li>0 / fd -> Supported</li>
 *   <li>EINVAL -> Unsupported</li>
 *   <li>E2BIG -> Supported (features hit; only the program size was rejected)</li>
 *   <li>EPERM -> ProbeUnavailable</li>
 *   <li>otherwise -> Unsupported("errno=" + n)</li>
 * </ul>
 */
public final class ProgramTypeProbe {

    static { LibraryLoader.load(); }

    private ProgramTypeProbe() {}

    static final HandlerWithErrno<Integer> BPF_PROG_LOAD =
            new HandlerWithErrno<>("bpf_prog_load",
                    FunctionDescriptor.of(JAVA_INT,
                            JAVA_INT,
                            PanamaUtil.POINTER,
                            PanamaUtil.POINTER,
                            PanamaUtil.POINTER,
                            JAVA_LONG,
                            PanamaUtil.POINTER));

    private static final byte[] INSNS_RETURN0 = new byte[] {
            (byte) 0xB7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            (byte) 0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    private static final String LICENSE_GPL = "GPL";

    private static final int EINVAL = 22;
    private static final int EPERM  = 1;
    private static final int E2BIG  = 7;

    public static ProbeResult probe(BPFProgramType type) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment insns = arena.allocate(INSNS_RETURN0.length);
            MemorySegment.copy(INSNS_RETURN0, 0, insns, JAVA_BYTE, 0, INSNS_RETURN0.length);
            MemorySegment license = arena.allocateFrom(LICENSE_GPL);

            ProbeSyscallCounter.increment();
            PanamaUtil.ResultAndErr<Integer> r = BPF_PROG_LOAD.call(arena,
                    type.id(),
                    MemorySegment.NULL,
                    license,
                    insns,
                    (long) (INSNS_RETURN0.length / 8),
                    MemorySegment.NULL);

            int fd = r.result();
            if (fd >= 0) {
                LibC.close(fd);
                return new ProbeResult.Supported();
            }

            int err = r.err() != 0 ? r.err() : -fd;
            return switch (err) {
                case EINVAL -> new ProbeResult.Unsupported("unknown prog_type");
                case E2BIG  -> new ProbeResult.Supported();
                case EPERM  -> new ProbeResult.ProbeUnavailable(
                        "missing CAP_BPF or CAP_SYS_ADMIN");
                default -> new ProbeResult.Unsupported("errno=" + err);
            };
        } catch (Throwable t) {
            return new ProbeResult.ProbeUnavailable(
                    "bpf_prog_load threw: " + t.getClass().getSimpleName()
                            + ": " + t.getMessage());
        }
    }
}
