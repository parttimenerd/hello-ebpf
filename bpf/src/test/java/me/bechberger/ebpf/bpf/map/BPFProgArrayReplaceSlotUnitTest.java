package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.bpf.BPFError;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.features.BPFProgramType;
import me.bechberger.ebpf.bpf.features.Features;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JVM-only sanity coverage of {@link BPFProgArray#replaceSlot}'s API surface.
 * Precondition and kernel-side behaviour are exercised end-to-end by the vng
 * test {@code bpf/src/test/java/me/bechberger/ebpf/bpf/TailCallReplaceSlotTest.java};
 * this test just guards against accidental signature drift.
 */
public class BPFProgArrayReplaceSlotUnitTest {

    @Test
    public void replaceSlotMethodExists() throws NoSuchMethodException {
        Method m = BPFProgArray.class.getMethod("replaceSlot", int.class, BPFProgram.ProgramHandle.class);
        assertEquals(BPFProgram.BPFLink.class, m.getReturnType(),
                "replaceSlot must return BPFLink to keep the freplace attachment alive");
        assertTrue(Modifier.isPublic(m.getModifiers()),
                "replaceSlot must be public");
    }

    @Test
    public void extProgramTypeIsAvailable() {
        // BPF_PROG_TYPE_EXT was added in kernel 5.10 and is the feature gate for
        // replaceSlot(). If the enum constant is renamed or removed, replaceSlot's
        // feature check will silently break.
        assertEquals(28, BPFProgramType.EXT.id(),
                "BPFProgramType.EXT should have id 28 (BPF_PROG_TYPE_EXT)");
    }

    @Test
    public void hasProgramTypeIsCallable() {
        // Just checking Features.hasProgramType(EXT) is callable — probing may
        // or may not succeed in this environment; we don't assert the result.
        try {
            Features.hasProgramType(BPFProgramType.EXT);
        } catch (Throwable t) {
            // Acceptable: probing needs kernel; we only care the API is present.
        }
    }
}
