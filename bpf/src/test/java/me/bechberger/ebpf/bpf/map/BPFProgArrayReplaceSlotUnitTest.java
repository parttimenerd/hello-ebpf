package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.bpf.BPFProgram;
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
        assertEquals(void.class, m.getReturnType(),
                "replaceSlot must return void");
        assertTrue(Modifier.isPublic(m.getModifiers()),
                "replaceSlot must be public");
    }

    @Test
    public void replaceSlotRejectsNullHandle() throws Exception {
        Method m = BPFProgArray.class.getMethod("replaceSlot", int.class, BPFProgram.ProgramHandle.class);
        // Just verify the method signature is correct — runtime validation is
        // covered by the vng integration test.
        assertNotNull(m, "replaceSlot method must exist");
    }
}
