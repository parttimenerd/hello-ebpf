package me.bechberger.ebpf.bpf;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class BPFProgramInnerMapFdTest {
    @Test
    void setInnerMapFdMethodExists() throws Exception {
        var m = BPFProgram.class.getDeclaredMethod(
                "setInnerMapFd", String.class, String.class);
        assertNotNull(m);
        // Confirm it's protected and callable from generated impl-class.
        assertTrue(java.lang.reflect.Modifier.isProtected(m.getModifiers())
                || java.lang.reflect.Modifier.isPublic(m.getModifiers()));
    }
}
