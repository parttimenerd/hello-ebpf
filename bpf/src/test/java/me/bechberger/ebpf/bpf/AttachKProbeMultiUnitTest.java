package me.bechberger.ebpf.bpf;

import org.junit.jupiter.api.Test;
import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.*;

class AttachKProbeMultiUnitTest {

    @Test
    void attachKProbeMultiIsPublicWithExpectedSignature() throws NoSuchMethodException {
        Method m = BPFProgram.class.getMethod("attachKProbeMulti",
                BPFProgram.ProgramHandle.class, String[].class, long[].class, boolean.class);
        assertEquals(BPFProgram.BPFLink.class, m.getReturnType());
        assertTrue(java.lang.reflect.Modifier.isPublic(m.getModifiers()));
    }

    @Test
    void attachKProbeMultiRejectsLengthMismatch() {
        assertThrows(IllegalArgumentException.class,
                () -> BPFProgram.validateMultiArrays(
                        new String[]{"a", "b"}, new long[]{1L}));
    }
}
