package me.bechberger.ebpf.bpf;

import org.junit.jupiter.api.Test;
import java.lang.reflect.Method;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Guards that {@code setInnerMapFd} is NOT present on {@link BPFProgram}
 * after the BTF {@code __array} migration — the runtime call is vestigial
 * once the C template carries the inner-map reference.
 */
class BPFProgramInnerMapFdTest {
    @Test
    void setInnerMapFdMethodDoesNotExist() {
        boolean found = false;
        for (Method m : BPFProgram.class.getDeclaredMethods()) {
            if ("setInnerMapFd".equals(m.getName())) {
                found = true;
                break;
            }
        }
        assertFalse(found,
                "setInnerMapFd should have been removed after BTF __array migration");
    }
}
