package me.bechberger.ebpf.bpf.userspace;

import me.bechberger.ebpf.bpf.UserspaceSchedulerBase;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Verifies the pluggable BPF-program-class hook: default is the base, and a subclass override is honored. */
class BpfProgramClassTest {

    /** A scheduler that does not override the hook must load the base transport. */
    static final class DefaultSched extends UserspaceScheduler {
        Class<? extends UserspaceSchedulerBase> exposed() { return bpfProgramClass(); }
    }

    /** A marker subclass standing in for a scheduler that contributes its own BPF code. */
    abstract static class CustomBase extends UserspaceSchedulerBase {}

    static final class CustomSched extends UserspaceScheduler {
        @Override
        protected Class<? extends UserspaceSchedulerBase> bpfProgramClass() {
            return CustomBase.class;
        }
        Class<? extends UserspaceSchedulerBase> exposed() { return bpfProgramClass(); }
    }

    @Test
    void defaultsToBase() {
        assertEquals(UserspaceSchedulerBase.class, new DefaultSched().exposed());
    }

    @Test
    void honorsSubclassOverride() {
        Class<? extends UserspaceSchedulerBase> c = new CustomSched().exposed();
        assertEquals(CustomBase.class, c);
        assertTrue(UserspaceSchedulerBase.class.isAssignableFrom(c));
    }
}
