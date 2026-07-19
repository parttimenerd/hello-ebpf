package me.bechberger.ebpf.bpf.userspace;

import me.bechberger.ebpf.bpf.UserspaceSchedulerBase;
import org.junit.jupiter.api.Test;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** Pins the ControlCtx and SignalCtx wire layouts bit-for-bit. */
class ControlDispatchedMarshallingTest {

    @Test
    void controlCtxLayout() {
        assertEquals(0,  UserspaceSchedulerBase.CTL_KIND);
        assertEquals(4,  UserspaceSchedulerBase.CTL_CPU);
        assertEquals(8,  UserspaceSchedulerBase.CTL_PID);
        assertEquals(16, UserspaceSchedulerBase.CTL_FLAGS);
        assertEquals(24, UserspaceSchedulerBase.CTL_SIZEOF);
    }

    @Test
    void controlCtxRoundTrip() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment seg = arena.allocate(UserspaceSchedulerBase.CTL_SIZEOF);
            seg.set(ValueLayout.JAVA_INT,  UserspaceSchedulerBase.CTL_KIND,  ControlKind.PREEMPT);
            seg.set(ValueLayout.JAVA_INT,  UserspaceSchedulerBase.CTL_CPU,   3);
            seg.set(ValueLayout.JAVA_INT,  UserspaceSchedulerBase.CTL_PID,   4242);
            seg.set(ValueLayout.JAVA_LONG, UserspaceSchedulerBase.CTL_FLAGS, 0L);

            assertEquals(ControlKind.PREEMPT, seg.get(ValueLayout.JAVA_INT,  UserspaceSchedulerBase.CTL_KIND));
            assertEquals(3,    seg.get(ValueLayout.JAVA_INT,  UserspaceSchedulerBase.CTL_CPU));
            assertEquals(4242, seg.get(ValueLayout.JAVA_INT,  UserspaceSchedulerBase.CTL_PID));
            assertEquals(0L,   seg.get(ValueLayout.JAVA_LONG, UserspaceSchedulerBase.CTL_FLAGS));
        }
    }

    @Test
    void signalCtxLayout() {
        assertEquals(0,  UserspaceSchedulerBase.SIG_KIND);
        assertEquals(4,  UserspaceSchedulerBase.SIG_PID);
        assertEquals(8,  UserspaceSchedulerBase.SIG_PAYLOAD);
        assertEquals(16, UserspaceSchedulerBase.SIG_TS);
        assertEquals(24, UserspaceSchedulerBase.SIG_SIZEOF);
    }
}
