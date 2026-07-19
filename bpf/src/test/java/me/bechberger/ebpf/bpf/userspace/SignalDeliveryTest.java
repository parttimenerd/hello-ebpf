package me.bechberger.ebpf.bpf.userspace;

import org.junit.jupiter.api.Test;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SignalDeliveryTest {

    static class TestSched extends UserspaceScheduler {
        final List<Signal> seen = new ArrayList<>();
        final List<MemorySegment> pending = new ArrayList<>();

        @Override protected void onSignal(Signal s) { seen.add(s); }

        @Override protected int drainSignalsRaw(java.util.function.Consumer<MemorySegment> sink) {
            int n = 0;
            for (MemorySegment seg : pending) { sink.accept(seg); n++; }
            pending.clear();
            return n;
        }
    }

    private MemorySegment sig(Arena a, int kind, int pid, long payload, long ts) {
        MemorySegment s = a.allocate(24);
        s.set(ValueLayout.JAVA_INT,  0,  kind);
        s.set(ValueLayout.JAVA_INT,  4,  pid);
        s.set(ValueLayout.JAVA_LONG, 8,  payload);
        s.set(ValueLayout.JAVA_LONG, 16, ts);
        return s;
    }

    @Test
    void signalsDeliveredInOrder() {
        try (Arena a = Arena.ofConfined()) {
            TestSched sched = new TestSched();
            sched.pending.add(sig(a, Signal.SignalKind.CPU_IDLE, 10, 0, 100));
            sched.pending.add(sig(a, 1000, 20, 42, 200));

            sched.drainSignalsOnce();

            assertEquals(2, sched.seen.size());
            assertEquals(Signal.SignalKind.CPU_IDLE, sched.seen.get(0).kind());
            assertEquals(10, sched.seen.get(0).pid());
            assertEquals(1000, sched.seen.get(1).kind());
            assertEquals(42, sched.seen.get(1).payload());
        }
    }
}
