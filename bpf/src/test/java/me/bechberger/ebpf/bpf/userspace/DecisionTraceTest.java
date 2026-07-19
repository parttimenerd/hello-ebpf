package me.bechberger.ebpf.bpf.userspace;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DecisionTraceTest {

    @Test
    void recordsAndSnapshots() {
        var trace = new DecisionTrace(4);
        trace.record(1000, 10, 3, DecisionTrace.Kind.DISPATCH, 0);
        trace.record(1001, 11, 4, DecisionTrace.Kind.PREEMPT, 7);

        List<DecisionTrace.TraceEntry> recent = trace.recentDecisions();
        assertEquals(2, recent.size());
        assertEquals(10, recent.get(0).pid());
        assertEquals(DecisionTrace.Kind.DISPATCH, recent.get(0).kind());
        assertEquals(7, recent.get(1).reason());
        assertEquals(DecisionTrace.Kind.PREEMPT, recent.get(1).kind());
    }

    @Test
    void wrapsAndKeepsMostRecentN() {
        var trace = new DecisionTrace(3);
        for (int i = 0; i < 5; i++) {
            trace.record(1000 + i, i, 0, DecisionTrace.Kind.DISPATCH, 0);
        }
        List<DecisionTrace.TraceEntry> recent = trace.recentDecisions();
        assertEquals(3, recent.size(), "capacity bounds the ring");
        assertEquals(List.of(2, 3, 4), recent.stream().map(DecisionTrace.TraceEntry::pid).toList());
    }

    @Test
    void reasonRoundTrips() {
        var trace = new DecisionTrace(2);
        trace.record(1, 1, 0, DecisionTrace.Kind.KICK, 42);
        assertEquals(42, trace.recentDecisions().get(0).reason());
    }

    @Test
    void zeroCapacityIsDisabled() {
        var trace = new DecisionTrace(0);
        trace.record(1, 1, 0, DecisionTrace.Kind.DISPATCH, 0);
        assertTrue(trace.recentDecisions().isEmpty(), "capacity 0 records nothing");
    }
}
