package me.bechberger.ebpf.bpf.features;

import me.bechberger.ebpf.bpf.features.probes.ProbeSyscallCounter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class FeaturesCacheTest {

    @BeforeEach
    void reset() {
        Features.resetCacheForTest();
        ProbeSyscallCounter.reset();
        Features.setDispatcherForTest(new StubDispatcher());
    }

    @AfterEach
    void restore() {
        Features.setDispatcherForTest(null);
        Features.resetCacheForTest();
    }

    @Test
    void firstCallInvokesDispatcher() {
        assertEquals(0, ProbeSyscallCounter.value());
        assertTrue(Features.hasProgramType(BPFProgramType.XDP));
        assertEquals(1, ProbeSyscallCounter.value());
    }

    @Test
    void secondCallHitsCache() {
        Features.hasProgramType(BPFProgramType.XDP);
        long after1 = ProbeSyscallCounter.value();
        Features.hasProgramType(BPFProgramType.XDP);
        assertEquals(after1, ProbeSyscallCounter.value(), "cache did not hit");
    }

    @Test
    void resetCacheForTestClears() {
        Features.hasProgramType(BPFProgramType.XDP);
        Features.resetCacheForTest();
        ProbeSyscallCounter.reset();
        Features.hasProgramType(BPFProgramType.XDP);
        assertEquals(1, ProbeSyscallCounter.value());
    }

    @Test
    void probeReturnsSameInstanceOnHit() {
        ProbeResult a = Features.probeProgramType(BPFProgramType.XDP);
        ProbeResult b = Features.probeProgramType(BPFProgramType.XDP);
        assertSame(a, b);
    }

    static class StubDispatcher implements Features.Dispatcher {
        @Override public ProbeResult probe(ProbeKey key) {
            ProbeSyscallCounter.increment();
            return new ProbeResult.Supported();
        }
    }
}
