package me.bechberger.ebpf.bpf.features;

import me.bechberger.ebpf.bpf.features.probes.ProbeSyscallCounter;
import me.bechberger.ebpf.bpf.map.MapTypeId;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Real-kernel umbrella that exercises the dispatcher wired in Task 15.
 * Runs under vng on thinkstation.
 */
@EnabledOnOs(OS.LINUX)
class FeaturesProbeTest {

    @BeforeEach
    void reset() {
        Features.resetCacheForTest();
        ProbeSyscallCounter.reset();
    }

    @Test
    void cacheHitAvoidsSecondSyscall() {
        Features.probeProgramType(BPFProgramType.XDP);
        long after1 = ProbeSyscallCounter.value();
        assertEquals(1, after1);
        Features.probeProgramType(BPFProgramType.XDP);
        assertEquals(after1, ProbeSyscallCounter.value(),
                "second call must hit the cache");
    }

    @Test
    void kernelVersionAtLeast6_14() {
        KernelVersion v = Features.kernelVersion();
        assertTrue(v.atLeast(6, 14),
                "kernel floor is 6.14, got " + v.raw());
    }

    @Test
    void snapshotContainsWellKnownEntries() {
        var snap = Features.snapshot();
        assertTrue(snap.get("prog:XDP") instanceof ProbeResult.Supported);
        assertTrue(snap.get("map:HASH") instanceof ProbeResult.Supported);
        assertTrue(snap.get("helper:KTIME_GET_NS") instanceof ProbeResult.Supported);
        assertTrue(snap.get("attach:TCX_INGRESS") instanceof ProbeResult.Supported);
        assertThrows(UnsupportedOperationException.class,
                () -> snap.put("x", new ProbeResult.Supported()));
    }

    @Test
    void mapTypeArenaSupported() {
        assertTrue(Features.hasMapType(MapTypeId.ARENA));
    }
}
