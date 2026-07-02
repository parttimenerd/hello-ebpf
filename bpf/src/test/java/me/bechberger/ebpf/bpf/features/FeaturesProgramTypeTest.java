package me.bechberger.ebpf.bpf.features;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import static org.junit.jupiter.api.Assertions.*;

@EnabledOnOs(OS.LINUX)
class FeaturesProgramTypeTest {

    @BeforeEach
    void reset() {
        Features.resetCacheForTest();
        Features.setDispatcherForTest(null);
        me.bechberger.ebpf.bpf.features.probes.ProbeSyscallCounter.reset();
    }

    @Test
    void xdpIsSupportedOn6_14Plus() {
        var r = Features.probeProgramType(BPFProgramType.XDP);
        assertInstanceOf(ProbeResult.Supported.class, r, "XDP must be supported: " + r);
    }

    @Test
    void kprobeIsSupported() {
        assertTrue(Features.hasProgramType(BPFProgramType.KPROBE));
    }

    @Test
    void unspecIsUnsupported() {
        var r = Features.probeProgramType(BPFProgramType.UNSPEC);
        assertInstanceOf(ProbeResult.Unsupported.class, r);
    }
}
