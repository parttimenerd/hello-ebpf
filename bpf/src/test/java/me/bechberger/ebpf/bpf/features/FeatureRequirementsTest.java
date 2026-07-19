package me.bechberger.ebpf.bpf.features;

import me.bechberger.ebpf.bpf.BPFProgram;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class FeatureRequirementsTest {

    @BeforeEach
    void reset() {
        Features.resetCacheForTest();
        Features.setDispatcherForTest(key -> {
            if (key instanceof ProbeKey.HelperKey h && h.h() == BPFHelper.LOOP) {
                return new ProbeResult.Unsupported("simulated");
            }
            if (key instanceof ProbeKey.KfuncKey k
                    && k.name().equals("bpf_never_existed")) {
                return new ProbeResult.Unsupported("simulated");
            }
            return new ProbeResult.Supported();
        });
    }

    @AfterEach
    void restore() {
        Features.setDispatcherForTest(null);
        Features.resetCacheForTest();
    }

    @Test
    void enforceMissingKfuncThrowsMissingKfunc() {
        var req = new FeatureRequirements.Builder()
                .programName("myProg")
                .kfunc("bpf_never_existed")
                .build();
        var ex = assertThrows(BPFProgram.BPFLoadError.MissingKfunc.class,
                () -> FeatureRequirements.enforce(req));
        assertTrue(ex.getMessage().contains("bpf_never_existed"));
        assertTrue(ex.getMessage().contains("myProg"));
    }

    @Test
    void enforceMissingHelperThrowsUnsupportedKernel() {
        var req = new FeatureRequirements.Builder()
                .programName("myProg")
                .helper(BPFHelper.LOOP, "5.17")
                .build();
        assertThrows(BPFProgram.BPFLoadError.UnsupportedKernel.class,
                () -> FeatureRequirements.enforce(req));
    }

    @Test
    void enforceEmptyRequirementsIsNoop() {
        FeatureRequirements.enforce(new FeatureRequirements.Builder().build());
    }
}
