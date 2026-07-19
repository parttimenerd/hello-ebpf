package me.bechberger.ebpf.bpf.features;

import me.bechberger.ebpf.bpf.BPFProgram;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class FeatureGatedLoadTest {

    @BeforeEach
    void resetFeatures() {
        Features.resetCacheForTest();
        Features.setDispatcherForTest(key -> {
            if (key instanceof ProbeKey.KfuncKey k
                    && "bpf_never_existed".equals(k.name())) {
                return new ProbeResult.Unsupported("simulated");
            }
            return new ProbeResult.Supported();
        });
    }

    @AfterEach
    void restoreFeatures() {
        Features.setDispatcherForTest(null);
        Features.resetCacheForTest();
    }

    @Test
    void enforceMissingKfuncThrowsBeforeConstructor() {
        var req = new FeatureRequirements.Builder()
                .programName("FakeMissingKfuncProgram")
                .kfunc("bpf_never_existed")
                .build();
        var ex = assertThrows(BPFProgram.BPFLoadError.MissingKfunc.class,
                () -> FeatureRequirements.enforce(req));
        assertTrue(ex.getMessage().contains("bpf_never_existed"));
        assertTrue(ex.getMessage().contains("FakeMissingKfuncProgram"));
    }
}
