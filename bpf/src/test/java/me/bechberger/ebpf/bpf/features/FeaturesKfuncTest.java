package me.bechberger.ebpf.bpf.features;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import static org.junit.jupiter.api.Assertions.*;

@EnabledOnOs(OS.LINUX)
class FeaturesKfuncTest {
    @BeforeEach void reset() {
        Features.setDispatcherForTest(null);
        Features.resetCacheForTest();
    }

    @Test
    void knownKfuncIsSupported() {
        assertTrue(Features.hasKfunc("bpf_arena_alloc_pages"));
    }

    @Test
    void unknownKfuncIsUnsupported() {
        assertFalse(Features.hasKfunc("bpf_never_existed_zzz"));
        var r = Features.probeKfunc("bpf_never_existed_zzz", null);
        assertInstanceOf(ProbeResult.Unsupported.class, r);
    }
}
