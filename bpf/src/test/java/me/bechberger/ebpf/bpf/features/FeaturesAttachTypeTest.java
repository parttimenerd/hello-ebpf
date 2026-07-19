package me.bechberger.ebpf.bpf.features;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import static org.junit.jupiter.api.Assertions.*;

@EnabledOnOs(OS.LINUX)
class FeaturesAttachTypeTest {

    @BeforeEach
    void reset() {
        Features.setDispatcherForTest(null);
        Features.resetCacheForTest();
    }

    @Test
    void kprobeMultiIsSupportedOn6_14() {
        assertTrue(Features.hasAttachType(BPFAttachType.TRACE_KPROBE_MULTI));
    }

    @Test
    void tcxIngressIsSupportedOn6_14() {
        assertTrue(Features.hasAttachType(BPFAttachType.TCX_INGRESS));
    }

    @Test
    void uprobeMultiIsSupportedOn6_14() {
        assertTrue(Features.hasAttachType(BPFAttachType.TRACE_UPROBE_MULTI));
    }
}
