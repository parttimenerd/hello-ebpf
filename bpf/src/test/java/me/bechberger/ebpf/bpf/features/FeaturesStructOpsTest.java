package me.bechberger.ebpf.bpf.features;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import static org.junit.jupiter.api.Assertions.*;

@EnabledOnOs(OS.LINUX)
class FeaturesStructOpsTest {
    @BeforeEach void reset() {
        Features.setDispatcherForTest(null);
        Features.resetCacheForTest();
    }

    @Test
    void schedExtOpsIsSupported() {
        assertTrue(Features.hasStructOps("sched_ext_ops"));
    }

    @Test
    void tcpCongestionOpsIsSupported() {
        assertTrue(Features.hasStructOps("tcp_congestion_ops"));
    }

    @Test
    void unknownStructIsUnsupported() {
        assertFalse(Features.hasStructOps("never_a_struct_zzz"));
    }
}
