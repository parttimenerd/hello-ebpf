package me.bechberger.ebpf.bpf.features;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import static org.junit.jupiter.api.Assertions.*;

@EnabledOnOs(OS.LINUX)
class FeaturesHelperTest {

    @BeforeEach
    void reset() { Features.resetCacheForTest(); }

    @Test
    void ktimeGetNsIsSupported() {
        assertTrue(Features.hasHelper(BPFHelper.KTIME_GET_NS));
    }

    @Test
    void ringbufReserveIsSupported() {
        assertTrue(Features.hasHelper(BPFHelper.RINGBUF_RESERVE));
    }

    @Test
    void loopHelperIsSupportedOn6_14() {
        assertTrue(Features.hasHelper(BPFHelper.LOOP));
    }
}
