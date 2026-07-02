package me.bechberger.ebpf.bpf.features;

import me.bechberger.ebpf.bpf.map.MapTypeId;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import static org.junit.jupiter.api.Assertions.*;

@EnabledOnOs(OS.LINUX)
class FeaturesMapTypeTest {

    @BeforeEach
    void reset() { Features.resetCacheForTest(); }

    @Test
    void hashIsSupported() {
        assertTrue(Features.hasMapType(MapTypeId.HASH));
    }

    @Test
    void arrayIsSupported() {
        assertTrue(Features.hasMapType(MapTypeId.ARRAY));
    }

    @Test
    void ringbufIsSupportedOn6_14() {
        assertTrue(Features.hasMapType(MapTypeId.RINGBUF));
    }

    @Test
    void arenaIsSupportedOn6_17() {
        assertTrue(Features.hasMapType(MapTypeId.ARENA));
    }
}
