package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.bpf.map.BPFHashOfMaps;
import me.bechberger.ebpf.bpf.map.MapTypeId;
import me.bechberger.ebpf.type.BPFType.BPFIntType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** JVM-only guard rails for the BPFHashOfMaps wrapper. Real-kernel behaviour
 *  is covered by {@code PerCpuInnerMapSampleTest} under vng. */
class HashOfMapsTest {

    @Test
    void mapTypeIdIsHashOfMaps() {
        // Reflection-safe check without touching the kernel.
        assertEquals(13, MapTypeId.HASH_OF_MAPS.getId());
    }

    @Test
    void nullFdRejected() {
        assertThrows(NullPointerException.class,
                () -> new BPFHashOfMaps<>(null, BPFIntType.UINT32));
    }
}
