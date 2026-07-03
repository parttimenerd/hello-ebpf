package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.bpf.map.BPFArrayOfMaps;
import me.bechberger.ebpf.bpf.map.MapTypeId;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** JVM-only guard rails for the BPFArrayOfMaps wrapper. Real-kernel behaviour
 *  is covered by {@code ArrayOfMapsSmokeTest} under vng. */
class ArrayOfMapsTest {

    @Test
    void mapTypeIdIsArrayOfMaps() {
        assertEquals(12, MapTypeId.ARRAY_OF_MAPS.getId());
    }

    @Test
    void nullFdRejected() {
        assertThrows(NullPointerException.class,
                () -> new BPFArrayOfMaps<>(null, 8));
    }
}
