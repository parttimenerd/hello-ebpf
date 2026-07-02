package me.bechberger.ebpf.bpf.features;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class KernelVersionTest {
    @Test
    void parsesTripleWithSuffix() {
        var v = KernelVersion.parse("6.17.0-35-generic");
        assertEquals(6, v.major());
        assertEquals(17, v.minor());
        assertEquals(0, v.patch());
        assertEquals("6.17.0-35-generic", v.raw());
    }

    @Test
    void parsesBareTriple() {
        var v = KernelVersion.parse("6.14.3");
        assertEquals(new KernelVersion(6, 14, 3, "6.14.3"), v);
    }

    @Test
    void parsesTwoPartFallsBackToZero() {
        var v = KernelVersion.parse("6.14");
        assertEquals(new KernelVersion(6, 14, 0, "6.14"), v);
    }

    @Test
    void atLeastMajorMinor() {
        var v = new KernelVersion(6, 17, 0, "6.17.0");
        assertTrue(v.atLeast(6, 14));
        assertTrue(v.atLeast(6, 17));
        assertFalse(v.atLeast(6, 18));
        assertFalse(v.atLeast(7, 0));
        assertTrue(v.atLeast(5, 99));
    }

    @Test
    void malformedRaisesIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> KernelVersion.parse(""));
        assertThrows(IllegalArgumentException.class, () -> KernelVersion.parse("abc"));
    }
}
