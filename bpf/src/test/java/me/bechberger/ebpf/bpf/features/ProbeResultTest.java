package me.bechberger.ebpf.bpf.features;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ProbeResultTest {
    @Test
    void patternMatchExhaustive() {
        ProbeResult r = new ProbeResult.Supported();
        String s = switch (r) {
            case ProbeResult.Supported() -> "yes";
            case ProbeResult.Unsupported u -> "no: " + u.reason();
            case ProbeResult.ProbeUnavailable u -> "cannot: " + u.reason();
        };
        assertEquals("yes", s);
    }

    @Test
    void isSupportedHelper() {
        assertTrue(new ProbeResult.Supported().isSupported());
        assertFalse(new ProbeResult.Unsupported("nope").isSupported());
        assertFalse(new ProbeResult.ProbeUnavailable("EPERM").isSupported());
    }
}
