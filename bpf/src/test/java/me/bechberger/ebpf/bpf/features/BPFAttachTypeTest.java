package me.bechberger.ebpf.bpf.features;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class BPFAttachTypeTest {
    @Test
    void idsMatchUapi() {
        assertEquals(0,  BPFAttachType.CGROUP_INET_INGRESS.id());
        assertEquals(1,  BPFAttachType.CGROUP_INET_EGRESS.id());
        assertEquals(24, BPFAttachType.TRACE_FENTRY.id());
        assertEquals(25, BPFAttachType.TRACE_FEXIT.id());
        assertEquals(42, BPFAttachType.TRACE_KPROBE_MULTI.id());
        assertEquals(46, BPFAttachType.TCX_INGRESS.id());
        assertEquals(47, BPFAttachType.TCX_EGRESS.id());
    }

    @Test
    void fromIdRoundTrip() {
        for (var t : BPFAttachType.values()) {
            assertEquals(t, BPFAttachType.fromId(t.id()));
        }
        assertNull(BPFAttachType.fromId(9999));
    }
}
