package me.bechberger.ebpf.bpf.features;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class BPFProgramTypeTest {
    @Test
    void idsMatchUapi() {
        assertEquals(0,  BPFProgramType.UNSPEC.id());
        assertEquals(1,  BPFProgramType.SOCKET_FILTER.id());
        assertEquals(2,  BPFProgramType.KPROBE.id());
        assertEquals(6,  BPFProgramType.XDP.id());
        assertEquals(26, BPFProgramType.TRACING.id());
        assertEquals(27, BPFProgramType.STRUCT_OPS.id());
        assertEquals(29, BPFProgramType.LSM.id());
        assertEquals(31, BPFProgramType.SYSCALL.id());
        assertEquals(32, BPFProgramType.NETFILTER.id());
    }

    @Test
    void fromIdRoundTrip() {
        for (var t : BPFProgramType.values()) {
            assertEquals(t, BPFProgramType.fromId(t.id()));
        }
        assertNull(BPFProgramType.fromId(9999));
    }
}
