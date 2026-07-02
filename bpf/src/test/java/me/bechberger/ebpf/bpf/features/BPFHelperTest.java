package me.bechberger.ebpf.bpf.features;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class BPFHelperTest {
    @Test
    void idsMatchUapi() {
        assertEquals(1,   BPFHelper.MAP_LOOKUP_ELEM.id());
        assertEquals(2,   BPFHelper.MAP_UPDATE_ELEM.id());
        assertEquals(6,   BPFHelper.TRACE_PRINTK.id());
        assertEquals(12,  BPFHelper.TAIL_CALL.id());
        assertEquals(131, BPFHelper.RINGBUF_RESERVE.id());
        assertEquals(132, BPFHelper.RINGBUF_SUBMIT.id());
    }

    @Test
    void everyHelperHasACarrier() {
        for (var h : BPFHelper.values()) {
            assertNotNull(h.carrierProgramType(), "no carrier: " + h);
        }
    }
}
