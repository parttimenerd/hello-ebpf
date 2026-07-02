package me.bechberger.ebpf.bpf.features;

import me.bechberger.ebpf.bpf.map.MapTypeId;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ProbeKeyTest {
    @Test
    void equalityHonoursDiscriminant() {
        ProbeKey a = new ProbeKey.ProgramTypeKey(BPFProgramType.XDP);
        ProbeKey b = new ProbeKey.ProgramTypeKey(BPFProgramType.XDP);
        ProbeKey c = new ProbeKey.ProgramTypeKey(BPFProgramType.KPROBE);
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
        assertNotEquals(a, c);
    }

    @Test
    void kfuncKeyIncludesModuleName() {
        ProbeKey a = new ProbeKey.KfuncKey("f", null);
        ProbeKey b = new ProbeKey.KfuncKey("f", null);
        ProbeKey c = new ProbeKey.KfuncKey("f", "mymod");
        assertEquals(a, b);
        assertNotEquals(a, c);
    }

    @Test
    void differentVariantsNeverEqual() {
        assertNotEquals(
            new ProbeKey.ProgramTypeKey(BPFProgramType.XDP),
            new ProbeKey.MapTypeKey(MapTypeId.HASH));
    }
}
