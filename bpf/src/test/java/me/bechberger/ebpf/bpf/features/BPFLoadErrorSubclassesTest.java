package me.bechberger.ebpf.bpf.features;

import me.bechberger.ebpf.bpf.BPFProgram;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class BPFLoadErrorSubclassesTest {

    @Test
    void unsupportedKernelMessageIncludesFeatureAndSince() {
        var e = new BPFProgram.BPFLoadError.UnsupportedKernel("attach_type TCX_INGRESS", "6.6");
        assertTrue(e.getMessage().contains("TCX_INGRESS"));
        assertTrue(e.getMessage().contains("6.6"));
        assertInstanceOf(BPFProgram.BPFLoadError.class, e);
    }

    @Test
    void missingKfuncCarriesNameAndProgram() {
        var e = new BPFProgram.BPFLoadError.MissingKfunc("bpf_never_existed", "myProgram");
        assertTrue(e.getMessage().contains("bpf_never_existed"));
        assertTrue(e.getMessage().contains("myProgram"));
        assertInstanceOf(BPFProgram.BPFLoadError.class, e);
    }
}
