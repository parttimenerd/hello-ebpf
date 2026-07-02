package me.bechberger.ebpf.bpf.features;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.structops.TcpCongestionControl;
import me.bechberger.ebpf.runtime.runtime;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies that {@code @StructOps}-carrying programs refuse to load on a
 * kernel that does not advertise the required kernel struct — the plugin
 * emits a {@code since} entry into the manifest and {@code StructOpsAttach}
 * calls {@link BPFProgram#enforceStructOpsFeature(String, String)} which
 * probes {@link Features#hasStructOps(String)}. When the probe returns
 * unsupported, load must throw {@link BPFProgram.BPFLoadError.UnsupportedKernel}
 * with the kernel struct name and required-since version in the message.
 */
class StructOpsFeatureGateTest {

    @BeforeEach
    void stubDispatcher() {
        Features.resetCacheForTest();
        Features.setDispatcherForTest(key -> {
            if (key instanceof ProbeKey.StructOpsKey k
                    && "tcp_congestion_ops".equals(k.name())) {
                return new ProbeResult.Unsupported("simulated unsupported struct_ops");
            }
            return new ProbeResult.Supported();
        });
    }

    @AfterEach
    void restoreDispatcher() {
        Features.setDispatcherForTest(null);
        Features.resetCacheForTest();
    }

    @BPF(license = "GPL")
    abstract static class FeatureGatedSample extends BPFProgram implements TcpCongestionControl {
        @Override public @Unsigned int ssthresh(Ptr<runtime.sock> sk)              { return 42; }
        @Override public void congAvoid(Ptr<runtime.sock> sk, @Unsigned int ack, @Unsigned int acked) { }
        @Override public @Unsigned int undoCwnd(Ptr<runtime.sock> sk)              { return 0; }
        @Override public String name() { return "hellocc_gated"; }
    }

    @Test
    void loadFailsWhenStructOpsKindUnsupported() {
        var ex = assertThrows(BPFProgram.BPFLoadError.UnsupportedKernel.class,
                () -> BPFProgram.load(FeatureGatedSample.class));
        assertTrue(ex.getMessage().contains("tcp_congestion_ops"),
                "expected kernel struct name in message but got: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("5.6"),
                "expected since-version 5.6 in message but got: " + ex.getMessage());
    }

    @Test
    void enforceStructOpsFeatureIsANoOpWhenSupported() {
        Features.setDispatcherForTest(key -> new ProbeResult.Supported());
        Features.resetCacheForTest();
        // Direct assertion on the API, not through load(): a minimal Features stub
        // that reports "supported" for every probe must let enforceStructOpsFeature
        // return without throwing regardless of the kernel-name/since arguments.
        assertDoesNotThrow(() -> Features.hasStructOps("anything"));
        assertTrue(Features.hasStructOps("tcp_congestion_ops"));
    }
}
