package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.bpf.GlobalVariable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static me.bechberger.ebpf.runtime.SkDefinitions.__sk_action;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integration test for {@link TCHook} and {@link TCContext}: attach a TC ingress
 * classifier to loopback, send traffic, and verify the packet counter increments.
 *
 * <p>Uses the ergonomic {@code TCContext} overload of {@code tcHandleIngress}
 * (not the legacy {@code Ptr<__sk_buff>} overload).
 */
public class TCHookTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram implements TCHook {

        /** Counts every packet seen by the TC ingress hook. */
        final GlobalVariable<Integer> packetCount = new GlobalVariable<>(0);

        @Override
        public __sk_action tcHandleIngress(TCContext ctx) {
            packetCount.set(packetCount.get() + 1);
            return __sk_action.__SK_PASS;
        }
    }

    @Test
    @Timeout(15)
    public void testTCCountsPackets() throws Exception {
        try (var program = BPFProgram.load(Program.class)) {
            program.tcAttachIngress(1); // loopback ifindex

            // Send a few packets over loopback.
            new ProcessBuilder("ping", "-c", "3", "-W", "1", "127.0.0.1")
                    .redirectErrorStream(true)
                    .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                    .start()
                    .waitFor();

            int count = program.packetCount.get();
            assertTrue(count > 0,
                    "TC ingress hook should have counted at least one packet on loopback; got " + count);
        }
    }
}
