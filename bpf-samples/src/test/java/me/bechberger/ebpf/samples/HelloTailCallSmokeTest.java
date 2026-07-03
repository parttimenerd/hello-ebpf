package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.bpf.BPFProgram;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.NetworkInterface;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Real-kernel smoke test for the {@link HelloTailCall} tail-call chain.
 *
 * <p>Loads the sample, attaches XDP to the loopback interface, blasts UDP
 * packets at itself, and asserts every slot ran at least 5 times. Any missing
 * slot means the auto-registration codegen did not run.
 */
public class HelloTailCallSmokeTest {

    @Test
    @Timeout(30)
    public void tailCallChainAdvancesAllThreeSlots() throws Exception {
        try (HelloTailCall program = BPFProgram.load(HelloTailCall.class)) {
            int loIndex = NetworkInterface.getByName("lo").getIndex();
            program.xdpAttach(loIndex);

            blastLoopbackUdp(50);

            long deadline = System.currentTimeMillis() + 5000;
            while (System.currentTimeMillis() < deadline
                    && program.countCalls.get() < 5) {
                Thread.sleep(50);
            }

            int e = program.parseEthCalls.get();
            int i = program.parseIpCalls.get();
            int c = program.countCalls.get();
            assertTrue(e >= 5, "parseEth < 5: " + e);
            assertTrue(i >= 5, "parseIp < 5: " + i);
            assertTrue(c >= 5, "count < 5: " + c);
            // Chain invariant - each stage is bounded above by the previous.
            assertTrue(e >= i, "parseEth (" + e + ") < parseIp (" + i + ")");
            assertTrue(i >= c, "parseIp (" + i + ") < count (" + c + ")");
        }
    }

    /** Sends {@code count} tiny UDP packets to 127.0.0.1:1 (discard) to drive XDP. */
    private static void blastLoopbackUdp(int count) throws IOException {
        try (DatagramSocket sock = new DatagramSocket()) {
            byte[] payload = new byte[8];
            InetAddress lo = InetAddress.getByName("127.0.0.1");
            for (int i = 0; i < count; i++) {
                sock.send(new DatagramPacket(payload, payload.length, lo, 1));
            }
        }
    }
}
