package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.map.BPFRingBuffer;
import me.bechberger.ebpf.runtime.XdpDefinitions.xdp_action;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end test for {@link BasePacketParser} on the loopback interface.
 *
 * <p>Attaches an XDP program to lo (ifindex 1), sends a ping, and checks that
 * the ring buffer receives at least one {@link BasePacketParser.PacketInfo}
 * with a non-zero source address (parsed from the IPv4 header).
 */
public class BasePacketParserTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram implements XDPHook, BasePacketParser {

        @BPFMapDefinition(maxEntries = 64)
        BPFRingBuffer<PacketInfo> packets;

        @Override
        public xdp_action xdpHandlePacket(XDPContext ctx) {
            Ptr<PacketInfo> info = packets.reserve();
            if (info == null) {
                return xdp_action.XDP_PASS;
            }
            if (!parsePacket(ctx, info)) {
                packets.discard(info);
                return xdp_action.XDP_PASS;
            }
            packets.submit(info);
            return xdp_action.XDP_PASS;
        }
    }

    @Test
    @Timeout(15)
    public void testBasePacketParserParsesLoopbackPing() throws Exception {
        List<BasePacketParser.PacketInfo> received = new ArrayList<>();
        try (Program program = BPFProgram.load(Program.class)) {
            program.packets.setCallback(pkt -> received.add(pkt));
            program.xdpAttach(1);

            // Trigger packet flow on lo.
            new ProcessBuilder("ping", "-c", "3", "-W", "1", "127.0.0.1")
                    .redirectErrorStream(true)
                    .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                    .start()
                    .waitFor();

            long deadline = System.currentTimeMillis() + 5000;
            while (received.isEmpty() && System.currentTimeMillis() < deadline) {
                program.packets.consume();
                Thread.sleep(50);
            }

            assertFalse(received.isEmpty(), "Should have received at least one parsed packet");
            BasePacketParser.PacketInfo pkt = received.get(0);
            // Loopback traffic is IPv4 with non-zero source address (127.0.0.1 = 0x0100007f LE).
            assertNotNull(pkt.source, "source address must not be null");
            assertTrue(pkt.source.v4(), "loopback packet should be IPv4");
            assertNotEquals(0, pkt.source.ipv4(), "source IPv4 address must be non-zero");
        }
    }
}
