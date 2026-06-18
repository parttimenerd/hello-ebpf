package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.map.BPFRingBuffer;
import me.bechberger.ebpf.runtime.EthtoolDefinitions.ethhdr;
import me.bechberger.ebpf.runtime.XdpDefinitions.xdp_action;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.ArrayList;
import java.util.List;

import static me.bechberger.ebpf.bpf.XDPHook.bpf_ntohs;
import static me.bechberger.ebpf.bpf.XDPHook.bpf_ntohl;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test for {@link XDPContext} instance methods.
 *
 * <p>Tests {@code length()}, {@code data()}, and {@code dataEnd()}.  Attaches
 * XDP to loopback (ifindex 1), pings 127.0.0.1, and verifies the parsed Ethernet
 * + IPv4 fields are correct.
 *
 * <h3>Known limitation of raw-offset accessors</h3>
 * {@code byteAt()}, {@code shortAtNetworkOrder()}, and {@code intAtNetworkOrder()}
 * each re-read {@code ctx->data} from the context struct, producing a fresh BPF
 * register with range 0.  The verifier cannot link these back to a bounds check
 * that used a different register, so they cause verifier rejection when called
 * after {@code boundsOk()}.  Similarly, {@code boundsOk()} itself loads
 * {@code ctx->data} independently, so a subsequent typed-pointer access through
 * {@code Ptr.voidPointer(ctx.data())} starts with a new range-0 register and is
 * also rejected.
 *
 * <p>The verifier-safe pattern is to load {@code data}/{@code dataEnd} once via
 * {@code ctx.data()}/{@code ctx.dataEnd()} and then use only typed {@link Ptr}
 * arithmetic (as in {@link BasePacketParser}) — never raw offset reads after a
 * separate {@code boundsOk()} call.
 */
public class XDPContextTest {

    @Type
    record PacketFields(
        int length,    // ctx.length() = data_end − data
        int etherType, // h_proto (host order) from Ethernet header
        int ipSrc      // IPv4 source (host order) from IP header
    ) {}

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram implements XDPHook {

        @BPFMapDefinition(maxEntries = 64)
        BPFRingBuffer<PacketFields> events;

        @Override
        public xdp_action xdpHandlePacket(XDPContext ctx) {
            // Load data/dataEnd once — the verifier tracks these as a single
            // register pair throughout the function.
            Ptr<?> data = Ptr.voidPointer(ctx.data());
            Ptr<?> dataEnd = Ptr.voidPointer(ctx.dataEnd());

            // ctx.length() is pure subtraction arithmetic — safe without any
            // packet-memory access.
            int len = ctx.length();

            // Ethernet header bounds check via the same 'data' register.
            Ptr<ethhdr> eth = data.<ethhdr>cast();
            if (eth.add(1).greaterThan(dataEnd)) {
                return xdp_action.XDP_PASS;
            }
            int hProto = bpf_ntohs(eth.val().h_proto);

            // Only capture IPv4 (EtherType 0x0800).
            if (hProto != 0x0800) {
                return xdp_action.XDP_PASS;
            }

            // IPv4 header starts at data+14 (after 14-byte Ethernet header).
            Ptr<me.bechberger.ebpf.runtime.runtime.iphdr> iph =
                    data.add(14).<me.bechberger.ebpf.runtime.runtime.iphdr>cast();
            if (iph.add(1).greaterThan(dataEnd)) {
                return xdp_action.XDP_PASS;
            }
            int srcAddr = bpf_ntohl(iph.val().addrs.saddr);

            Ptr<PacketFields> ev = events.reserve();
            if (ev == null) {
                return xdp_action.XDP_PASS;
            }
            Ptr.of(ev.val().length).set(len);
            Ptr.of(ev.val().etherType).set(hProto);
            Ptr.of(ev.val().ipSrc).set(srcAddr);
            events.submit(ev);
            return xdp_action.XDP_PASS;
        }
    }

    @Test
    @Timeout(15)
    public void testXDPContextLengthAndData() throws Exception {
        List<PacketFields> captured = new ArrayList<>();
        try (Program program = BPFProgram.load(Program.class)) {
            program.events.setCallback((BPFRingBuffer.EventCallbackWOBuffer<PacketFields>) ev -> captured.add(ev));
            program.xdpAttach(1); // loopback ifindex

            new ProcessBuilder("ping", "-c", "3", "-W", "1", "127.0.0.1")
                    .redirectErrorStream(true)
                    .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                    .start()
                    .waitFor();

            long deadline = System.currentTimeMillis() + 5000;
            while (captured.isEmpty() && System.currentTimeMillis() < deadline) {
                program.events.consume();
                Thread.sleep(50);
            }

            assertFalse(captured.isEmpty(),
                    "XDP hook should have captured at least one IPv4 packet on loopback");

            PacketFields pkt = captured.get(0);

            // ctx.length() = data_end − data: ping ICMP frame is 42 bytes minimum.
            assertTrue(pkt.length() >= 42,
                    "ctx.length() >= 42 for ping (14 Eth + 20 IP + 8 ICMP), got " + pkt.length());

            // EtherType from ethhdr.h_proto (network order → host via bpf_ntohs).
            assertEquals(0x0800, pkt.etherType(),
                    "EtherType should be 0x0800 (IPv4), got 0x" + Integer.toHexString(pkt.etherType()));

            // IPv4 source on loopback = 127.0.0.1 = 0x7f000001 (host order).
            assertEquals(0x7f000001, pkt.ipSrc(),
                    "IPv4 source should be 0x7f000001 (127.0.0.1), got 0x" + Integer.toHexString(pkt.ipSrc()));
        }
    }
}
