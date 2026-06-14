package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.XDPContext;
import me.bechberger.ebpf.bpf.XDPHook;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.runtime.XdpDefinitions.xdp_action;
import me.bechberger.ebpf.type.Ptr;

/**
 * Counts incoming packets by their length using {@link XDPContext} helpers.
 *
 * <p>Demonstrates the ergonomic {@code ctx.length()} instance method on the
 * high-level {@link XDPContext} hook context.
 */
@BPF(license = "GPL")
public abstract class PacketCountByLength extends BPFProgram implements XDPHook {

    /** Maps packet length (bytes) → count of packets with that length. */
    @BPFMapDefinition(maxEntries = 65536)
    BPFHashMap<Integer, @Unsigned Long> countByLength;

    @Override
    public xdp_action xdpHandlePacket(XDPContext ctx) {
        int len = ctx.length();

        Ptr<@Unsigned Long> counter = countByLength.bpf_get(len);
        if (counter != null) {
            long one = 1;
            me.bechberger.ebpf.bpf.BPFJ.sync_fetch_and_add(counter, one);
        } else {
            long one = 1;
            countByLength.put(len, one);
        }

        return xdp_action.XDP_PASS;
    }

    public static void main(String[] args) throws InterruptedException {
        try (var program = BPFProgram.load(PacketCountByLength.class)) {
            program.xdpAttach();
            System.out.println("Counting packets by length. Press Ctrl-C to stop.");
            while (true) {
                Thread.sleep(2000);
                System.out.println("=== Packet length histogram ===");
                program.countByLength.forEach((len, count) ->
                        System.out.printf("  %5d bytes: %d packets%n", len, count));
            }
        }
    }
}
