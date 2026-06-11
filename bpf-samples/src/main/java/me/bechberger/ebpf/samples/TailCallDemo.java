package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.GlobalVariable;
import me.bechberger.ebpf.bpf.NetworkUtil;
import me.bechberger.ebpf.bpf.XDPHook;
import me.bechberger.ebpf.bpf.map.BPFProgArray;
import me.bechberger.ebpf.runtime.XdpDefinitions.xdp_action;
import me.bechberger.ebpf.runtime.XdpDefinitions.xdp_md;
import me.bechberger.ebpf.type.Ptr;

/**
 * Demonstrates BPF tail calls using a {@link BPFProgArray}.
 *
 * <p>The main XDP program counts packets and tail-calls to one of two sub-programs:
 * <ul>
 *   <li>slot 0 ({@code xdpDropPacket}) — drops the packet</li>
 *   <li>slot 1 ({@code xdpPassPacket}) — passes the packet</li>
 * </ul>
 * Every third packet (count % 3 == 0) is dropped; all others pass.
 *
 * <p>Usage:
 * <pre>
 *   sudo ./run.sh TailCallDemo
 * </pre>
 */
@BPF(license = "GPL")
public abstract class TailCallDemo extends BPFProgram implements XDPHook {

    static final int SLOT_DROP = 0;
    static final int SLOT_PASS = 1;

    @BPFMapDefinition(maxEntries = 2)
    BPFProgArray progs;

    final GlobalVariable<@Unsigned Integer> packetCount = new GlobalVariable<>(0);

    /** Sub-program: drop the packet (registered in slot 0). */
    @BPFFunction(section = "xdp")
    public xdp_action xdpDropPacket(Ptr<xdp_md> ctx) {
        return xdp_action.XDP_DROP;
    }

    /** Sub-program: pass the packet (registered in slot 1). */
    @BPFFunction(section = "xdp")
    public xdp_action xdpPassPacket(Ptr<xdp_md> ctx) {
        return xdp_action.XDP_PASS;
    }

    @Override
    public xdp_action xdpHandlePacket(Ptr<xdp_md> ctx) {
        @Unsigned int count = packetCount.get() + 1;
        packetCount.set(count);
        int slot = (count % 3 == 0) ? SLOT_DROP : SLOT_PASS;
        progs.tailCall(ctx, slot);
        return xdp_action.XDP_PASS;
    }

    public static void main(String[] args) throws InterruptedException {
        try (TailCallDemo program = BPFProgram.load(TailCallDemo.class)) {
            program.progs.register(SLOT_DROP, program.getProgramByName("xdpDropPacket"));
            program.progs.register(SLOT_PASS, program.getProgramByName("xdpPassPacket"));
            program.xdpAttach();
            while (true) {
                System.out.println("Packets seen: " + program.packetCount.get());
                Thread.sleep(1000);
            }
        }
    }
}
