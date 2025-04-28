package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.GlobalVariable;
import me.bechberger.ebpf.bpf.XDPHook;
import me.bechberger.ebpf.bpf.NetworkUtil;
import me.bechberger.ebpf.runtime.XdpDefinitions.xdp_action;
import me.bechberger.ebpf.runtime.XdpDefinitions.xdp_md;
import me.bechberger.ebpf.type.Ptr;

/**
 * Use XDP to block every third incoming packet
 */
@BPF(license = "GPL")
public abstract class XDPDropEveryThirdPacket extends BPFProgram implements XDPHook {

    final GlobalVariable<@Unsigned Integer> count = new GlobalVariable<>(0);

    @BPFFunction
    public boolean shouldDrop() {
        return count.get() % 3 == 1;
    }

    @Override
    public xdp_action xdpHandlePacket(Ptr<xdp_md> ctx) {
        count.set(count.get() + 1);
        return shouldDrop() ? xdp_action.XDP_DROP : xdp_action.XDP_PASS;
    }

    public static void main(String[] args) throws InterruptedException {
        try (XDPDropEveryThirdPacket program = BPFProgram.load(XDPDropEveryThirdPacket.class)) {
            program.xdpAttach();
            while (true) {
                System.out.println("Packet count " + program.count.get());
                Thread.sleep(1000);
            }
        }
    }
}
