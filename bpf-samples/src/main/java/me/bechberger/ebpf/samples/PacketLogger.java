package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.*;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.*;
import me.bechberger.ebpf.bpf.map.BPFRingBuffer;
import static me.bechberger.ebpf.runtime.SkDefinitions.*;
import static me.bechberger.ebpf.runtime.XdpDefinitions.*;

import me.bechberger.ebpf.type.Ptr;

/**
 * TC and XDP based packet logger, capturing incoming and outgoing packets
 * <p>
 * Based on the examples from the <a href="https://github.com/xdp-project/bpf-examples">xdp-project</a>.
 */
@BPF(license = "GPL")
public abstract class PacketLogger extends BPFProgram implements XDPHook, TCHook, BasePacketParser {

    @BPFMapDefinition(maxEntries = 4096 * 256)
    BPFRingBuffer<PacketInfo> packetLog;

    /**
     * Handle a packet, storing the information in the packet log
     */
    @BPFFunction
    @AlwaysInline
    void handlePacket(PacketDirection direction, @Unsigned int start, @Unsigned int end) {
        PacketInfo info = new PacketInfo();
        info.direction = direction;
        if (parsePacket(Ptr.voidPointer(start), Ptr.voidPointer(end), Ptr.of(info))) {
            var ptr = packetLog.reserve();
            if (ptr != null) {
                ptr.set(info);
                packetLog.submit(ptr);
            }
        }
    }

    @Override
    public xdp_action xdpHandlePacket(Ptr<xdp_md> ctx) {
        handlePacket(PacketDirection.INCOMING, ctx.val().data, ctx.val().data_end);
        return xdp_action.XDP_PASS;
    }

    @Override
    public __sk_action tcHandleEgress(Ptr<__sk_buff> packet) {
        handlePacket(PacketDirection.OUTGOING, packet.val().data, packet.val().data_end);
        return __sk_action.__SK_PASS;
    }

    public static void main(String[] args) throws InterruptedException {
        try (PacketLogger program = BPFProgram.load(PacketLogger.class)) {
            program.packetLog.setCallback((info) -> {
                if (info.direction == PacketDirection.INCOMING) {
                    System.out.print("Incoming from " +
                            NetworkUtil.intToIpAddress(info.source.ipv4())
                                    .getHostAddress());
                } else {
                    System.out.print("Outgoing to   " +
                            NetworkUtil.intToIpAddress(info.destination.ipv4())
                                    .getHostAddress());
                }
                System.out.printf(" protocol %s port %5d -> %5d  length %d%n",
                        info.protocol, info.sourcePort, info.destinationPort, info.length);
            });
            program.xdpAttach();
            program.tcAttachEgress();
            while (true) {
                program.consumeAndThrow();
                Thread.sleep(500);
            }
        }
    }
}
