package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.BPFTailCallTable;
import me.bechberger.ebpf.annotations.bpf.TailCallSlot;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.GlobalVariable;
import me.bechberger.ebpf.bpf.XDPHook;
import me.bechberger.ebpf.bpf.map.BPFProgArray;
import me.bechberger.ebpf.runtime.XdpDefinitions.xdp_action;
import me.bechberger.ebpf.runtime.XdpDefinitions.xdp_md;
import me.bechberger.ebpf.type.Ptr;

/**
 * A 3-stage XDP tail-call chain wired via {@link BPFTailCallTable} and
 * {@link TailCallSlot}. Each stage is a sub-program; the entry point
 * dispatches to the first stage.
 *
 * <p>Stages:
 * <ol>
 *   <li>{@link Slot#PARSE_ETH} - bumps {@code parseEthCalls}, tail-calls PARSE_IP.</li>
 *   <li>{@link Slot#PARSE_IP} - bumps {@code parseIpCalls}, tail-calls COUNT.</li>
 *   <li>{@link Slot#COUNT}   - bumps {@code countCalls} and returns XDP_PASS.</li>
 * </ol>
 *
 * <p>Slot registration is emitted automatically by the annotation processor -
 * no manual {@code progs.register(...)} calls in {@code main}.
 *
 * <p>Usage:
 * <pre>
 *   sudo ./run.sh HelloTailCall
 *   # in another shell:
 *   ping -c 5 127.0.0.1
 * </pre>
 */
@BPF(license = "GPL")
public abstract class HelloTailCall extends BPFProgram implements XDPHook {

    public enum Slot { PARSE_ETH, PARSE_IP, COUNT }

    // Enum ordinals mirrored as integer literals for BPF-side use.
    // The compiler plugin cannot lower Slot.X.ordinal() into C, so we keep
    // the enum as the source of truth for @TailCallSlot validation and use
    // these constants inside @BPFFunction bodies.
    static final int SLOT_PARSE_ETH = 0;
    static final int SLOT_PARSE_IP  = 1;
    static final int SLOT_COUNT     = 2;

    @BPFTailCallTable(slots = Slot.class)
    @BPFMapDefinition(maxEntries = 3)
    BPFProgArray dispatch;

    final GlobalVariable<@Unsigned Integer> parseEthCalls = new GlobalVariable<>(0);
    final GlobalVariable<@Unsigned Integer> parseIpCalls  = new GlobalVariable<>(0);
    final GlobalVariable<@Unsigned Integer> countCalls    = new GlobalVariable<>(0);

    @BPFFunction(section = "xdp")
    @TailCallSlot("PARSE_ETH")
    public xdp_action parseEthImpl(Ptr<xdp_md> ctx) {
        parseEthCalls.set(parseEthCalls.get() + 1);
        dispatch.tailCall(ctx, SLOT_PARSE_IP);
        return xdp_action.XDP_PASS; // unreachable - tailCall never returns
    }

    @BPFFunction(section = "xdp")
    @TailCallSlot("PARSE_IP")
    public xdp_action parseIpImpl(Ptr<xdp_md> ctx) {
        parseIpCalls.set(parseIpCalls.get() + 1);
        dispatch.tailCall(ctx, SLOT_COUNT);
        return xdp_action.XDP_PASS;
    }

    @BPFFunction(section = "xdp")
    @TailCallSlot("COUNT")
    public xdp_action countImpl(Ptr<xdp_md> ctx) {
        countCalls.set(countCalls.get() + 1);
        return xdp_action.XDP_PASS;
    }

    @Override
    public xdp_action xdpHandlePacket(Ptr<xdp_md> ctx) {
        dispatch.tailCall(ctx, SLOT_PARSE_ETH);
        return xdp_action.XDP_PASS;
    }

    public static void main(String[] args) throws InterruptedException {
        try (HelloTailCall program = BPFProgram.load(HelloTailCall.class)) {
            // No manual register(...) calls - the processor did it in the ctor.
            program.xdpAttach();
            for (int i = 0; i < 30; i++) {
                System.out.printf("parseEth=%d parseIp=%d count=%d%n",
                        program.parseEthCalls.get(),
                        program.parseIpCalls.get(),
                        program.countCalls.get());
                Thread.sleep(1000);
            }
        }
    }
}
