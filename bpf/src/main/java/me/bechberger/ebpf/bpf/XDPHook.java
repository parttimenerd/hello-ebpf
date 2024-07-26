package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.runtime.XdpDefinitions.xdp_action;
import me.bechberger.ebpf.runtime.XdpDefinitions.xdp_md;
import me.bechberger.ebpf.type.Ptr;

/**
 * Interface for the XDP hook to check incoming packets
 */
public interface XDPHook {

    // some constants that help to identify the type of the packet

    int ETH_P_8021Q = 0x8100;
    int ETH_P_8021AD = 0x88A8;
    int ETH_P_IP = 0x0800;
    int ETH_P_IPV6 = 0x86DD;
    int ETH_P_ARP = 0x0806;

    /**
     * XDP hook function that get's passed all incoming packets
     * @param ctx XDP context which includes the network packet
     * @return what to do with the packet ({@link xdp_action#XDP_PASS}, ...)
     */
    @BPFFunction(section = "xdp")
    @NotUsableInJava
    xdp_action xdpHandlePacket(Ptr<xdp_md> ctx);

    /**
     * Attach this program to a network interface
     * @param ifindex network interface index, e.g. via {@link XDPUtil#getNetworkInterfaceIndex()}
     */
    default void xdpAttach(int ifindex) {
        if (this instanceof BPFProgram program) {
            program.xdpAttach(program.getProgramByName("xdpHandlePacket"), ifindex);
        } else {
            throw new IllegalStateException("This is not a BPF program");
        }
    }

    /**
     * Converts a short from host byte order to network byte order
     * <p>
     * @param value the short to convert
     * @return the converted short
     */
    @BuiltinBPFFunction
    @NotUsableInJava
    static short bpf_htons(short value) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Converts an int from host byte order to network byte order
     * <p>
     * @param value the int to convert
     * @return the converted int
     */
    @BuiltinBPFFunction
    @NotUsableInJava
    static long bpf_htonl(int value) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Converts a short from network byte order to host byte order
     * <p>
     * @param value the short to convert
     * @return the converted short
     */
    @BuiltinBPFFunction
    @NotUsableInJava
    static short bpf_ntons(short value) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Converts an int from network byte order to host byte order
     * <p>
     * @param value the int to convert
     * @return the converted int
     */
    @BuiltinBPFFunction
    @NotUsableInJava
    static long bpf_ntonl(int value) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Converts a long from host byte order to network byte order
     * <p>
     * @param value the long to convert
     * @return the converted long
     */
    @BuiltinBPFFunction
    @NotUsableInJava
    static long bpf_cpu_to_be64(long value) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Converts a long from network byte order to host byte order
     * <p>
     * @param value the long to convert
     * @return the converted long
     */
    @BuiltinBPFFunction
    @NotUsableInJava
    static long bpf_be64_to_cpu(long value) {
        throw new MethodIsBPFRelatedFunction();
    }

}
