package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.runtime.XdpDefinitions.xdp_action;
import me.bechberger.ebpf.runtime.XdpDefinitions.xdp_md;
import me.bechberger.ebpf.type.Ptr;

import java.util.List;

/**
 * Interface for the XDP hook to check incoming packets
 * <p>
 * Be aware that network fields might have a different byte order than
 * your host machine, so use {@link XDPHook#bpf_ntohl(int)} to convert from network
 * to host byte order and {@link XDPHook#bpf_htonl(int)} to convert from host to network byte order
 * in the eBPF program (other methods for other integer data types are available).
 */
public interface XDPHook {

    // some constants that help to identify the type of the packet

    short ETH_P_8021Q = (short)0x8100;
    short ETH_P_8021AD = (short)0x88A8;
    short ETH_P_IP = (short)0x0800;
    short ETH_P_IPV6 = (short)0x86DD;
    short ETH_P_ARP = (short)0x0806;

    /**
     * XDP hook function that get's passed all incoming packets
     * @param ctx XDP context which includes the network packet
     * @return what to do with the packet ({@link xdp_action#XDP_PASS}, ...)
     */
    @BPFFunction(section = "xdp")
    @NotUsableInJava
    xdp_action xdpHandlePacket(Ptr<xdp_md> ctx);

    /**
     * Attach this program to a network interfaces
     * @param ifindexes network interface indexes, e.g. via {@link NetworkUtil#getNetworkInterfaceIndexes()}
     */
    default void xdpAttach(List<Integer> ifindexes) {
        if (this instanceof BPFProgram program) {
            program.xdpAttach(program.getProgramByName("xdpHandlePacket"), ifindexes);
        } else {
            throw new IllegalStateException("This is not a BPF program");
        }
    }

    /**
     * Attach this program to a network interface
     * @param ifindex network interface index
     */
    default void xdpAttach(int ifindex) {
        xdpAttach(List.of(ifindex));
    }

    /**
     * Attach this program all network interfaces that are up and not a loopback interface
     */
    default void xdpAttach() {
        xdpAttach(NetworkUtil.getNetworkInterfaceIndexes());
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
     * Converts an int from network byte order to host byte order
     * <p>
     * @param value the int to convert
     * @return the converted int
     */
    @BuiltinBPFFunction
    @NotUsableInJava
    static int bpf_ntohl(int value) {
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

    /**
     * Converts a short from network byte order to host byte order
     */
    @BuiltinBPFFunction
    @NotUsableInJava
    static short bpf_ntohs(short value) {
        throw new MethodIsBPFRelatedFunction();
    }
}
