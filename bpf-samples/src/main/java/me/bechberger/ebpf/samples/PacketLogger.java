package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.*;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.*;
import me.bechberger.ebpf.bpf.map.BPFRingBuffer;

import static me.bechberger.ebpf.bpf.raw.Lib.*;
import static me.bechberger.ebpf.bpf.raw.Lib_3.*;
import static me.bechberger.ebpf.runtime.SkDefinitions.*;
import static me.bechberger.ebpf.runtime.XdpDefinitions.*;

import static me.bechberger.ebpf.runtime.EthtoolDefinitions.*;
import static me.bechberger.ebpf.runtime.VlanDefinitions.*;
import static me.bechberger.ebpf.runtime.runtime.*;

import static me.bechberger.ebpf.type.BPFType.BPFIntType.UnsignedInt128;

import static me.bechberger.ebpf.runtime.Ipv6Definitions.*;
import me.bechberger.ebpf.type.Enum;
import me.bechberger.ebpf.type.Ptr;

/**
 * TC and XDP based packet logger, capturing incoming and outgoing packets
 * <p>
 * Based on the examples from the <a href="https://github.com/xdp-project/bpf-examples">xdp-project</a>.
 */
@BPF(license = "GPL")
public abstract class PacketLogger extends BPFProgram implements XDPHook, TCHook {

    /**
     * A IPv4 or IPv6 address
     */
    @Type
    record IPAddress(boolean v4, @Unsigned int ipv4, UnsignedInt128 ipv6) {}

    @Type
    enum PacketDirection implements Enum<PacketDirection> {
        INCOMING, OUTGOING
    }

    @Type
    enum Protocol implements Enum<Protocol> {
        TCP, UDP, OTHER
    }

    @Type
    static class PacketInfo {
        PacketDirection direction;
        Protocol protocol;
        IPAddress source;
        IPAddress destination;
        int port;
        int length;
    }

    @BPFMapDefinition(maxEntries = 4096 * 256)
    BPFRingBuffer<PacketInfo> packetLog;

    /**
     * Parse the inner of an IP (v4 or v6) packet
     * and store the port and protocol in info
     */
    @BPFFunction
    boolean parseIPInnerPacket(char protocol, Ptr<?> afterHdr,
                               Ptr<?> dataEnd, Ptr<PacketInfo> info) {
        if (protocol == IPPROTO_TCP()) {
            info.val().protocol = Protocol.TCP;
            // get the port
            Ptr<tcphdr> tcp = afterHdr.<tcphdr>cast();
            if (tcp.add(1).greaterThan(dataEnd)) {
                return false;
            }
            info.val().port = tcp.val().dest;
        } else if (protocol == IPPROTO_UDP()) {
            info.val().protocol = Protocol.UDP;
            // get the port
            Ptr<udphdr> udp = afterHdr.<udphdr>cast();
            if (udp.add(1).greaterThan(dataEnd)) {
                return false;
            }
            info.val().port = udp.val().dest;
        } else {
            info.val().protocol = Protocol.OTHER;
            info.val().port = -1;
        }
        return true;
    }

    /**
     * Parse an IPv4 packet and extract the source
     * and destination IP address and the protocol
     * @param iph start of the IP header
     * @param dataEnd end of the packet data
     * @param info output parameter for the extracted information
     * @return true if the packet is an IP packet and could be parsed,
     *         false otherwise
     */
    @BPFFunction
    boolean parseIPPacket(Ptr<iphdr> iph, Ptr<?> dataEnd, Ptr<PacketInfo> info) {
        if (iph.add(1).greaterThan(dataEnd)) {
            return false; // invalid packet
        }
        info.val().source = new IPAddress(true, iph.val().addrs.saddr,
                new UnsignedInt128(0,0));
        info.val().destination = new IPAddress(true, iph.val().addrs.daddr,
                new UnsignedInt128(0,0));
        return parseIPInnerPacket(iph.val().protocol, iph.add(1), dataEnd, info);
    }

    /* Longest chain of IPv6 extension headers to resolve */
    static final int IPV6_EXT_MAX_CHAIN = 6;

    /**
     * Parse an IPv6 packet and extract the source
     * and destination IP address and the protocol
     */
    @BPFFunction
    @AlwaysInline
    boolean parseIPv6Packet(Ptr<ipv6hdr> iph, Ptr<?> dataEnd, Ptr<PacketInfo> info) {
        if (iph.add(1).greaterThan(dataEnd) || iph.val().version != 6) {
            return false; // invalid packet
        }
        var saddr = iph.val().addrs.saddr;
        var daddr = iph.val().addrs.daddr;
        info.val().source = new IPAddress(false, 0,
                new UnsignedInt128(saddr.in6_u.u6_addr32[0], saddr.in6_u.u6_addr32[1]));
        info.val().destination = new IPAddress(false, 0,
                new UnsignedInt128(daddr.in6_u.u6_addr32[0], daddr.in6_u.u6_addr32[1]));

        iph = iph.add(1);

        if (iph.add(BPFJ.sizeof(iph.val())).greaterThan(dataEnd)) {
            return false;
        }

        // the following skips thw IPv6 extension headers
        // and is based on https://github.com/xdp-project/bpf-examples/blob/5343ed3377471c7b7ef2237526c8bdc0f00a0cef/include/xdp/parsing_helpers.h

        var nextHdrType = iph.val().nexthdr;

        Ptr<ipv6_opt_hdr> hdr = iph.<ipv6_opt_hdr>cast();
        for (int i = 0; i < IPV6_EXT_MAX_CHAIN; i++) {
            if (hdr.add(1).greaterThan(dataEnd)) {
                return false;
            }

            if (nextHdrType == IPPROTO_HOPOPTS() ||
                    nextHdrType == IPPROTO_DSTOPTS() ||
                    nextHdrType == IPPROTO_ROUTING() ||
                    nextHdrType == IPPROTO_MH()) {
                nextHdrType = hdr.val().nexthdr;
                hdr = hdr.asVoidPointer().add((hdr.val().hdrlen + 1) * 8L)
                        .<ipv6_opt_hdr>cast();
            } else if (nextHdrType == IPPROTO_AH()) {
                nextHdrType = hdr.val().nexthdr;
                hdr = hdr.asVoidPointer().add((hdr.val().hdrlen + 2) * 4L)
                        .<ipv6_opt_hdr>cast();
            } else if (nextHdrType == IPPROTO_FRAGMENT()) {
                nextHdrType = hdr.val().nexthdr;
                hdr = hdr.asVoidPointer().add(8).<ipv6_opt_hdr>cast();
            } else {
                // Found a header that is not an IPv6 extension header
                return parseIPInnerPacket(nextHdrType, hdr, dataEnd, info);
            }
        }

        return false;
    }

    /**
     * Parse a packet and extract the source and destination IP address and the protocol
     * @param start start of the packet data
     * @param end end of the packet data
     * @param info output parameter for the extracted information
     * @return true if the packet is an IP packet and could be parsed, false otherwise
     */
    @BPFFunction
    @AlwaysInline
    boolean parsePacket(Ptr<?> start, Ptr<?> end, Ptr<PacketInfo> info) {

        @Unsigned long offset;
        @Unsigned short ethType;

        Ptr<ethhdr> eth = start.<ethhdr>cast();
        offset = BPFJ.sizeof(eth.val());
        if (start.add(offset).greaterThan(end)) {
            // ethernet package header is incomplete
            return false;
        }
        info.val().length = (int)(end.asLong() - start.asLong());
        ethType = eth.val().h_proto;
        // handle VLAN tagged packet
        if (ethType == XDPHook.bpf_htons(ETH_P_8021Q) ||
                ethType == XDPHook.bpf_htons(ETH_P_8021AD)) {
            Ptr<vlan_hdr> vlan_hdr = eth.add(offset).<vlan_hdr>cast();
            offset += BPFJ.sizeof(vlan_hdr.val());
            if (eth.add(offset).greaterThan(end)) {
                // ethernet package header is incomplete
                return false;
            }
            ethType = vlan_hdr.val().h_vlan_encapsulated_proto;
        }

        if ((int)ethType == XDPHook.bpf_htons(ETH_P_IP)) {
            return parseIPPacket(start.add(offset).<iphdr>cast(), end, info);
        }
        if ((int)ethType == XDPHook.bpf_htons((short)ETH_P_IPV6)) {
            return parseIPv6Packet(start.add(offset).<ipv6hdr>cast(), end, info);
        }
        return false;
    }

    /**
     * Handle a packet, storing the information in the packet log
     */
    @BPFFunction
    @AlwaysInline
    void handlePacket(PacketDirection direction, Ptr<?> start, Ptr<?> end) {
        PacketInfo info = new PacketInfo();
        info.direction = direction;
        if (parsePacket(start, end, Ptr.of(info))) {
            var ptr = packetLog.reserve();
            if (ptr != null) {
                ptr.set(info);
                packetLog.submit(ptr);
            }
        }
    }

    @Override
    public xdp_action xdpHandlePacket(Ptr<xdp_md> ctx) {
        handlePacket(PacketDirection.INCOMING,
                Ptr.voidPointer(ctx.val().data),
                Ptr.voidPointer(ctx.val().data_end));
        return xdp_action.XDP_PASS;
    }

    @Override
    public sk_action tcHandleEgress(Ptr<__sk_buff> packet) {
        handlePacket(PacketDirection.OUTGOING,
                Ptr.voidPointer(packet.val().data),
                Ptr.voidPointer(packet.val().data_end));
        return sk_action.SK_PASS;
    }

    public static void main(String[] args) throws InterruptedException {
        try (PacketLogger program = BPFProgram.load(PacketLogger.class)) {
            program.packetLog.setCallback((info) -> {
                if (info.direction == PacketDirection.INCOMING) {
                    System.out.print("Incoming from " +
                            NetworkUtil.intToIpAddress(info.source.ipv4)
                                    .getHostAddress());
                } else {
                    System.out.print("Outgoing to   " +
                            NetworkUtil.intToIpAddress(info.destination.ipv4)
                                    .getHostAddress());
                }
                System.out.printf(" protocol %s port %5d length %d%n",
                        info.protocol, info.port, info.length);
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
