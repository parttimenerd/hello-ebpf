package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.AlwaysInline;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFInterface;
import me.bechberger.ebpf.bpf.BPFJ;
import me.bechberger.ebpf.bpf.XDPHook;
import me.bechberger.ebpf.runtime.*;
import me.bechberger.ebpf.runtime.SkDefinitions.__sk_buff;
import me.bechberger.ebpf.type.BPFType;
import me.bechberger.ebpf.type.Enum;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.bpf.XDPHook.*;
import static me.bechberger.ebpf.bpf.raw.Lib.*;
import static me.bechberger.ebpf.bpf.raw.Lib_3.IPPROTO_FRAGMENT;
import static me.bechberger.ebpf.bpf.raw.Lib_3.IPPROTO_MH;

/**
 * Parse helpers for IP packets.
 * <p>
 * Based on the examples from the <a href="https://github.com/xdp-project/bpf-examples">xdp-project</a>.
 */
@BPFInterface
public interface BasePacketParser {

    int HTTP_PORT = 80;
    int HTTPS_PORT = 443;

    /**
     * A IPv4 or IPv6 address
     */
    @Type
    record IPAddress(boolean v4, @Unsigned int ipv4, BPFType.BPFIntType.UnsignedInt128 ipv6) {
    }

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
        public PacketDirection direction;
        public Protocol protocol;
        public IPAddress source;
        public IPAddress destination;
        public @Unsigned int destinationPort;
        public @Unsigned int sourcePort;
        public int length;
    }

    /**
     * Parse the inner of an IP (v4 or v6) packet
     * and store the port and protocol in info
     */
    @BPFFunction
    @AlwaysInline
    default boolean parseIPInnerPacket(char protocol, Ptr<?> afterHdr,
                                       Ptr<?> dataEnd, Ptr<PacketInfo> info) {
        if (protocol == IPPROTO_TCP()) {
            info.val().protocol = Protocol.TCP;
            // get the port
            Ptr<runtime.tcphdr> tcp = afterHdr.<runtime.tcphdr>cast();
            if (tcp.add(2).greaterThan(dataEnd)) {
                return false;
            }
            info.val().sourcePort = bpf_ntohs(tcp.val().source);
            info.val().destinationPort = bpf_ntohs(tcp.val().dest);
        } else if (protocol == IPPROTO_UDP()) {
            info.val().protocol = Protocol.UDP;
            // get the port
            Ptr<runtime.udphdr> udp = afterHdr.<runtime.udphdr>cast();
            if (udp.add(1).greaterThan(dataEnd)) {
                return false;
            }
            info.val().sourcePort = bpf_ntohs(udp.val().source);
            info.val().destinationPort = bpf_ntohs(udp.val().dest);
        } else {
            info.val().protocol = Protocol.OTHER;
            info.val().destinationPort = -1;
            info.val().sourcePort = -1;
        }
        return true;
    }

    /**
     * Parse an IPv4 packet and extract the source
     * and destination IP address and the protocol
     *
     * @param iph     start of the IP header
     * @param dataEnd end of the packet data
     * @param info    output parameter for the extracted information
     * @return true if the packet is an IP packet and could be parsed,
     * false otherwise
     */
    @BPFFunction
    @AlwaysInline
    default boolean parseIPPacket(Ptr<runtime.iphdr> iph, Ptr<?> dataEnd, Ptr<PacketInfo> info) {
        if (iph.add(1).greaterThan(dataEnd)) {
            return false; // invalid packet
        }
        info.val().source = new IPAddress(true, iph.val().addrs.saddr,
                new BPFType.BPFIntType.UnsignedInt128(0, 0));
        info.val().destination = new IPAddress(true, iph.val().addrs.daddr,
                new BPFType.BPFIntType.UnsignedInt128(0, 0));
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
    default boolean parseIPv6Packet(Ptr<runtime.ipv6hdr> iph, Ptr<?> dataEnd, Ptr<PacketInfo> info) {
        if (iph.add(1).greaterThan(dataEnd) || iph.val().version != 6) {
            return false; // invalid packet
        }
        var saddr = iph.val().addrs.saddr;
        var daddr = iph.val().addrs.daddr;
        info.val().source = new IPAddress(false, 0,
                new BPFType.BPFIntType.UnsignedInt128(saddr.in6_u.u6_addr32[0], saddr.in6_u.u6_addr32[1]));
        info.val().destination = new IPAddress(false, 0,
                new BPFType.BPFIntType.UnsignedInt128(daddr.in6_u.u6_addr32[0], daddr.in6_u.u6_addr32[1]));

        iph = iph.add(1);

        if (iph.add(BPFJ.sizeof(iph.val())).greaterThan(dataEnd)) {
            return false;
        }

        // the following skips thw IPv6 extension headers
        // and is based on https://github.com/xdp-project/bpf-examples/blob/5343ed3377471c7b7ef2237526c8bdc0f00a0cef/include/xdp/parsing_helpers.h

        var nextHdrType = iph.val().nexthdr;

        Ptr<Ipv6Definitions.ipv6_opt_hdr> hdr = iph.<Ipv6Definitions.ipv6_opt_hdr>cast();
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
                        .<Ipv6Definitions.ipv6_opt_hdr>cast();
            } else if (nextHdrType == IPPROTO_AH()) {
                nextHdrType = hdr.val().nexthdr;
                hdr = hdr.asVoidPointer().add((hdr.val().hdrlen + 2) * 4L)
                        .<Ipv6Definitions.ipv6_opt_hdr>cast();
            } else if (nextHdrType == IPPROTO_FRAGMENT()) {
                nextHdrType = hdr.val().nexthdr;
                hdr = hdr.asVoidPointer().add(8).<Ipv6Definitions.ipv6_opt_hdr>cast();
            } else {
                // Found a header that is not an IPv6 extension header
                return parseIPInnerPacket(nextHdrType, hdr, dataEnd, info);
            }
        }

        return false;
    }

    /**
     * Parse a packet and extract the source and destination IP address and the protocol
     *
     * @param start start of the packet data
     * @param end   end of the packet data
     * @param info  output parameter for the extracted information
     * @return true if the packet is an IP packet and could be parsed, false otherwise
     */
    @BPFFunction
    @AlwaysInline
    default boolean parsePacket2(@Unsigned int start, @Unsigned int end, Ptr<PacketInfo> info) {
        return parsePacket(Ptr.voidPointer(start), Ptr.voidPointer(end), info);
    }

    /**
     * Parse a packet and extract the source and destination IP address and the protocol
     *
     * @param start start of the packet data
     * @param end   end of the packet data
     * @param info  output parameter for the extracted information
     * @return true if the packet is an IP packet and could be parsed, false otherwise
     */
    @BPFFunction
    @AlwaysInline
    default boolean parsePacket(Ptr<?> start, Ptr<?> end, Ptr<PacketInfo> info) {

        @Unsigned long offset;
        @Unsigned short ethType;

        Ptr<EthtoolDefinitions.ethhdr> eth = start.<EthtoolDefinitions.ethhdr>cast();
        offset = BPFJ.sizeof(eth.val());
        if (start.add(offset).greaterThan(end)) {
            // ethernet package header is incomplete
            return false;
        }
        info.val().length = (int) (end.asLong() - start.asLong());
        ethType = eth.val().h_proto;
        // handle VLAN tagged packet
        if (ethType == bpf_htons(XDPHook.ETH_P_8021Q) ||
                ethType == bpf_htons(XDPHook.ETH_P_8021AD)) {
            Ptr<VlanDefinitions.vlan_hdr> vlan_hdr = eth.add(offset).<VlanDefinitions.vlan_hdr>cast();
            offset += BPFJ.sizeof(vlan_hdr.val());
            if (eth.add(offset).greaterThan(end)) {
                // ethernet package header is incomplete
                return false;
            }
            ethType = vlan_hdr.val().h_vlan_encapsulated_proto;
        }

        ethType = bpf_ntohs(ethType);

        if (ethType == XDPHook.ETH_P_IP) {
            return parseIPPacket(start.add(offset).<runtime.iphdr>cast(), end, info);
        }
        if (ethType == XDPHook.ETH_P_IPV6) {
            return parseIPv6Packet(start.add(offset).<runtime.ipv6hdr>cast(), end, info);
        }
        return false;
    }
}