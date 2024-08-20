package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.AlwaysInline;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.*;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.bpf.map.BPFLRUHashMap;
import me.bechberger.ebpf.bpf.map.BPFRingBuffer;
import me.bechberger.ebpf.type.Enum;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.XdpDefinitions.*;

/**
 * Simple firewall blocking incoming IPv4 traffic
 */
@BPF(license = "GPL")
public abstract class Firewall extends BPFProgram implements XDPHook, BasePacketParser {

    @Type
    record IPAndPort(int ip, int port, boolean ingress) {
    }

    @Type
    record FirewallRule(int ip,
                       /* the low bytes of ip should be 0 */
                       int ignoreLowBytes,
                       /* -1 for ignored */
                       int port, boolean ingress) {
    }

    @Type
    enum FirewallAction implements Enum<FirewallAction> {
        ALLOW, DROP, NONE
    }

    @BPFMapDefinition(maxEntries = 1000)
    BPFHashMap<FirewallRule, FirewallAction> firewallRules;

    @BPFMapDefinition(maxEntries = 1000)
    BPFLRUHashMap<IPAndPort, Long> connectionCount;

    @BPFMapDefinition(maxEntries = 1000 * 128)
    BPFRingBuffer<IPAndPort> blockedConnections;

    @BPFMapDefinition(maxEntries = 1000)
    BPFLRUHashMap<IPAndPort, FirewallAction> resolvedRules;

    @BPFFunction
    @AlwaysInline
    int zeroLowBytes(int ip, int ignoreLowBytes) {
        return ip & (0xFFFFFFFF << (ignoreLowBytes * 8));
    }

    @BPFFunction
    @AlwaysInline
    FirewallAction computeSpecificAction(Ptr<IPAndPort> info, int ignoreLowBytes) {
        int ip = info.val().ip;
        // first null the bytes that should be ignored
        int matchingAddressBytes = zeroLowBytes(ip, ignoreLowBytes);
        var rule = new FirewallRule(matchingAddressBytes, ignoreLowBytes, info.val().port, info.val().ingress);
        var action = firewallRules.bpf_get(rule);
        if (action != null) {
            return action.val();
        }
        rule = new FirewallRule(matchingAddressBytes, ignoreLowBytes, -1, info.val().ingress);
        action = firewallRules.bpf_get(rule);
        if (action != null) {
            return action.val();
        }
        return FirewallAction.NONE;
    }

    @BPFFunction
    @AlwaysInline
    FirewallAction computeAction(Ptr<IPAndPort> info) {
        // for all possible ip address matching bytes, check if there is a rule for port or without port
        for (int i = 0; i < 5; i++) {
            var action = computeSpecificAction(info, i);
            if (action != FirewallAction.NONE) {
                return action;
            }
        }
        return FirewallAction.NONE;
    }

    @BPFFunction
    @AlwaysInline
    FirewallAction getAction(Ptr<PacketInfo> packetInfo) {
        // first create IPAndPort object
        IPAndPort ipAndPort = new IPAndPort(
                packetInfo.val().source.ipv4(), packetInfo.val().sourcePort,
                packetInfo.val().direction == PacketDirection.INCOMING);
        // then check resolved rules
        Ptr<FirewallAction> action = resolvedRules.bpf_get(ipAndPort);
        if (action != null) {
            return action.val();
        }
        // then check firewall rules
        var newAction = computeAction(Ptr.of(ipAndPort));
        resolvedRules.put(ipAndPort, newAction);
        return newAction;
    }

    @BPFFunction
    @AlwaysInline
    void countConnection(PacketInfo info) {
        IPAndPort ipAndPort;
        if (info.direction == PacketDirection.OUTGOING) {
            ipAndPort = new IPAndPort(info.destination.ipv4(), info.destinationPort, false);
        } else {
            ipAndPort = new IPAndPort(info.source.ipv4(), info.sourcePort, true);
        }
        Ptr<Long> count = connectionCount.bpf_get(ipAndPort);
        if (count == null) {
            long one = 1;
            connectionCount.put(ipAndPort, one);
        } else {
            count.set(count.val() + 1);
        }
    }

    @BPFFunction
    void recordBlockedConnection(PacketInfo info) {
        Ptr<IPAndPort> ptr = blockedConnections.reserve();
        if (ptr == null) {
            return;
        }
        if (info.direction == PacketDirection.OUTGOING) {
            ptr.set(new IPAndPort(info.destination.ipv4(), info.destinationPort, false));
        } else {
            ptr.set(new IPAndPort(info.source.ipv4(), info.sourcePort, true));
        }
        blockedConnections.submit(ptr);
    }

    @Override
    public xdp_action xdpHandlePacket(Ptr<xdp_md> ctx) {
        PacketInfo info = new PacketInfo();
        info.direction = PacketDirection.INCOMING;
        if (parsePacket2(ctx.val().data, ctx.val().data_end, Ptr.of(info))) {
            countConnection(info);
            var action = getAction(Ptr.of(info));
            if (action == FirewallAction.DROP) {
                recordBlockedConnection(info);
                return xdp_action.XDP_DROP;
            }
        }
        return xdp_action.XDP_PASS;
    }

    FirewallRule createRule(String url, int ignoreLowBytes, int port, boolean ingress) {
        int ip = NetworkUtil.ipAddressToInt(url);
        return new FirewallRule(zeroLowBytes(ip, ignoreLowBytes), ignoreLowBytes, port, ingress);
    }

    public static void main(String[] args) throws InterruptedException {
        try (Firewall program = BPFProgram.load(Firewall.class)) {
            program.firewallRules.put(program.createRule("google.com", 0, 80, false), FirewallAction.DROP);
            program.xdpAttach();
            // TODO logging and parse arguments from command line
            // use spring boot for small server
            program.blockedConnections.setCallback((info) -> {
                System.out.println("Blocked connection from " +
                        NetworkUtil.intToIpAddress(info.ip)
                                .getHostAddress() + " port " + info.port);
            });
            program.tracePrintLoop();
            while (true) {
                program.consumeAndThrow();
                Thread.sleep(500);
            }
        }
    }
}
