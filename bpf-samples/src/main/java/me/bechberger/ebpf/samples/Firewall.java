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
import org.jetbrains.annotations.Nullable;

import static me.bechberger.ebpf.runtime.XdpDefinitions.*;

/**
 * Simple firewall blocking incoming IPv4 traffic
 */
@BPF(license = "GPL")
public abstract class Firewall extends BPFProgram implements XDPHook, BasePacketParser {

    @Type
    record IPAndPort(int ip, int port) {
    }

    @Type
    record FirewallRule(int ip,
                       /* the low bytes of ip should be 0 */
                       int ignoreLowBytes,
                       /* -1 for ignored */
                       int port) {
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
    static int zeroLowBytes(int ip, int ignoreLowBytes) {
        return ip & (0xFFFFFFFF << (ignoreLowBytes * 8));
    }

    @BPFFunction
    @AlwaysInline
    FirewallAction computeSpecificAction(Ptr<IPAndPort> info, int ignoreLowBytes) {
        int ip = info.val().ip;
        // first null the bytes that should be ignored
        int matchingAddressBytes = zeroLowBytes(ip, ignoreLowBytes);
        var rule = new FirewallRule(matchingAddressBytes, ignoreLowBytes, info.val().port);
        var action = firewallRules.bpf_get(rule);
        if (action != null) {
            return action.val();
        }
        rule = new FirewallRule(matchingAddressBytes, ignoreLowBytes, -1);
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
                packetInfo.val().source.ipv4(), packetInfo.val().sourcePort);
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
        IPAndPort ipAndPort = new IPAndPort(info.source.ipv4(), info.sourcePort);
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
        ptr.set(new IPAndPort(info.source.ipv4(), info.sourcePort));
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

    private static int parsePort(String port) {
        return switch (port) {
            case "HTTP" -> HTTP_PORT;
            case "HTTPS" -> HTTPS_PORT;
            case "ANY" -> -1;
            default -> Integer.parseInt(port);
        };
    }

    private record FirewallRuleAndAction(FirewallRule rule, FirewallAction action) {
    }

    /**
     * Rules can have two different formats:
     * 1. {@code <ipv4>/<mask, used top bits, factor of 8>:<port or HTTP,HTTPS,ANY> <drop, pass>},
     * 2. {@code <url>:<port or HTTP,HTTPS,ANY> <drop, pass>}.
     * @return FirewallRule
     */
    private static FirewallRuleAndAction parseRule(String rule) {
        FirewallRule firewallRule;
        var rulePart = rule.split(" ")[0];
        if (rule.contains("/")) { // we have the first type
            String[] parts = rulePart.split(":");
            String[] ipParts = parts[0].split("/");
            int ip = NetworkUtil.ipAddressToInt(ipParts[0]);
            int ignoreLowBytes = 32 - Integer.parseInt(ipParts[1]) / 8;
            int port = parsePort(parts[1]);
            firewallRule = new FirewallRule(zeroLowBytes(ip, ignoreLowBytes), ignoreLowBytes, port);
        } else {
            String[] parts = rulePart.split(":");
            int ip = NetworkUtil.getFirstIPAddress(parts[0]);
            int port = parsePort(parts[1]);
            firewallRule = new FirewallRule(ip, 0, port);
        }
        var actionPart = rule.split(" ")[1];
        FirewallAction action = switch (actionPart) {
            case "drop" -> FirewallAction.DROP;
            case "pass" -> FirewallAction.ALLOW;
            default -> throw new IllegalArgumentException("Unknown action: " + actionPart);
        };
        System.out.println("Rule: " + firewallRule + " action: " + action);
        return new FirewallRuleAndAction(firewallRule, action);
    }

    public static void main(String[] args) throws InterruptedException {
        try (Firewall program = BPFProgram.load(Firewall.class)) {
            for (String rule : args) {
                var ruleAndAction = parseRule(rule);
                program.firewallRules.put(ruleAndAction.rule, ruleAndAction.action);
            }
            program.xdpAttach();
            // use spring boot for small server
            program.blockedConnections.setCallback((info) -> {
                System.out.println("Blocked packet from " +
                        NetworkUtil.intToIpAddress(info.ip)
                                .getHostAddress() + " port " + info.port);
            });
            while (true) {
                program.consumeAndThrow();
                Thread.sleep(500);
            }
        }
    }
}
