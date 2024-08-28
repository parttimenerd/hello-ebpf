package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.AlwaysInline;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.*;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.bpf.map.BPFLRUHashMap;
import me.bechberger.ebpf.bpf.map.BPFRingBuffer;
import me.bechberger.ebpf.type.Enum;
import me.bechberger.ebpf.type.Ptr;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static me.bechberger.ebpf.bpf.BPFJ.bpf_trace_printk;
import static me.bechberger.ebpf.runtime.XdpDefinitions.*;
import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.bpf_ktime_get_ns;

@BPF(license = "GPL")
public abstract class Firewall extends BPFProgram implements XDPHook, BasePacketParser {

    private static final Logger logger = LoggerFactory.getLogger(Firewall.class);

    @Type
    record IPAndPort(int ip, int sourcePort, int destPort) {
    }

@Type
record LogEntry(IPAndPort connection, long timeInMs) {
}

    @Type
    record FirewallRule(@Unsigned int ip,
                        int ignoreLowBytes,
                        int sourcePort,
                        int destPort) {
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
    BPFRingBuffer<LogEntry> blockedConnections;

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
        var sourcePort = info.val().sourcePort;
        var destPort = info.val().destPort;
        // first null the bytes that should be ignored
        int matchingAddressBytes = zeroLowBytes(ip, ignoreLowBytes);
        if (matchingAddressBytes == 0) { // don't ask
            bpf_trace_printk("Checking rule for %d:%d\n", matchingAddressBytes, sourcePort);
        }
        var rule = new FirewallRule(matchingAddressBytes, ignoreLowBytes, sourcePort, destPort);
        var action = firewallRules.bpf_get(rule);
        if (action != null) {
            return action.val();
        }
        rule = new FirewallRule(matchingAddressBytes, ignoreLowBytes, sourcePort, -1);
        action = firewallRules.bpf_get(rule);
        if (action != null) {
            return action.val();
        }
        rule = new FirewallRule(matchingAddressBytes, ignoreLowBytes, -1, destPort);
        action = firewallRules.bpf_get(rule);
        if (action != null) {
            return action.val();
        }
        rule = new FirewallRule(matchingAddressBytes, ignoreLowBytes, -1, -1);
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
        IPAndPort ipAndPort = new IPAndPort(
                packetInfo.val().source.ipv4(), packetInfo.val().sourcePort, packetInfo.val().destinationPort);
        Ptr<FirewallAction> action = resolvedRules.bpf_get(ipAndPort);
        if (action != null) {
            return action.val();
        }
        var newAction = computeAction(Ptr.of(ipAndPort));
        bpf_trace_printk("Unresolved action for %d:%d %d\n", ipAndPort.ip(), ipAndPort.sourcePort, newAction.value());
        resolvedRules.put(ipAndPort, newAction);
        return newAction;
    }

    @BPFFunction
    @AlwaysInline
    void countConnection(PacketInfo info) {
        IPAndPort ipAndPort = new IPAndPort(info.source.ipv4(), info.sourcePort, info.destinationPort);
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
        Ptr<LogEntry> ptr = blockedConnections.reserve();
        if (ptr == null) {
            return;
        }
        ptr.set(
                new LogEntry(new IPAndPort(info.source.ipv4(), info.sourcePort, info.destinationPort),
                        bpf_ktime_get_ns() / 1000000));
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

    record FirewallRuleAndAction(FirewallRule rule, FirewallAction action) {
    }

    static FirewallRuleAndAction parseRule(String rule) {
        FirewallRule firewallRule;
        var rulePart = rule.split(" ")[0];
        if (rule.contains("/")) {
            if (!rulePart.matches(".*/(0|8|16|32):.*(:.*)?")) {
                throw new IllegalArgumentException("Invalid rule: " + rule + ", should match .*/(0|8|16|32):.*(:.*)?");
            }
            String[] parts = rulePart.split(":");
            String[] ipParts = parts[0].split("/");
            int ip = NetworkUtil.ipAddressToInt(ipParts[0]);
            int ignoreLowBytes = 32 - Integer.parseInt(ipParts[1]) / 8;
            int sourcePort = parsePort(parts[1]);
            int targetPort = parts.length == 3 ? parsePort(parts[2]) : -1;
            firewallRule = new FirewallRule(zeroLowBytes(ip, ignoreLowBytes), ignoreLowBytes, sourcePort, targetPort);
        } else {
            if (!rulePart.matches(".+:.*(:.*)?")) {
                throw new IllegalArgumentException("Invalid rule: " + rule + ", should match .+:.*(:.*)?");
            }
            String[] parts = rulePart.split(":");
            int ip = NetworkUtil.getFirstIPAddress(parts[0]);
            int sourcePort = parsePort(parts[1]);
            int targetPort = parts.length == 3 ? parsePort(parts[2]) : -1;
            firewallRule = new FirewallRule(ip, 0, sourcePort, targetPort);
        }
        var actionPart = rule.split(" ")[1];
        FirewallAction action = switch (actionPart) {
            case "drop" -> FirewallAction.DROP;
            case "pass" -> FirewallAction.ALLOW;
            default -> throw new IllegalArgumentException("Unknown action: " + actionPart);
        };
        logger.info("Rule: {} action: {}", firewallRule, action);
        return new FirewallRuleAndAction(firewallRule, action);
    }

    public static void main(String[] args) throws InterruptedException {
        try (Firewall program = BPFProgram.load(Firewall.class)) {
            for (String rule : args) {
                var ruleAndAction = parseRule(rule);
                program.firewallRules.put(ruleAndAction.rule, ruleAndAction.action);
            }
            program.xdpAttach();
            program.blockedConnections.setCallback((info) -> {
                logger.info("Blocked packet from {} port {} to port {}",
                        NetworkUtil.intToIpAddress(info.connection.ip).getHostAddress(),
                        info.connection.sourcePort, info.connection.destPort);
            });
            while (true) {
                program.consumeAndThrow();
                Thread.sleep(500);
            }
        }
    }
}