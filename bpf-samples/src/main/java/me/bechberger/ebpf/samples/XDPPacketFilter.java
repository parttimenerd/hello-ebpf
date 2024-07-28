package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.BPFJ;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.XDPHook;
import me.bechberger.ebpf.bpf.XDPUtil;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.runtime.EthtoolDefinitions.ethhdr;
import me.bechberger.ebpf.runtime.VlanDefinitions.vlan_hdr;
import me.bechberger.ebpf.runtime.XdpDefinitions.xdp_action;
import me.bechberger.ebpf.runtime.XdpDefinitions.xdp_md;
import me.bechberger.ebpf.runtime.runtime.iphdr;
import me.bechberger.ebpf.type.Ptr;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.net.*;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Use XDP to block incoming packages from specific URLs in Java
 * <p>
 * Based on the code from <a href="https://sematext.com/blog/ebpf-and-xdp-for-processing-packets-at-bare-metal-speed/">sematext.com</a>.
 * Albeit, this code can be found in many other places, as
 * it is the most straightforward example of using XDP to block incoming packages.
 * <p>
 * This is the new version of {@link XDPPacketFilter2} which is implemented without a single line of C code
 * using the Java compiler plugin.
 */
@BPF(license = "GPL")
@Command(name = "XDPPacketFilter", mixinStandardHelpOptions = true,
        description = "Use XDP to block incoming IPv4 packages from a URLs")
public abstract class XDPPacketFilter extends BPFProgram implements XDPHook, Runnable {

    @BPFMapDefinition(maxEntries = 256 * 4096)
    BPFHashMap<Integer, Boolean> blockedIPs;

    @BPFMapDefinition(maxEntries = 256 * 4096)
    BPFHashMap<Integer, Integer> blockingStats;

    @Override
    public xdp_action xdpHandlePacket(Ptr<xdp_md> ctx) {
        Ptr<?> end = Ptr.voidPointer(ctx.val().data_end);
        Ptr<?> data = Ptr.voidPointer(ctx.val().data);
        @Unsigned int ip_src;
        @Unsigned long offset;
        @Unsigned short eth_type;

        Ptr<ethhdr> eth = data.<ethhdr>cast();
        offset = BPFJ.sizeof(eth.val());
        if (data.add(offset).greaterThan(end)) {
            // ethernet package header is incomplete
            return xdp_action.XDP_ABORTED;
        }
        eth_type = eth.val().h_proto;
        // handle VLAN tagged packet
        if (eth_type == XDPHook.bpf_htons(ETH_P_8021Q) || eth_type == XDPHook.bpf_htons(ETH_P_8021AD)) {
            Ptr<vlan_hdr> vlan_hdr = eth.add(offset).<vlan_hdr>cast();
            offset += BPFJ.sizeof(vlan_hdr.val());
            if (eth.add(offset).greaterThan(end)) {
                // ethernet package header is incomplete
                return xdp_action.XDP_PASS;
            }
            eth_type = vlan_hdr.val().h_vlan_encapsulated_proto;
        }

        // let's only handle IPv4 addresses
        if (eth_type != XDPHook.bpf_htons(ETH_P_IP)) {
            return xdp_action.XDP_PASS;
        }

        Ptr<iphdr> iph = data.add(offset).<iphdr>cast();
        offset += BPFJ.sizeof(iph.val());
        // make sure the bytes you want to read are within the packet's range before reading them
        if (iph.add(1).greaterThan(end)) {
            return xdp_action.XDP_ABORTED;
        }

        ip_src = iph.val().addrs.saddr;
        Ptr<?> ret = blockedIPs.bpf_get(ip_src);
        if (ret == null) {
            return xdp_action.XDP_PASS;
        }

        // count the number of blocked packages
        Ptr<Integer> counter = blockingStats.bpf_get(ip_src);
        if (counter != null) {
            // use atomics to prevent a race condition when a packet
            // from the same IP address is received on two
            // different cores at the same time
            // (thanks Dylan Reimerink for catching this bug)
            BPFJ.sync_fetch_and_add(counter, 1);
        } else {
            int value = 1;
            blockingStats.put(ip_src, value);
        }

        return xdp_action.XDP_DROP;
    }

    @Parameters(arity = "1..*", description = "URLs to block")
    private String[] blockedUrls;

    @Option(names = "--run-url-retrieve-loop", description = "Try to retrieve the content of the first URL in a loop")
    private boolean runURLRetrieveLoop;

    private Map<Integer, String> ipToUrlMap;

    void setupBlockedIPMap() {
        ipToUrlMap = Arrays.stream(blockedUrls).flatMap(url -> {
            try {
                return Arrays.stream(InetAddress.getAllByName(url)).map(addr -> Map.entry(XDPUtil.ipAddressToInt(addr), url));
            } catch (UnknownHostException e) {
                throw new RuntimeException(e);
            }
        }).collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
        ipToUrlMap.keySet().forEach(ip -> {
            blockedIPs.put(ip, true);
        });
    }

    void printBlockedLog() {
        System.out.println("Blocked packages:");
        blockingStats.forEach((ip, count) -> {
            System.out.println("  Blocked " + count + " packages from " +
                    XDPUtil.intToIpAddress(ip) +
                    " (" + ipToUrlMap.get(ip) + ")");
        });
    }

    @Override
    public void run() {
        setupBlockedIPMap();
        if (runURLRetrieveLoop) {
            XDPUtil.openURLInLoop(blockedUrls[0]);
        }
        xdpAttach(XDPUtil.getNetworkInterfaceIndex());
        while (true) {
            printBlockedLog();
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }
    }

    public static void main(String[] args) {
        try (XDPPacketFilter program = BPFProgram.load(XDPPacketFilter.class)) {
            var cmd = new CommandLine(program);
            cmd.parseArgs(args);
            if (cmd.isUsageHelpRequested()) {
                cmd.usage(System.out);
                return;
            }
            program.run();
        }
    }
}
