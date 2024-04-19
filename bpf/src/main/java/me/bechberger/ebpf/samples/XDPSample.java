package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.XDPUtil;
import me.bechberger.ebpf.bpf.map.BPFHashMap;

import java.net.*;

/**
 * Use XDP to block incoming packages from a certain URL (first argument, default is google.com)
 * <p>
 * Based on the code from https://sematext.com/blog/ebpf-and-xdp-for-processing-packets-at-bare-metal-speed/
 */
@BPF(license = "GPL")
public abstract class XDPSample extends BPFProgram {

    @BPFMapDefinition(maxEntries = 256 * 4096)
    BPFHashMap<Integer, Boolean> blockedIPs;

    @BPFMapDefinition(maxEntries = 256 * 4096)
    BPFHashMap<Integer, Integer> blockingStats;

    private static final String EBPF_PROGRAM = """
            #include <vmlinux.h>
            #include <bpf/bpf_endian.h>
            #include <bpf/bpf_helpers.h>
            #include <bpf/bpf_tracing.h>
            
            // copied from the linux kernel
            #define AF_INET		2
            #define AF_INET6	10
            
            #define ETH_ALEN 6
            #define ETH_P_802_3_MIN 0x0600
            #define ETH_P_8021Q 0x8100
            #define ETH_P_8021AD 0x88A8
            #define ETH_P_IP 0x0800
            #define ETH_P_IPV6 0x86DD
            #define ETH_P_ARP 0x0806
            #define IPPROTO_ICMPV6 58

            SEC("xdp")
            int xdp_pass(struct xdp_md *ctx) {
              void *end = (void *)(long)ctx->data_end;
              void *data = (void *)(long)ctx->data;
              u32 ip_src;
              u64 offset;
              u16 eth_type;
          
              struct ethhdr *eth = data;
              offset = sizeof(*eth);
          
              if (data + offset > end) {
                return XDP_ABORTED;
              }
              eth_type = eth->h_proto;
          
              /* handle VLAN tagged packet */
              if (eth_type == bpf_htons(ETH_P_8021Q) || eth_type == bpf_htons(ETH_P_8021AD)) {
                    struct vlan_hdr *vlan_hdr;
          
                    vlan_hdr = (void *)eth + offset;
                    offset += sizeof(*vlan_hdr);
                    if ((void *)eth + offset > end)
                         return false;
                    eth_type = vlan_hdr->h_vlan_encapsulated_proto;
              }
              
              /* let's only handle IPv4 addresses */
              if (eth_type == bpf_ntohs(ETH_P_IPV6)) {
                  return XDP_PASS;
              }
          
              struct iphdr *iph = data + offset;
              offset += sizeof(struct iphdr);
              /* make sure the bytes you want to read are within the packet's range before reading them */
              if (iph + 1 > end) {
                  return XDP_ABORTED;
              }
              ip_src = iph->saddr;
              if (ip_src == 33925312) { // ignore the router IP
                  return XDP_PASS;
              }
              
              // find entry in block list
              void* ret = (void*)bpf_map_lookup_elem(&blockedIPs, &ip_src);
              if (!ret) {
                  return XDP_PASS;
              }
              if (*(s8*)ret) { // log if requested
                bpf_printk("IP source address: %d.%d.%d.%d", (ip_src >> 0) & 0xff, (ip_src >> 8) & 0xff, (ip_src >> 16) & 0xff, (ip_src >> 24) & 0xff);
              }
                
              // count the number of blocked packages
              s32* counter = bpf_map_lookup_elem(&blockingStats, &ip_src);
              if (counter) {
                 *counter += 1;
              } else {
                 u64 value = 1;
                 bpf_map_update_elem(&blockingStats, &ip_src, &value, BPF_ANY);
              }
          
              return XDP_DROP;
            }
            """;

    public static void main(String[] args) {
        var blockedUrl = args.length > 0 ? args[0] : "google.com";
        try (XDPSample program = BPFProgram.load(XDPSample.class)) {
            program.blockedIPs.put(XDPUtil.ipAddressToInt(InetAddress.getAllByName(blockedUrl)[0]), /* log */ true);
            XDPUtil.openURLInLoop(blockedUrl);
            program.xdpAttach(program.getProgramByName("xdp_pass"), XDPUtil.getNetworkInterfaceIndex());
            while (true) {
                program.blockingStats.forEach((ip, count) -> {
                    System.out.println("Blocked " + count + " packages from " + XDPUtil.intToIpAddress(ip));
                });
                Thread.sleep(1000);
            }
        } catch (UnknownHostException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
}
