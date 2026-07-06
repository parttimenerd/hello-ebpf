package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.*;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.SkDefinitions.__sk_action;

/**
 * TC-based firewall: block ingress traffic on specific destination ports.
 * <p>
 * Usage: {@code sudo java --enable-native-access=ALL-UNNAMED -cp target/bpf-samples.jar \
 *   me.bechberger.ebpf.samples.TCFirewall 80 443}
 * <p>
 * Any port numbers passed as command-line arguments are blocked. All other traffic passes.
 */
@BPF(license = "GPL")
public abstract class TCFirewall extends BPFProgram implements TCHook, BasePacketParser {

    /** Ports to block: key = destination port, value = 1. */
    @BPFMapDefinition(maxEntries = 256)
    BPFHashMap<Integer, Integer> blockedPorts;

    @Override
    public __sk_action tcHandleIngress(TCContext skb) {
        PacketInfo info = new PacketInfo();
        if (parsePacket(skb, Ptr.of(info))) {
            Ptr<Integer> blocked = blockedPorts.bpf_get(info.destinationPort);
            if (blocked != null) {
                return __sk_action.__SK_DROP;
            }
        }
        return __sk_action.__SK_PASS;
    }

    public static void main(String[] args) throws InterruptedException {
        try (TCFirewall program = BPFProgram.load(TCFirewall.class)) {
            for (String arg : args) {
                int port = Integer.parseInt(arg);
                program.blockedPorts.put(port, 1);
                System.out.println("Blocking destination port " + port);
            }
            program.tcAttachIngress();
            System.out.println("TC firewall running. Ctrl-C to stop.");
            while (true) {
                Thread.sleep(1000);
            }
        }
    }
}
