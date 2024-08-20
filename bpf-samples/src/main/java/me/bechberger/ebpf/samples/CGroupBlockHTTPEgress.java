package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.CGroupHook;

import static me.bechberger.ebpf.bpf.BPFJ.bpf_trace_printk;
import static me.bechberger.ebpf.bpf.XDPHook.bpf_ntohl;
import static me.bechberger.ebpf.runtime.SkDefinitions.*;
import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.bpf_get_current_comm;
import static me.bechberger.ebpf.samples.BasePacketParser.HTTP_PORT;

import me.bechberger.ebpf.bpf.GlobalVariable;
import me.bechberger.ebpf.shared.TraceLog;
import me.bechberger.ebpf.type.Ptr;

/**
 * Log egress packets on a cgroup and drop every third packet
 * <p>
 * Inspiration from <a href="https://nfil.dev/coding/security/ebpf-firewall-with-cgroups/">nfil.dev</a>
 */
@BPF(license = "GPL")
public abstract class CGroupSample extends BPFProgram implements CGroupHook {

    @Override
    public CGroupAction cgroupHandleEgress(Ptr<__sk_buff> skb) {
        if (bpf_ntohl(skb.val().remote_port) == HTTP_PORT) {
            bpf_trace_printk("Blocked process from using HTTP", comm);
            return CGroupAction.DROP;
        }
        return CGroupAction.PASS;
    }

    public static void main(String[] args) {
        try (CGroupSample program = BPFProgram.load(CGroupSample.class)) {
            program.cgroupAttachEgress();
            program.tracePrintLoop();
        }
    }

}
