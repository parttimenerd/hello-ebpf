package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.bpf.BPFJ;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.CGroupHook;

import static me.bechberger.ebpf.bpf.BPFJ.bpf_trace_printk;
import static me.bechberger.ebpf.bpf.BPFJ.sizeof;
import static me.bechberger.ebpf.bpf.XDPHook.*;
import static me.bechberger.ebpf.runtime.SkDefinitions.*;
import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.bpf_skb_load_bytes;
import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.bpf_skb_load_bytes_relative;
import static me.bechberger.ebpf.samples.BasePacketParser.HTTP_PORT;

import me.bechberger.ebpf.bpf.raw.Lib_3;
import me.bechberger.ebpf.runtime.runtime;
import me.bechberger.ebpf.type.Ptr;

/**
 * Block all user processes from using HTTP
 * <p>
 * Inspiration from <a href="https://nfil.dev/coding/security/ebpf-firewall-with-cgroups/">nfil.dev</a>
 */
@BPF(license = "GPL")
public abstract class CGroupBlockHTTPEgress extends BPFProgram implements CGroupHook {

    @Override
    public CGroupAction cgroupHandleEgress(Ptr<__sk_buff> skb) {
        if (bpf_ntohl(skb.val().remote_port) == HTTP_PORT) {
            bpf_trace_printk("Blocked process from using HTTP");
            return CGroupAction.DROP;
        }
        return CGroupAction.PASS;
    }

    public static void main(String[] args) {
        try (CGroupBlockHTTPEgress program = BPFProgram.load(CGroupBlockHTTPEgress.class)) {
            program.cgroupAttachEgress();
            program.tracePrintLoop();
        }
    }

}
