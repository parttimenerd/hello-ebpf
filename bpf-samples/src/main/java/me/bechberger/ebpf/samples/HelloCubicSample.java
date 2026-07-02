// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.bpf.BPFJ;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.structops.TcpCongestionControl;
import me.bechberger.ebpf.runtime.runtime;
import me.bechberger.ebpf.type.Ptr;

/**
 * A minimal TCP congestion-control algorithm registered as {@code hellocubic}.
 * On each {@code congAvoid} call, the program emits a {@code bpf_trace_printk}
 * line so the trace pipe shows evidence the algorithm is active.
 *
 * <p>Usage:
 * <pre>{@code
 *   sudo java -cp ... HelloCubicSample
 *   # in another terminal:
 *   echo hellocubic | sudo tee /proc/sys/net/ipv4/tcp_congestion_control
 *   # generate traffic (e.g. curl a large file), then:
 *   sudo cat /sys/kernel/debug/tracing/trace_pipe
 * }</pre>
 *
 * <p>The kernel accepts algorithms declared here as valid entries in
 * {@code /proc/sys/net/ipv4/tcp_available_congestion_control} for as
 * long as the program is loaded; unloading (this JVM exits) removes them.
 */
@BPF
public abstract class HelloCubicSample extends BPFProgram implements TcpCongestionControl {

    @Override
    public @Unsigned int ssthresh(Ptr<runtime.sock> sk) {
        return 4;
    }

    @Override
    public void congAvoid(Ptr<runtime.sock> sk, @Unsigned int ack, @Unsigned int acked) {
        BPFJ.bpf_trace_printk("hellocubic congAvoid ack=%u acked=%u", ack, acked);
    }

    @Override
    public String name() {
        return "hellocubic";
    }

    public static void main(String[] args) throws Exception {
        try (var prog = BPFProgram.load(HelloCubicSample.class)) {
            System.out.println("hellocubic registered. To activate:");
            System.out.println("  echo hellocubic | sudo tee /proc/sys/net/ipv4/tcp_congestion_control");
            System.out.println("Trace: sudo cat /sys/kernel/debug/tracing/trace_pipe");
            System.out.println("Press Ctrl-C to unregister.");
            Thread.sleep(Long.MAX_VALUE);
        }
    }
}
