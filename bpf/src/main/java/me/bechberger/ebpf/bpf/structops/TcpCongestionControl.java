package me.bechberger.ebpf.bpf.structops;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.StructOps;
import me.bechberger.ebpf.runtime.runtime;
import me.bechberger.ebpf.runtime.misc;
import me.bechberger.ebpf.type.Ptr;

/**
 * Marker interface for {@code tcp_congestion_ops}. Implement on a
 * {@code @BPF} class to register a TCP congestion-control algorithm.
 * After {@code BPFProgram.load()}, the algorithm's {@link #name()} appears
 * in {@code /proc/sys/net/ipv4/tcp_available_congestion_control} and can
 * be selected system-wide via {@code sysctl}.
 *
 * <p>The kernel accepts NULL for optional callbacks; only override what
 * you implement. {@link #name()} is required and must be unique across
 * loaded CC algorithms.
 */
@StructOps("tcp_congestion_ops")
public interface TcpCongestionControl {

    default void init(Ptr<runtime.sock> sk)                 { }
    default void release(Ptr<runtime.sock> sk)              { }
    default @Unsigned int ssthresh(Ptr<runtime.sock> sk)    { return 0; }
    default void congAvoid(Ptr<runtime.sock> sk, @Unsigned int ack, @Unsigned int acked) { }
    default void setState(Ptr<runtime.sock> sk, @Unsigned int newState) { }
    default void cwndEvent(Ptr<runtime.sock> sk, @Unsigned int event) { }
    default @Unsigned int undoCwnd(Ptr<runtime.sock> sk)    { return 0; }
    default void pktsAcked(Ptr<runtime.sock> sk, Ptr<misc.rate_sample> rs) { }
    default @Unsigned int minTso(Ptr<runtime.sock> sk)      { return 0; }

    /** Algorithm name. Registered as the identifier the kernel selects on. */
    default String name() { return "hello_cc"; }
}
