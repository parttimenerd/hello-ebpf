package me.bechberger.ebpf.bpf.structops;

import me.bechberger.ebpf.annotations.bpf.StructOps;
import me.bechberger.ebpf.runtime.SkDefinitions;
import me.bechberger.ebpf.runtime.runtime;
import me.bechberger.ebpf.type.Ptr;

/**
 * Marker interface for {@code Qdisc_ops}. Implement to register a
 * BPF-driven queueing discipline (qdisc) — used by the traffic-control
 * subsystem to queue and dequeue packets on a network interface.
 *
 * <p>{@link #enqueue(Ptr, Ptr)} returns an {@code __u32} kernel status
 * ({@code NET_XMIT_SUCCESS} = 0, {@code NET_XMIT_DROP} = 1, etc.).
 */
@StructOps("Qdisc_ops")
public interface QdiscOps {

    default int  enqueue(Ptr<SkDefinitions.sk_buff> skb, Ptr<runtime.Qdisc> sch) { return 0; /* NET_XMIT_SUCCESS */ }
    default Ptr<SkDefinitions.sk_buff> dequeue(Ptr<runtime.Qdisc> sch)           { return null; }
    default int  init(Ptr<runtime.Qdisc> sch)                                     { return 0; }
    default void reset(Ptr<runtime.Qdisc> sch)                                    { }
    default void destroy(Ptr<runtime.Qdisc> sch)                                  { }
}
