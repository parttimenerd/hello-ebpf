package me.bechberger.ebpf.bpf.structops;

import me.bechberger.ebpf.annotations.bpf.StructOps;
import me.bechberger.ebpf.runtime.NetlinkDefinitions;
import me.bechberger.ebpf.runtime.SkDefinitions;
import me.bechberger.ebpf.runtime.runtime;
import me.bechberger.ebpf.type.Ptr;

/**
 * Marker interface for {@code Qdisc_ops}. Implement to register a
 * BPF-driven queueing discipline (qdisc) — used by the traffic-control
 * subsystem to queue and dequeue packets on a network interface.
 *
 * <p>{@link #enqueue} returns a kernel {@code NET_XMIT_*} status
 * ({@code NET_XMIT_SUCCESS} = 0, {@code NET_XMIT_DROP} = 1, etc.).
 *
 * <p>{@link #id()} is the qdisc kind string (max 16 chars including the
 * terminating null). It is what {@code tc qdisc add ... <id>} matches on.
 */
@StructOps("Qdisc_ops")
public interface QdiscOps {

    default int enqueue(Ptr<SkDefinitions.sk_buff> skb, Ptr<runtime.Qdisc> sch,
                        Ptr<Ptr<SkDefinitions.sk_buff>> toFree)                  { return 0; }
    default Ptr<SkDefinitions.sk_buff> dequeue(Ptr<runtime.Qdisc> sch)           { return null; }
    default int init(Ptr<runtime.Qdisc> sch, Ptr<runtime.nlattr> opt,
                     Ptr<NetlinkDefinitions.netlink_ext_ack> extack)             { return 0; }
    default void reset(Ptr<runtime.Qdisc> sch)                                    { }
    default void destroy(Ptr<runtime.Qdisc> sch)                                  { }

    /** Qdisc kind identifier — the string {@code tc qdisc add ... <id>} matches on. */
    default String id() { return "hello_qdisc"; }
}
