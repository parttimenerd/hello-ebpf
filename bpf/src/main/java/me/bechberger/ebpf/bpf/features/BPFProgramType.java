package me.bechberger.ebpf.bpf.features;

import org.jetbrains.annotations.Nullable;

/** Kernel BPF program types. Values match {@code uapi/linux/bpf.h} enum bpf_prog_type. */
public enum BPFProgramType {
    UNSPEC(0), SOCKET_FILTER(1), KPROBE(2), SCHED_CLS(3), SCHED_ACT(4),
    TRACEPOINT(5), XDP(6), PERF_EVENT(7), CGROUP_SKB(8), CGROUP_SOCK(9),
    LWT_IN(10), LWT_OUT(11), LWT_XMIT(12), SOCK_OPS(13), SK_SKB(14),
    CGROUP_DEVICE(15), SK_MSG(16), RAW_TRACEPOINT(17), CGROUP_SOCK_ADDR(18),
    LWT_SEG6LOCAL(19), LIRC_MODE2(20), SK_REUSEPORT(21), FLOW_DISSECTOR(22),
    CGROUP_SYSCTL(23), RAW_TRACEPOINT_WRITABLE(24), CGROUP_SOCKOPT(25),
    TRACING(26), STRUCT_OPS(27), EXT(28), LSM(29), SK_LOOKUP(30),
    SYSCALL(31), NETFILTER(32);

    private final int id;
    BPFProgramType(int id) { this.id = id; }
    public int id() { return id; }

    public static @Nullable BPFProgramType fromId(int id) {
        for (var t : values()) if (t.id == id) return t;
        return null;
    }
}
