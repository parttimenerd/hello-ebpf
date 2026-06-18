package me.bechberger.ebpf.annotations.bpf;

/**
 * BPF program types that helpers may be allowed in.
 *
 * <p>Used as values for {@link AllowedIn} to declare which program types may
 * call a given {@link BuiltinBPFFunction}.
 *
 * <p>The string form ({@link #fromSection}) maps libbpf-style section prefixes
 * (e.g. {@code "xdp"}, {@code "kprobe/do_sys_open"}, {@code "tp/syscalls/sys_enter_openat"})
 * to enum values. {@link #UNKNOWN} is returned for sections that don't match a
 * known prefix; the helper-context pass treats {@code UNKNOWN} as permissive
 * (no error reported).
 */
public enum ProgramType {
    XDP,
    TC,
    CGROUP_SKB,
    LSM,
    KPROBE,
    KRETPROBE,
    FENTRY,
    FEXIT,
    TRACEPOINT,
    RAW_TRACEPOINT,
    KSYSCALL,
    STRUCT_OPS,
    UNKNOWN;

    /** Map a libbpf section string to a {@link ProgramType}. */
    public static ProgramType fromSection(String section) {
        if (section == null || section.isEmpty()) return UNKNOWN;
        if (section.equals("xdp") || section.startsWith("xdp/")) return XDP;
        if (section.equals("tc") || section.startsWith("tc/") || section.startsWith("classifier/")) return TC;
        if (section.startsWith("cgroup_skb/") || section.startsWith("cgroup/")) return CGROUP_SKB;
        if (section.startsWith("lsm/") || section.startsWith("lsm_cgroup/")) return LSM;
        if (section.startsWith("kprobe/")) return KPROBE;
        if (section.startsWith("kretprobe/")) return KRETPROBE;
        if (section.startsWith("fentry/")) return FENTRY;
        if (section.startsWith("fexit/")) return FEXIT;
        if (section.startsWith("tp/") || section.startsWith("tracepoint/")) return TRACEPOINT;
        if (section.startsWith("raw_tracepoint/") || section.startsWith("raw_tp/")) return RAW_TRACEPOINT;
        if (section.startsWith("ksyscall/") || section.startsWith("kretsyscall/")) return KSYSCALL;
        if (section.startsWith("struct_ops/") || section.startsWith("struct_ops.s/")) return STRUCT_OPS;
        return UNKNOWN;
    }
}
