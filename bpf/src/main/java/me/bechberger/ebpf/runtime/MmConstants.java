package me.bechberger.ebpf.runtime;

/** Memory-management constants used by BPF arena helpers. */
public final class MmConstants {
    private MmConstants() {}

    /** Pass to {@code bpfArenaAllocPages} when no NUMA node preference. */
    public static final int NUMA_NO_NODE = -1;
}
