package me.bechberger.ebpf.bpf.structops;

/**
 * Post-attach diagnostic for a single {@code @StructOps} instance.
 * Available via {@code BPFProgram.structOpsInfo()}.
 *
 * @param kernelName kernel BTF type name (e.g. {@code "tcp_congestion_ops"})
 * @param mapName    C-side struct variable name (matches
 *                   {@code bpf_object__find_map_by_name})
 * @param mapFd      the map's file descriptor
 * @param bpfLinkId  the {@code bpf_map__attach_struct_ops} return; 0 if the
 *                   attach was rejected as unsupported and gracefully skipped
 */
public record StructOpsInfo(
        String kernelName,
        String mapName,
        int mapFd,
        long bpfLinkId) {}
