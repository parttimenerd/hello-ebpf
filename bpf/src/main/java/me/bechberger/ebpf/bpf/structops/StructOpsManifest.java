package me.bechberger.ebpf.bpf.structops;

import java.util.List;

/**
 * SPI: the compiler plugin emits an implementation of this alongside
 * {@code BPFImpl}. {@link StructOpsAttach#attachAll} reads it at runtime
 * to know which struct_ops maps to attach without reflecting over the
 * class's Java interfaces.
 *
 * <p>Companion class naming: for user class {@code Foo}, the plugin emits
 * {@code FooStructOpsManifest} in the same package.
 */
public interface StructOpsManifest {

    /**
     * One entry per {@code @StructOps} interface implemented by the user's class.
     *
     * @param kernelName the kernel struct_ops kind (e.g. "tcp_congestion_ops")
     * @param mapName    the C-side instance variable name — matches
     *                   {@code bpf_object__find_map_by_name}
     * @param since      minimum kernel version (from the JSON layout;
     *                   fed into {@code BPFLoadError.UnsupportedKernel} on miss)
     */
    record Entry(String kernelName, String mapName, String since) {}

    List<Entry> entries();
}
