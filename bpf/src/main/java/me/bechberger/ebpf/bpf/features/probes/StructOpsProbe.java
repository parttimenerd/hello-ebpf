package me.bechberger.ebpf.bpf.features.probes;

import me.bechberger.ebpf.bpf.features.ProbeResult;

/**
 * Struct_ops probe via vmlinux BTF scan (spec §6.5). Presence of the kernel
 * struct type is treated as authoritative — the registration path always
 * accompanies the type definition on 6.14+.
 */
public final class StructOpsProbe {

    private StructOpsProbe() {}

    public static ProbeResult probe(String kernelStructName) {
        if (!BtfLoader.isAvailable()) {
            return new ProbeResult.ProbeUnavailable(
                    "cannot read /sys/kernel/btf/vmlinux");
        }
        return BtfLoader.hasStructByName(kernelStructName)
                ? new ProbeResult.Supported()
                : new ProbeResult.Unsupported("struct not present in vmlinux BTF");
    }
}
