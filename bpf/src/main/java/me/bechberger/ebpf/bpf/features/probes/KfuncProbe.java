package me.bechberger.ebpf.bpf.features.probes;

import me.bechberger.ebpf.bpf.features.ProbeResult;
import org.jetbrains.annotations.Nullable;

/**
 * Kfunc probe via vmlinux BTF scan. Module kfuncs (moduleName != null) are
 * currently reported as {@code ProbeUnavailable} — module BTF loading is a
 * follow-up (see spec §6.4 caveat).
 */
public final class KfuncProbe {

    private KfuncProbe() {}

    public static ProbeResult probe(String name, @Nullable String moduleName) {
        if (moduleName != null) {
            return new ProbeResult.ProbeUnavailable(
                    "module-kfunc probing not implemented (module=" + moduleName + ")");
        }
        if (!BtfLoader.isAvailable()) {
            return new ProbeResult.ProbeUnavailable(
                    "cannot read /sys/kernel/btf/vmlinux");
        }
        return BtfLoader.hasFuncByName(name)
                ? new ProbeResult.Supported()
                : new ProbeResult.Unsupported("not present in vmlinux BTF");
    }
}
