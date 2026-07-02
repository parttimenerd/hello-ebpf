package me.bechberger.ebpf.bpf.features;

import me.bechberger.ebpf.bpf.map.MapTypeId;
import org.jetbrains.annotations.Nullable;

/**
 * Cache key discriminant for {@link Features}' probe cache.
 * One record per probe kind; record equality gives us the map key semantics
 * for free.
 */
public sealed interface ProbeKey {

    record ProgramTypeKey(BPFProgramType t)             implements ProbeKey {}
    record MapTypeKey(MapTypeId t)                      implements ProbeKey {}
    record HelperKey(BPFHelper h)                       implements ProbeKey {}
    record KfuncKey(String name, @Nullable String mod)  implements ProbeKey {}
    record StructOpsKey(String name)                    implements ProbeKey {}
    record AttachTypeKey(BPFAttachType t)               implements ProbeKey {}
}
