package me.bechberger.ebpf.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a pointer as living in a {@link me.bechberger.ebpf.bpf.map.BPFArena}'s
 * address space (clang AS1, spelled {@code __arena} in C).
 *
 * <p>The compiler plugin emits the {@code __arena} type qualifier on the
 * declaration so clang's address-space inference picks the correct
 * load/store path. With clang 17+ {@code __BPF_FEATURE_ADDR_SPACE_CAST}
 * (kernel ≥6.17), the implicit {@code cast_kern}/{@code cast_user}
 * conversions happen automatically, so user code can dereference arena
 * pointers like any other pointer.
 *
 * <p>Region inference uses {@link InArena} to seed the
 * {@link me.bechberger.ebpf.bpf.compiler.flow.MemoryRegion#ARENA} lattice
 * value so cross-region mixing (e.g. an arena pointer joined with a kernel
 * pointer) can be flagged.
 *
 * <p>Applies to fields, local variables, parameters, and as a
 * {@link ElementType#TYPE_USE} qualifier on a wrapped {@code Ptr<T>}.
 *
 * @see me.bechberger.ebpf.bpf.map.BPFArena
 */
@Target({
        ElementType.FIELD,
        ElementType.LOCAL_VARIABLE,
        ElementType.PARAMETER,
        ElementType.TYPE_USE
})
@Retention(RetentionPolicy.SOURCE)
public @interface InArena {
}
