package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a {@code @BPFMapDefinition} map-of-maps field with the name of a
 * sibling {@code @BPFMapDefinition} field that supplies the inner-map
 * template. The processor substitutes the sibling field name into the outer
 * map's C template as {@code __array(values, innerFieldName)}, which is
 * libbpf's BTF idiom for declaring an inner-map template. libbpf then
 * resolves the inner-map fd automatically during {@code bpf_object__load}.
 *
 * <p>Example:
 * <pre>{@code
 * @BPFMapDefinition(maxEntries = 1)
 * BPFHashMap<Long, Long> innerTemplate;
 *
 * @InnerMap("innerTemplate")
 * @BPFMapDefinition(maxEntries = 256)
 * BPFHashOfMaps<Integer, BPFHashMap<Long, Long>> outer;
 * }</pre>
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface InnerMap {
    /** Name of the sibling {@code @BPFMapDefinition} field to use as template. */
    String value();
}
