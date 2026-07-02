package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a {@code @BPFMapDefinition} map-of-maps field with the name of a
 * sibling {@code @BPFMapDefinition} field that supplies the inner-map
 * template. The processor emits a runtime call to
 * {@code bpf_map__set_inner_map_fd(outer, inner->fd)} between
 * {@code bpf_object__open_file} and {@code bpf_object__load} so libbpf
 * knows the inner-map layout before load.
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
