package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Declare maps for the eBPF program by annotating non-final, non-private instance fields of a type
 * annotated with {@link BPFMapClass} with this annotation. The generic type parameters have to adhere
 * to the same constraints as the members of {@link Type} annotated records.
 * <p>
 * Example:
 * {@snippet :
 *   @BPFMapDefinition(maxEntries = 1024)
 *   private BPFHashMap<Integer, Integer> map;
 * }
 * this defines a hash map with 1024 entries.
 */
@Target(ElementType.TYPE_USE)
@Retention(RetentionPolicy.RUNTIME)
public @interface BPFMapDefinition {
    /**
     * Maximum number of entries in the map.
     * <p>
     * For ring buffers, this is the number of bytes in the buffer which should be a multiple of the kernel page size
     * (usually 4096), has to be larger than zero
     */
    int maxEntries();
}