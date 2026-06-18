package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Mark a {@link BPFMapDefinition} field on a consumer {@code @BPF} class to import
 * a kernel-visible BPF map from another (producer) {@code @BPF} class.
 *
 * <p>The two ELFs are wired to the same kernel map at load time via libbpf's
 * {@code bpf_map__set_pin_path}: the producer pins the map at a stable path
 * under {@code /sys/fs/bpf}; the consumer registers the same path before
 * {@code bpf_object__load}, so libbpf reuses the existing kernel map instead
 * of creating a new one.
 *
 * <p>The annotation processor enforces that the consumer's map type (key, value,
 * map class, and {@code maxEntries}) matches the producer's. Mismatches produce
 * compile-time errors that name the offending field and recommend the fix.
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * @BPF(license = "GPL")
 * abstract class Producer extends BPFProgram {
 *     @Type static class Stats { @Unsigned int count; @Unsigned long ts; }
 *
 *     @BPFMapDefinition(maxEntries = 1024)
 *     BPFHashMap<Long, Stats> stats;
 * }
 *
 * @BPF(license = "GPL")
 * abstract class Consumer extends BPFProgram {
 *     // Imports the producer's map; same name -> mapName defaults to "stats".
 *     @SharedFrom(Producer.class)
 *     @BPFMapDefinition(maxEntries = 1024)
 *     BPFHashMap<Long, Producer.Stats> stats;
 * }
 *
 * try (var producer = BPFProgram.load(Producer.class);
 *      var consumer = BPFProgram.load(Consumer.class, producer)) {
 *     // both programs see the same kernel map.
 * }
 * }</pre>
 *
 * <p>The processor generates a parameterized constructor on the consumer's impl
 * class that takes one instance per distinct producer referenced by the
 * consumer's {@code @SharedFrom} fields. Use
 * {@link me.bechberger.ebpf.annotations.bpf.BPFMapDefinition} on the same field;
 * {@code @SharedFrom} alone is not enough.
 */
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface SharedFrom {
    /**
     * The producer {@code @BPF} class that owns the map. The processor verifies
     * that the producer declares a matching {@link BPFMapDefinition} field.
     */
    Class<?> value();

    /**
     * Name of the map field on the producer. Defaults to the empty string,
     * which means "use the consumer field's own simple name". Override only
     * when the consumer's field has a different local name than the producer's.
     */
    String mapName() default "";
}
