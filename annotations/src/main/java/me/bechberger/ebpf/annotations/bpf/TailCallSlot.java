package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

/**
 * Marks a {@link BPFFunction}-annotated method as the implementation of a
 * specific slot in a {@link BPFTailCallTable}.
 *
 * <p>The {@link #value()} must be the exact name of a constant of the enum
 * referenced by the sibling table's {@code slots()} class. The processor
 * cross-checks this at compile time and emits a diagnostic on mismatch.
 *
 * <p>If the enclosing class declares multiple {@code @BPFTailCallTable} fields,
 * the {@link #table()} attribute disambiguates by field name; otherwise it may
 * be left empty and the sole table is used.
 *
 * <p>Annotation values cannot be arbitrary enum instances, so we take the
 * constant's name as a {@code String} and validate it at annotation-processing
 * time.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface TailCallSlot {
    /** Name of an enum constant of the target table's {@code slots()} class. */
    String value();

    /** Optional table field name when the class has more than one table. */
    String table() default "";
}
