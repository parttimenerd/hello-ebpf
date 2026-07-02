package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

/**
 * Marks a {@code BPFProgArray} field as a tail-call dispatch table with
 * named, enum-driven slots. Sits alongside {@link BPFMapDefinition} on the
 * same field:
 *
 * {@snippet :
 *   enum Slot { PARSE_ETH, PARSE_IP, COUNT }
 *
 *   @BPFTailCallTable(slots = Slot.class)
 *   @BPFMapDefinition(maxEntries = 3)
 *   BPFProgArray dispatch;
 * }
 *
 * <p>Every {@code @BPFFunction} method annotated with {@link TailCallSlot} whose
 * {@code value()} names a constant of {@link #slots()} will be auto-registered
 * into this table at program load time. The slot index is the enum constant's
 * {@link Enum#ordinal() ordinal}.
 *
 * <p>The annotation processor emits {@code register(ordinal, getProgramByName(methodName))}
 * calls into the generated {@code ProgramImpl} constructor. Users may still call
 * {@link me.bechberger.ebpf.bpf.map.BPFProgArray#register} manually to override slots.
 *
 * <p>{@code maxEntries} on the sibling {@code @BPFMapDefinition} must equal
 * {@code slots().getEnumConstants().length}; the processor emits a compile-time
 * error otherwise.
 */
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface BPFTailCallTable {
    /** The enum type whose constants name the slots. Slot index = ordinal. */
    Class<? extends Enum<?>> slots();
}
