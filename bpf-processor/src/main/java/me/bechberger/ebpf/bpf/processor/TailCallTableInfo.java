package me.bechberger.ebpf.bpf.processor;

import java.util.List;

/**
 * Result of {@link TypeProcessor#processTailCallTables} — one entry per
 * {@code @BPFTailCallTable} field.
 *
 * @param fieldName    Java field name of the {@code BPFProgArray} field.
 * @param slotEnumFqn  Fully-qualified name of the enum whose ordinals are slot indices.
 * @param slotNames    Enum constants in declaration order (ordinal 0 first).
 * @param registrations One entry per method carrying a matching {@code @TailCallSlot}.
 */
public record TailCallTableInfo(String fieldName,
                                String slotEnumFqn,
                                List<String> slotNames,
                                List<Registration> registrations) {

    /**
     * A single method-to-slot binding. {@code ordinal} is
     * {@code slotNames.indexOf(slotConstant)}.
     */
    public record Registration(String methodName, String slotConstant, int ordinal) {}
}
