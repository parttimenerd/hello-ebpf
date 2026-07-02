package me.bechberger.ebpf.bpf.compiler.structops;

/**
 * Method-to-BTF-field validation for {@code @StructOps} interfaces.
 * Pure functions on top of {@link StructOpsLayout} data; produces
 * {@link ValidationException}s that callers translate to javac diagnostics
 * at the method source position.
 */
public final class StructOpsValidator {

    private StructOpsValidator() {}

    public static final class ValidationException extends RuntimeException {
        public ValidationException(String msg) { super(msg); }
    }

    /** camelCase -&gt; snake_case per spec section 6.1; acronym-aware (e.g. selectCPU -&gt; select_cpu). */
    public static String camelToSnake(String s) {
        var sb = new StringBuilder(s.length() + 4);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isUpperCase(c)) {
                boolean atStart = i == 0;
                boolean prevLower = !atStart && Character.isLowerCase(s.charAt(i - 1));
                boolean nextLower = i + 1 < s.length() && Character.isLowerCase(s.charAt(i + 1));
                if (!atStart && (prevLower || nextLower)) {
                    sb.append('_');
                }
                sb.append(Character.toLowerCase(c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * Throws if the layout has no field with {@code fieldName} (already lowered).
     * Message names the kernel struct so users know what to search.
     */
    public static void validateFieldExists(StructOpsLayout layout, String fieldName) {
        if (!layout.hasField(fieldName)) {
            throw new ValidationException(
                    "method '" + fieldName + "' has no matching field in kernel struct '"
                            + layout.kernelName() + "'");
        }
    }

    /**
     * Compares the BTF return type against a rendered Java return type
     * (the caller lowers Java types to their C equivalent — see
     * {@code StructOpsSynthesizer} for the mapping table).
     */
    public static void validateReturnType(
            StructOpsLayout.Field field, String javaReturnRendered, String fieldName) {
        if (!typesMatch(field.returnType(), javaReturnRendered)) {
            throw new ValidationException(
                    "method '" + fieldName + "' return type '" + javaReturnRendered
                            + "' does not match BTF field '" + fieldName
                            + "' return type '" + field.returnType() + "'");
        }
    }

    public static void validateArgCount(StructOpsLayout.Field field, int javaArgCount, String fieldName) {
        int expected = field.args().size();
        if (javaArgCount != expected) {
            throw new ValidationException(
                    "expected " + expected + " args, method has " + javaArgCount
                            + " for field '" + fieldName + "'");
        }
    }

    public static void validateArgType(
            StructOpsLayout.Field.Arg btfArg, String javaArgRendered,
            int argIndex, String fieldName) {
        if (!typesMatch(btfArg.type(), javaArgRendered)) {
            throw new ValidationException(
                    "method '" + fieldName + "' arg " + argIndex + " (" + btfArg.name()
                            + ") type '" + javaArgRendered + "' does not match BTF type '"
                            + btfArg.type() + "'");
        }
    }

    /**
     * Lightweight type comparison: normalizes whitespace + trailing star spacing,
     * then compares. BTF renders {@code "struct task_struct *"} and callers should
     * render the same way; exact string equality after normalization suffices for
     * the four supported kinds. If a mismatch surfaces in real use, tighten this
     * here rather than silently coercing.
     *
     * <p>Sub-word integers ({@code unsigned char}, {@code short}, etc.) match wider
     * Java ints — the BPF calling convention passes all args through 64-bit
     * registers, so signed/unsigned width mismatches are wire-safe below 64 bits.
     */
    private static boolean typesMatch(String btfType, String rendered) {
        String a = normalise(btfType);
        String b = normalise(rendered);
        if (a.equals(b)) return true;
        // All int widths below 64 bits are ABI-compatible in the BPF call convention.
        return isSubWordInt(a) && isSubWordInt(b);
    }

    private static boolean isSubWordInt(String norm) {
        return switch (norm) {
            case "i8", "i16", "i32" -> true;
            default -> false;
        };
    }

    private static String normalise(String t) {
        String n = t.replaceAll("\\s+", " ").replace(" *", "*").trim();
        // Enum tags in BTF (e.g. "enum hid_report_type") are int-width at the ABI —
        // callers pass Java int / __u32 for them.
        if (n.startsWith("enum ")) return "i32";
        // Collapse all 8/16/32/64-bit integer type spellings to a canonical form
        // that ignores signed/unsigned differences and the __u/__s BPF header prefix.
        // Java uses plain int/long regardless of sign; BTF uses s32/u32/s64/u64;
        // the renderer may emit __u32/__u64 for @Unsigned params.  All of these
        // are wire-compatible at the struct_ops ABI level.
        return switch (n) {
            case "u8",  "s8",  "__u8",  "__s8",
                 "char", "unsigned char", "signed char"    -> "i8";
            case "u16", "s16", "__u16", "__s16", "short"  -> "i16";
            case "u32", "s32", "__u32", "__s32", "int"    -> "i32";
            case "u64", "s64", "__u64", "__s64", "long"   -> "i64";
            default    -> n;
        };
    }
}
