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

    /** camelCase -&gt; snake_case per spec section 6.1. */
    public static String camelToSnake(String s) {
        var sb = new StringBuilder(s.length() + 4);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isUpperCase(c)) {
                if (i > 0) sb.append('_');
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
     */
    private static boolean typesMatch(String btfType, String rendered) {
        return normalise(btfType).equals(normalise(rendered));
    }

    private static String normalise(String t) {
        return t.replaceAll("\\s+", " ").replace(" *", "*").trim();
    }
}
