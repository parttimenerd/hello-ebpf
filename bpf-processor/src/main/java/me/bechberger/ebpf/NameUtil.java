package me.bechberger.ebpf;

/**
 * Utility class for name and identifier conversions
 */
public class NameUtil {
    /**
     * Convert a name to snake case
     * <p>
     * Example: "HelloWorld" -> "hello_world"
     */
    public static String toSnakeCase(String name) {
        return name.replaceAll("([a-z0-9])([A-Z])", "$1_$2");
    }

    /**
     * Convert a name to upper-cased snake case
     */
    public static String toConstantCase(String name) {
        return toSnakeCase(name).toUpperCase();
    }
}
