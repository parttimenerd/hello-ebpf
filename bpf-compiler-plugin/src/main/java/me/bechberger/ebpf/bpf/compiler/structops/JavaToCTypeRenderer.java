package me.bechberger.ebpf.bpf.compiler.structops;

/**
 * Renders Java type strings (as they appear in erased method signatures)
 * to the C strings the plugin emits in {@code BPF_PROG(...)} headers and
 * compares against BTF field types.
 *
 * <p>Deliberately narrow: covers the primitives, {@code Ptr<X>}, and
 * {@code String}. Other types produce a runtime error — the four supported
 * struct_ops kinds do not use anything else.
 */
public final class JavaToCTypeRenderer {

    public String render(String javaType) {
        return renderWithAnnotation(javaType, false);
    }

    public String renderWithAnnotation(String javaType, boolean unsigned) {
        return switch (javaType) {
            case "void" -> "void";
            case "int"     -> unsigned ? "__u32" : "int";
            case "long"    -> unsigned ? "__u64" : "long";
            case "short"   -> unsigned ? "__u16" : "short";
            case "byte"    -> unsigned ? "__u8"  : "signed char";
            case "boolean" -> "bool";
            case "java.lang.String" -> "char *";
            default -> {
                // Ptr<X>: extract X and render.
                //   Ptr<Foo>       -> "struct Foo *"
                //   Ptr<Ptr<Foo>>  -> "struct Foo **" (recurse, append '*')
                if (javaType.startsWith("me.bechberger.ebpf.type.Ptr<")
                        && javaType.endsWith(">")) {
                    String inner = javaType.substring(
                            "me.bechberger.ebpf.type.Ptr<".length(),
                            javaType.length() - 1);
                    if (inner.startsWith("me.bechberger.ebpf.type.Ptr<")) {
                        yield renderWithAnnotation(inner, unsigned) + "*";
                    }
                    // "me.bechberger.ebpf.runtime.NetworkingDefinitions.sock" → "sock"
                    int dot = inner.lastIndexOf('.');
                    String simple = (dot >= 0) ? inner.substring(dot + 1) : inner;
                    yield "struct " + simple + " *";
                }
                throw new IllegalArgumentException("unsupported Java type: " + javaType);
            }
        };
    }
}
