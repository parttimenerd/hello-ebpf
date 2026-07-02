package me.bechberger.ebpf.bpf.compiler.structops;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * A pre-dumped BTF layout for one kernel struct_ops kind (e.g.
 * {@code sched_ext_ops}, {@code tcp_congestion_ops}). Loaded from
 * {@code struct-ops-layouts/<kernelName>.json} on the plugin classpath.
 */
public record StructOpsLayout(
        String kernelName,
        String since,
        List<Field> fields) {

    public record Field(String name, String kind, String returnType, List<Arg> args) {
        public record Arg(String name, String type) {}
    }

    private static final Set<String> SUPPORTED = Set.of(
            "sched_ext_ops", "tcp_congestion_ops", "Qdisc_ops", "hid_bpf_ops");

    public static StructOpsLayout load(String kernelName) {
        if (!SUPPORTED.contains(kernelName)) {
            throw new IllegalArgumentException(
                    "unknown struct_ops kind '" + kernelName + "' — supported: "
                            + String.join(", ", SUPPORTED)
                            + ". Refresh bpf-compiler-plugin/src/main/resources/struct-ops-layouts/ "
                            + "if you're adding a new one.");
        }
        String path = "/struct-ops-layouts/" + kernelName + ".json";
        try (InputStream in = StructOpsLayout.class.getResourceAsStream(path)) {
            if (in == null) {
                throw new IllegalStateException(
                        "bundled layout missing: " + path
                                + " — this is a hello-ebpf build error, please report.");
            }
            byte[] bytes = in.readAllBytes();
            return parse(new String(bytes, StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new IllegalStateException("failed to read " + path, e);
        }
    }

    public boolean hasField(String name) {
        return fields.stream().anyMatch(f -> f.name().equals(name));
    }

    public Field field(String name) {
        return fields.stream().filter(f -> f.name().equals(name)).findFirst()
                .orElseThrow(() -> new IllegalArgumentException(
                        "no field '" + name + "' in " + kernelName));
    }

    static StructOpsLayout parse(String json) {
        return new Parser(json).readTopLevel();
    }

    private static final class Parser {
        private final String src;
        private int i = 0;

        Parser(String s) {
            this.src = s;
        }

        void skipWs() {
            while (i < src.length() && Character.isWhitespace(src.charAt(i))) {
                i++;
            }
        }

        void expect(char c) {
            skipWs();
            if (i >= src.length()) {
                throw new IllegalStateException(
                        "JSON parse error at index " + i + ": expected '" + c + "', found end of input");
            }
            if (src.charAt(i) != c) {
                throw new IllegalStateException(
                        "JSON parse error at index " + i + ": expected '" + c
                                + "', found '" + src.charAt(i) + "'");
            }
            i++;
        }

        boolean tryConsume(char c) {
            skipWs();
            if (i < src.length() && src.charAt(i) == c) {
                i++;
                return true;
            }
            return false;
        }

        String readString() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (i < src.length()) {
                char c = src.charAt(i++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c == '\\') {
                    if (i >= src.length()) {
                        break;
                    }
                    char esc = src.charAt(i++);
                    switch (esc) {
                        case '"' -> sb.append('"');
                        case '\\' -> sb.append('\\');
                        default -> throw new IllegalStateException(
                                "unsupported escape \\" + esc + " at index " + (i - 1));
                    }
                } else {
                    sb.append(c);
                }
            }
            throw new IllegalStateException("unterminated string near index " + i);
        }

        StructOpsLayout readTopLevel() {
            expect('{');
            String kernelName = null;
            String since = null;
            List<Field> fields = null;

            while (!tryConsume('}')) {
                String key = readString();
                expect(':');
                switch (key) {
                    case "kernelName" -> kernelName = readString();
                    case "since" -> since = readString();
                    case "fields" -> fields = readFieldsArray();
                    default -> throw new IllegalStateException(
                            "JSON parse error at index " + i + ": unexpected top-level key '" + key + "'");
                }
                if (!tryConsume(',')) {
                    expect('}');
                    break;
                }
            }

            if (kernelName == null) {
                throw new IllegalStateException("JSON parse error: missing required key 'kernelName'");
            }
            if (since == null) {
                throw new IllegalStateException("JSON parse error: missing required key 'since'");
            }
            if (fields == null) {
                throw new IllegalStateException("JSON parse error: missing required key 'fields'");
            }
            return new StructOpsLayout(kernelName, since, fields);
        }

        List<Field> readFieldsArray() {
            expect('[');
            List<Field> result = new ArrayList<>();
            if (tryConsume(']')) {
                return result;
            }
            do {
                result.add(readField());
            } while (tryConsume(','));
            expect(']');
            return result;
        }

        Field readField() {
            expect('{');
            String name = null;
            String kind = null;
            String returnType = null;
            List<Field.Arg> args = null;

            while (!tryConsume('}')) {
                String key = readString();
                expect(':');
                switch (key) {
                    case "name" -> name = readString();
                    case "kind" -> kind = readString();
                    case "returnType" -> returnType = readString();
                    case "args" -> args = readArgsArray();
                    default -> throw new IllegalStateException(
                            "JSON parse error at index " + i + ": unexpected field key '" + key + "'");
                }
                if (!tryConsume(',')) {
                    expect('}');
                    break;
                }
            }

            if (name == null) {
                throw new IllegalStateException("JSON parse error: field object missing 'name'");
            }
            if (kind == null) {
                throw new IllegalStateException("JSON parse error: field object missing 'kind'");
            }
            if (returnType == null) {
                throw new IllegalStateException("JSON parse error: field object missing 'returnType'");
            }
            if (args == null) {
                args = List.of();
            }
            return new Field(name, kind, returnType, args);
        }

        List<Field.Arg> readArgsArray() {
            expect('[');
            List<Field.Arg> result = new ArrayList<>();
            if (tryConsume(']')) {
                return result;
            }
            do {
                result.add(readArg());
            } while (tryConsume(','));
            expect(']');
            return result;
        }

        Field.Arg readArg() {
            expect('{');
            String name = null;
            String type = null;

            while (!tryConsume('}')) {
                String key = readString();
                expect(':');
                switch (key) {
                    case "name" -> name = readString();
                    case "type" -> type = readString();
                    default -> throw new IllegalStateException(
                            "JSON parse error at index " + i + ": unexpected arg key '" + key + "'");
                }
                if (!tryConsume(',')) {
                    expect('}');
                    break;
                }
            }

            if (name == null) {
                throw new IllegalStateException("JSON parse error: arg object missing 'name'");
            }
            if (type == null) {
                throw new IllegalStateException("JSON parse error: arg object missing 'type'");
            }
            return new Field.Arg(name, type);
        }
    }
}
