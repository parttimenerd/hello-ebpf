package me.bechberger.ebpf.bpf.compiler.structops;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.bpf.compiler.util.TreeConstants;

import javax.annotation.processing.ProcessingEnvironment;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.Modifier;
import javax.lang.model.element.TypeElement;
import javax.lang.model.element.VariableElement;
import javax.lang.model.util.ElementFilter;
import javax.tools.Diagnostic;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Turns {@link StructOpsDiscovery.Kind}s into (a) synthesized
 * {@link BPFFunction} proxies attached to concrete methods and (b)
 * {@code SEC(".struct_ops.link")} struct instance C declarations.
 *
 * <p>The synthesized {@link BPFFunction} uses the same {@link Proxy} shape
 * as {@code CompilerPlugin.synthesizeBPFFunction} today, so downstream
 * translation treats these as regular {@code @BPFFunction} entry points.
 */
public final class StructOpsSynthesizer {

    /** A method + the synthetic annotation the plugin should treat it as carrying. */
    public record SynthFunction(ExecutableElement method, BPFFunction bpfFunction) {}

    /** One {@code SEC(".struct_ops.link")} struct instance snippet. */
    public record SynthInstance(String kernelName, String mapName, String cSource) {}

    public record Result(List<SynthFunction> functions, List<SynthInstance> instances) {}

    private final ProcessingEnvironment env;

    public StructOpsSynthesizer(ProcessingEnvironment env) {
        this.env = env;
    }

    public Result synthesize(TypeElement bpfClass, List<StructOpsDiscovery.Kind> kinds) {
        List<SynthFunction> functions = new ArrayList<>();
        List<SynthInstance> instances = new ArrayList<>();

        for (var kind : kinds) {
            StructOpsLayout layout = StructOpsLayout.load(kind.kernelName());
            String mapName = kind.instanceName().isEmpty()
                    ? bpfClass.getSimpleName().toString()
                    : kind.instanceName();

            List<String> initializerLines = new ArrayList<>();

            for (ExecutableElement ifaceMethod : kind.overriddenMethods()) {
                String fieldName = StructOpsValidator.camelToSnake(
                        ifaceMethod.getSimpleName().toString());
                StructOpsValidator.validateFieldExists(layout, fieldName);
                StructOpsLayout.Field field = layout.field(fieldName);

                if ("data".equals(field.kind())) {
                    // Data field → literal initializer only; no synthesized program.
                    String line = renderDataInitializer(bpfClass, ifaceMethod, field);
                    if (line != null) initializerLines.add(line);
                } else {
                    StructOpsValidator.validateArgCount(
                            field, ifaceMethod.getParameters().size(), fieldName);
                    // Function field → synthetic @BPFFunction on the concrete method.
                    ExecutableElement concrete = findConcreteMethod(bpfClass, ifaceMethod);
                    ExecutableElement target = concrete != null ? concrete : ifaceMethod;
                    String prefix = kind.sectionPrefix();
                    if (concrete != null && concrete.getAnnotation(
                            me.bechberger.ebpf.annotations.bpf.Sleepable.class) != null) {
                        prefix = "struct_ops.s/";
                    }
                    String section = prefix + fieldName;
                    String header = renderHeader(field, ifaceMethod);
                    // Function name matches the kernel field so the init below can
                    // reference it without a Java-vs-C name gap (e.g. congAvoid vs cong_avoid).
                    functions.add(new SynthFunction(target, makeProxy(section, header, fieldName)));
                    initializerLines.add("    ." + fieldName + " = (void *)" + fieldName);
                }
            }

            StringBuilder src = new StringBuilder()
                    .append("SEC(\".struct_ops.link\")\n")
                    .append("struct ").append(kind.kernelName())
                    .append(' ').append(mapName).append(" = {\n");
            if (!initializerLines.isEmpty()) {
                src.append(String.join(",\n", initializerLines)).append(",\n");
            }
            src.append("};\n");
            instances.add(new SynthInstance(kind.kernelName(), mapName, src.toString()));
        }
        return new Result(functions, instances);
    }

    /**
     * Renders the {@code $return BPF_PROG($name, args…)} header string. Return
     * and arg types come from the pre-dumped BTF layout (with a small
     * fixed-width rename so {@code u32 → __u32}), and parameter names come
     * from the Java interface method — libbpf's {@code BPF_PROG} macro
     * doesn't need arg names to match, but readable diagnostics do.
     */
    private String renderHeader(StructOpsLayout.Field field, ExecutableElement ifaceMethod) {
        String ret = mapBtfType(field.returnType(), returnAnnotatedUnsigned(ifaceMethod));

        var params = ifaceMethod.getParameters();
        var btfArgs = field.args();
        // validateArgCount has already run — sizes match.
        int n = params.size();
        var parts = new ArrayList<String>(n);
        for (int i = 0; i < n; i++) {
            VariableElement p = params.get(i);
            boolean unsigned = p.getAnnotation(Unsigned.class) != null;
            if (!unsigned) {
                // TYPE_USE-scoped @Unsigned lives on the parameter's type mirror.
                for (var a : p.asType().getAnnotationMirrors()) {
                    String fqn = ((TypeElement) a.getAnnotationType().asElement())
                            .getQualifiedName().toString();
                    if (fqn.equals(Unsigned.class.getName())) {
                        unsigned = true;
                        break;
                    }
                }
            }
            String cType = mapBtfType(btfArgs.get(i).type(), unsigned);
            parts.add(cType.endsWith("*") ? cType + p.getSimpleName()
                                          : cType + " " + p.getSimpleName());
        }
        String args = String.join(", ", parts);
        return ret + " BPF_PROG($name" + (args.isEmpty() ? "" : ", " + args) + ")";
    }

    /**
     * Translates BTF field types to the C spelling the plugin emits.
     * {@code u32/u64/u16/u8} become {@code __u32/…} (BPF headers pun on
     * the double-underscore form); everything else passes through.
     * The {@code unsigned} hint promotes plain {@code int/long/…} to
     * their {@code __uN} equivalents, matching {@code JavaToCTypeRenderer}.
     */
    private String mapBtfType(String btfType, boolean unsigned) {
        return switch (btfType) {
            case "u8"  -> "__u8";
            case "u16" -> "__u16";
            case "u32" -> "__u32";
            case "u64" -> "__u64";
            case "int"    -> unsigned ? "__u32" : "int";
            case "long"   -> unsigned ? "__u64" : "long";
            case "short"  -> unsigned ? "__u16" : "short";
            case "signed char", "char" -> unsigned ? "__u8" : "signed char";
            default -> btfType;
        };
    }

    /**
     * Reads {@code @Unsigned} off the interface method's return type.
     * {@code @Unsigned} is {@code TYPE_USE}-scoped, so we walk the annotation
     * mirrors on the return {@link javax.lang.model.type.TypeMirror} rather
     * than calling {@code m.getAnnotation(Unsigned.class)} which would look
     * on the method element itself.
     */
    private static boolean returnAnnotatedUnsigned(ExecutableElement m) {
        for (var a : m.getReturnType().getAnnotationMirrors()) {
            String fqn = ((TypeElement) a.getAnnotationType().asElement())
                    .getQualifiedName().toString();
            if (fqn.equals(Unsigned.class.getName())) return true;
        }
        // Fallback for compilers that surface @Unsigned as an element-scoped
        // annotation on the method (older javac / non-Type_Use mirroring).
        return m.getAnnotation(Unsigned.class) != null;
    }

    /**
     * For a data field like {@code name}, emits {@code    .name = "hellocc"}
     * — reading the string literal from the concrete class's overriding
     * method body via {@link TreeConstants}.
     */
    private String renderDataInitializer(TypeElement bpfClass, ExecutableElement ifaceMethod,
                                         StructOpsLayout.Field field) {
        ExecutableElement concrete = findConcreteMethod(bpfClass, ifaceMethod);
        Optional<String> literal = concrete != null
                ? TreeConstants.stringReturnLiteral(env, concrete)
                : Optional.empty();
        if (literal.isEmpty()) {
            env.getMessager().printMessage(
                    Diagnostic.Kind.ERROR,
                    "@StructOps data field '" + field.name()
                            + "' must be initialised with a String literal — "
                            + "dynamic values not supported",
                    concrete != null ? concrete : ifaceMethod);
            return null;
        }
        return "    ." + field.name() + " = \"" + escapeC(literal.get()) + "\"";
    }

    /** Escape a Java string literal for safe emission as a C string literal. */
    private static String escapeC(String s) {
        var sb = new StringBuilder(s.length() + 4);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\' -> sb.append("\\\\");
                case '"'  -> sb.append("\\\"");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default   -> sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * Locates the concrete override of {@code ifaceMethod} declared directly
     * on {@code bpfClass}. Match by simple name + arity — {@link StructOpsDiscovery}
     * has already vetted that the override exists and is non-abstract.
     */
    private ExecutableElement findConcreteMethod(TypeElement bpfClass,
                                                 ExecutableElement ifaceMethod) {
        for (ExecutableElement m : ElementFilter.methodsIn(bpfClass.getEnclosedElements())) {
            if (m.getModifiers().contains(Modifier.ABSTRACT)) continue;
            if (!m.getSimpleName().contentEquals(ifaceMethod.getSimpleName())) continue;
            if (m.getParameters().size() != ifaceMethod.getParameters().size()) continue;
            return m;
        }
        return null;
    }

    /**
     * Builds a {@link BPFFunction} proxy that exposes {@code section} and
     * {@code headerTemplate} for downstream translation, mirroring the shape
     * of {@code CompilerPlugin.synthesizeBPFFunction}. All seven annotation
     * fields are covered so the downstream pipeline never reads a
     * {@code null}.
     */
    private BPFFunction makeProxy(String section, String headerTemplate, String name) {
        return (BPFFunction) Proxy.newProxyInstance(
                BPFFunction.class.getClassLoader(),
                new Class[]{BPFFunction.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "callTemplate"   -> "$name";
                    case "headerTemplate" -> headerTemplate;
                    case "lastStatement"  -> "";
                    case "section"        -> section;
                    // struct_ops entries are wired up via
                    // bpf_map__attach_struct_ops, not autoAttachPrograms.
                    case "autoAttach"     -> false;
                    case "name"           -> name;
                    case "addDefinition"  -> true;
                    // entry points must not be inlined
                    case "inline"         -> false;
                    case "annotationType" -> BPFFunction.class;
                    case "toString"       -> "@BPFFunction(section=\"" + section + "\")";
                    case "hashCode"       -> section.hashCode();
                    case "equals"         -> args[0] == proxy;
                    default               -> method.getDefaultValue();
                });
    }
}
