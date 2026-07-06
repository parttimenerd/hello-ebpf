package me.bechberger.ebpf.bpf.compiler.structops;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.bpf.compiler.util.TreeConstants;

import com.sun.source.util.Trees;
import javax.annotation.processing.ProcessingEnvironment;
import org.jetbrains.annotations.Nullable;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.Modifier;
import javax.lang.model.element.TypeElement;
import javax.lang.model.element.VariableElement;
import javax.lang.model.type.DeclaredType;
import javax.lang.model.type.TypeMirror;
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
    private final Trees trees;

    public StructOpsSynthesizer(ProcessingEnvironment env, Trees trees) {
        this.env = env;
        this.trees = trees;
    }

    /** Convenience overload for test callers that don't have a javac task Trees. */
    public StructOpsSynthesizer(ProcessingEnvironment env) {
        this.env = env;
        Trees t;
        try {
            t = Trees.instance(env);
        } catch (IllegalArgumentException e) {
            t = null;
        }
        this.trees = t;
    }

    /**
     * Kernel-specific override table: {@code (kernelName + "." + fieldName)} -&gt;
     * literal C expression to emit instead of the default {@code (void *)name}
     * / string-literal initializer. Populated only for kinds that use
     * hello-ebpf's property-substitution mechanism (currently just
     * {@code sched_ext_ops}).
     *
     * <p>These placeholders are resolved at {@code BPFProgram.load()} time
     * via {@code getPropertyValue()} string substitution. The plugin's role
     * is verbatim passthrough.
     */
    private static final java.util.Map<String, String> PROPERTY_OVERRIDES;
    static {
        var m = new java.util.LinkedHashMap<String, String>();
        m.put("sched_ext_ops.timeout_ms", "__property_timeout_ms");
        m.put("sched_ext_ops.name",       "\"__property_sched_name\"");
        m.put("sched_ext_ops.flags",
              "SCX_OPS_ENQ_LAST | SCX_OPS_KEEP_BUILTIN_IDLE | (__property_extra_flags)");
        PROPERTY_OVERRIDES = java.util.Collections.unmodifiableMap(m);
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
                // Skip utility methods declared on the interface that have no
                // matching field in the kernel layout (e.g. runSchedulerLoop,
                // attachScheduler, getSchedulerName, isSchedulerAttachedProperly).
                if (!layout.hasField(fieldName)) continue;
                StructOpsValidator.validateFieldExists(layout, fieldName);
                StructOpsLayout.Field field = layout.field(fieldName);

                if ("data".equals(field.kind())) {
                    // If this data field has a PROPERTY_OVERRIDE, skip renderDataInitializer:
                    // the PROPERTY_OVERRIDES loop below will emit the placeholder directly.
                    if (PROPERTY_OVERRIDES.containsKey(kind.kernelName() + "." + fieldName)) continue;
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
                    boolean sleepable = (concrete != null
                            && concrete.getAnnotation(me.bechberger.ebpf.annotations.bpf.Sleepable.class) != null)
                            || ifaceMethod.getAnnotation(me.bechberger.ebpf.annotations.bpf.Sleepable.class) != null;
                    if (sleepable) {
                        prefix = "struct_ops.s/";
                    }
                    String section = prefix + fieldName;
                    // Prefer concrete method for parameter names: abstract interface methods
                    // compiled into a .jar without -parameters lose their names (arg0, arg1, …)
                    // while default methods and concrete overrides retain them.
                    String header = renderHeader(field, ifaceMethod, concrete);
                    // Function name matches the kernel field so the init below can
                    // reference it without a Java-vs-C name gap (e.g. congAvoid vs cong_avoid).
                    // emittedName may carry a prefix (e.g. "sched_") from the @StructOps annotation;
                    // fieldName is still the BTF field name used on the left of the initializer.
                    String emittedName = kind.emittedNamePrefix() + fieldName;
                    functions.add(new SynthFunction(target, makeProxy(section, header, emittedName)));
                    initializerLines.add("    ." + fieldName + " = (void *)" + emittedName);
                }
            }

            // Property-substituted defaults: fields like sched_ext_ops.flags /
            // .timeout_ms / .name aren't shaped as Java methods on the interface,
            // but the runtime property-substitution pass still needs their
            // __property_ placeholders in the generated C. Emit any override
            // whose kernelName matches this kind's, unless the user already
            // covered that field via an @Override method above.
            for (var entry : PROPERTY_OVERRIDES.entrySet()) {
                String[] parts = entry.getKey().split("\\.", 2);
                if (!parts[0].equals(kind.kernelName())) continue;
                String fname = parts[1];
                String prefix = "    ." + fname + " =";
                boolean alreadyPresent = initializerLines.stream()
                        .anyMatch(l -> l.startsWith(prefix));
                if (alreadyPresent) continue;
                initializerLines.add("    ." + fname + " = " + entry.getValue());
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
     * Renders the {@code $return BPF_PROG($name, args...)} header string. Return
     * and arg types come from the pre-dumped BTF layout (with a small
     * fixed-width rename so {@code u32} to {@code __u32}), and parameter names come
     * from the Java interface method. When the interface method's parameters have
     * synthesized names ({@code arg0}, {@code arg1}, ...) — which happens for abstract
     * interface methods compiled without {@code -parameters} — the concrete
     * override's parameter names are used instead for readability.
     * libbpf's {@code BPF_PROG} macro does not require arg names to match the
     * kernel, but readable diagnostics do.
     */
    private String renderHeader(StructOpsLayout.Field field, ExecutableElement ifaceMethod,
                                @Nullable ExecutableElement concreteMethod) {
        String ret = mapBtfType(field.returnType(), returnAnnotatedUnsigned(ifaceMethod));

        var ifaceParams = ifaceMethod.getParameters();
        // Prefer concrete method params for names when the interface has synthesized names (arg0, arg1, ...).
        // Abstract interface methods compiled without -parameters lose original names in the .class.
        // However, always use the interface params for @Unsigned type-use annotations since the
        // concrete override may not redeclare them.
        boolean useConcreteNames = concreteMethod != null
                && ifaceParams.stream().allMatch(p -> p.getSimpleName().toString().matches("arg\\d+"));
        var nameParams = useConcreteNames ? concreteMethod.getParameters() : ifaceParams;
        var btfArgs = field.args();
        // validateArgCount has already run — sizes match.
        int n = nameParams.size();
        var parts = new ArrayList<String>(n);
        for (int i = 0; i < n; i++) {
            VariableElement namePar = nameParams.get(i);
            // @Unsigned check: prefer interface param (has canonical type-use annotations),
            // fall back to concrete param.
            VariableElement unsignedPar = i < ifaceParams.size() ? ifaceParams.get(i) : namePar;
            boolean unsigned = unsignedPar.getAnnotation(Unsigned.class) != null;
            if (!unsigned) {
                // TYPE_USE-scoped @Unsigned lives on the parameter's type mirror.
                for (var a : unsignedPar.asType().getAnnotationMirrors()) {
                    String fqn = ((TypeElement) a.getAnnotationType().asElement())
                            .getQualifiedName().toString();
                    if (fqn.equals(Unsigned.class.getName())) {
                        unsigned = true;
                        break;
                    }
                }
            }
            String cType = mapBtfType(btfArgs.get(i).type(), unsigned);
            parts.add(cType.endsWith("*") ? cType + namePar.getSimpleName()
                                          : cType + " " + namePar.getSimpleName());
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
        // Enum tags pass through as-is: the emitted C header can use them directly
        // (the kernel headers included in the BPF program already declare them).
        if (btfType.startsWith("enum ")) return btfType;
        return switch (btfType) {
            case "u8"  -> "__u8";
            case "u16" -> "__u16";
            case "u32" -> "__u32";
            case "u64" -> "__u64";
            case "int"    -> unsigned ? "__u32" : "int";
            case "long"   -> unsigned ? "__u64" : "long";
            case "short"  -> unsigned ? "__u16" : "short";
            case "signed char", "char" -> unsigned ? "__u8" : "signed char";
            case "unsigned char"       -> "unsigned char";
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
     * method body via {@link TreeConstants}. Integer-typed data fields
     * (e.g. {@code hid_bpf_ops.hid_id}) accept an int-literal body and emit
     * {@code    .hid_id = 0}.
     */
    private String renderDataInitializer(TypeElement bpfClass, ExecutableElement ifaceMethod,
                                         StructOpsLayout.Field field) {
        ExecutableElement concrete = findConcreteMethod(bpfClass, ifaceMethod);
        String btf = field.returnType();
        boolean isInt = switch (btf) {
            case "int", "long", "short", "u8", "u16", "u32", "u64",
                 "s8", "s16", "s32", "s64", "signed char", "unsigned char", "char" -> true;
            default -> false;
        };
        if (isInt) {
            Optional<Long> lit = (concrete != null && trees != null)
                    ? TreeConstants.integerReturnLiteral(trees, concrete)
                    : concrete != null
                        ? TreeConstants.integerReturnLiteral(env, concrete)
                        : Optional.empty();
            if (lit.isEmpty()) {
                env.getMessager().printMessage(
                        Diagnostic.Kind.ERROR,
                        "@StructOps data field '" + field.name()
                                + "' must be initialised with an integer literal — "
                                + "dynamic values not supported",
                        concrete != null ? concrete : ifaceMethod);
                return null;
            }
            return "    ." + field.name() + " = " + lit.get();
        }
        Optional<String> literal = (concrete != null && trees != null)
                ? TreeConstants.stringReturnLiteral(trees, concrete)
                : concrete != null
                    ? TreeConstants.stringReturnLiteral(env, concrete)
                    : Optional.empty();
        if (literal.isEmpty()) {
            System.err.println("DEBUG2: field=" + field.name() + " trees=" + trees + " concrete=" + (concrete != null ? concrete.getEnclosingElement() + "." + concrete.getSimpleName() : "null") + " treesGetTree=" + (trees != null && concrete != null ? trees.getTree(concrete) : "N/A"));
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
     * Locates the concrete override of {@code ifaceMethod} starting from
     * {@code bpfClass} and walking the superclass chain up to (not including)
     * {@code java.lang.Object}. Match by simple name + arity — the most-derived
     * non-abstract declaration is returned.
     */
    private ExecutableElement findConcreteMethod(TypeElement bpfClass,
                                                 ExecutableElement ifaceMethod) {
        TypeElement cursor = bpfClass;
        while (cursor != null) {
            if (cursor.getQualifiedName().contentEquals("java.lang.Object")) break;
            for (ExecutableElement m : ElementFilter.methodsIn(cursor.getEnclosedElements())) {
                if (m.getModifiers().contains(Modifier.ABSTRACT)) continue;
                if (!m.getSimpleName().contentEquals(ifaceMethod.getSimpleName())) continue;
                if (m.getParameters().size() != ifaceMethod.getParameters().size()) continue;
                return m;
            }
            TypeMirror sup = cursor.getSuperclass();
            cursor = (sup instanceof DeclaredType d) ? (TypeElement) d.asElement() : null;
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
                    // struct_ops entry points are referenced by (void*)name in the
                    // struct instance, which is emitted after all function bodies.
                    // A forward declaration would conflict when BPF_PROG/BPF_STRUCT_OPS
                    // expands to the same identifier (especially for no-arg functions
                    // where the macro-with-args regex in canEmitDeclaratorFor does not
                    // suppress the forward-decl).  Original hand-written @BPFFunction
                    // annotations on Scheduler.java all used addDefinition=false for
                    // the same reason.
                    case "addDefinition"  -> false;
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
