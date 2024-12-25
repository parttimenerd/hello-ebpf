package me.bechberger.ebpf.bpf.compiler;

import com.sun.source.tree.Tree;
import com.sun.tools.javac.code.Symbol;
import com.sun.tools.javac.code.Symbol.ClassSymbol;
import com.sun.tools.javac.code.Symbol.MethodSymbol;
import me.bechberger.cast.CAST;
import me.bechberger.cast.CAST.Expression;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFFunctionAlternative;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.bpf.compiler.CompilerPlugin.TypedTreePath;
import me.bechberger.ebpf.bpf.compiler.MethodTemplate.CallArgs;
import org.jetbrains.annotations.Nullable;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static me.bechberger.cast.CAST.Expression.constant;

/**
 * Processes the templates of {@link BuiltinBPFFunction} annotated methods
 */
public class MethodTemplateCache {

    public static class TemplateRenderException extends RuntimeException {
        public TemplateRenderException(String message) {
            super(message);
        }
    }

    private static final Map<String, Map<String, MethodTemplate>> SPECIAL_CASES = Map.of(
            "java.lang.String", Map.ofEntries(
                    entry("length", "$strlen$this"),
                    entry("charAt", "$this[$arg1]"),
                    entry("getBytes", "($this)")
            )
    );

    private static final Map<String, Map<String, MethodTemplate>> AUTO_BOXING = Map.of(
            "java.lang.Short", Map.ofEntries(
                    entry("shortValue", "($this)"),
                    entry("valueOf", "($arg1)")
            ),
            "java.lang.Integer", Map.ofEntries(
                    entry("intValue", "($this)"),
                    entry("valueOf", "($arg1)")
            ),
            "java.lang.Long", Map.ofEntries(
                    entry("longValue", "($this)"),
                    entry("valueOf", "($arg1)")
            ),
            "java.lang.Float", Map.ofEntries(
                    entry("floatValue", "($this)"),
                    entry("valueOf", "($arg1)")
            ),
            "java.lang.Double", Map.ofEntries(
                    entry("doubleValue", "($this)"),
                    entry("valueOf", "($arg1)")
            ),
            "java.lang.Character", Map.ofEntries(
                    entry("charValue", "($this)"),
                    entry("valueOf", "($arg1)")
            ),
            "java.lang.Byte", Map.ofEntries(
                    entry("byteValue", "($this)"),
                    entry("valueOf", "($arg1)")
            ),
            "java.lang.Boolean", Map.ofEntries(
                    entry("booleanValue", "($this)"),
                    entry("valueOf", "($arg1)")
            )
    );

    private static Map.Entry<String, MethodTemplate> entry(String methodName, String template) {
        return Map.entry(methodName, MethodTemplate.parse(methodName, template));
    }

    private final CompilerPlugin compilerPlugin;
    private final Map<MethodSymbol, MethodTemplate> cache;

    public MethodTemplateCache(CompilerPlugin compilerPlugin) {
        this.compilerPlugin = compilerPlugin;
        this.cache = new HashMap<>();
    }

    public @Nullable MethodTemplate getMethodTemplate(TypedTreePath<?> path, Tree invocation,
                                                      MethodSymbol methodSymbol) {
        var specialCase = handleSpecialCases(methodSymbol);
        return specialCase != null ? specialCase : cache.computeIfAbsent(methodSymbol, k -> create(path, invocation,
                k));
    }

    /**
     * Throws a template exception if the template can't be parsed or rendering failed
     */
    public CAST.PrimaryExpression.VerbatimExpression render(TypedTreePath<?> path, Tree invocation, MethodSymbol methodSymbol, CallArgs args) {
        var template = getMethodTemplate(path, invocation, methodSymbol);
        if (template == null) {
            throw new TemplateRenderException("No template found for method " + methodSymbol.getSimpleName());
        }
        try {
            return template.call(args);
        } catch (TemplateRenderException e) {
            throw new TemplateRenderException("Can't render template for method " + methodSymbol.getSimpleName() + " " +
                    "(" + template.raw() + "): " + e.getMessage());
        }
    }

    private @Nullable MethodTemplate handleSpecialCases(MethodSymbol symbol) {
        String className = symbol.owner.getQualifiedName().toString();
        String methodName = symbol.getSimpleName().toString();
        if (SPECIAL_CASES.containsKey(className)) {
            return SPECIAL_CASES.get(className).get(methodName);
        }
        if (AUTO_BOXING.containsKey(className)) {
            return AUTO_BOXING.get(className).get(methodName);
        }
        return null;
    }

    public boolean isAutoUnboxing(MethodSymbol symbol) {
        String className = symbol.owner.getQualifiedName().toString();
        String methodName = symbol.getSimpleName().toString();
        return AUTO_BOXING.containsKey(className) && AUTO_BOXING.get(className).containsKey(methodName);
    }

    private MethodTemplate create(TypedTreePath<?> path, Tree invocation, MethodSymbol symbol) {
        var ann = symbol.getAnnotation(BuiltinBPFFunction.class);
        var ann2 = compilerPlugin.getAnnotationOfMethodOrSuper(symbol, BPFFunction.class);
        if (ann == null && ann2 == null) {
            // does it have a BPFFunctionAlternative annotation?
            var altAnn = symbol.getAnnotation(BPFFunctionAlternative.class);
            if (altAnn != null) {
                throw new TemplateRenderException("Method " + symbol.getQualifiedName() + " cannot be used, please " +
                        "use " + altAnn.value() + " instead");
            }
            // but it could be a record field accessor
            if (symbol.getEnclosingElement().getKind().isClass()) {
                var record = (ClassSymbol) symbol.getEnclosingElement();
                var recordAnn = record.getAnnotation(Type.class);
                if (recordAnn == null || !record.isRecord()) {
                    // check whether it's still support
                    var similarMembers = record.getEnclosedElements().stream().filter(s -> s.getSimpleName().equals(symbol.getSimpleName())).toList();
                    if (similarMembers.isEmpty() && symbol.baseSymbol().getEnclosingElement() instanceof ClassSymbol baseRecord && !baseRecord.isRecord()) {
                        // check whether it's a method in a record that is not annotated with @Type
                        similarMembers = baseRecord.getEnclosedElements().stream().filter(s -> s.getSimpleName().equals(symbol.getSimpleName())).toList();
                    }
                    var backingVariable = similarMembers.stream().filter(s -> s instanceof Symbol.VarSymbol).findFirst();
                    if (symbol.isStatic() && similarMembers.size() == 2 && backingVariable.isPresent()) {
                        // We assume this to be a jextract generated method for a constant, e.g.
                        //   private static final int IPPROTO_HOPOPTS = (int)0L;
                        //   public static int IPPROTO_HOPOPTS() {
                        //      return IPPROTO_HOPOPTS;
                        //   }
                        // We just take the variable's constant value
                        Object constantValue = ((Symbol.VarSymbol) backingVariable.get()).getConstantValue();
                        if (constantValue != null) {
                            return MethodTemplate.parse(symbol.getSimpleName().toString(),
                                    constant(constantValue).toPrettyString(), symbol);
                        }
                    }
                    throw new TemplateRenderException("Method " + symbol.getQualifiedName() + " is not in a record " +
                            "annotated with @Type");
                }
                // check that the method is a record field accessor
                var field =
                        record.getRecordComponents().stream().filter(f -> f.getSimpleName().equals(symbol.getSimpleName())).findFirst();
                if (field.isEmpty()) {
                    throw new TemplateRenderException("Method " + symbol.getQualifiedName() + " is not a record field" +
                            " accessor and is not annotated with @BuiltinBPFFunction");
                }
                return MethodTemplate.parse(symbol.getSimpleName().toString(), "$this.$name", symbol);
            }
            throw new TemplateRenderException("Method " + symbol.getQualifiedName() + " is not annotated with " +
                    "@BuiltinBPFFunction");
        }
        var template = ann != null ? ann.value() : ann2.callTemplate();
        try {
            return MethodTemplate.parse(symbol.getSimpleName().toString(), template, symbol);
        } catch (TemplateRenderException e) {
            compilerPlugin.logError(path, invocation, "Can't parse template for method " + symbol.getSimpleName() +
                    ": " + e.getMessage());
            return new MethodTemplate(symbol.getSimpleName().toString(), "", List.of());
        }
    }
}
