package me.bechberger.ebpf.bpf.compiler;

import com.sun.tools.javac.code.Symbol.MethodSymbol;
import me.bechberger.cast.CAST;
import me.bechberger.cast.CAST.Declarator.FunctionParameter;
import me.bechberger.cast.CAST.Expression;
import me.bechberger.cast.CAST.PrimaryExpression;
import me.bechberger.cast.CAST.PrimaryExpression.Constant;
import me.bechberger.cast.CAST.PrimaryExpression.VerbatimExpression;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.bpf.compiler.MethodTemplate.Argument.Lambda;
import me.bechberger.ebpf.bpf.compiler.MethodTemplate.Argument.Value;
import me.bechberger.ebpf.bpf.compiler.MethodTemplate.TemplatePart.*;
import me.bechberger.ebpf.bpf.compiler.MethodTemplateCache.TemplateRenderException;
import me.bechberger.ebpf.type.Ptr;
import org.jetbrains.annotations.Nullable;

import javax.lang.model.type.TypeKind;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * Processed method call templates of {@link BuiltinBPFFunction} annotated methods
 */
public record MethodTemplate(String methodName, String raw, List<TemplatePart> parts) {

    public class NewVariableContext {

        private record NewVariable(String name, String value) {
        }

        private List<NewVariable> newVariables = new ArrayList<>();

        public String request(String value) {
            var name = "___pointery__" + newVariables.size();
            newVariables.add(new NewVariable(name, value));
            return name;
        }

        @Override
        public String toString() {
            return newVariables.stream().map(nv -> String.format("auto %s = %s;", nv.name, nv.value)).collect(Collectors.joining(" "));
        }

        public VerbatimExpression wrap(VerbatimExpression expression) {
            if (newVariables.isEmpty()) {
                return expression;
            }
            return new VerbatimExpression(String.format("({%s %s;})", this, expression.toPrettyString()));
        }

        public CAST.Statement.VerbatimStatement wrap(CAST.Statement.VerbatimStatement statement) {
            if (newVariables.isEmpty()) {
                return statement;
            }
            return new CAST.Statement.VerbatimStatement(String.format("{%s %s;}", this, statement.toPrettyString()));
        }
    }

    public sealed interface Argument {
        record Lambda(List<FunctionParameter> parameters, CAST.Statement.CompoundStatement code) implements Argument {
            @Override
            public String toPrettyString() {
                return String.format("(%s) { %s }", parameters.stream().map(FunctionParameter::toPrettyString).collect(Collectors.joining(", ")),
                        code.toPrettyString());
            }
        }
        record Value(Expression expression) implements Argument {
            @Override
            public String toPrettyString() {
                return expression.toPrettyString();
            }
        }

        String toPrettyString();
    }

    public record CallArgs(@Nullable CAST.Expression thisExpression,
                           List<? extends Argument> arguments,
                           List<CAST.Declarator> typeArguments,
                           List<CAST.Declarator> classTypeArguments) {
        public CallArgs(@Nullable CAST.Expression thisExpression,
                        List<? extends Argument> arguments, List<CAST.Declarator> typeArguments) {
            this(thisExpression, arguments, typeArguments, List.of());
        }
    }

    public record CallProps(String methodName, CallArgs args) {
    }

    /**
     * A part of a template, modelled after the different placeholders in the template in {@link BuiltinBPFFunction}
     */
    sealed interface TemplatePart {
        default String render(CallProps props) {
            return render(props, null);
        }

        String render(CallProps props, @Nullable NewVariableContext context);

        record Verbatim(String verb) implements TemplatePart {
            @Override
            public String render(CallProps props, @Nullable NewVariableContext context) {
                return verb;
            }
        }

        record Name() implements TemplatePart {
            @Override
            public String render(CallProps props, @Nullable NewVariableContext context) {
                return props.methodName;
            }
        }

        record Arg(int n) implements TemplatePart {
            @Override
            public String render(CallProps props, @Nullable NewVariableContext context) {
                if (n >= props.args.arguments.size()) {
                    throw new TemplateRenderException("Argument " + (n + 1) + " not given for $arg" + (n + 1));
                }
                return props.args.arguments.get(n).toPrettyString();
            }
        }

        record SubArgs(int n) implements TemplatePart {
            @Override
            public String render(CallProps props, @Nullable NewVariableContext context) {
                return IntStream.range(n, props.args.arguments.size())
                        .mapToObj(i -> props.args.arguments.get(i).toPrettyString())
                        .collect(Collectors.joining(", "));
            }
        }

        record Args() implements TemplatePart {
            @Override
            public String render(CallProps props, @Nullable NewVariableContext context) {
                return new SubArgs(0).render(props, context);
            }
        }

        record This() implements TemplatePart {
            @Override
            public String render(CallProps props, @Nullable NewVariableContext context) {
                if (props.args.thisExpression == null) {
                    throw new TemplateRenderException("No this expression given for $this");
                }
                return props.args.thisExpression.toPrettyString();
            }
        }

        sealed interface StrLen extends TemplatePart {
            static String render(Argument arg, @Nullable NewVariableContext context) {
                if (arg instanceof Value value && value.expression instanceof Constant.StringConstant constant) {
                    return Integer.toString(constant.value().length());
                }
                throw new TemplateRenderException("Argument " + arg + " is not a literal string");
            }
            static String render(Expression arg, @Nullable NewVariableContext context) {
                if (arg instanceof Constant.StringConstant constant) {
                    return Integer.toString(constant.value().length());
                }
                throw new TemplateRenderException("Argument " + arg + " is not a literal string");
            }
        }

        record StrLenArg(int n) implements StrLen {
            @Override
            public String render(CallProps props, @Nullable NewVariableContext context) {
                return StrLen.render(props.args.arguments.get(n), context);
            }
        }

        record StrLenThis() implements StrLen {
            @Override
            public String render(CallProps props, @Nullable NewVariableContext context) {
                if (props.args.thisExpression == null) {
                    throw new TemplateRenderException("No this expression given for $strlen$this");
                }
                return StrLen.render(props.args.thisExpression, context);
            }
        }

        record StrArg(int n) implements TemplatePart {
            @Override
            public String render(CallProps props, @Nullable NewVariableContext context) {
                if (n >= props.args.arguments.size()) {
                    throw new TemplateRenderException("Argument " + (n + 1) + " not given for $str" + (n + 1));
                }
                var arg = props.args.arguments.get(n);
                if (arg instanceof Value value && value.expression instanceof Constant.StringConstant constant) {
                    return constant.value();
                }
                throw new TemplateRenderException("Argument " + arg + " is not a literal string");
            }
        }

        record TypeArgument(int n) implements TemplatePart {
            @Override
            public String render(CallProps props, @Nullable NewVariableContext context) {
                if (n >= props.args.typeArguments.size() || props.args.typeArguments.get(n) == null){
                    throw new TemplateRenderException("Template type argument " + (n + 1) + " not given");
                }
                return props.args.typeArguments.get(n).toPrettyString();
            }
        }

        record ClassTypeArgument(int n) implements TemplatePart {
            @Override
            public String render(CallProps props, @Nullable NewVariableContext context) {
                if (n >= props.args.classTypeArguments.size() || props.args.classTypeArguments.get(n) == null){
                    throw new TemplateRenderException("Template class type argument " + (n + 1) + " not given");
                }
                return props.args.classTypeArguments.get(n).toPrettyString();
            }
        }

        record PointeryArg(int n) implements TemplatePart {
            @Override
            public String render(CallProps props, @Nullable NewVariableContext context) {
                if (n >= props.args.arguments.size()) {
                    throw new TemplateRenderException("Argument " + (n + 1) + " not given for $pointery" + (n + 1));
                }
                var arg = props.args.arguments.get(n);
                if (!(arg instanceof Value value)) {
                    throw new TemplateRenderException("Argument " + arg + " is not a primary expression");
                }
                var inner = value.expression.toPrettyString();
                if (context == null || inner.matches("[(]*[a-zA-z_]+[)]*")) {
                    return "&" + inner;
                }
                return "&" + context.request(inner);
            }
        }

        private static Lambda getLambdaParam(CallProps props, int n, String text) {
            if (n >= props.args.arguments.size()) {
                throw new TemplateRenderException("Argument " + (n + 1) + " not given for " + text);
            }
            if (!(props.args.arguments.get(n) instanceof Lambda lambda)) {
                throw new TemplateRenderException("Argument " + (n + 1) + " is not a lambda for " + text);
            }
            return lambda;
        }

        private static FunctionParameter getLambdaParam(CallProps props, int n, int m, String text) {
            var lambda = getLambdaParam(props, n, text);
            if (m >= lambda.parameters.size()) {
                throw new TemplateRenderException("Not enough parameters in lambda " + (n + 1) + " for " + text);
            }
            return lambda.parameters.get(m);
        }

        record LambdaParam(int n, int m) implements TemplatePart {
            @Override
            public String render(CallProps props, @Nullable NewVariableContext context) {
                String text = String.format("$lambda%d:param%d", n + 1, m + 1);
                return TemplatePart.getLambdaParam(props, n, m, text).toPrettyString();
            }
        }

        record LambdaParamName(int n, int m) implements TemplatePart {
            @Override
            public String render(CallProps props, @Nullable NewVariableContext context) {
                String text = String.format("$lambda%d:param%d:name", n + 1, m + 1);
                return TemplatePart.getLambdaParam(props, n, m, text).name().toPrettyString();
            }
        }

        record LambdaParamType(int n, int m) implements TemplatePart {
            @Override
            public String render(CallProps props, @Nullable NewVariableContext context) {
                String text = String.format("$lambda%d:param%d:type", n + 1, m + 1);
                return TemplatePart.getLambdaParam(props, n, m, text).declarator().toPrettyString();
            }
        }

        record LambdaCode(int n) implements TemplatePart {
            @Override
            public String render(CallProps props, @Nullable NewVariableContext context) {
                String text = String.format("$lambda%d:code", n + 1);
                var code = TemplatePart.getLambdaParam(props, n, text).code();
                return code.toPrettyStringWithoutBraces();
            }
        }
    }

    static MethodTemplate parse(String methodName, String template) {
        return parse(methodName, template, null);
    }

    static MethodTemplate parse(String methodName, String template, @Nullable MethodSymbol methodSymbol) {
        if (template.isEmpty()) {
            return new MethodTemplate(methodName, template, List.of());
        }
        var parts = template.split("\\$");
        var templateParts = new ArrayList<TemplatePart>();
        for (int i = 0; i < parts.length; i++) {
            var part = parts[i];
            if (part.isEmpty()) {
                continue;
            }
            if (i == 0) {
                templateParts.add(new Verbatim(part));
                continue;
            }
            boolean hadStrLenBefore = false;
            boolean hadStrBefore = false;
            boolean hadPointeryBefore = false;
            if (part.startsWith("strlen")) {
                if (part.equals("strlen")) {
                    hadStrLenBefore = true;
                    i++;
                    part = parts[i];
                }
            } else if (part.startsWith("str")) {
                if (part.equals("str")) {
                    hadStrBefore = true;
                    i++;
                    part = parts[i];
                }
            } else if (part.equals("pointery")) {
                hadPointeryBefore = true;
                i++;
                part = parts[i];
            } else if (part.startsWith("lambda")) {
                // we're in $Lambda...
                /*
                 *     <li>{@code $lambdaM:code}: the code of the m-th lambda</li>
                 *     <li>{@code $lambdaM:paramN}: variable declaration for param n of the m-th lambda</li>
                 *     <li>{@code $lambdaM:paramN:type}: type of the parameter N of the m-th lambda</li>
                 *     <li>{@code $lambdaM:paramN:name}: name of the parameter N of the m-th lambda</li>
                 */
                int end = 6;
                while (end < part.length() && Character.isDigit(part.charAt(end))) {
                    end++;
                }
                int lambdaNum;
                try {
                    lambdaNum = Integer.parseInt(part.substring(6, end));
                } catch (NumberFormatException e) {
                    throw new TemplateRenderException("Invalid lambda number: $" + part);
                }
                String rest = part.substring(end);
                if (!rest.startsWith(":")) {
                    throw new TemplateRenderException("Invalid lambda part: $" + part + ", missing ':' after lambda number");
                }
                rest = rest.substring(1);
                if (rest.startsWith("code")) {
                    templateParts.add(new LambdaCode(lambdaNum - 1));
                    part = rest.substring(4);
                } else if (rest.startsWith("param")) {
                    int paramNum;
                    end = 5;
                    while (end < rest.length() && Character.isDigit(rest.charAt(end))) {
                        end++;
                    }
                    try {
                        paramNum = Integer.parseInt(rest.substring(5, end));
                    } catch (NumberFormatException e) {
                        throw new TemplateRenderException("Invalid lambda parameter number: $" + part);
                    }
                    String rest2 = rest.substring(end);
                    if (!rest2.startsWith(":")) {
                        templateParts.add(new LambdaParam(lambdaNum - 1, paramNum - 1));
                        part = rest2;
                    } else {
                        rest2 = rest2.substring(1);
                        if (rest2.startsWith("type")) {
                            templateParts.add(new LambdaParamType(lambdaNum - 1, paramNum - 1));
                            part = rest2.substring(4);
                        } else if (rest2.startsWith("name")) {
                            templateParts.add(new LambdaParamName(lambdaNum - 1, paramNum - 1));
                            part = rest2.substring(4);
                        } else {
                            throw new TemplateRenderException("Unknown lambda part: $" + part);
                        }
                    }
                } else {
                    throw new TemplateRenderException("Unknown lambda part: $" + part);
                }
                if (!part.isEmpty()) {
                    templateParts.add(new Verbatim(part));
                }
                continue;
            }

            if (part.startsWith("name")) {
                templateParts.add(new Name());
                part = part.substring(4);
            } else if (part.startsWith("this")) {
                templateParts.add(hadStrLenBefore ? new StrLenThis() : new This());
                part = part.substring(4);
            } else {
                // split at first char that is neither number nor char
                int j = 0;
                while (j < part.length() && Character.isAlphabetic(part.charAt(j))) {
                    j++;
                }
                String name = part.substring(0, j);
                if (name.isEmpty()) {
                    throw new TemplateRenderException("Unknown template part: $" + part);
                }
                int k = j;
                while (k < part.length() && Character.isDigit(part.charAt(k))) {
                    k++;
                }
                String numStr = part.substring(j, k);
                switch (name) {
                    case "args" -> {
                        if (numStr.isEmpty()) {
                            templateParts.add(new Args());
                        } else {
                            templateParts.add(new SubArgs(Integer.parseInt(numStr) - 1));
                            if (k < part.length() && part.charAt(k) == '_') {
                                k++;
                            }
                        }
                    }
                    case "arg" -> {
                        int num;
                        try {
                            num = Integer.parseInt(numStr) - 1;
                        } catch (NumberFormatException e) {
                            throw new TemplateRenderException("Invalid argument number: $" + part);
                        }
                        // if _ comes directly after the number
                        if (k < part.length() && part.charAt(k) == '_') {
                            templateParts.add(new SubArgs(num));
                            k++;
                        } else {
                            if (hadStrBefore) {
                                templateParts.add(new StrArg(num));
                            } else if (hadStrLenBefore) {
                                templateParts.add(new StrLenArg(num));
                            } else if (hadPointeryBefore) {
                                // only if non pointery itself
                                if (methodSymbol == null) {
                                    throw new AssertionError();
                                }
                                var type = methodSymbol.getParameters().get(num).asType();
                                var typeName = type.baseType().asElement().getQualifiedName().toString();
                                if (type.getKind() == TypeKind.ARRAY || typeName.equals("java.lang.String") ||
                                        typeName.equals(Ptr.class.getName())) {
                                    templateParts.add(new Arg(num));
                                } else {
                                    templateParts.add(new PointeryArg(num));
                                }
                            } else {
                                templateParts.add(new Arg(num));
                            }
                        }
                    }
                    case "T" -> {
                        try {
                            templateParts.add(new TypeArgument(Integer.parseInt(numStr) - 1));
                        } catch (NumberFormatException e) {
                            throw new TemplateRenderException("Invalid type argument number: $" + part);
                        }
                    }
                    case "C" -> {
                        try {
                            templateParts.add(new ClassTypeArgument(Integer.parseInt(numStr) - 1));
                        } catch (NumberFormatException e) {
                            throw new TemplateRenderException("Invalid class type argument number: $" + part);
                        }
                    }
                    default -> throw new TemplateRenderException("Unknown template part: $" + part);
                }
                part = part.substring(k);
            }
            if (hadStrLenBefore && !(templateParts.getLast() instanceof StrLen)) {
                throw new TemplateRenderException("strlen can only be used with a $argN or $this argument");
            }
            if (hadStrBefore && !(templateParts.getLast() instanceof StrArg)) {
                throw new TemplateRenderException("str can only be used with a $argN argument");
            }
            if (!part.isEmpty()) {
                templateParts.add(new Verbatim(part));
            }
        }
        if (templateParts.size() == 1 && templateParts.getFirst() instanceof Name) {
            return new MethodTemplate(methodName, template, List.of(new Name(), new Verbatim("("), new Args(),
                    new Verbatim(")")));
        }
        return new MethodTemplate(methodName, template, templateParts);
    }

    public VerbatimExpression call(CallArgs args) {
        NewVariableContext context = new NewVariableContext();
        List<String> renderedParts = parts.stream()
                .map(part -> part.render(new CallProps(methodName, args), context))
                .toList();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < parts.size(); i++) {
            var rendered = renderedParts.get(i);
            // handle $argsN case where the resulting expression is empty
            // and $argsN is prefixed by a comma
            if (i < parts.size() - 1 &&
                    renderedParts.get(i + 1).isEmpty() &&
                    parts.get(i + 1) instanceof SubArgs &&
                    rendered.strip().endsWith(",")) {
                var stripped = rendered.strip();
                sb.append(stripped, 0, stripped.length() - 1);
            } else {
                sb.append(renderedParts.get(i));
            }
        }
        return context.wrap(new VerbatimExpression(sb.toString()));
    }
}
