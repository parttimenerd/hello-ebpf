package me.bechberger.ebpf.bpf.compiler;

import me.bechberger.cast.CAST;
import me.bechberger.cast.CAST.Expression;
import me.bechberger.cast.CAST.PrimaryExpression.Constant;
import me.bechberger.cast.CAST.PrimaryExpression.VerbatimExpression;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.bpf.compiler.MethodTemplate.TemplatePart.*;
import me.bechberger.ebpf.bpf.compiler.MethodTemplateCache.TemplateRenderException;
import org.jetbrains.annotations.Nullable;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * Processed method call templates of {@link BuiltinBPFFunction} annotated methods
 */
public record MethodTemplate(String methodName, String raw, List<TemplatePart> parts) {

    public record CallArgs(@Nullable CAST.Expression thisExpression,
                           List<? extends Expression> arguments, List<CAST.Declarator> typeArguments) {
    }

    public record CallProps(String methodName, CallArgs args) {
    }

    /**
     * A part of a template, modelled after the different placeholders in the template in {@link BuiltinBPFFunction}
     */
    sealed interface TemplatePart {
        String render(CallProps props);

        record Verbatim(String verb) implements TemplatePart {
            @Override
            public String render(CallProps props) {
                return verb;
            }
        }

        record Name() implements TemplatePart {
            @Override
            public String render(CallProps props) {
                return props.methodName;
            }
        }

        record Arg(int n) implements TemplatePart {
            @Override
            public String render(CallProps props) {
                if (n >= props.args.arguments.size()) {
                    throw new TemplateRenderException("Argument " + (n + 1) + " not given for $arg" + (n + 1));
                }
                return props.args.arguments.get(n).toPrettyString();
            }
        }

        record SubArgs(int n) implements TemplatePart {
            @Override
            public String render(CallProps props) {
                return IntStream.range(n, props.args.arguments.size())
                        .mapToObj(i -> props.args.arguments.get(i).toPrettyString())
                        .collect(Collectors.joining(", "));
            }
        }

        record Args() implements TemplatePart {
            @Override
            public String render(CallProps props) {
                return new SubArgs(0).render(props);
            }
        }

        record This() implements TemplatePart {
            @Override
            public String render(CallProps props) {
                if (props.args.thisExpression == null) {
                    throw new TemplateRenderException("No this expression given for $this");
                }
                return props.args.thisExpression.toPrettyString();
            }
        }

        sealed interface StrLen extends TemplatePart {
            static String render(Expression arg) {
                if (arg instanceof Constant.StringConstant constant) {
                    return Integer.toString(constant.value().length());
                }
                throw new TemplateRenderException("Argument " + arg + " is not a literal string");
            }
        }

        record StrLenArg(int n) implements StrLen {
            @Override
            public String render(CallProps props) {
                return StrLen.render(props.args.arguments.get(n));
            }
        }

        record StrLenThis() implements StrLen {
            @Override
            public String render(CallProps props) {
                if (props.args.thisExpression == null) {
                    throw new TemplateRenderException("No this expression given for $strlen$this");
                }
                return StrLen.render(props.args.thisExpression);
            }
        }

        record StrArg(int n) implements TemplatePart {
            @Override
            public String render(CallProps props) {
                if (n >= props.args.arguments.size()) {
                    throw new TemplateRenderException("Argument " + (n + 1) + " not given for $str" + (n + 1));
                }
                var arg = props.args.arguments.get(n);
                if (arg instanceof Constant.StringConstant constant) {
                    return constant.value();
                }
                throw new TemplateRenderException("Argument " + arg + " is not a literal string");
            }
        }

        record TypeArgument(int n) implements TemplatePart {
            @Override
            public String render(CallProps props) {
                if (n >= props.args.typeArguments.size()) {
                    throw new TemplateRenderException("Template type argument " + (n + 1) + " not given");
                }
                return props.args.typeArguments.get(n).toPrettyString();
            }
        }
    }

    static MethodTemplate parse(String methodName, String template) {
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
            if (part.startsWith("strlen")) {
                if (part.equals("strlen")) {
                    hadStrLenBefore = true;
                    i++;
                    part = parts[i];
                }
            }
            if (part.startsWith("str")) {
                if (part.equals("str")) {
                    hadStrBefore = true;
                    i++;
                    part = parts[i];
                }
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

    public Expression call(CallArgs args) {
        List<String> renderedParts = parts.stream().map(part -> part.render(new CallProps(methodName, args)))
                .toList();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < parts.size(); i++) {
            var rendered = renderedParts.get(i);
            // handle $argsN case where the resulting expression is empt
            // and $argsN is prefixed by a comma
            if (i < parts.size() - 1 &&
                    renderedParts.get(i + 1).isEmpty() &&
                    parts.get(i + 1) instanceof SubArgs &&
                    rendered.strip().endsWith(",")) {
                continue;
            }
            sb.append(renderedParts.get(i));
        }
        return new VerbatimExpression(sb.toString());
    }
}
