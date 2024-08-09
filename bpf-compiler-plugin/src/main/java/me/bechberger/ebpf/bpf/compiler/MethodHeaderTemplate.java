package me.bechberger.ebpf.bpf.compiler;

import me.bechberger.cast.CAST.Declarator.FunctionDeclarator;
import me.bechberger.cast.CAST.Declarator.FunctionHeader;
import me.bechberger.cast.CAST.Declarator.FunctionParameter;
import me.bechberger.cast.CAST.Declarator.VerbatimFunctionDeclarator;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.bpf.compiler.MethodHeaderTemplate.TemplatePart.*;
import me.bechberger.ebpf.bpf.compiler.MethodTemplateCache.TemplateRenderException;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Processed header templates of {@link BPFFunction} annotated methods
 */
public record MethodHeaderTemplate(String raw, List<TemplatePart> parts) {

    /**
     * A part of a template, modelled after the different placeholders in the template in {@link BuiltinBPFFunction}
     */
    sealed interface TemplatePart {
        String render(FunctionDeclarator declarator);

        record Verbatim(String verb) implements TemplatePart {
            @Override
            public String render(FunctionDeclarator declarator) {
                return verb;
            }
        }

        record Name() implements TemplatePart {
            @Override
            public String render(FunctionDeclarator declarator) {
                return declarator.name().toString();
            }
        }

        record Return() implements TemplatePart {
            @Override
            public String render(FunctionDeclarator declarator) {
                return declarator.returnValue().toPrettyString();
            }
        }

        record ParamName(int n) implements TemplatePart {
            @Override
            public String render(FunctionDeclarator declarator) {
                if (n >= declarator.parameters().size()) {
                    throw new TemplateRenderException("Parameter " + (n + 1) + " not given for $paramName" + (n + 1));
                }
                return declarator.parameters().get(n).name().toString();
            }
        }

        record ParamType(int n) implements TemplatePart {
            @Override
            public String render(FunctionDeclarator declarator) {
                if (n >= declarator.parameters().size()) {
                    throw new TemplateRenderException("Parameter " + (n + 1) + " not given for $paramType" + (n + 1));
                }
                return declarator.parameters().get(n).declarator().toPrettyString();
            }
        }

        record Param(int n) implements TemplatePart {
            @Override
            public String render(FunctionDeclarator declarator) {
                if (n >= declarator.parameters().size()) {
                    throw new TemplateRenderException("Parameter " + (n + 1) + " not given for $param" + (n + 1));
                }
                return declarator.parameters().get(n).toPrettyString();
            }
        }

        record Params() implements TemplatePart {
            @Override
            public String render(FunctionDeclarator declarator) {
                return declarator.parameters().stream().map(FunctionParameter::toPrettyString).collect(Collectors.joining(", "));
            }
        }
    }

    static MethodHeaderTemplate parse(String template) {
        if (template.isEmpty()) {
            throw new TemplateRenderException("Empty header template");
        }
        if (template.endsWith(";")) {
            template = template.substring(0, template.length() - 1);
        }
        var parts = template.split("\\$");
        var templateParts = new ArrayList<TemplatePart>();
        for (int i = 0; i < parts.length; i++) {
            var part = parts[i];
            if (part.isEmpty()) {
                continue;
            }
            if (i == 0) {
                templateParts.add(new TemplatePart.Verbatim(part));
                continue;
            }

            if (part.startsWith("name")) {
                templateParts.add(new TemplatePart.Name());
                part = part.substring(4);
            } else if (part.startsWith("return")) {
                templateParts.add(new TemplatePart.Return());
                part = part.substring(6);
            } else if (part.startsWith("params")) {
                templateParts.add(new TemplatePart.Params());
                part = part.substring(5);
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
                int num = Integer.parseInt(part.substring(j, k));
                switch (name) {
                    case "paramName" -> templateParts.add(new ParamName(num - 1));
                    case "paramType" -> templateParts.add(new ParamType(num - 1));
                    case "param" -> templateParts.add(new Param(num - 1));
                    default -> throw new TemplateRenderException("Unknown template part: $" + name + num);
                }
                part = part.substring(k);
            }
            if (!part.isEmpty()) {
                templateParts.add(new TemplatePart.Verbatim(part));
            }
        }
        if (templateParts.size() == 1 && templateParts.getFirst() instanceof TemplatePart.Name) {
            return new MethodHeaderTemplate(template,
                    List.of(new Return(), new Verbatim(" "), new Name(), new Verbatim("("), new Params(),
                            new Verbatim(")")));
        }
        return new MethodHeaderTemplate(template, templateParts);
    }

    public FunctionHeader call(FunctionDeclarator declarator) {
        return call(declarator, "");
    }

    public FunctionHeader call(FunctionDeclarator declarator, String prefix) {
        if (raw.equals("$name")) {
            return new VerbatimFunctionDeclarator(prefix + declarator.toPrettyString());
        }
        return new VerbatimFunctionDeclarator(prefix + parts.stream().map(part -> part.render(declarator)).collect(Collectors.joining("")));
    }
}
