package me.bechberger.ebpf.gen;

import me.bechberger.ebpf.gen.Generator.Kind;
import me.bechberger.ebpf.gen.Generator.NameTranslator;
import me.bechberger.ebpf.gen.Generator.Type;
import me.bechberger.ebpf.gen.Generator.Type.*;
import org.jetbrains.annotations.Nullable;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.stream.Stream;

import static me.bechberger.ebpf.gen.SystemCallProcessor.clean;

/**
 * Parse C declarations to generate {@link FuncType} instances
 * <p>
 * This assumes that the {@link Generator} generated the BPF types and that they are in
 * the same package.
 * <p>
 * Best effort, it doesn't try to parse all possible C declarations, just the declarations
 * found in the ebpf context
 * <p>
 * Supported are currently the following types
 * <ul>
 *     <li>structs</li>
 *     <li>unions</li>
 *     <li>int, long, ... ("__" are ignored)</li>
 *     <li>void</li>
 *     <li>pointer to a supported type (and {@code restricted} and {@code _Nullable} annotations)</li>
 *     <li>array of a supported type (with {@code restricted} and {@code _Nullable} annotations in the index
 *     expression)</li>
 *     <li>Functions (albeit they are represented as {@code Ptr<?>} for now)</li>
 * </ul>
 */
public class DeclarationParser {

    public static class CannotParseException extends RuntimeException {
        public CannotParseException(String message) {
            super(message);
        }

        public CannotParseException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public static FuncType parseFunctionDeclaration(String declaration) {
        return parseFunctionDeclaration(new NameTranslator(new Generator("")), declaration);
    }
    /**
     * Parse a C function declaration to generate a {@link FuncType} instance
     * <p>
     * Example declaration {@code void print(char* param);}
     *
     * @param declaration the C declaration
     * @return the {@link FuncType} instance
     */
    public static FuncType parseFunctionDeclaration(NameTranslator translator, String declaration) {
        try {
            return parseFunctionDeclarationParts(declaration).toFuncType(translator);
        } catch (CannotParseException e) {
            throw new CannotParseException("Cannot parse function declaration: " + declaration, e);
        }
    }

    public static FuncType parseFunctionVariableDeclaration(String declaration) {
        return parseFunctionVariableDeclaration(new NameTranslator(new Generator("")), declaration);
    }

    /**
     * Parse a C function variable declaration to generate a {@link FuncType} instance
     * {@code static long (* const bpf_bind)(struct bpf_sock_addr *ctx, struct sockaddr *addr, int addr_len) = (void
     * *) 64;}
     */
    public static FuncType parseFunctionVariableDeclaration(NameTranslator translator, String declaration) {
        try {
            return parseFunctionDeclarationVariableParts(declaration).toFuncType(translator);
        } catch (CannotParseException e) {
            throw new CannotParseException("Cannot parse function variable declaration: " + declaration, e);
        }
    }

    /**
     * A function declaration split into its major parts
     */
    record FuncDeclParts(String returnType, String name, String[] params) {

        FuncType toFuncType() {
            return toFuncType(new NameTranslator(new Generator("")));
        }

        FuncType toFuncType(NameTranslator translator) {
            var parsedParams = Stream.of(params).map(p -> parseFunctionParameter(translator, p)).toList();
            boolean isVariadic = false;
            List<FuncParameter> parameters = new ArrayList<>();
            for (int i = 0; i < parsedParams.size(); i++) {
                var param = parsedParams.get(i);
                if (param.kind == ParamParseResultKind.VARARGS) {
                    if (i != parsedParams.size() - 1) {
                        throw new CannotParseException("Variadic parameter must be the last parameter");
                    }
                    isVariadic = true;
                    parameters.add(new FuncParameter("args", new ArrayType(new AnyType(), -1)));
                }
                if (param.kind == ParamParseResultKind.PARAM) {
                    parameters.add(param.param);
                }
            }
            return new FuncType(name, new FuncProtoType(parameters, parseType(translator, returnType), isVariadic));
        }
    }

    /**
     * Parse something like {@code static void (* const print)(void) = (void*) 0}
     * and split it into its major parts, throwing away static and the initializer
     */
    private static DeclarationParser.FuncDeclParts parseFunctionDeclarationVariableParts(String declaration) {
        var withoutInit = clean(declaration.split(" = ")[0]);
        var withoutStatic = withoutInit.replace("static ", "");
        var parts = topParenthesesSplit(withoutStatic);
        if (parts.length != 3 || !parts[1].startsWith("(") || !parts[1].endsWith(")")) {
            throw new CannotParseException("Cannot parse function variable declaration: " + declaration);
        }
        var returnType = parts[0].trim();
        var nameContParts = parts[1].substring(1, parts[1].length() - 1).split(" ");
        var name = nameContParts[nameContParts.length - 1];
        // function pointers as parameters are not supported
        var paramPart = parts[2].substring(1, parts[2].length() - 1);
        var params = Arrays.stream(topCommaSplit(paramPart)).filter(s -> !s.isBlank()).toArray(String[]::new);
        return new FuncDeclParts(returnType, name, params);
    }

    /**
     * Parse something like {@code void* print();}
     * and split it into its major parts, throwing away static and the initializer
     */
    private static DeclarationParser.FuncDeclParts parseFunctionDeclarationParts(String declaration) {
        declaration = clean(declaration);
        // remove annotations like [[deprecated]]
        declaration = declaration.replaceAll("\\[\\[[a-zA-Z-_]+]]", "").trim();
        if (declaration.endsWith(";")) { // remove comma at the end
            declaration = declaration.substring(0, declaration.length() - 1);
        }
        var parts = topParenthesesSplit(declaration);
        if (parts.length != 2 || !parts[1].startsWith("(") || !parts[1].endsWith(")")) {
            throw new CannotParseException("Cannot parse function declaration: " + declaration);
        }
        var returnTypeAndName = parts[0];
        // name has to start with a letter, rest is type
        var matcher = java.util.regex.Pattern.compile("[a-zA-Z_][a-zA-Z0-9_]*$").matcher(returnTypeAndName);
        var name = returnTypeAndName.substring(matcher.find() ? matcher.start() : 0).trim();
        var returnType = returnTypeAndName.substring(0, returnTypeAndName.length() - name.length()).trim();
        // remove outer parentheses from params
        var paramPart = parts[1].substring(1, parts[1].length() - 1);
        var params = Arrays.stream(topCommaSplit(paramPart)).filter(s -> !s.isBlank()).toArray(String[]::new);
        return new FuncDeclParts(returnType, name, params);
    }

    /**
     * Split a string at the top level parentheses and strip the parts
     * <p>
     * Example: {@code void (*print)(int i, int j)} will be split into {@code ["void", "(*print)", "(int i, int j)"]}
     *
     * @param input the input string
     * @return the split string
     */
    static String[] topParenthesesSplit(String input) {
        List<String> parts = new ArrayList<>();
        var open = 0;
        var start = 0;
        for (int i = 0; i < input.length(); i++) {
            if (input.charAt(i) == '(') {
                if (open == 0 && start != i) {
                    parts.add(input.substring(start, i).strip());
                    start = i;
                }
                open++;
            }
            if (input.charAt(i) == ')') {
                open--;
                if (open == 0) {
                    parts.add(input.substring(start, i + 1).strip());
                    start = i + 1;
                }
            }
        }
        if (start != input.length()) {
            parts.add(input.substring(start).strip());
        }
        return parts.toArray(new String[0]);
    }

    /**
     * Split a string at the top level commas, keeping paranthese groups together, stripping the parts
     * <p>
     * Example: {@code int (i), int j} will be split into {@code ["int (i)", "int j"]}
     *
     */
    static String[] topCommaSplit(String input) {
        List<String> parts = new ArrayList<>();
        var open = 0;
        var start = 0;
        for (int i = 0; i < input.length(); i++) {
            if (input.charAt(i) == '(') {
                open++;
            }
            if (input.charAt(i) == ')') {
                open--;
            }
            if (input.charAt(i) == ',' && open == 0) {
                parts.add(input.substring(start, i).strip());
                start = i + 1;
            }
        }
        if (start != input.length()) {
            parts.add(input.substring(start).strip());
        }
        return parts.toArray(new String[0]);
    }

    enum ParamParseResultKind {
        VARARGS,
        PARAM,
        NONE
    }

    record ParamParseResult(ParamParseResultKind kind, @Nullable FuncParameter param) {
        public static ParamParseResult none() {
            return new ParamParseResult(ParamParseResultKind.NONE, null);
        }

        public static ParamParseResult param(FuncParameter param) {
            return new ParamParseResult(ParamParseResultKind.PARAM, param);
        }

        public static ParamParseResult varargs() {
            return new ParamParseResult(ParamParseResultKind.VARARGS, null);
        }
    }

    /**
     * Parse a C function parameter to generate a {@link FuncParameter} instance
     *
     * @return null for any variadic ({@code ...})
     */
    static ParamParseResult parseFunctionParameter(NameTranslator translator, String param) {

        if (param.contains("(*") && param.contains(")")) {
            return parseFunctionTypeParameter(param);
        }

        // get last match of "[a-zA-Z0-9_]+$" in param
        param = param.strip();
        if (param.equals("...")) {
            return ParamParseResult.varargs();
        }
        // if is array, handle specially
        Matcher m = java.util.regex.Pattern.compile("[a-zA-Z0-9_]+$").matcher(param);
        if (!m.find()) {
            // this might be because it is an array expression
            // match the last bracket
            m = java.util.regex.Pattern.compile("\\[.*]$").matcher(param);
            if (!m.find()) {
                throw new DeclarationParser.CannotParseException("Cannot parse parameter: " + param);
            }
            // remove array expression
            var bracket = m.group();
            param = param.substring(0, param.length() - bracket.length()).trim();
            var elemTypeResult = parseFunctionParameter(translator, param);
            if (elemTypeResult.kind != ParamParseResultKind.PARAM) {
                throw new DeclarationParser.CannotParseException("Cannot parse parameter: " + param);
            }
            assert elemTypeResult.param != null;
            var elemType = elemTypeResult.param.type();
            var arraySizeExpression = bracket.substring(1, bracket.length() - 1);
            var nullable = arraySizeExpression.contains("_Nullable");
            arraySizeExpression = arraySizeExpression.replace("_Nullable", "").strip();
            if (arraySizeExpression.matches("[0-9]+")) {
                // a size we can work with, so create an array
                var size = Integer.parseInt(arraySizeExpression);
                return ParamParseResult.param(new FuncParameter(elemTypeResult.param.name(), new ArrayType(elemType.resolve(),
                        size, nullable)));
            }
            // we cannot parse the size, so we just create a pointer
            return ParamParseResult.param(new FuncParameter(elemTypeResult.param.name(), new PtrType(elemType.resolve(),
                    nullable)));
        }
        // last match
        var name = m.group();
        // remove type from param
        var type = param.substring(0, param.length() - name.length()).trim();
        if (type.isEmpty()) {
            if (!name.equals("void")) {
                throw new DeclarationParser.CannotParseException("Cannot parse parameter: " + param);
            }
            return ParamParseResult.none();
        }
        return ParamParseResult.param(new FuncParameter(name, parseType(translator, type)));
    }

    public static Type parseType(NameTranslator translator, String type) {
        type = type.strip();
        if (type.equals("void")) {
            return new VoidType();
        }
        if (KnownTypes.isKnownInt(type)) {
            return new IntType(KnownTypes.getKnowIntUnchecked(type));
        }
        if (type.endsWith("*")) {
            var t = parseType(translator, type.substring(0, type.length() - 1));
            return new PtrType(t);
        }
        if (type.endsWith("_Nullable")) { // a nullable pointer
            var t = parseType(translator, type.substring(0, type.length() - 9));
            // assume that this is a pointer
            if (!(t instanceof PtrType)) {
                throw new DeclarationParser.CannotParseException(type + " cannot be nullable");
            }
            return new PtrType(((PtrType) t).resolvedPointee(), true);
        }
        if (type.endsWith("restrict")) {
            var t = parseType(translator, type.substring(0, type.length() - 8));
            return new MirrorType(Kind.RESTRICT, t);
        }
        if (type.startsWith("const ")) {
            var t = parseType(translator, type.substring(6));
            return new MirrorType(Kind.CONST, t);
        }
        if (type.startsWith("volatile ")) {
            var t = parseType(translator, type.substring(9));
            return new MirrorType(Kind.VOLATILE, t);
        }
        if (type.endsWith("*const")) {
            // we drop the const here, to make it easier
            var t = parseType(translator, type.substring(0, type.length() - 5));
            return new PtrType(t);
        }
        if (!type.contains(" ")) {
            var translated = translator.translate(type);
            if (KnownTypes.isKnownInt(translated.cName())) {
                return new IntType(KnownTypes.getKnowIntUnchecked(translated.cName()));
            }
            return translated;
        }
        if (type.startsWith("struct ")) {
            var name = type.substring(7);
            var translated = translator.translate(name);
            return new VerbatimType("struct " + translated.cName(), translated);
        }
        if (type.startsWith("union ")) {
            var name = type.substring(6);
            var translated = translator.translate(name);
            return new VerbatimType("union " + translated.cName(), translated);
        }
        if (type.startsWith("enum ")) {
            var name = type.substring(5);
            var translated = translator.translate(name);
            return new VerbatimType("enum " + translated.cName(), translated);
        }
        throw new CannotParseException("Cannot parse type: " + type);
    }

    /**
     * parses parameters with type function
     */
    private static ParamParseResult parseFunctionTypeParameter(String param) {
        // get name group
        var parts = topParenthesesSplit(param);
        if (parts.length != 3 && parts[1].matches("\\(\\*[a-zA-Z]+\\)")) {
            throw new DeclarationParser.CannotParseException("Cannot parse parameter: " + param);
        }
        var name = parts[1].substring(2, parts[1].length() - 1);
        return ParamParseResult.param(new FuncParameter(name, new PtrType(new VoidType())));
    }
}
