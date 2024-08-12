package me.bechberger.cast;

import me.bechberger.cast.CAST.Declarator.FunctionHeader;
import me.bechberger.cast.CAST.Declarator.Pointery;
import me.bechberger.cast.CAST.PrimaryExpression.CAnnotation;
import me.bechberger.cast.CAST.PrimaryExpression.Constant;
import me.bechberger.cast.CAST.PrimaryExpression.Constant.FloatConstant;
import me.bechberger.cast.CAST.PrimaryExpression.Variable;
import me.bechberger.cast.CAST.Statement.VerbatimStatement;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static me.bechberger.cast.CAST.OperatorExpression.stripPrint;

/**
 * Represents an abstract syntax tree for C,
 * loosely based on the grammar from <a href="https://www.lysator.liu.se/c/ANSI-C-grammar-y.html">lysator.liu.se</a>,
 * for generating eBPF C programs.
 * <p>
 * Example: {@snippet :
 *  variableDefinition(struct(variable("myStruct"),
 *       List.of(
 *           structMember(Declarator.identifier("int"), variable("b")))
 *       ), variable("myVar", sec("a"))
 *  )
 *}
 */
public interface CAST {

    List<? extends CAST> children();

    Statement toStatement();

    /**
     * Generate pretty printed code
     */
    default String toPrettyString() {
        return toPrettyString("", "  ");
    }

    /**
     * Generate pretty printed code
     */
    String toPrettyString(String indent, String increment);

    static String toStringLiteral(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\"";
    }

    sealed interface Expression extends CAST permits Declarator, InitDeclarator, Initializer, OperatorExpression,
            PrimaryExpression {

        @Override
        List<? extends Expression> children();

        @Override
        default Statement toStatement() {
            return Statement.expression(this);
        }

        static PrimaryExpression.Constant<?> constant(Object value) {
            switch (value) {
                case Integer i -> {
                    return new PrimaryExpression.Constant.IntegerConstant(i);
                }
                case Long l -> {
                    return new PrimaryExpression.Constant.LongConstant(l);
                }
                case Character c -> {
                    return new PrimaryExpression.Constant.CharConstant(c);
                }
                case String s -> {
                    return new PrimaryExpression.Constant.StringConstant(s);
                }
                case Double d -> {
                    return new PrimaryExpression.Constant.DoubleConstant(d);
                }
                case Float f -> {
                    return new FloatConstant(f);
                }
                case Byte b -> {
                    return new PrimaryExpression.Constant.IntegerConstant((int) b);
                }
                case Short s -> {
                    return new PrimaryExpression.Constant.IntegerConstant((int) s);
                }
                case Boolean b -> {
                    return new PrimaryExpression.Constant.IntegerConstant(b ? 1 : 0);
                }
                default -> throw new IllegalArgumentException("Unsupported constant type: " + value.getClass());
            }
        }

        static PrimaryExpression.Variable variable(String name) {
            return name == null ? null : new PrimaryExpression.Variable(name);
        }

        static PrimaryExpression.Variable variable(String name, PrimaryExpression.CAnnotation... annotations) {
            return new PrimaryExpression.Variable(name, annotations);
        }

        static PrimaryExpression.ParenthesizedExpression parenthesizedExpression(Expression expression) {
            return new PrimaryExpression.ParenthesizedExpression(expression);
        }

        static PrimaryExpression.EnumerationConstant enumerationConstant(String name) {
            return new PrimaryExpression.EnumerationConstant(name);
        }

        static PrimaryExpression.VerbatimExpression verbatim(String code) {
            return new PrimaryExpression.VerbatimExpression(code);
        }

        static PrimaryExpression.Variable _void() {
            return new PrimaryExpression.Variable("void");
        }
    }

    /**
     * {@snippet :
     * primary_expression
     * 	: IDENTIFIER
     * 	| constant
     * 	| string
     * 	| '(' expression ')'
     * 	;
     *}
     */
    sealed interface PrimaryExpression extends Expression {

        @Override
        default List<? extends Expression> children() {
            return List.of();
        }

        /**
         * Annotation like <code>@SEC("...")</code>
         *
         * @param annotation
         * @param value
         */
        record CAnnotation(String annotation, String value) implements CAST {
            @Override
            public List<? extends CAST> children() {
                return List.of();
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                return indent + annotation + "(" + Expression.constant(value).toPrettyString() + ")";
            }

            static CAnnotation annotation(String annotation, String value) {
                return new CAnnotation(annotation, value);
            }

            public static CAnnotation sec(String value) {
                return new CAnnotation("SEC", value);
            }

            @Override
            public Statement toStatement() {
                throw new UnsupportedOperationException("CAnnotation cannot be converted to a statement");
            }
        }

        /**
         * Variable name for expressions
         */
        record Variable(String name, CAnnotation... annotations) implements PrimaryExpression {
            @Override
            public String toPrettyString(String indent, String increment) {
                var annString = annotationsString();
                return indent + name + (annString.isEmpty() ? "" : " " + annString);
            }

            public String annotationsString() {
                return Arrays.stream(annotations).map(CAnnotation::toPrettyString).collect(Collectors.joining(" "));
            }

            @Override
            public String toString() {
                return toPrettyString("", "");
            }
        }

        record EnumerationConstant(String name) implements PrimaryExpression {
            @Override
            public String toPrettyString(String indent, String increment) {
                return indent + name;
            }
        }

        sealed interface Constant<T> extends PrimaryExpression {
            T value();

            record IntegerConstant(Integer value) implements Constant<Integer> {
                @Override
                public String toPrettyString(String indent, String increment) {
                    return indent + value;
                }
            }

            record LongConstant(Long value) implements Constant<Long> {
                @Override
                public String toPrettyString(String indent, String increment) {
                    return indent + value + "L";
                }
            }

            record CharConstant(Character value) implements Constant<Character> {
                @Override
                public String toPrettyString(String indent, String increment) {
                    return indent + "'" + (value == '\'' ? "\\'" : value) + "'";
                }
            }

            record StringConstant(String value) implements Constant<String> {
                @Override
                public String toPrettyString(String indent, String increment) {
                    return indent + toStringLiteral(value);
                }
            }

            record FloatConstant(Float value) implements Constant<Float> {
                @Override
                public String toPrettyString(String indent, String increment) {
                    return indent + value;
                }
            }

            record DoubleConstant(Double value) implements Constant<Double> {
                @Override
                public String toPrettyString(String indent, String increment) {
                    return indent + value;
                }
            }
        }

        /**
         * Wraps an expression in parentheses
         */
        record ParenthesizedExpression(Expression expression) implements PrimaryExpression {
            @Override
            public String toPrettyString(String indent, String increment) {
                return indent + "(" + expression.toPrettyString() + ")";
            }

            @Override
            public List<? extends Expression> children() {
                return List.of(expression);
            }
        }

        record VerbatimExpression(String code) implements PrimaryExpression {
            @Override
            public List<? extends PrimaryExpression> children() {
                return List.of();
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                return indent + code;
            }
        }

        record TypeExpression(Declarator declarator) implements PrimaryExpression {
            @Override
            public String toPrettyString(String indent, String increment) {
                return indent + declarator.toPrettyString();
            }
        }
    }

    /**
     * Operators with precedence and associativity,
     * based on <a href="https://en.cppreference.com/w/cpp/language/operator_precedence">cppreference.com</a>
     */
    enum Operator {
        SUFFIX_INCREMENT("++", 2), SUFFIX_DECREMENT("--", 2), FUNCTION_CALL("()", 2), SUBSCRIPT("[]", 2),
        PTR_MEMBER_ACCESS("->", 2), MEMBER_ACCESS(".", 2), POSTFIX_INCREMENT("++", 3), POSTFIX_DECREMENT("--", 3), UNARY_PLUS("+", 3),
        UNARY_MINUS("-", 3), LOGICAL_NOT("!", 3), BITWISE_NOT("~", 3), DEREFERENCE("*", 3), ADDRESS_OF("&", 3),
        SIZEOF("sizeof", 3), CAST("cast", 3), MULTIPLICATION("*", 5), DIVISION("/", 5), MODULUS("%", 5), ADDITION("+"
                , 6), SUBTRACTION("-", 6), SHIFT_LEFT("<<", 7), SHIFT_RIGHT(">>", 7), LESS_THAN("<", 9),
        LESS_THAN_OR_EQUAL("<=", 9), GREATER_THAN(">", 9), GREATER_THAN_OR_EQUAL(">=", 9), EQUAL("==", 10),
        NOT_EQUAL("!=", 10), BITWISE_AND("&", 11), BITWISE_XOR("^", 12), BITWISE_OR("|", 13), LOGICAL_AND("&&", 14),
        LOGICAL_OR("||", 15), CONDITIONAL("?", 16), ASSIGNMENT("=", 16), MULTIPLICATION_ASSIGNMENT("*=", 16),
        DIVISION_ASSIGNMENT("/=", 16), MODULUS_ASSIGNMENT("%=", 16), ADDITION_ASSIGNMENT("+=", 16),
        SUBTRACTION_ASSIGNMENT("-=", 16), SHIFT_LEFT_ASSIGNMENT("<<=", 16), SHIFT_RIGHT_ASSIGNMENT(">>=", 16),
        BITWISE_AND_ASSIGNMENT("&=", 16), BITWISE_XOR_ASSIGNMENT("^=", 16), BITWISE_OR_ASSIGNMENT("|=", 16), COMMA(","
                , 17);

        private static final Map<String, Operator> OPERATORS = new HashMap<>();
        private static final Map<String, Operator> ASSIGNMENT_OPERATORS = new HashMap<>();
        private static final Map<String, Operator> UNARY_OPERATORS = new HashMap<>();
        private static final Map<String, Operator> BINARY_OPERATORS = new HashMap<>();
        private static final Map<String, Operator> POSTFIX_OPERATORS = new HashMap<>();

        static {
// sort all operators into their respective maps
            for (Operator op : Operator.values()) {
                OPERATORS.put(op.op, op);
                if (op.op.endsWith("=")) {
                    ASSIGNMENT_OPERATORS.put(op.op, op);
                } else if (op.precedence == 3) {
                    UNARY_OPERATORS.put(op.op, op);
                } else if (op.precedence == 2) {
                    POSTFIX_OPERATORS.put(op.op, op);
                } else {
                    BINARY_OPERATORS.put(op.op, op);
                }
            }
        }

        public enum Associativity {
            LEFT, RIGHT
        }

        public final String op;
        public final int precedence;

        public final Associativity associativity;

        Operator(String op, int precedence) {
            this.op = op;
            this.precedence = precedence;
            if (precedence == 3 || precedence == 16) {
                this.associativity = Associativity.RIGHT;
            } else {
                this.associativity = Associativity.LEFT;
            }
        }

        public boolean isPostfix() {
            return this.name().startsWith("POSTFIX_");
        }

        public boolean isUnitary() {
            return precedence == 3 || precedence == 2;
        }

        @Override
        public String toString() {
            return op;
        }

        static Operator binary(String op) {
            return BINARY_OPERATORS.get(op);
        }

        static Operator unary(String op) {
            return UNARY_OPERATORS.get(op);
        }

        static Operator postfix(String op) {
            return POSTFIX_OPERATORS.get(op);
        }


        static Operator assignment(String op) {
            return ASSIGNMENT_OPERATORS.get(op);
        }

        static Operator fromString(String op) {
            return OPERATORS.get(op);
        }
    }

    record OperatorExpression(Operator operator, Expression... expressions) implements Expression {

        @Override
        public List<? extends Expression> children() {
            return Arrays.asList(expressions);
        }

        static String stripPrint(Expression expr) {
            var str = expr.toPrettyString();
            if (str.startsWith("(") && str.endsWith(")") && !str.contains(")") && !str.contains("(")) {
                return str.substring(1, str.length() - 1);
            }
            return str;
        }

        static String stripPrintOp(Expression op, Operator ownOp) {
            String stripped = stripPrint(op);
            if (op instanceof OperatorExpression expr && expr.operator.precedence >= ownOp.precedence && expr.operator != ownOp && !stripped.matches("[0-9A-Za-z_]+")) {
                return "(" + stripped + ")";
            }
            return stripped;
        }

        /**
         * Takes care of operator precedence and associativity
         */
        @Override
        public String toPrettyString(String indent, String increment) {
            if (operator().precedence == 3) {
                Expression operator1 = children().getFirst();
                String op1String = stripPrint(operator1);

                if (operator() == Operator.CAST) {
                    return indent + "(" + op1String + ")" + stripPrintOp(children().get(1), operator());
                }

                if (operator1 instanceof OperatorExpression operatorExpression) {
                    if (operatorExpression.operator().precedence < operator().precedence) {
                        op1String = "(" + op1String + ")";
                    }
                }
                if (operator().isPostfix()) {
                    return indent + op1String + operator();
                }
                return indent + operator() + op1String;
            } else {
                if (operator().precedence == 2) {
                    Expression operator1 = children().getFirst();
                    String op1String = stripPrintOp(operator1, operator);
                    if (operator == Operator.SUBSCRIPT) {
                        String op2String = stripPrint(children().get(1));
                        return indent + op1String + "[" + op2String + "]";
                    }
                    if (operator == Operator.MEMBER_ACCESS) {
                        String op2String = stripPrint(children().get(1));
                        return indent + op1String + "." + op2String;
                    }
                    if (operator == Operator.PTR_MEMBER_ACCESS) {
                        String op2String = stripPrint(children().get(1));
                        return indent + op1String + "->" + op2String;
                    }
                    return indent + op1String + operator();
                } else {
                    if (operator().precedence == 16) {
                        if (operator() == Operator.CONDITIONAL) {
                            Expression operator1 = children().get(0);
                            Expression operator2 = children().get(1);
                            Expression operator3 = children().get(2);
                            String op1String = stripPrintOp(operator1, operator);
                            String op2String = stripPrintOp(operator2, operator);
                            String op3String = stripPrintOp(operator3, operator);
                            return indent + op1String + " ? " + op2String + " : " + op3String;
                        }
                        Expression operator1 = children().get(0);
                        Expression operator2 = children().get(1);
                        String op1String = stripPrintOp(operator1, operator);
                        String op2String = stripPrintOp(operator2, operator);
                        return indent + op1String + " " + operator() + " " + op2String;
                    } else {
// if the operator is a ternary operator, we need to wrap the children in parentheses
                        if (operator() == Operator.MEMBER_ACCESS) {
                            Expression operator1 = children().get(0);
                            Expression operator2 = children().get(1);
                            String op1String = stripPrintOp(operator1, operator);
                            String op2String = stripPrintOp(operator2, operator);
                            return indent + op1String + "." + op2String;
                        } else if (operator() == Operator.SUBSCRIPT) {
                            Expression operator1 = children().get(0);
                            Expression operator2 = children().get(1);
                            String op1String = stripPrintOp(operator1, operator);
                            String op2String = stripPrintOp(operator2, operator);
                            return indent + op1String + "[" + op2String + "]";
                        } else if (operator() == Operator.FUNCTION_CALL) {
                            Expression func = children().getFirst();
                            String funcString = stripPrint(func);
                            if (func instanceof OperatorExpression) {
                                funcString = "(" + funcString + ")";
                            }
                            return indent + funcString + "(" + children().stream().skip(1).map(OperatorExpression::stripPrint).collect(Collectors.joining(", ")) + ")";
                        } else if (operator() == Operator.SIZEOF) {
                            Expression operator1 = children().getFirst();
                            String op1String = stripPrint(operator1);
                            return indent + "sizeof(" + op1String + ")";
                        } else if (operator().isUnitary()) {
                            Expression operator1 = children().getFirst();
                            String op1String = stripPrintOp(operator1, operator);
                            if (operator().associativity == Operator.Associativity.RIGHT) {
                                return indent + operator() + op1String;
                            } else {
                                return indent + op1String + operator();
                            }
                        } else {
                            Expression operator1 = children().get(0);
                            Expression operator2 = children().get(1);
                            String op1String = stripPrint(operator1);
                            String op2String = stripPrint(operator2);
                            if (operator1 instanceof OperatorExpression operatorExpression) {
                                if (operatorExpression.operator().precedence < operator().precedence) {
                                    op1String = "(" + op1String + ")";
                                } else if (operatorExpression.operator().precedence == operator().precedence) {
                                    if (operatorExpression.operator().associativity == Operator.Associativity.LEFT) {
                                        op1String = "(" + op1String + ")";
                                    }
                                }
                            }
                            if (operator2 instanceof OperatorExpression operatorExpression) {
                                if (operatorExpression.operator().precedence < operator().precedence) {
                                    op2String = "(" + op2String + ")";
                                } else if (operatorExpression.operator().precedence == operator().precedence) {
                                    if (operatorExpression.operator().associativity == Operator.Associativity.RIGHT) {
                                        op2String = "(" + op2String + ")";
                                    }
                                }
                            }
                            return indent + op1String + " " + operator() + " " + op2String;
                        }
                    }

                }
            }
        }

        public static OperatorExpression binary(String op, Expression left, Expression right) {
            return new OperatorExpression(Operator.binary(op), left, right);
        }

        public static OperatorExpression unary(String op, Expression expression) {
            return new OperatorExpression(Operator.unary(op), expression);
        }

        public static OperatorExpression postfix(String op, Expression expression) {
            return new OperatorExpression(Operator.postfix(op), expression);
        }

        public static OperatorExpression assignment(String op, Expression left, Expression right) {
            return new OperatorExpression(Operator.assignment(op), left, right);
        }

        public static OperatorExpression ternary(Expression condition, Expression trueExpression,
                                                 Expression falseExpression) {
            return new OperatorExpression(Operator.CONDITIONAL, condition, trueExpression, falseExpression);
        }

        public static OperatorExpression memberAccess(Expression left, Expression right) {
            return new OperatorExpression(Operator.MEMBER_ACCESS, left, right);
        }

        public static OperatorExpression arrayAccess(Expression left, Expression right) {
            return new OperatorExpression(Operator.SUBSCRIPT, left, right);
        }

        public static OperatorExpression call(Expression func, Expression... args) {
            return new OperatorExpression(Operator.FUNCTION_CALL,
                    Stream.concat(Stream.of(func), Arrays.stream(args)).toArray(Expression[]::new));
        }

        public static OperatorExpression pointer(Expression expression) {
            return new OperatorExpression(Operator.DEREFERENCE, expression);
        }

        public static OperatorExpression cast(Declarator type, Expression expression) {
            return new OperatorExpression(Operator.CAST, type, expression);
        }
    }

    record InitDeclarator(@Nullable PrimaryExpression.Variable name, Expression expression) implements Expression {

        @Override
        public List<? extends Expression> children() {
            return List.of(expression);
        }

        @Override
        public String toPrettyString(String indent, String increment) {
            return indent + (name == null ? "" : "." + name.toPrettyString() + " = ") + expression.toPrettyString();
        }
    }

    sealed interface Initializer extends Expression {

        record InitializerList(List<InitDeclarator> declarators) implements Initializer {
            @Override
            public List<? extends Expression> children() {
                return declarators;
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                return indent + "{" + declarators.stream().map(InitDeclarator::toPrettyString).collect(Collectors.joining(", ")) + "}";
            }
        }
    }

    sealed interface Declarator extends Expression {

        interface Pointery {
            default String toPrettyVariableDefinition(@Nullable Expression name, String indent) {
                return toPrettyVariableDefinition(name, null, indent);
            }

            String toPrettyVariableDefinition(@Nullable Expression name, @Nullable String tag, String indent);
        }

        record PointerDeclarator(Declarator declarator) implements Declarator, Pointery {
            @Override
            public List<? extends Expression> children() {
                return List.of(declarator);
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                return indent + declarator.toPrettyString() + "*";
            }

            @Override
            public String toPrettyVariableDefinition(@Nullable Expression name, @Nullable String tag, String indent) {
                if (declarator instanceof TaggedDeclarator tagged) {
                    if (tagged.declarator instanceof Pointery pointery) {
                        var combinedTag = tag == null ? tagged.tag : tag + " " + tagged.tag;
                        return pointery.toPrettyVariableDefinition(name, combinedTag, indent) + (pointery instanceof FunctionDeclarator ? "" : "*");
                    }
                    return tagged.toPrettyString() + "*";
                }
                if (declarator instanceof FunctionDeclarator fun) {
                    return fun.toPrettyVariableDefinition(name, tag, indent);
                }
                if (name == null) {
                    return toPrettyString(indent, "");
                }
                if (declarator instanceof ArrayDeclarator arr) {
                    return arr.toPrettyVariableDefinition(Expression.parenthesizedExpression(OperatorExpression.pointer(name)), tag, indent);
                }
                if (declarator instanceof PointerDeclarator ptr) {
                    return ptr.toPrettyVariableDefinition(OperatorExpression.pointer(name), tag, indent);
                }
                return indent + declarator.toPrettyString() + (tag == null ? " " : tag + " ") + "*" + name.toPrettyString();
            }
        }

        record ArrayDeclarator(Declarator declarator, Expression size) implements Declarator, Pointery {
            @Override
            public List<? extends Expression> children() {
                return size == null ? List.of(declarator) : List.of(declarator, size);
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                return toPrettyVariableDefinition(null, indent);
            }

            @Override
            public String toPrettyVariableDefinition(@Nullable Expression name, @Nullable String tag, String indent) {
                List<String> sizes = new ArrayList<>();
                CAST cur = this;
                while (cur instanceof ArrayDeclarator arr) {
                    sizes.add(((ArrayDeclarator) cur).sizeBracket());
                    cur = arr.declarator;
                }
                return indent + cur.toPrettyString() + (tag == null ? "" : " " + tag) + (name != null ?
                        " " + name.toPrettyString() : "") +
                        String.join("", sizes);
            }

            private @NotNull String sizeBracket() {
                return size == null ? "[]" : "[" + size.toPrettyString() + "]";
            }
        }

        /**
         * Struct member with optional size for ebpf member declaration (e.g. <code>u32 (var, 10)</code>)
         */
        record StructMember(Declarator declarator, PrimaryExpression.Variable name,
                            @Nullable PrimaryExpression ebpfSize) implements Declarator {

            @Override
            public List<? extends Expression> children() {
                return List.of(declarator, name);
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                if (ebpfSize == null) {
                    if (declarator instanceof Pointery arr) {
                        return arr.toPrettyVariableDefinition(name, indent) + ";";
                    }
                    if (declarator instanceof UnionDeclarator union && union.name == null) {
                        return declarator.toPrettyString(indent, increment) + ";";
                    }
                    return declarator.toPrettyString(indent, increment) + (name == null ? "" :
                            " " + name.toPrettyString()) + ";";
                }
                return indent + declarator.toPrettyString() + " (" + name.toPrettyString() + ", " + ebpfSize.toPrettyString() + ");";
            }
        }

        record StructDeclarator(@Nullable PrimaryExpression.Variable name,
                                List<StructMember> members) implements Declarator {
            @Override
            public List<? extends Expression> children() {
                if (name == null) {
                    return members;
                }
                return Stream.concat(Stream.of(name), members.stream()).collect(Collectors.toList());
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                return indent + "struct " + (name == null ? "" : name.toPrettyString() + " ") + "{\n" + members.stream().map(m -> m.toPrettyString(indent + increment, increment)).collect(Collectors.joining("\n")) + "\n" + indent + "}";
            }
        }

        record TypedefedStructDeclarator(PrimaryExpression.Variable name,
                                         List<StructMember> members) implements Declarator {
            @Override
            public List<? extends Expression> children() {
                return Stream.concat(Stream.of(name), members.stream()).collect(Collectors.toList());
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                return indent + "typedef struct {\n" + members.stream().map(m -> m.toPrettyString(indent + increment,
                        increment)).collect(Collectors.joining("\n")) + "\n" + indent + "} " + name.toPrettyString();
            }
        }

        record UnionMember(Declarator declarator, PrimaryExpression.Variable name) implements Declarator {
            @Override
            public List<? extends Expression> children() {
                return List.of(declarator, name);
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                if (declarator instanceof Pointery arr) {
                    return arr.toPrettyVariableDefinition(name, indent) + ";";
                }
                if (name == null) {
                    return declarator.toPrettyString(indent, increment) + ";";
                }
                return declarator.toPrettyString(indent, increment) + " " + name.toPrettyString() + ";";
            }
        }

        record UnionDeclarator(@Nullable PrimaryExpression.Variable name,
                               List<UnionMember> members) implements Declarator {
            @Override
            public List<? extends Expression> children() {
                if (name == null) {
                    return members;
                }
                return Stream.concat(Stream.of(name), members.stream()).collect(Collectors.toList());
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                return indent + "union " + (name == null ? "" : name.toPrettyString() + " ") + "{\n" + members.stream().map(m -> m.toPrettyString(indent + increment, increment)).collect(Collectors.joining("\n")) + "\n" + indent + "}";
            }
        }

        record TypedefedUnionDeclarator(PrimaryExpression.Variable name,
                                        List<UnionMember> members) implements Declarator {
            @Override
            public List<? extends Expression> children() {
                return Stream.concat(Stream.of(name), members.stream()).collect(Collectors.toList());
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                return indent + "typedef union {\n" + members.stream().map(m -> m.toPrettyString(indent + increment,
                        increment)).collect(Collectors.joining("\n")) + "\n" + indent + "} " + name.toPrettyString();
            }
        }

        record EnumMember(PrimaryExpression.Variable name, Constant<?> value) implements Declarator {
            @Override
            public List<? extends Expression> children() {
                return List.of(name, value);
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                return indent + name.toPrettyString() + " = " + value.toPrettyString();
            }
        }

        record EnumDeclarator(@Nullable PrimaryExpression.Variable name,
                              List<EnumMember> members) implements Declarator {
            @Override
            public List<? extends Expression> children() {
                if (name == null) {
                    return members;
                }
                return Stream.concat(Stream.of(name), members.stream()).collect(Collectors.toList());
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                return indent + "enum " + (name == null ? "" : name.toPrettyString() + " ") + "{\n" + members.stream().map(m -> m.toPrettyString(indent + increment, increment)).collect(Collectors.joining(",\n")) + "\n" + indent + "}";
            }
        }

        record FunctionParameter(Variable name, Declarator declarator) implements Declarator {
            @Override
            public List<? extends Expression> children() {
                return List.of(name, declarator);
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                if (name == null) {
                    return declarator.toPrettyString(indent, increment);
                }
                if (declarator instanceof Pointery ptr) {
                    return ptr.toPrettyVariableDefinition(name, indent);
                }
                return declarator.toPrettyString(indent, increment) + " " + name.toPrettyString();
            }
        }

        sealed interface FunctionHeader extends CAST {
        }

        record FunctionDeclarator(Variable name, Declarator returnValue,
                                  List<FunctionParameter> parameters) implements Declarator, Pointery, FunctionHeader {
            @Override
            public List<? extends Expression> children() {
                return Stream.concat(Stream.of(name, returnValue), parameters.stream()).collect(Collectors.toList());
            }

            private String paramDecl() {
                return "(" + parameters.stream().map(CAST::toPrettyString).collect(Collectors.joining(", ")) + ")";
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                return returnValue.toPrettyString(indent, increment) + " " + name + paramDecl();
            }

            @Override
            public String toPrettyVariableDefinition(@Nullable Expression name, @Nullable String tag, String indent) {
                return returnValue.toPrettyString(indent, "") + " (" + (tag == null ? "" : " " + tag) + "*" + (name == null ? "" : name.toPrettyString()) + ")" + paramDecl();
            }
        }

        record VerbatimFunctionDeclarator(String header) implements FunctionHeader {
            @Override
            public List<? extends CAST> children() {
                return List.of();
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                return indent + header;
            }

            @Override
            public Statement toStatement() {
                return new VerbatimStatement(header + ";");
            }
        }

        record IdentifierDeclarator(PrimaryExpression.Variable name) implements Declarator {
            @Override
            public List<? extends Expression> children() {
                return List.of(name);
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                return name.toPrettyString(indent, increment);
            }
        }

        record StructIdentifierDeclarator(PrimaryExpression.Variable name) implements Declarator {
            @Override
            public List<? extends Expression> children() {
                return List.of(name);
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                return indent + "struct " + name.toPrettyString();
            }
        }

        record UnionIdentifierDeclarator(PrimaryExpression.Variable name) implements Declarator {
            @Override
            public List<? extends Expression> children() {
                return List.of(name);
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                return indent + "union " + name.toPrettyString();
            }
        }

        record EnumIdentifierDeclarator(PrimaryExpression.Variable name) implements Declarator {
            @Override
            public List<? extends Expression> children() {
                return List.of(name);
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                return indent + "enum " + name.toPrettyString();
            }
        }

        record TaggedDeclarator(String tag, Declarator declarator) implements Declarator {
            @Override
            public List<? extends Expression> children() {
                return List.of(declarator);
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                return indent + tag + " " + declarator.toPrettyString();
            }
        }

        static Declarator pointer(Declarator declarator) {
            return new PointerDeclarator(declarator);
        }

        static Declarator voidPointer() {
            return new PointerDeclarator(new IdentifierDeclarator(new PrimaryExpression.Variable("void")));
        }

        static Declarator array(Declarator declarator, @Nullable Expression size) {
            return new ArrayDeclarator(declarator, size);
        }

        static Declarator function(Variable name, Declarator returnValue, List<FunctionParameter> parameters) {
            return new FunctionDeclarator(name, returnValue, parameters);
        }

        static Declarator identifier(PrimaryExpression.Variable name) {
            return new IdentifierDeclarator(name);
        }

        static Declarator _void() {
            return new IdentifierDeclarator(Expression._void());
        }

        static Declarator identifier(String name) {
            return new IdentifierDeclarator(new PrimaryExpression.Variable(name));
        }

        static Declarator struct(PrimaryExpression.Variable name, List<StructMember> members) {
            return new StructDeclarator(name, members);
        }

        static Declarator typedefedStruct(PrimaryExpression.Variable name, List<StructMember> members) {
            return new TypedefedStructDeclarator(name, members);
        }

        static Declarator typedefedUnion(PrimaryExpression.Variable name, List<UnionMember> members) {
            return new TypedefedUnionDeclarator(name, members);
        }

        static StructMember structMember(Declarator declarator, PrimaryExpression.Variable name) {
            return new StructMember(declarator, name, null);
        }

        static StructMember structMember(Declarator declarator, PrimaryExpression.Variable name,
                                         PrimaryExpression ebpfSize) {
            return new StructMember(declarator, name, ebpfSize);
        }

        static Declarator structIdentifier(PrimaryExpression.Variable name) {
            return new StructIdentifierDeclarator(name);
        }

        static Declarator union(@Nullable PrimaryExpression.Variable name, List<UnionMember> members) {
            return new UnionDeclarator(name, members);
        }

        static Declarator inlineUnion(List<UnionMember> members) {
            return new UnionDeclarator(null, members);
        }

        static UnionMember unionMember(Declarator declarator, PrimaryExpression.Variable name) {
            return new UnionMember(declarator, name);
        }

        static Declarator unionIdentifier(PrimaryExpression.Variable name) {
            return new UnionIdentifierDeclarator(name);
        }

        static Declarator unionIdentifier(String name) {
            return new UnionIdentifierDeclarator(new PrimaryExpression.Variable(name));
        }

        static Declarator _enum(PrimaryExpression.Variable name, List<EnumMember> members) {
            return new EnumDeclarator(name, members);
        }

        static EnumMember enumMember(PrimaryExpression.Variable name, Constant<?> value) {
            return new EnumMember(name, value);
        }

        static Declarator enumIdentifier(PrimaryExpression.Variable name) {
            return new EnumIdentifierDeclarator(name);
        }

        static Declarator enumIdentifier(String name) {
            return new EnumIdentifierDeclarator(new PrimaryExpression.Variable(name));
        }

        static Declarator tagged(String tag, Declarator declarator) {
            return new TaggedDeclarator(tag, declarator);
        }
    }


    interface Statement extends CAST {

        @Override
        default Statement toStatement() {
            return this;
        }


        /** Replace all statements that start with {@code return } with the passed statement */
        default Statement replaceReturnStatement(Statement newLastStatement) {
            return this;
        }

        default String toPrettyStringWithoutBraces(String indent, String increment) {
            return toPrettyString(indent, increment);
        }

        record ExpressionStatement(Expression expression) implements Statement {

            @Override
            public List<? extends CAST> children() {
                return List.of(expression);
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                return expression.toPrettyString(indent, increment) + ";";
            }
        }

        record VariableDefinition(Declarator type, PrimaryExpression.Variable name,
                                  @Nullable Expression value) implements Statement {

            @Override
            public List<? extends CAST> children() {
                if (value == null) {
                    return List.of(type, name);
                }
                return List.of(type, name, value);
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                String app = value == null ? "" : " = " + stripPrint(value);
                if (type instanceof Pointery arr) {
                    return arr.toPrettyVariableDefinition(Expression.variable(name.name), indent) + (name.annotations.length == 0 ? "" : " " + name.annotationsString()) + app + ";";
                }
                return type.toPrettyString(indent, increment) + " " + name.toPrettyString() + app + ";";
            }

        }

        record CompoundStatement(List<Statement> statements) implements Statement {

            @Override
            public List<? extends CAST> children() {
                return statements;
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                return indent + "{\n" + toPrettyStringWithoutBraces(indent + increment, increment) + "\n" + indent +
                        "}";
            }

            @Override
            public String toPrettyStringWithoutBraces(String indent, String increment) {
                return statements.stream().map(s -> s.toPrettyString(indent, increment)).collect(Collectors.joining(
                        "\n"));
            }

            @Override
            public CompoundStatement replaceReturnStatement(Statement newLastStatement) {
                return new CompoundStatement(statements.stream()
                        .map(s -> isReturnStatement(s) ? newLastStatement : s.replaceReturnStatement(newLastStatement))
                        .collect(Collectors.toList()));
            }

            private boolean isReturnStatement(Statement statement) {
                if (statement instanceof ReturnStatement) {
                    return true;
                }
                if (statement instanceof VerbatimStatement) {
                    String str = statement.toPrettyString();
                    return str.startsWith("return ") || str.equals("return;");
                }
                return false;
            }
        }

        record IfStatement(Expression condition, Statement thenStatement,
                           @Nullable Statement elseStatement) implements Statement {

            @Override
            public List<? extends CAST> children() {
                return elseStatement == null ? List.of(condition, thenStatement) : List.of(condition, thenStatement,
                        elseStatement);
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                String code =
                        indent + "if (" + stripPrint(condition) + ") {\n" + thenStatement.toPrettyStringWithoutBraces(indent + increment,
                        increment) + "\n" + indent + "}";
                if (elseStatement != null) {
                    if (elseStatement instanceof IfStatement) {
                        return code + " else " + elseStatement.toPrettyString(indent, increment).strip();
                    }
                    return code + " else {\n" + elseStatement.toPrettyStringWithoutBraces(indent + increment,
                            increment) + "\n" + indent + "}";
                }
                return code;
            }

            @Override
            public IfStatement replaceReturnStatement(Statement newLastStatement) {
                return new IfStatement(condition, thenStatement.replaceReturnStatement(newLastStatement),
                        elseStatement == null ? null : elseStatement.replaceReturnStatement(newLastStatement));
            }
        }

        record WhileStatement(Expression condition, Statement body) implements Statement {

            @Override
            public List<? extends CAST> children() {
                return List.of(condition, body);
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                return indent + "while (" + stripPrint(condition) + ") {\n" + body.toPrettyStringWithoutBraces(indent + increment, increment) + "\n" + indent + "}";
            }

            @Override
            public WhileStatement replaceReturnStatement(Statement newLastStatement) {
                return new WhileStatement(condition, body.replaceReturnStatement(newLastStatement));
            }
        }

        record ForStatement(List<Statement> init, @Nullable Expression condition, List<Statement> increment,
                            Statement body) implements Statement {

            @Override
            public List<? extends CAST> children() {
                List<CAST> children = new ArrayList<>();
                if (init != null) {
                    children.addAll(init);
                }
                if (condition != null) {
                    children.add(condition);
                }
                if (increment != null) {
                    children.addAll(increment);
                }
                children.add(body);
                return children;
            }

            private String prettyList(List<Statement> list) {
                return list.stream().map(Statement::toPrettyString)
                        .map(s -> s.endsWith(";") ? s.substring(0, s.length() - 1) : s)
                        .collect(Collectors.joining(", "));
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                return indent + "for (" + prettyList(init) + "; " + (condition == null ? "" :
                        condition.toPrettyString()) +
                        "; " + prettyList(this.increment) + ") {\n" + body.toPrettyStringWithoutBraces(indent + increment, increment) + "\n" + indent + "}";
            }

            @Override
            public ForStatement replaceReturnStatement(Statement newLastStatement) {
                return new ForStatement(init, condition, increment, body.replaceReturnStatement(newLastStatement));
            }
        }

        record ReturnStatement(@Nullable Expression expression) implements Statement {

            @Override
            public List<? extends CAST> children() {
                return expression == null ? List.of() : List.of(expression);
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                return indent + "return" + (expression == null ? "" : " " + stripPrint(expression)) + ";";
            }
        }

        record BreakStatement() implements Statement {

            @Override
            public List<? extends CAST> children() {
                return List.of();
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                return indent + "break;";
            }
        }

        record ContinueStatement() implements Statement {

            @Override
            public List<? extends CAST> children() {
                return List.of();
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                return indent + "continue;";
            }
        }

        record EmptyStatement() implements Statement {

            @Override
            public List<? extends CAST> children() {
                return List.of();
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                return indent + ";";
            }
        }

        record DeclarationStatement(Declarator declarator, @Nullable Initializer initializer) implements Statement {

            @Override
            public List<? extends CAST> children() {
                return initializer == null ? List.of(declarator) : List.of(declarator, initializer);
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                return indent + declarator.toPrettyString() + (initializer == null ? "" :
                        " = " + stripPrint(initializer)) + ";";
            }
        }

        record StructDeclarationStatement(Declarator.StructDeclarator declarator) implements Statement {

            @Override
            public List<? extends CAST> children() {
                return List.of(declarator);
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                return declarator.toPrettyString(indent, increment) + ";";
            }
        }

        record FunctionDeclarationStatement(FunctionHeader declarator,
                                            CompoundStatement body,
                                            CAnnotation... annotations) implements Statement {

            @Override
            public List<? extends CAST> children() {
                List<CAST> children = new ArrayList<>();
                children.add(declarator);
                children.add(body);
                children.addAll(Arrays.asList(annotations));
                return children;
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                var anns = Arrays.stream(annotations).map(CAST::toPrettyString).collect(Collectors.joining(" "));
                return indent + (anns.isEmpty() ? "" : anns + " ") + declarator.toPrettyString("", increment) + " {\n"
                        + body.toPrettyStringWithoutBraces(indent + increment, increment) + "\n" + indent + "}";
            }
        }

        record Define(String name, PrimaryExpression.Constant<?> value) implements Statement {

            @Override
            public List<? extends CAST> children() {
                return List.of(value);
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                return indent + "#define " + name + " " + value.toPrettyString();
            }

            @Override
            public int hashCode() {
                return toPrettyString().hashCode();
            }

            @Override
            public boolean equals(Object obj) {
                if (this == obj) {
                    return true;
                }
                if (obj == null || getClass() != obj.getClass()) {
                    return false;
                }
                return toPrettyString().equals(((Define) obj).toPrettyString());
            }
        }

        record Include(String file) implements Statement {

            @Override
            public List<? extends CAST> children() {
                return List.of();
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                return indent + "#include <" + file + ">";
            }

            @Override
            public int hashCode() {
                return file.hashCode();
            }

            @Override
            public boolean equals(Object obj) {
                if (this == obj) {
                    return true;
                }
                if (obj == null || getClass() != obj.getClass()) {
                    return false;
                }
                return file.equals(((Include) obj).file);
            }

            public boolean isAlreadyPresent(List<String> codeLines) {
                return codeLines.stream().anyMatch(l -> l.contains("#include <" + file + ">") || l.contains("#include" +
                        " \"" + file + "\""));
            }
        }

        record Typedef(Declarator declarator, PrimaryExpression.Variable name) implements Statement {

            @Override
            public List<? extends CAST> children() {
                return List.of(declarator, name);
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                if (declarator instanceof Pointery arr) {
                    return indent + "typedef " + arr.toPrettyVariableDefinition(name, indent) + ";";
                }
                return indent + "typedef " + declarator.toPrettyString() + " " + name.toPrettyString() + ";";
            }
        }

        record CaseStatement(Expression expression, Statement body) implements Statement {

            @Override
            public List<? extends CAST> children() {
                return List.of(expression, body);
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                return indent + "case " + expression.toPrettyString() + ":\n" + body.toPrettyString(indent + increment, increment);
            }
        }

        record DefaultStatement(Statement body) implements Statement {

            @Override
            public List<? extends CAST> children() {
                return List.of(body);
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                return indent + "default:\n" + body.toPrettyString(indent + increment, increment);
            }
        }

        record SwitchStatement(Expression expression, Statement body) implements Statement {

            @Override
            public List<? extends CAST> children() {
                return List.of(expression, body);
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                return indent + "switch (" + expression.toPrettyString() + ")\n" + body.toPrettyString(indent + increment, increment);
            }
        }

        record VerbatimStatement(String code) implements Statement {
            @Override
            public List<? extends CAST> children() {
                return List.of();
            }

            @Override
            public String toPrettyString(String indent, String increment) {
                return code.lines().map(l -> indent + l).collect(Collectors.joining("\n"));
            }
        }

        static Statement expression(Expression expression) {
            return new ExpressionStatement(expression);
        }

        static Statement compound(Statement... statements) {
            return new CompoundStatement(List.of(statements));
        }

        static Statement compound(List<Statement> statements) {
            return new CompoundStatement(statements);
        }

        static Statement ifStatement(Expression condition, Statement thenStatement, @Nullable Statement elseStatement) {
            return new IfStatement(condition, thenStatement, elseStatement);
        }

        static Statement whileStatement(Expression condition, Statement body) {
            return new WhileStatement(condition, body);
        }

        static Statement returnStatement(@Nullable Expression expression) {
            return new ReturnStatement(expression);
        }

        static Statement breakStatement() {
            return new BreakStatement();
        }

        static Statement continueStatement() {
            return new ContinueStatement();
        }

        static Statement emptyStatement() {
            return new EmptyStatement();
        }

        static Statement declarationStatement(Declarator declarator, @Nullable Initializer initializer) {
            return new DeclarationStatement(declarator, initializer);
        }

        static Statement structDeclarationStatement(Declarator.StructDeclarator declarator) {
            return new StructDeclarationStatement(declarator);
        }

        static Statement functionDeclarationStatement(Declarator.FunctionDeclarator declarator,
                                                      CompoundStatement body) {
            return new FunctionDeclarationStatement(declarator, body);
        }

        static Define define(String name, PrimaryExpression.Constant<?> value) {
            return new Define(name, value);
        }

        static Statement include(String file) {
            return new Include(file);
        }

        static Statement typedef(Declarator declarator, PrimaryExpression.Variable name) {
            return new Typedef(declarator, name);
        }

        static Statement caseStatement(Expression expression, Statement body) {
            return new CaseStatement(expression, body);
        }

        static Statement defaultStatement(Statement body) {
            return new DefaultStatement(body);
        }

        static Statement switchStatement(Expression expression, Statement body) {
            return new SwitchStatement(expression, body);
        }

        static Statement variableDefinition(Declarator type, PrimaryExpression.Variable name) {
            return new VariableDefinition(type, name, null);
        }

        static Statement variableDefinition(Declarator type, PrimaryExpression.Variable name, Expression value) {
            return new VariableDefinition(type, name, value);
        }

        static Statement verbatim(String code) {
            return new VerbatimStatement(code);
        }
    }
}