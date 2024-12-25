package me.bechberger.ebpf.bpf.compiler;

import com.sun.source.tree.*;
import com.sun.tools.javac.code.Symbol.ClassSymbol;
import com.sun.tools.javac.code.Symbol.MethodSymbol;
import com.sun.tools.javac.code.Symbol.TypeVariableSymbol;
import com.sun.tools.javac.code.Type;
import com.sun.tools.javac.code.Type.ClassType;
import com.sun.tools.javac.tree.JCTree.*;
import me.bechberger.cast.CAST;
import me.bechberger.cast.CAST.Declarator.*;
import me.bechberger.cast.CAST.Initializer.InitializerList;
import me.bechberger.cast.CAST.PrimaryExpression.CAnnotation;
import me.bechberger.cast.CAST.PrimaryExpression.Constant.IntegerConstant;
import me.bechberger.cast.CAST.PrimaryExpression.VerbatimExpression;
import me.bechberger.cast.CAST.Statement.*;
import me.bechberger.ebpf.annotations.AlwaysInline;
import me.bechberger.ebpf.annotations.CustomType;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.EnumMember;
import me.bechberger.ebpf.bpf.compiler.CompilerPlugin.TypedTreePath;
import me.bechberger.ebpf.bpf.compiler.MethodTemplate.Argument;
import me.bechberger.ebpf.bpf.compiler.MethodTemplate.Argument.Lambda;
import me.bechberger.ebpf.bpf.compiler.MethodTemplate.Argument.Value;
import me.bechberger.ebpf.bpf.compiler.MethodTemplate.CallArgs;
import me.bechberger.ebpf.bpf.compiler.MethodTemplateCache.TemplateRenderException;
import me.bechberger.ebpf.bpf.processor.AnnotationUtils;
import me.bechberger.ebpf.bpf.processor.BPFTypeLike.VerbatimBPFOnlyType;
import me.bechberger.ebpf.bpf.processor.BPFTypeLike.VerbatimBPFOnlyType.PrefixKind;
import me.bechberger.ebpf.bpf.processor.TypeProcessor;
import me.bechberger.ebpf.bpf.processor.TypeProcessor.DataTypeKind;
import me.bechberger.ebpf.type.BPFType;
import me.bechberger.ebpf.type.BPFType.BPFIntType;
import me.bechberger.ebpf.type.Ptr;
import org.jetbrains.annotations.Nullable;

import javax.lang.model.element.Element;
import javax.lang.model.element.ElementKind;
import javax.lang.model.element.TypeElement;
import javax.lang.model.element.VariableElement;
import javax.lang.model.type.TypeKind;
import javax.lang.model.type.TypeMirror;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static me.bechberger.cast.CAST.Expression.*;
import static me.bechberger.ebpf.NameUtil.toConstantCase;
import static me.bechberger.ebpf.bpf.compiler.NullHelpers.callIfNonNull;

/**
 * Translate method bodies to CAST
 */
class Translator {
    private final CompilerPlugin compilerPlugin;
    private final TypedTreePath<MethodTree> methodPath;
    private final Set<Define> requiredDefines = new HashSet<>();

    Translator(CompilerPlugin compilerPlugin, TypedTreePath<MethodTree> methodPath) {
        this.compilerPlugin = compilerPlugin;
        this.methodPath = methodPath;
    }

    public Set<Define> getRequiredDefines() {
        return requiredDefines;
    }

    void logError(Tree tree, String message) {
        compilerPlugin.logError(methodPath, tree, message);
    }

    @Nullable
    FunctionHeader toDeclarator() {
        var annotation =
                compilerPlugin.getAnnotationOfMethodOrSuper((MethodSymbol) compilerPlugin.trees.getElement(methodPath.path()), BPFFunction.class);
        var method = methodPath.leaf();
        var methodElement = (MethodSymbol) compilerPlugin.trees.getElement(methodPath.path(method));
        var name = method.getName().toString();
        if (annotation != null && !annotation.name().isEmpty()) {
            name = annotation.name();
        }
        var retKind = typeKind(methodElement.getReturnType().asElement());
        var returnType = translateType(methodElement, methodElement.getReturnType());
        if (retKind != DataTypeKind.ENUM && retKind != DataTypeKind.NONE && returnType != null) {
            logError(method, "Unsupported return type: " + method.getReturnType() + " as BPF does not support " +
                    "returning structs from functions");
            return null;
        }
        boolean hadError = false;
        if (returnType == null) {
            logError(method, "Unsupported return type: " + method.getReturnType());
            hadError = true;
        }
        // check if the method returns void
        if (returnType != null && returnType.toPrettyString().equals("void")) {
            returnType = Declarator.identifier("int");
        }
        var params = translateFunctionParameters(method.getParameters());
        if (params == null) {
            return null;
        }
        var decl = new FunctionDeclarator(variable(name), returnType, params);
        assert annotation != null;
        var alwaysInline = compilerPlugin.getAnnotationOfMethodOrSuper(methodElement, AlwaysInline.class);
        return MethodHeaderTemplate.parse(annotation.headerTemplate()).call(decl, alwaysInline != null ? "__always_inline " : "");
    }

    @Nullable
    List<FunctionParameter> translateFunctionParameters(List<? extends VariableTree> parameters) {
        var translated = new ArrayList<FunctionParameter>();
        var hadError = false;
        for (var parameter : parameters) {
            var typeMirror = compilerPlugin.trees.getElement(methodPath.path(parameter)).asType();
            var type = translateType(compilerPlugin.trees.getElement(methodPath.path(parameter)), typeMirror);
            if (type == null) {
                logError(parameter, "Unsupported parameter type: " + typeMirror);
                hadError = true;
            }
            var name = parameter.getName().toString();
            translated.add(new FunctionParameter(variable(name), type));
        }
        return hadError ? null : translated;
    }

    public boolean addDefinition() {
        var annotation =
                compilerPlugin.getAnnotationOfMethodOrSuper((MethodSymbol) compilerPlugin.trees.getElement(methodPath.path()), BPFFunction.class);
        return annotation == null || annotation.addDefinition();
    }

    CAST.Statement.FunctionDeclarationStatement translate() {
        return translate(false);
    }

    CAST.Statement.FunctionDeclarationStatement translateIgnoringBody() {
        return translate(true);
    }

    @Nullable
    private CAST.Statement.FunctionDeclarationStatement translate(boolean ignoreBody) {
        var method = methodPath.leaf();
        var bpfAnn =
                compilerPlugin.getAnnotationOfMethodOrSuper((MethodSymbol) compilerPlugin.trees.getElement(methodPath.path()), BPFFunction.class);
        if (bpfAnn == null) {
            logError(method, "Method is not annotated with @BPFFunction");
            return null;
        }
        var declarator = toDeclarator();
        var body = ignoreBody ? new CompoundStatement(List.of()) : translate(method.getBody());
        boolean addReturnZero = method.getReturnType().toString().equals("void");
        return callIfNonNull(declarator, body,
                (d, b) -> {
                    if (!bpfAnn.lastStatement().isBlank() || addReturnZero) {
                        var returnStatement = new VerbatimStatement(bpfAnn.lastStatement().isBlank() ? "return 0;" : bpfAnn.lastStatement());
                        var statements = new ArrayList<>(b.replaceReturnStatement(returnStatement).statements());
                        if (statements.isEmpty() || !(statements.getLast().equals(returnStatement))) {
                            statements.add(returnStatement);
                        }
                        b = new CompoundStatement(statements);
                    }
                    if (bpfAnn.section().isBlank()) {
                        return new FunctionDeclarationStatement(d, b);
                    }
                    return new FunctionDeclarationStatement(d, b,
                            CAnnotation.sec(bpfAnn.section()));
                });
    }

    @Nullable
    CAST.Statement.CompoundStatement translate(BlockTree block) {
        var statements = block.getStatements();
        var translated = new ArrayList<Statement>();
        var hadError = false;
        for (var statement : statements) {
            var translatedStatement = translate(statement);
            if (translatedStatement != null) {
                translated.add(translatedStatement);
            } else {
                hadError = true;
            }
        }
        return hadError ? null : new CompoundStatement(translated);
    }

    @Nullable
    List<Statement> translate(List<? extends StatementTree> statements) {
        var translated = new ArrayList<Statement>();
        var hadError = false;
        for (var statement : statements) {
            var translatedStatement = translate(statement);
            if (translatedStatement != null) {
                translated.add(translatedStatement);
            } else {
                hadError = true;
            }
        }
        return hadError ? null : translated;
    }

    @Nullable
    Statement translate(StatementTree statement) {
        return switch (statement) {
            case ReturnTree returnTree -> translate(returnTree);
            case BlockTree blockTree -> translate(blockTree);
            case ExpressionStatementTree expressionStatementTree -> {
                var expression = translate(expressionStatementTree.getExpression());
                yield expression != null ? new CAST.Statement.ExpressionStatement(expression) : null;
            }
            case VariableTree variableTree -> {
                var typeMirror = compilerPlugin.trees.getElement(methodPath.path(variableTree)).asType();
                CAST.Expression initializer = null;
                List<Integer> sizes = List.of();
                var initTree = variableTree.getInitializer();
                if (initTree != null) {
                    if (initTree instanceof NewArrayTree newArrayTree) {
                        var initAnd = translate(typeMirror, newArrayTree);
                        if (initAnd != null) {
                            initializer = initAnd.expression();
                            sizes = initAnd.sizes();
                        } else {
                            yield null;
                        }
                    } else {
                        initializer = translate(initTree);
                        if (initializer == null) {
                            yield null;
                        }
                    }
                }
                var type = translateType(compilerPlugin.trees.getElement(methodPath.path(variableTree)),
                        typeMirror, sizes);
                var name = variableTree.getName().toString();
                // new VerbatimExpression("{}")
                if (initializer instanceof OperatorExpression exp && exp.operator() == Operator.CAST) {
                    if (exp.expressions()[1] instanceof VerbatimExpression valExpr && valExpr.code().equals("{}")) {
                        initializer = null;
                    }
                }
                yield type != null ? new CAST.Statement.VariableDefinition(type, variable(name), initializer) : null;
            }
            case IfTree ifTree -> {
                var condition = translate(ifTree.getCondition());
                var thenStatement = translate(ifTree.getThenStatement());
                var elseStatement = callIfNonNull(ifTree.getElseStatement(), this::translate);
                yield condition != null && thenStatement != null ? new CAST.Statement.IfStatement(condition,
                        thenStatement, elseStatement) : null;
            }
            case ForLoopTree forLoopTree -> {
                var initializer = callIfNonNull(forLoopTree.getInitializer(), this::translate);
                var condition = callIfNonNull(forLoopTree.getCondition(), this::translate);
                var update = callIfNonNull(forLoopTree.getUpdate(), this::translate);
                var body = translate(forLoopTree.getStatement());
                yield initializer != null && condition != null && update != null && body != null ?
                        new CAST.Statement.ForStatement(initializer, condition, update, body) : null;
            }
            case BreakTree breakTree -> {
                if (breakTree.getLabel() != null) {
                    logError(statement, "Unsupported label in break statement: " + statement);
                    yield null;
                }
                yield new BreakStatement();
            }
            case ContinueTree continueTree -> {
                if (continueTree.getLabel() != null) {
                    logError(statement, "Unsupported label in continue statement: " + statement);
                    yield null;
                }
                yield new ContinueStatement();
            }
            default -> {
                logError(statement, "Unsupported statement kind " + statement.getKind() + ": " + statement);
                yield null;
            }
        };
    }

    @Nullable
    CAST.Statement.ReturnStatement translate(ReturnTree returnTree) {
        if (returnTree.getExpression() == null) {
            return new ReturnStatement(null);
        }
        return callIfNonNull(translate(returnTree.getExpression()), ReturnStatement::new);
    }

    @Nullable
    CAST.Expression translate(ExpressionTree expression) {
        return switch (expression) {
            case LiteralTree literalTree -> translate(literalTree);
            case IdentifierTree identifierTree -> {
                var element = compilerPlugin.trees.getElement(methodPath.path(identifierTree));
                var defaultReturn = variable(identifierTree.getName().toString());
                if (element == null) {
                    yield defaultReturn;
                }
                if (!(element.getEnclosingElement() instanceof ClassSymbol classElement)) {
                    yield defaultReturn;
                }
                var memberSymbolOpt = classElement.getEnclosedElements().stream()
                        .filter(e -> e.getSimpleName().toString().equals(identifierTree.getName().toString()))
                        .findFirst();
                if (memberSymbolOpt.isEmpty()) {
                    // it could still be a record member

                    yield null;
                }
                var memberSymbol = (VariableElement) memberSymbolOpt.get();
                var define =
                        new TypeProcessor(compilerPlugin.createProcessingEnvironment(), true).processField(memberSymbol);
                if (define == null) {
                    yield defaultReturn;
                }
                requiredDefines.add(define);
                yield variable(define.name());
            }
            case ArrayAccessTree arrayAccessTree -> {
                var array = translate(arrayAccessTree.getExpression());
                var index = translate(arrayAccessTree.getIndex());
                yield array != null && index != null ? new OperatorExpression(Operator.SUBSCRIPT, array, index) : null;
            }
            case AssignmentTree assignmentTree -> {
                var variable = translate(assignmentTree.getVariable());
                var expr = assignmentTree.getExpression();
                Expression value = translate(expr);
                if (variable == null || value == null) {
                    yield null;
                }
                if (variable instanceof OperatorExpression vexpr && vexpr.operator() == Operator.MEMBER_ACCESS) {
                    if (vexpr.expressions()[0] instanceof OperatorExpression base && base.operator() == Operator.CAST) {
                        if (base.expressions()[1] instanceof VerbatimExpression valExpr && valExpr.code().startsWith("*(") && valExpr.code().endsWith(")")) {
                            // we can be certain that this is an assignment to a pointers' value
                            // replace *(X).Y with X->Y
                            var strippedValExpr = new VerbatimExpression(valExpr.code().substring(1));
                            yield new OperatorExpression(Operator.ASSIGNMENT, new OperatorExpression(Operator.PTR_MEMBER_ACCESS, strippedValExpr, vexpr.expressions()[1]), value);
                        }
                    }
                }

                yield new OperatorExpression(Operator.ASSIGNMENT, variable, value);
            }
            case BinaryTree binaryTree -> {
                if (compilerPlugin.isSameType(methodPath, binaryTree, String.class)) {
                    logError(expression, "Unsupported string operation: " + expression);
                }
                var left = translate(binaryTree.getLeftOperand());
                var right = translate(binaryTree.getRightOperand());

                var operator = switch (binaryTree.getKind()) {
                    case PLUS -> Operator.ADDITION;
                    case MINUS -> Operator.SUBTRACTION;
                    case MULTIPLY -> Operator.MULTIPLICATION;
                    case DIVIDE -> Operator.DIVISION;
                    case REMAINDER -> Operator.MODULUS;
                    case AND -> Operator.BITWISE_AND;
                    case OR -> Operator.BITWISE_OR;
                    case XOR -> Operator.BITWISE_XOR;
                    case LEFT_SHIFT -> Operator.SHIFT_LEFT;
                    case RIGHT_SHIFT -> Operator.SHIFT_RIGHT;
                    case LESS_THAN -> Operator.LESS_THAN;
                    case GREATER_THAN -> Operator.GREATER_THAN;
                    case LESS_THAN_EQUAL -> Operator.LESS_THAN_OR_EQUAL;
                    case GREATER_THAN_EQUAL -> Operator.GREATER_THAN_OR_EQUAL;
                    case CONDITIONAL_AND -> Operator.LOGICAL_AND;
                    case CONDITIONAL_OR -> Operator.LOGICAL_OR;
                    case EQUAL_TO -> Operator.EQUAL;
                    case NOT_EQUAL_TO -> Operator.NOT_EQUAL;
                    default -> null;
                };

                if (operator == null) {
                    logError(expression, "Unsupported binary operator " + binaryTree.getKind() + ": " + expression);
                    yield null;
                }

                yield left != null && right != null ? new OperatorExpression(operator, left, right) : null;
            }
            case UnaryTree unaryTree -> {
                var operand = translate(unaryTree.getExpression());

                var operator = switch (unaryTree.getKind()) {
                    case UNARY_MINUS -> Operator.UNARY_MINUS;
                    case LOGICAL_COMPLEMENT -> Operator.LOGICAL_NOT;
                    case BITWISE_COMPLEMENT -> Operator.BITWISE_NOT;
                    case POSTFIX_INCREMENT -> Operator.POSTFIX_INCREMENT;
                    case POSTFIX_DECREMENT -> Operator.POSTFIX_DECREMENT;
                    case PREFIX_INCREMENT -> Operator.SUFFIX_INCREMENT;
                    case PREFIX_DECREMENT -> Operator.SUFFIX_DECREMENT;
                    default -> null;
                };

                if (operator == null) {
                    logError(expression, "Unsupported unary operator " + unaryTree.getKind() + ": " + expression);
                    yield null;
                }

                yield operand != null ? new OperatorExpression(operator, operand) : null;
            }
            case MethodInvocationTree methodInvocationTree -> translate(methodInvocationTree);
            case MemberSelectTree memberSelectTree -> {
                var member = memberSelectTree.getIdentifier().toString();
                if (memberSelectTree.getExpression() instanceof JCIdent ident) {
                    var t = compilerPlugin.trees.getElement(methodPath.path(ident)).asType();
                    if (t != null) {
                        var element = compilerPlugin.trees.getElement(methodPath.path(ident));
                        if (element instanceof TypeElement) {
                            var kind = typeKind(element);
                            if (kind != DataTypeKind.ENUM) {
                                // handle constants
                                var classElement = (ClassSymbol) element;
                                var memberSymbolOpt = classElement.getEnclosedElements().stream()
                                        .filter(e -> e.getSimpleName().toString().equals(member))
                                        .findFirst();
                                if (memberSymbolOpt.isEmpty()) {
                                    // it could still be a record member
                                    logError(memberSelectTree, "Can't find member: " + classElement.getQualifiedName() + "." + member);
                                    yield null;
                                }
                                var memberSymbol = (VariableElement) memberSymbolOpt.orElseThrow();
                                var define =
                                        new TypeProcessor(compilerPlugin.createProcessingEnvironment(), true).processField(memberSymbol);
                                if (define == null) {
                                    logError(memberSelectTree,
                                            "Unsupported constant: " + classElement.getQualifiedName() + "." + member);
                                    yield null;
                                }
                                requiredDefines.add(define);
                                yield variable(define.name());
                            }
                            for (var tMember : ((ClassType) t).tsym.getEnclosedElements()) {
                                if (tMember.getSimpleName().toString().equals(member)) {
                                    var ann = tMember.getAnnotation(EnumMember.class);
                                    if (ann != null && !ann.name().isEmpty()) {
                                        yield variable(ann.name());
                                    }
                                    yield variable(toConstantCase(((ClassType) t).tsym.getSimpleName() + "_" + member));
                                }
                            }
                            throw new AssertionError();
                        }
                    }
                }
                var expr = translate(memberSelectTree.getExpression());
                if (member.matches("anon(\\d+)(\\$\\d+)*")) {
                    // anonymous struct member
                    yield expr;
                }
                yield expr != null ? new OperatorExpression(Operator.MEMBER_ACCESS, expr, variable(member)) : null;
            }
            case ParenthesizedTree parenthesizedTree ->
                    callIfNonNull(translate(parenthesizedTree.getExpression()), Expression::parenthesizedExpression);
            case ConditionalExpressionTree conditionalExpressionTree -> {
                var condition = translate(conditionalExpressionTree.getCondition());
                var trueExpression = translate(conditionalExpressionTree.getTrueExpression());
                var falseExpression = translate(conditionalExpressionTree.getFalseExpression());
                yield condition != null && trueExpression != null && falseExpression != null ?
                        new OperatorExpression(Operator.CONDITIONAL, condition, trueExpression, falseExpression) : null;
            }
            case TypeCastTree typeCastTree -> {
                var expr = translate(typeCastTree.getExpression());
                var typeTree = typeCastTree.getType();
                Expression typeExpression;
                if (typeTree instanceof JCPrimitiveTypeTree primitiveTypeTree) {
                    var bpfType = switch (primitiveTypeTree.getPrimitiveTypeKind()) {
                        case INT -> BPFType.BPFIntType.INT32;
                        case LONG -> BPFType.BPFIntType.INT64;
                        case FLOAT -> BPFType.BPFIntType.FLOAT;
                        case DOUBLE -> BPFType.BPFIntType.DOUBLE;
                        case BOOLEAN -> BPFType.BPFIntType.BOOL;
                        case CHAR -> BPFType.BPFIntType.CHAR;
                        case SHORT -> BPFIntType.INT16;
                        case BYTE -> BPFIntType.INT8;
                        case VOID -> BPFType.VOID;
                        default ->
                                throw new IllegalStateException("Unexpected primitive type kind: " + primitiveTypeTree.getPrimitiveTypeKind());
                    };
                    typeExpression = bpfType.toCUse();
                } else {
                    var element = compilerPlugin.trees.getElement(methodPath.path(typeTree));
                    if (element != null) {
                        var type = element.asType();
                        if (type.toString().equals("java.lang.Object")) {
                            yield expr;
                        }
                        if (typeCastTree instanceof JCTypeCast cast && cast.pos == cast.expr.pos) {
                            yield expr; // a cast introduced by the compiler
                        }
                        if (type.toString().equals(Ptr.class.getName())) {
                            logError(expression, "Unsupported type cast to " + type + " use 'Ptr::cast' instead: " + typeCastTree);
                            yield null;
                        }
                        if (type instanceof ClassType classType && classType.asElement().getQualifiedName().toString().equals(Ptr.class.getName())) {
                            logError(expression, "Unsupported type cast to " + type + " use 'Ptr.<Type>cast(...)' instead: " + typeCastTree);
                            yield null;
                        }
                    }
                    var typeCastTreeElement = compilerPlugin.trees.getElement(methodPath.path(typeCastTree));
                    if (typeTree instanceof JCAnnotatedType annType) {
                        typeExpression = translateTypeForClassTypeArguments(compilerPlugin.trees.getElement(methodPath.path()), annType.type);
                    } else {
                        if (element == null) {
                            logError(typeCastTree, "Unsupported type cast: " + typeCastTreeElement);
                            yield null;
                        }
                        typeExpression = translateType(typeCastTreeElement, element.asType());
                    }
                }
                yield typeExpression != null && expr != null ? new OperatorExpression(Operator.CAST, typeExpression,
                        expr) : null;
            }
            case NewClassTree newClassTree -> {

                if (newClassTree.getClassBody() != null) {
                    logError(expression, "Unsupported class body: " + newClassTree.getClassBody());
                    yield null;
                }

                var typeElement = compilerPlugin.trees.getElement(methodPath.path(newClassTree.getIdentifier()));

                if (typeElement == null) {
                    logError(expression, "Unsupported class type: " + newClassTree.getIdentifier());
                    yield null;
                }

                var typeKind = typeKind(typeElement);

                var customTypeAnnotation = typeElement.getAnnotation(CustomType.class);

                if (typeKind == DataTypeKind.NONE && customTypeAnnotation != null) {
                    var template = customTypeAnnotation.constructorTemplate();
                    var methodTemplate = MethodTemplate.parse(customTypeAnnotation.name(), template);
                    List<Argument> arguments = new ArrayList<>();
                    boolean hasError = false;
                    for (int i = 0; i < newClassTree.getArguments().size(); i++) {
                        var translated = translateArgument(newClassTree.getArguments().get(i));
                        if (translated == null) {
                            hasError = true;
                        }
                        arguments.add(translated);
                    }
                    if (hasError) {
                        yield null;
                    }
                    yield methodTemplate.call(new CallArgs(null, arguments, List.of()));
                }

                if (typeKind == DataTypeKind.ENUM || typeKind == DataTypeKind.NONE) {

                    logError(expression, "Unsupported constructor call: " + newClassTree);
                    yield null;
                }

                var type = translateType(typeElement, typeElement.asType());

                if (type == null) {
                    logError(expression, "Unsupported constructor call: " + newClassTree);
                    yield null;
                }

                var args = newClassTree.getArguments();

                if (args.isEmpty()) {
                    yield CAST.OperatorExpression.cast(type, new VerbatimExpression("{}"));
                }
                /*if (typeElement.getKind() != ElementKind.RECORD) {
                    logError(expression,
                            "No constructor arguments support for class based structs or unions: " + newClassTree);
                    yield null;
                }*/

                var record = (ClassSymbol) typeElement;
                var fieldNames = record.getEnclosedElements().stream()
                        .filter(e -> e.getKind() == ElementKind.FIELD)
                        .map(e -> (VariableElement) e)
                        .map(VariableElement::getSimpleName)
                        .toList();

                if (args.size() != fieldNames.size()) {
                    logError(expression, "Constructor arguments mismatch: " + args.size() + " vs " + fieldNames.size());
                    yield null;
                }

                var fieldValues = new ArrayList<InitDeclarator>();
                var hadError = false;
                for (int i = 0; i < args.size(); i++) {
                    var arg = args.get(i);
                    var value = translate(arg);
                    if (value == null) {
                        hadError = true;
                    }
                    fieldValues.add(new InitDeclarator(variable(fieldNames.get(i).toString()), value));
                }
                if (hadError) {
                    yield null;
                }
                if (typeKind == DataTypeKind.TYPEDEF) {
                    yield fieldValues.getFirst().expression();
                }

                yield new CAST.OperatorExpression(Operator.CAST, type, new InitializerList(fieldValues));
            }
            case CompoundAssignmentTree compoundAssignmentTree -> {
                var left = translate(compoundAssignmentTree.getVariable());
                var right = translate(compoundAssignmentTree.getExpression());

                var operator = switch (compoundAssignmentTree.getKind()) {
                    case PLUS_ASSIGNMENT -> Operator.ADDITION_ASSIGNMENT;
                    case MINUS_ASSIGNMENT -> Operator.SUBTRACTION_ASSIGNMENT;
                    case MULTIPLY_ASSIGNMENT -> Operator.MULTIPLICATION_ASSIGNMENT;
                    case DIVIDE_ASSIGNMENT -> Operator.DIVISION_ASSIGNMENT;
                    case REMAINDER_ASSIGNMENT -> Operator.MODULUS_ASSIGNMENT;
                    case AND_ASSIGNMENT -> Operator.BITWISE_AND_ASSIGNMENT;
                    case OR_ASSIGNMENT -> Operator.BITWISE_OR_ASSIGNMENT;
                    case XOR_ASSIGNMENT -> Operator.BITWISE_XOR_ASSIGNMENT;
                    case LEFT_SHIFT_ASSIGNMENT -> Operator.SHIFT_LEFT_ASSIGNMENT;
                    case RIGHT_SHIFT_ASSIGNMENT -> Operator.SHIFT_RIGHT_ASSIGNMENT;
                    default -> {
                        logError(expression,
                                "Unsupported binary operator " + compoundAssignmentTree.getKind() + ": " + expression);
                        yield null;
                    }
                };

                yield left != null && right != null ? new OperatorExpression(operator, left, right) : null;
            }
            case LambdaExpressionTree lambda -> {
                logError(expression, "Lambdas are only supported in calls to built-in functions: " + expression);
                yield null;
            }
            default -> {
                logError(expression, "Unsupported expression kind in translator " + expression.getKind() + ": " + expression);
                yield null;
            }
        };
    }

    /**
     * This method has to deal with parsing the template
     */
    @Nullable
    Expression translate(MethodInvocationTree methodInvocationTree) {
        var calledMethod = methodInvocationTree.getMethodSelect();
        var methodTree = (JCMethodInvocation) methodInvocationTree;
        MethodSymbol symbol;
        Expression thisExpression = null;
        JCExpression thisJavacExpression = null;
        switch (methodTree.meth) {
            case JCFieldAccess access -> {
                symbol = (MethodSymbol) access.sym;
                if (symbol.isStatic()) {
                    break;
                }
                thisExpression = translate(access.selected);
                thisJavacExpression = access.selected;
                if (compilerPlugin.methodTemplateCache.isAutoUnboxing(symbol)) {
                    // ((Integer)X).intValue() -> X
                    if (thisExpression instanceof OperatorExpression opExpr && opExpr.operator() == Operator.CAST) {
                        return opExpr.expressions()[1];
                    }
                }
            }
            case JCIdent ident -> {
                symbol = (MethodSymbol) ident.sym;
            }
            default -> {
                logError(calledMethod, "Unsupported method invocation: " + methodInvocationTree);
                return null;
            }
        }
        List<Argument> arguments = new ArrayList<>();
        boolean hasError = false;
        for (int i = 0; i < methodTree.getArguments().size(); i++) {
            var argument = methodTree.getArguments().get(i);
            if (symbol.isVarArgs() && i >= symbol.getParameters().size() - 1) {
                // handle varargs by expanding the last argument
                if (argument instanceof JCNewArray newArray) {
                    for (var elem : newArray.elems) {
                        var translated = translateArgumentWithoutLambda(elem);
                        if (translated == null) {
                            hasError = true;
                        }
                        arguments.add(translated);
                    }
                } else {
                    var translated = translateArgument(argument);
                    if (translated == null) {
                        hasError = true;
                    }
                    arguments.add(translated);
                }
            } else {
                var translated = translateArgument(argument);
                if (translated == null) {
                    hasError = true;
                }
                arguments.add(translated);
            }
        }
        List<Declarator> declarators = new ArrayList<>();
        List<Declarator> typeDeclarators = new ArrayList<>();
        for (var templateArg : methodTree.getTypeArguments()) {
            var type = translateType(compilerPlugin.trees.getElement(methodPath.path(templateArg)),
                    compilerPlugin.trees.getTypeMirror(methodPath.path(templateArg)));
            if (type == null) {
                logError(templateArg,
                        "Unsupported argument type: " + compilerPlugin.trees.getTypeMirror(methodPath.path(templateArg)));
                hasError = true;
            }
            declarators.add(type);
        }
        if (thisJavacExpression instanceof JCIdent methodIdent) {
            for (var templateArg : methodIdent.sym.type.getTypeArguments()) {
                if (templateArg.asElement() instanceof TypeVariableSymbol) {
                    typeDeclarators.add(null);
                } else {
                    var type = translateTypeForClassTypeArguments(templateArg.asElement(), templateArg);
                    typeDeclarators.add(type);
                }
            }
        }
        if (hasError) {
            return null;
        }
        try {
            return compilerPlugin.methodTemplateCache.render(methodPath, methodInvocationTree, symbol,
                    new CallArgs(thisExpression, arguments, declarators, typeDeclarators));
        } catch (TemplateRenderException e) {
            logError(calledMethod, e.getMessage());
            return null;
        }
    }

    @Nullable
    Argument translateArgumentWithoutLambda(ExpressionTree argument) {
        var arg = translate(argument);
        if (arg == null) {
            return null;
        }
        return new Argument.Value(arg);
    }

    @Nullable
    Argument translateArgument(ExpressionTree argument) {
        if (argument instanceof LambdaExpressionTree lambda) {
            var params = translateFunctionParameters(lambda.getParameters());
            if (params == null) {
                return null;
            }
            CompoundStatement body = switch (lambda.getBody()) {
                case BlockTree block -> translate(block);
                case ExpressionTree exprTree -> {
                    var expr = translate(exprTree);
                    if (expr == null) {
                        yield null;
                    }
                    yield new CompoundStatement(List.of(new ExpressionStatement(expr)));
                }
                default -> {
                    logError(lambda, "Unsupported lambda body: " + lambda.getBody());
                    yield null;
                }
            };
            if (body == null) {
                return null;
            }
            return new Lambda(params, body);
        }
        return translateArgumentWithoutLambda(argument);
    }
    // translate(((JCLambda) argument).body)

    @Nullable
    CAST.Expression translate(LiteralTree literalTree) {
        try {
            if (literalTree.getValue() == null) {
                return new VerbatimExpression("NULL");
            }
            return constant(literalTree.getValue());
        } catch (IllegalArgumentException e) {
            logError(literalTree, "Unsupported literal value " + literalTree.getValue());
            return null;
        }
    }

    @Nullable
    CAST.Declarator translateType(Element element, TypeMirror type) {
        return translateType(element, type, List.of());
    }

    @SuppressWarnings({"rawtypes"})
    @Nullable
    CAST.Declarator translateType(Element element, TypeMirror type, List<Integer> sizes) {
        TypeProcessor typeProcessor = new TypeProcessor(compilerPlugin.createProcessingEnvironment(), true);
        var anns = AnnotationUtils.getAnnotationValuesForRecordMember(type);
        if (anns.size().isEmpty()) {
            // e.g. int arr[2]
            anns = anns.addSizes(sizes);
        } else if (!sizes.isEmpty()) {
            if (!anns.size().equals(sizes)) {
                compilerPlugin.createProcessingEnvironment().getMessager().printError("Size annotation mismatch: " + anns.size() + " vs " + sizes, element);
                return null;
            }
        }
        var typeElement = (TypeElement) compilerPlugin.task.getTypes().asElement(type);
        if (typeElement != null) {
            var customTypeInfo = typeProcessor.getCustomTypeInfo(typeElement);
            if (customTypeInfo != null) {
                var name = variable(customTypeInfo.bpfName().name());
                if (customTypeInfo.isStruct()) {
                    return new StructIdentifierDeclarator(name);
                }
                return new IdentifierDeclarator(name);
            }
        }
        var t = typeProcessor.processBPFTypeRecordMemberType(element, anns, type);
        return t.map(m -> m.toBPFType(j -> new VerbatimBPFOnlyType(j.name(), PrefixKind.NORMAL)).toCustomType().toCUse()).orElse(null);
    }

    @SuppressWarnings({"rawtypes"})
    @Nullable
    CAST.Declarator translateTypeForClassTypeArguments(Element element, Type type) {
        TypeProcessor typeProcessor = new TypeProcessor(compilerPlugin.createProcessingEnvironment(), true);
        var anns = AnnotationUtils.getAnnotationValuesForRecordMember(type);
        var typeElementOrIdent = compilerPlugin.task.getTypes().asElement(type);
        if (typeElementOrIdent instanceof TypeElement typeElement) {
            var customTypeInfo = typeProcessor.getCustomTypeInfo(typeElement);
            if (customTypeInfo != null) {
                var name = variable(customTypeInfo.bpfName().name());
                if (customTypeInfo.isStruct()) {
                    return new StructIdentifierDeclarator(name);
                }
                return new IdentifierDeclarator(name);
            }
        }

        var t = typeProcessor.processBPFTypeRecordMemberType(element, anns, type);
        return t.map(m -> m.toBPFType(j -> new VerbatimBPFOnlyType(j.name(), PrefixKind.NORMAL)).toCustomType().toCUse()).orElse(null);
    }

    DataTypeKind typeKind(Element element) {
        var typeProcessor = new TypeProcessor(compilerPlugin.createProcessingEnvironment(), true);
        var customTypeInfo = typeProcessor.getCustomTypeInfo((TypeElement) element);
        if (customTypeInfo != null) {
            var name = variable(customTypeInfo.bpfName().name());
            if (customTypeInfo.isStruct()) {
                return DataTypeKind.STRUCT;
            }
            return DataTypeKind.NONE;
        }
        return typeProcessor.isValidDataType(element, false);
    }

    record ExpressionAndPossibleSizes(CAST.Expression expression, List<Integer> sizes) {
    }

    @Nullable
    ExpressionAndPossibleSizes translate(TypeMirror type, NewArrayTree newArrayTree) {
        assert newArrayTree instanceof JCNewArray;
        var array = (JCNewArray) newArrayTree;
        List<Integer> sizes = new ArrayList<>();
        if (array.dims != null) {
            // e.g. new int[2][3] <---
            // check for every dimension that it is a constant
            boolean hadError = false;
            for (var dim : array.dims) {
                var translation = translate(dim);
                if (translation instanceof IntegerConstant constant) {
                    sizes.add(constant.value());
                } else {
                    logError(dim, "Array sizes have to be integer constants, not " + dim);
                    hadError = true;
                }
            }
            if (hadError) {
                return null;
            }
        }
        if (array.elems == null) {
            // e.g. int[] arr = new int[2];
            return new ExpressionAndPossibleSizes(null, sizes);
        } else {
            if (array.dims != null && array.dims.size() > 1) {
                logError(newArrayTree, "Only the last dimension can be initialized");
                return null;
            }
            // e.g. int[] arr = new int[]{1, 2, 3};
            var elements = new ArrayList<Expression>();
            for (var elem : array.elems) {
                var translation = translate(elem);
                if (translation == null) {
                    return null;
                }
                elements.add(translation);
            }
            if (sizes.size() == 1) {
                if (sizes.getFirst() != elements.size()) {
                    logError(newArrayTree, "Array size mismatch: " + sizes.getFirst() + " vs " + elements.size());
                    return null;
                }
            }
            return new ExpressionAndPossibleSizes(
                    new InitializerList(elements.stream().map(e -> new InitDeclarator(null, e)).toList()),
                    List.of(elements.size()));
        }
    }
}
