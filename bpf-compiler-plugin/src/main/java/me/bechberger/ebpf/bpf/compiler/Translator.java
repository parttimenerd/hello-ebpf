package me.bechberger.ebpf.bpf.compiler;

import com.sun.source.tree.*;
import com.sun.source.util.TreePath;
import com.sun.source.util.TreeScanner;
import com.sun.tools.javac.code.Symbol.ClassSymbol;
import com.sun.tools.javac.code.Symbol.MethodSymbol;
import com.sun.tools.javac.code.Symbol.TypeVariableSymbol;
import com.sun.tools.javac.code.Type;
import com.sun.tools.javac.code.Type.ClassType;
import com.sun.tools.javac.tree.JCTree.*;
import me.bechberger.cast.CAST;
import me.bechberger.cast.CAST.Declarator.*;
import me.bechberger.cast.CAST.Initializer.InitializerList;
import me.bechberger.cast.CAST.Operator;
import me.bechberger.cast.CAST.PrimaryExpression.CAnnotation;
import me.bechberger.cast.CAST.PrimaryExpression.Constant.IntegerConstant;
import me.bechberger.cast.CAST.PrimaryExpression.VerbatimExpression;
import me.bechberger.cast.CAST.Statement.*;
import me.bechberger.ebpf.annotations.AlwaysInline;
import me.bechberger.ebpf.annotations.CustomType;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFInline;
import me.bechberger.ebpf.annotations.EnumMember;
import me.bechberger.ebpf.bpf.compiler.CompilerPlugin.TypedTreePath;
import me.bechberger.ebpf.bpf.compiler.MethodTemplate.Argument;
import me.bechberger.ebpf.bpf.compiler.MethodTemplate.Argument.Lambda;
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
import java.util.Optional;
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
    /** Top-level synthetic C functions emitted for {@code $funcN} lambda lifts.
     *  Collected during translation; emitted alongside the main method declaration. */
    private final List<FunctionDeclarationStatement> syntheticFunctions = new ArrayList<>();
    /** Per-method counter for synthetic-function naming. */
    private int syntheticLambdaCounter = 0;

    Translator(CompilerPlugin compilerPlugin, TypedTreePath<MethodTree> methodPath) {
        this.compilerPlugin = compilerPlugin;
        this.methodPath = methodPath;
    }

    /** Synthetic top-level C functions generated to back {@code $funcN} lambda
     *  arguments (function-pointer-style helpers like {@code bpf_loop}). */
    public List<FunctionDeclarationStatement> getSyntheticFunctions() {
        return syntheticFunctions;
    }

    /** Emit a {@code #line N "File.java"} directive for the given AST node so that
     *  clang embeds Java source locations in the BPF object's BTF/DWARF line info.
     *  The kernel verifier then reports Java file:line in its error output. */
    private @Nullable VerbatimStatement lineDirective(Tree tree) {
        var cu = methodPath.root();
        var sp = compilerPlugin.trees.getSourcePositions();
        long pos = sp.getStartPosition(cu, tree);
        if (pos == javax.tools.Diagnostic.NOPOS) return null;
        long line = cu.getLineMap().getLineNumber(pos);
        if (line <= 0) return null;
        var sourceFile = cu.getSourceFile().getName();
        // Normalise to just the filename (no path) so #line directives are portable.
        var slash = sourceFile.lastIndexOf('/');
        if (slash >= 0) sourceFile = sourceFile.substring(slash + 1);
        var bslash = sourceFile.lastIndexOf('\\');
        if (bslash >= 0) sourceFile = sourceFile.substring(bslash + 1);
        return new VerbatimStatement("#line " + line + " \"" + sourceFile + "\"");
    }

    /**
     * Evaluate an expression to its compile-time constant value, if possible.
     * Handles boolean/int literals and {@code static final} field references.
     */
    private Optional<Object> evaluateToConstant(ExpressionTree expr) {
        // javac wraps if-conditions in JCParens; unwrap before evaluating
        if (expr instanceof ParenthesizedTree paren) {
            return evaluateToConstant(paren.getExpression());
        }
        if (expr instanceof LiteralTree lit && lit.getValue() != null) {
            Object v = lit.getValue();
            // javac may represent boolean literals as Integer(0)/Integer(1) with kind BOOLEAN_LITERAL,
            // or as Boolean directly depending on internal AST stage.
            if (lit.getKind() == Tree.Kind.BOOLEAN_LITERAL) {
                if (v instanceof Boolean b) return Optional.of(b);
                if (v instanceof Number n) return Optional.of(n.intValue() != 0);
                return Optional.of(Boolean.parseBoolean(v.toString()));
            }
            if (v instanceof Boolean b) return Optional.of(b);
            return Optional.of(v);
        }
        // static final field reference (simple name in same class)
        if (expr instanceof IdentifierTree ident) {
            var element = compilerPlugin.trees.getElement(methodPath.path(ident));
            if (element instanceof VariableElement ve && ve.getConstantValue() != null) {
                return Optional.of(ve.getConstantValue());
            }
        }
        // static final field reference (qualified: ClassName.FIELD)
        if (expr instanceof MemberSelectTree mst) {
            var element = compilerPlugin.trees.getElement(methodPath.path(mst));
            if (element instanceof VariableElement ve && ve.getConstantValue() != null) {
                return Optional.of(ve.getConstantValue());
            }
        }
        return Optional.empty();
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
                compilerPlugin.getEffectiveBPFFunction((MethodSymbol) compilerPlugin.trees.getElement(methodPath.path()));
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
        var bpfInline = compilerPlugin.getAnnotationOfMethodOrSuper(methodElement, BPFInline.class);
        // Helper functions (no SEC entry point) default to __always_inline unless opted out.
        // Entry-point functions (section != "") do not inline by default.
        boolean isEntryPoint = !annotation.section().isBlank();
        boolean shouldInline = (alwaysInline != null || bpfInline != null)
                || (!isEntryPoint && annotation.inline());
        return MethodHeaderTemplate.parse(annotation.headerTemplate()).call(decl, shouldInline ? "__always_inline " : "");
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
                compilerPlugin.getEffectiveBPFFunction((MethodSymbol) compilerPlugin.trees.getElement(methodPath.path()));
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
                compilerPlugin.getEffectiveBPFFunction((MethodSymbol) compilerPlugin.trees.getElement(methodPath.path()));
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
        return translate(block, true);
    }

    CAST.Statement.CompoundStatement translate(BlockTree block, boolean emitLineDirectives) {
        var statements = block.getStatements();
        var translated = new ArrayList<Statement>();
        var hadError = false;
        for (var statement : statements) {
            // Skip line directive + statement entirely if constant folding will eliminate this branch
            if (statement instanceof IfTree ifTree) {
                var foldVal = evaluateToConstant(ifTree.getCondition());
                if (foldVal.isPresent() && foldVal.get() instanceof Boolean b && !b && ifTree.getElseStatement() == null) {
                    continue;
                }
            }
            if (emitLineDirectives) {
                var line = lineDirective(statement);
                if (line != null) translated.add(line);
            }
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
                // Constant folding: if (true) → then-block, if (false) → else-block (or nothing)
                var constVal = evaluateToConstant(ifTree.getCondition());
                if (constVal.isPresent() && constVal.get() instanceof Boolean boolVal) {
                    if (boolVal) {
                        yield translate(ifTree.getThenStatement());
                    } else {
                        yield ifTree.getElseStatement() != null
                                ? translate(ifTree.getElseStatement()) : new VerbatimStatement("");
                    }
                }
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
            case WhileLoopTree whileLoopTree -> {
                var condition = callIfNonNull(whileLoopTree.getCondition(), this::translate);
                var body = translate(whileLoopTree.getStatement());
                yield new CAST.Statement.WhileStatement(condition, body);
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
    CAST.Statement.Statement translate(ReturnTree returnTree) {
        if (returnTree.getExpression() == null) { // Since void functions aren't allowed, returns without an argument don't make sense
            return new VerbatimStatement("return 0;");
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
                // CO-RE: if this MemberSelect is the outermost link of a
                // kernel-BTF chain, lift the whole chain to a single
                // BPF_CORE_READ(root, m1, m2, ...) call. The recursive
                // translate(getExpression()) above already computed `expr`
                // for the inner part — we discard it because the outermost
                // lift rebuilds the chain from the AST. Inner kernel-BTF
                // MemberSelects detect that their parent is also kernel-BTF
                // and themselves bail out of the lift, falling through to
                // a (discarded) MEMBER_ACCESS expression.
                var coreLifted = tryLiftCoreRead(memberSelectTree);
                if (coreLifted != null) {
                    yield coreLifted;
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
                    var res = methodTemplate.call(new CallArgs(null, arguments, List.of()));
                    if (!(res instanceof Expression expr)) {
                        throw new IllegalStateException("Unexpected type " + res.getClass());
                    }
                    yield  expr;
                }

                if (typeKind == DataTypeKind.ENUM || typeKind == DataTypeKind.NONE) {
                    // Allow new String() as a zero-initializer alias for BPFJ.charBuf(N).
                    // The @Size annotation on the enclosing variable declaration carries the size;
                    // the compiler plugin picks it up when translating the VariableTree.
                    if (typeElement.toString().equals("java.lang.String") && newClassTree.getArguments().isEmpty()) {
                        yield new VerbatimExpression("{}");
                    }
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
        MethodSymbol symbol = null;
        Expression thisExpression = null;
        JCExpression thisJavacExpression = null;
        switch (methodTree.meth) {
            case JCFieldAccess access -> {
                if (!(access.sym instanceof MethodSymbol)) {
                    logError(calledMethod, "Unsupported method invocation (not a method symbol): " + methodInvocationTree);
                    return null;
                }
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
                if (!(ident.sym instanceof MethodSymbol)) {
                    logError(calledMethod, "Unsupported method invocation (not a method symbol): " + methodInvocationTree);
                    return null;
                }
                symbol = (MethodSymbol) ident.sym;
            }
            default -> {
                logError(calledMethod, "Unsupported method invocation: " + methodInvocationTree);
                return null;
            }
        }
        if (symbol == null) {
            return null;
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
                } else {
                    // Auto-Ptr: if the declared parameter is Ptr<X> but the caller passes X, wrap with &
                    if (i < symbol.getParameters().size()) {
                        var declared = symbol.getParameters().get(i).asType();
                        var actual = ((JCExpression) argument).type;
                        translated = maybeAutoRef(translated, declared, actual);
                    }
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
            var res = compilerPlugin.methodTemplateCache.render(methodPath, methodInvocationTree, symbol,
                    new CallArgs(thisExpression, arguments, declarators, typeDeclarators,
                            this::promoteLambda));
            return new VerbatimExpression(
                                res.code().endsWith(";") ?
                                        res.code().substring(0, res.code().length() - 1) :
                                        res.code());
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
            var params = translateLambdaParameters(lambda.getParameters());
            if (params == null) {
                return null;
            }
            CompoundStatement body = switch (lambda.getBody()) {
                case BlockTree block -> translate(block, false);
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
            return new Lambda(params, body, lambda);
        }
        return translateArgumentWithoutLambda(argument);
    }

    /**
     * Translate lambda parameters with one MVP relaxation over the regular path:
     * a parameter typed {@code Object} is mapped to {@code void *}. This supports the
     * function-pointer-style lambdas (e.g. {@code BPFJ.bpfLoop}) where the user-side
     * Java signature treats {@code ctx} as opaque (typically {@code Object}) but the
     * libbpf-side C signature requires {@code void *}.
     * <p>
     * For inline-expansion lambdas this relaxation is harmless: a {@code void *}
     * parameter declaration in the inlined body is equivalent to what the user wrote.
     */
    @Nullable
    private List<FunctionParameter> translateLambdaParameters(List<? extends VariableTree> parameters) {
        var translated = new ArrayList<FunctionParameter>();
        var hadError = false;
        for (var parameter : parameters) {
            // Two type sources can disagree for inferred lambda parameters:
            //   - element.asType()    → from the parameter Symbol; erasure erases generic
            //                           type variables (C in `<C> bpfLoop(..., C ctx)`) to
            //                           Object.
            //   - trees.getTypeMirror → walks the AST node and reflects post-inference
            //                           types, so for `BPFJ.<Ptr<State>>bpfLoop(5, (i, st) -> ...)`
            //                           it returns Ptr<State> for `st`.
            // Prefer the AST-side type when the symbol-side is `Object` — that's the
            // erasure-vs-inference disagreement that costs typed-ctx lambdas.
            var astType = compilerPlugin.trees.getTypeMirror(methodPath.path(parameter));
            var symType = compilerPlugin.trees.getElement(methodPath.path(parameter)).asType();
            var typeMirror = (astType != null
                    && symType != null
                    && "java.lang.Object".equals(symType.toString())
                    && !"java.lang.Object".equals(astType.toString()))
                    ? astType
                    : symType;
            CAST.Declarator type;
            if (typeMirror != null && "java.lang.Object".equals(typeMirror.toString())) {
                type = Declarator.pointer(Declarator.identifier("void"));
            } else {
                type = translateType(compilerPlugin.trees.getElement(methodPath.path(parameter)), typeMirror);
            }
            if (type == null) {
                logError(parameter, "Unsupported parameter type: " + typeMirror);
                hadError = true;
            }
            var name = parameter.getName().toString();
            translated.add(new FunctionParameter(variable(name), type));
        }
        return hadError ? null : translated;
    }
    // translate(((JCLambda) argument).body)

    /**
     * If the declared parameter type is {@code Ptr<X>} and the actual argument type is {@code X},
     * wrap the translated expression with {@code &} (address-of) so the caller doesn't have to
     * write {@code Ptr.of(x)} everywhere.
     *
     * <p>The reverse (unwrapping {@code *} when the context expects {@code X} but the expr is
     * {@code Ptr<X>}) is intentionally not done here because call sites typically capture the
     * result in a typed variable anyway, and the deref placement is context-dependent.
     */
    private Argument maybeAutoRef(Argument arg, Type declared, Type actual) {
        if (declared instanceof ClassType declClass
                && declClass.asElement().getQualifiedName().contentEquals(Ptr.class.getName())
                && actual != null) {
            // declared is Ptr<X>; check actual is not already Ptr<?>
            if (actual instanceof ClassType actualClass
                    && actualClass.asElement().getQualifiedName().contentEquals(Ptr.class.getName())) {
                return arg; // already a Ptr, pass through
            }
            if (actual.getKind() == TypeKind.ARRAY || actual.getKind() == TypeKind.VOID) {
                return arg; // arrays and void don't need auto-ref
            }
            if (arg instanceof Argument.Value val) {
                return new Argument.Value(new OperatorExpression(Operator.ADDRESS_OF, val.expression()));
            }
        }
        return arg;
    }

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
        var t = typeProcessor.processBPFTypeRecordMemberTypeWithBox(element, anns, type);
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

        var t = typeProcessor.processBPFTypeRecordMemberTypeWithBox(element, anns, type);
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

    /**
     * Lift a lambda argument to a top-level static {@code __always_inline} C function.
     * <p>
     * Called by {@link MethodTemplate.LambdaPromoter} when the builtin's template uses
     * {@code $funcN} (function-pointer-style helper such as {@code bpf_loop} or
     * {@code bpf_for_each_map_elem}). Performs capture analysis (rejecting captures of
     * locals defined outside the lambda); generates a function with shape:
     * <pre>{@code
     *   static __always_inline int __bpf_lambda_<method>_<n>(<p0> p0, <p1> p1, void *ctx) {
     *       <translated lambda body>
     *       return 0;
     *   }
     * }</pre>
     * Adds the function to {@link #syntheticFunctions} for emission alongside the
     * enclosing BPF method.
     *
     * @return the synthetic function name, or {@code null} if capture analysis or body
     *         translation failed (a {@code Diagnostic.Kind.ERROR} has been emitted).
     */
    @Nullable
    String promoteLambda(int argIndex, MethodTemplate.Argument.Lambda lambda,
                         MethodTemplate.FuncShape shape,
                         List<CAST.Declarator> typeArguments) {
        if (!(lambda.source() instanceof LambdaExpressionTree lambdaTree)) {
            // Internal: every Lambda built by translateArgument carries its source tree.
            // If this is null we have no way to do capture analysis safely.
            logError(methodPath.leaf(), "Internal: lambda promotion requires source tree (argument "
                    + (argIndex + 1) + ")");
            return null;
        }
        if (!checkLambdaCaptures(lambdaTree)) {
            return null;
        }
        var enclosingMethodName = methodPath.leaf().getName().toString();
        var name = "__bpf_lambda_" + enclosingMethodName + "_" + (syntheticLambdaCounter++);

        // Resolve the ctx param name (user may have called one of their lambda params
        // "ctx" — rename ours to avoid the collision). Used by both shapes.
        boolean clash = lambda.parameters().stream()
                .anyMatch(p -> p.name() != null && "ctx".equals(p.name().name()));
        var ctxName = clash ? "__ctx" : "ctx";

        // Translate the lambda body into a list of statements. For an expression-form
        // lambda `(...) -> expr`, the single ExpressionStatement is turned into a
        // ReturnStatement so the lifted C function returns the value (this is opposite
        // to inline `$lambdaN:code` callers, which expand the expression in-place).
        List<Statement> bodyStatements = new ArrayList<>(lambda.code().statements());
        if (lambdaTree.getBodyKind() == LambdaExpressionTree.BodyKind.EXPRESSION) {
            if (bodyStatements.size() == 1 && bodyStatements.get(0) instanceof ExpressionStatement es) {
                bodyStatements = new ArrayList<>(List.of(new ReturnStatement(es.expression())));
            }
        }

        List<FunctionParameter> params;
        VerbatimFunctionDeclarator verbatimHeader = null;
        if (shape == MethodTemplate.FuncShape.MAPELEM) {
            // libbpf bpf_for_each_map_elem expects:
            //   long (*cb)(struct bpf_map *map, const void *key, void *value, void *ctx)
            // The user writes `(k, v) -> ...` so we generate
            //   (struct bpf_map *__map, const void *__key, void *__value, void *ctx)
            // and prepend
            //   <KType> k = *(<KType> *)__key;
            //   <VType> v = *(<VType> *)__value;
            // so the user's body sees plain `k`/`v` of the right types.
            if (lambda.parameters().size() != 2) {
                logError(methodPath.leaf(), "Map.forEach lambda must have exactly two parameters (key, value), got "
                        + lambda.parameters().size());
                return null;
            }
            var keyParam = lambda.parameters().get(0);
            var valueParam = lambda.parameters().get(1);
            var keyName = keyParam.name() != null ? keyParam.name().name() : "k";
            var valueName = valueParam.name() != null ? valueParam.name().name() : "v";
            var keyTypeStr = keyParam.declarator().toPrettyString();
            var valueTypeStr = valueParam.declarator().toPrettyString();
            var prologue = List.<Statement>of(
                    new VerbatimStatement(keyTypeStr + " " + keyName + " = *((" + keyTypeStr + " *)__key);"),
                    new VerbatimStatement(valueTypeStr + " " + valueName + " = *((" + valueTypeStr + " *)__value);")
            );
            var newBody = new ArrayList<Statement>(prologue);
            newBody.addAll(bodyStatements);
            bodyStatements = newBody;
            verbatimHeader = new VerbatimFunctionDeclarator(
                    "static __always_inline int " + name +
                            "(struct bpf_map *__map, const void *__key, void *__value, void *" + ctxName + ")");
            params = null;
        } else {
            // PLAIN shape: emit lambda parameters verbatim. The user's lambda already
            // includes the ctx parameter (e.g. `(i, ctx) -> ...` for bpf_loop). The
            // libbpf ABI demands the LAST parameter be `void *`, but inferred lambda
            // parameter types come back as `Object` (erasure of the generic ctx type
            // parameter), so without help we'd end up with `void *st` and the body's
            // `st.val()` accesses won't compile.
            //
            // Workaround: if the call provided an explicit type argument
            // (e.g. `BPFJ.<Ptr<State>>bpfLoop(...)`), use that to type the ctx and
            // prepend a cast prologue:
            //   <UserType> st = (<UserType>)__libbpf_ctx;
            // so the user's body sees the typed value directly. Without an explicit
            // type argument we keep the legacy behaviour (last param → `void *` named
            // as the user wrote it).
            var pl = new ArrayList<>(lambda.parameters());
            if (!pl.isEmpty()) {
                var last = pl.getLast();
                if (last.name() != null) {
                    String currentType = last.declarator().toPrettyString().trim();
                    boolean lastIsVoidPtr = "void *".equals(currentType) || "void*".equals(currentType);
                    boolean haveCtxTypeArg = typeArguments != null && !typeArguments.isEmpty()
                            && typeArguments.getLast() != null;
                    // libbpf's callback ABI is `void *ctx` — emit that as the C parameter, then
                    // recover the user's typed name with a cast prologue at function entry.
                    // We have a real type if either (a) translateLambdaParameters resolved one
                    // via the AST (currentType != "void *"), or (b) the call provided an
                    // explicit type argument like `BPFJ.<Ptr<State>>bpfLoop(...)`.
                    String userType = !lastIsVoidPtr ? currentType
                            : haveCtxTypeArg ? typeArguments.getLast().toPrettyString()
                            : null;
                    if (userType != null) {
                        String userName = last.name().name();
                        var prologue = new VerbatimStatement(
                                userType + " " + userName + " = (" + userType + ")__libbpf_ctx;");
                        var newBody = new ArrayList<Statement>();
                        newBody.add(prologue);
                        newBody.addAll(bodyStatements);
                        bodyStatements = newBody;
                        pl.set(pl.size() - 1, new FunctionParameter(
                                CAST.Expression.variable("__libbpf_ctx"),
                                Declarator.pointer(Declarator.identifier("void"))));
                    }
                    // No type witness available: leave the parameter as `void *<userName>` —
                    // the user wrote `(i, c) -> ...` with no use of `c`, so the body doesn't
                    // need a typed view. (The legacy behaviour.)
                }
            }
            params = pl;
        }

        boolean endsWithReturn = !bodyStatements.isEmpty()
                && (bodyStatements.getLast() instanceof ReturnStatement
                    || (bodyStatements.getLast() instanceof VerbatimStatement vs
                        && vs.code().trim().startsWith("return")));
        if (!endsWithReturn) {
            bodyStatements.add(new VerbatimStatement("return 0;"));
        }
        VerbatimFunctionDeclarator inlinedHeader;
        if (verbatimHeader != null) {
            inlinedHeader = verbatimHeader;
        } else {
            var declarator = new FunctionDeclarator(variable(name),
                    Declarator.identifier("int"), params);
            // Wrap with `static __always_inline` so the verifier inlines the call site
            // (libbpf otherwise rejects indirect calls under most program types).
            inlinedHeader = new VerbatimFunctionDeclarator("static __always_inline " +
                    declarator.toPrettyString());
        }
        var inlinedFn = new FunctionDeclarationStatement(inlinedHeader,
                new CompoundStatement(bodyStatements));
        syntheticFunctions.add(inlinedFn);
        return name;
    }

    /**
     * Reject captures of locals defined outside the lambda. The user must use the
     * {@code ctx} parameter to thread state into a function-pointer-style callback.
     * Allowed: lambda params, locals defined inside the lambda body, fields (incl.
     * static), method references via {@code this}, type names.
     *
     * @return {@code true} if all references are legal, {@code false} if a capture
     *         was reported (caller should not promote).
     */
    private boolean checkLambdaCaptures(LambdaExpressionTree lambdaTree) {
        // Collect element references to locals/parameters that resolve to symbols
        // declared OUTSIDE the lambda subtree. We use Trees.getElement() per identifier
        // and inspect the enclosing element of the symbol.
        var trees = compilerPlugin.trees;
        var lambdaPath = methodPath.path(lambdaTree);
        // Set of parameter elements declared by THIS lambda; references to these are fine.
        Set<Element> lambdaParamElements = new HashSet<>();
        for (var p : lambdaTree.getParameters()) {
            var elPath = methodPath.path(p);
            var el = elPath == null ? null : trees.getElement(elPath);
            if (el != null) lambdaParamElements.add(el);
        }
        boolean[] hadIllegal = {false};
        // Collect elements declared inside the lambda body (locals declared in the lambda body)
        Set<Element> bodyDeclared = new HashSet<>();
        if (lambdaTree.getBody() instanceof Tree bodyTree) {
            new TreeScanner<Void, Void>() {
                @Override
                public Void visitVariable(VariableTree node, Void ignored) {
                    var elPath = TreePath.getPath(lambdaPath, node);
                    if (elPath != null) {
                        var el = trees.getElement(elPath);
                        if (el != null) bodyDeclared.add(el);
                    }
                    return super.visitVariable(node, ignored);
                }
            }.scan(bodyTree, null);
        }

        new TreeScanner<Void, Void>() {
            @Override
            public Void visitIdentifier(IdentifierTree node, Void ignored) {
                var idPath = TreePath.getPath(lambdaPath, node);
                if (idPath == null) return super.visitIdentifier(node, ignored);
                var el = trees.getElement(idPath);
                if (el == null) return super.visitIdentifier(node, ignored);
                var kind = el.getKind();
                // We only care about locals/parameters; fields, methods, types are fine.
                if (kind != ElementKind.LOCAL_VARIABLE && kind != ElementKind.PARAMETER) {
                    return super.visitIdentifier(node, ignored);
                }
                if (lambdaParamElements.contains(el) || bodyDeclared.contains(el)) {
                    return super.visitIdentifier(node, ignored);
                }
                // Capture detected.
                logError(node, "Lambda passed to a function-pointer-style BPF helper "
                        + "captures local variable '" + node.getName()
                        + "' from the enclosing method. The kernel verifier requires the lambda "
                        + "to compile to a standalone C function, so captures of locals are not "
                        + "supported. Pass state via the `ctx` parameter instead.");
                hadIllegal[0] = true;
                return super.visitIdentifier(node, ignored);
            }
        }.scan(lambdaTree.getBody(), null);
        return !hadIllegal[0];
    }

    // ───────────────────────── CO-RE (Phase E) ─────────────────────────

    /**
     * Returns true if {@code typeMirror} (or, after unwrapping a single
     * {@code Ptr<T>} layer, its argument) refers to a class that bpf-gen
     * marked with {@code @KernelBTF}. These are the kernel-BTF types whose
     * field offsets must be relocated by libbpf at load time.
     */
    private boolean isKernelBtfType(@Nullable TypeMirror typeMirror) {
        if (typeMirror == null) return false;
        if (!(typeMirror instanceof Type t)) return false;
        // Unwrap Ptr<T> → T
        if (t instanceof ClassType ct
                && ct.asElement().getQualifiedName().contentEquals(Ptr.class.getName())
                && !ct.getTypeArguments().isEmpty()) {
            t = (Type) ct.getTypeArguments().get(0);
        }
        var elem = t.asElement();
        if (elem == null) return false;
        return elem.getAnnotation(me.bechberger.ebpf.annotations.KernelBTF.class) != null;
    }

    /** Type of the given expression in this method's tree. */
    private @Nullable TypeMirror typeOf(ExpressionTree expr) {
        var path = methodPath.path(expr);
        if (path == null) return null;
        var trees = compilerPlugin.trees;
        return trees.getTypeMirror(path);
    }

    /**
     * Detect whether {@code outer}'s parent is itself a kernel-BTF
     * MemberSelectTree. If so, the parent will perform the lift; this node
     * must not.
     */
    private boolean parentIsKernelBtfMemberSelect(MemberSelectTree outer) {
        var path = methodPath.path(outer);
        if (path == null) return false;
        var parent = path.getParentPath();
        if (parent == null) return false;
        var parentLeaf = parent.getLeaf();
        if (!(parentLeaf instanceof MemberSelectTree pmst)) return false;
        // Sanity: this node must actually be the parent's expression
        // (not, e.g., the parent's identifier — identifiers aren't ExpressionTrees here anyway).
        if (pmst.getExpression() != outer) return false;
        return isKernelBtfType(typeOf(pmst.getExpression()));
    }

    /**
     * If {@code top} is the outermost link of a kernel-BTF field-access chain,
     * walk inward and emit {@code BPF_CORE_READ(rootExpr, m1, m2, ...)}.
     * Returns null if the chain doesn't qualify (e.g., receiver isn't a
     * kernel-BTF type, or this isn't the outermost link).
     */
    /**
     * Detect whether {@code outer}'s parent is a {@code Ptr.val()} method
     * invocation that is itself nested inside a kernel-BTF MemberSelect chain.
     * In that case, an outer lift will fold the whole chain; this node must
     * not lift on its own.
     */
    private boolean parentIsKernelBtfPtrValCall(MemberSelectTree outer) {
        var path = methodPath.path(outer);
        if (path == null) return false;
        var parent = path.getParentPath();
        if (parent == null) return false;
        var parentLeaf = parent.getLeaf();
        // The .val() shape: MethodInvocation whose select is MemberSelect(.val)
        // and whose receiver is `outer`.
        if (!(parentLeaf instanceof MethodInvocationTree mit)) return false;
        if (!mit.getArguments().isEmpty()) return false;
        if (!(mit.getMethodSelect() instanceof MemberSelectTree pmst)) return false;
        if (pmst.getExpression() != outer) return false;
        if (!"val".contentEquals(pmst.getIdentifier())) return false;
        // Now check the grandparent: is the .val() result fed into another
        // kernel-BTF MemberSelect?
        var grand = parent.getParentPath();
        if (grand == null) return false;
        var grandLeaf = grand.getLeaf();
        if (!(grandLeaf instanceof MemberSelectTree gmst)) return false;
        if (gmst.getExpression() != mit) return false;
        return isKernelBtfType(typeOf(gmst.getExpression()));
    }

    private @Nullable CAST.Expression tryLiftCoreRead(MemberSelectTree top) {
        // Only the outermost kernel-BTF MemberSelect performs the lift.
        if (parentIsKernelBtfMemberSelect(top) || parentIsKernelBtfPtrValCall(top)) return null;
        if (!isKernelBtfType(typeOf(top.getExpression()))) return null;

        // Walk inward, prepending member names. The chain may interleave
        // MemberSelect(.field) and MethodInvocation(.val()) when intermediate
        // fields are Ptr<KernelBTF> or embedded struct values.
        //
        // BPF_CORE_READ(src, a, b, c) walks pointers: each comma-separated
        // accessor follows a pointer deref. Embedded-struct field accesses
        // (no Ptr in between) must be joined with '.' inside a single
        // accessor segment.
        //
        // We collect a list of segments, each built from one or more
        // consecutive .field accesses without an intervening .val() pierce.
        // A .val() pierce closes the current segment.
        var segments = new ArrayList<List<String>>();
        var currentSegment = new ArrayList<String>();
        segments.add(0, currentSegment);
        ExpressionTree cursor = top;
        while (true) {
            if (cursor instanceof MemberSelectTree mst
                    && isKernelBtfType(typeOf(mst.getExpression()))) {
                currentSegment.add(0, mst.getIdentifier().toString());
                cursor = mst.getExpression();
                continue;
            }
            // Pierce a `.val()` call iff its receiver is a Ptr<KernelBTF>
            // chain we can keep walking. Each pierce closes the segment.
            ExpressionTree pierced = stripPtrVal(cursor);
            if (pierced != cursor && isKernelBtfType(typeOf(pierced))) {
                cursor = pierced;
                currentSegment = new ArrayList<>();
                segments.add(0, currentSegment);
                continue;
            }
            break;
        }
        // The leading segment may be empty if the very innermost step was a
        // .val() (e.g., bare `task.val()` with no further field). Drop it —
        // BPF_CORE_READ requires at least one trailing accessor segment.
        while (!segments.isEmpty() && segments.get(0).isEmpty()) {
            segments.remove(0);
        }
        if (segments.isEmpty()) return null;

        // The chain root is whatever expression remains. BPF_CORE_READ wants
        // a *pointer*, so when the root is foo.val(), strip val() to get foo.
        ExpressionTree rootTree = stripPtrVal(cursor);
        var rootExpr = translate(rootTree);
        if (rootExpr == null) return null;

        var sb = new StringBuilder();
        // BPF_CORE_READ wraps the source expression in
        // __builtin_preserve_access_index, which records a CO-RE relocation
        // for *every* field access inside it. If the root is a non-trivial
        // expression like `userStruct.kernelPtr`, the user-side
        // `userStruct.kernelPtr` access generates a bogus relocation against
        // the user struct (whose BTF doesn't exist in vmlinux). To prevent
        // that, bind the root to a local first using a statement-expression,
        // then call BPF_CORE_READ with the bare local.
        boolean rootIsTrivial = rootTree instanceof IdentifierTree;
        if (!rootIsTrivial) {
            sb.append("({ typeof(").append(rootExpr.toPrettyString()).append(") __core_root = ")
                    .append(rootExpr.toPrettyString()).append("; BPF_CORE_READ(__core_root");
        } else {
            sb.append("BPF_CORE_READ(").append(rootExpr.toPrettyString());
        }
        for (List<String> seg : segments) {
            sb.append(", ");
            for (int i = 0; i < seg.size(); i++) {
                if (i > 0) sb.append('.');
                sb.append(seg.get(i));
            }
        }
        if (!rootIsTrivial) {
            sb.append("); })");
        } else {
            sb.append(")");
        }
        return CAST.Expression.verbatim(sb.toString());
    }

    /**
     * If {@code expr} is a {@code Ptr.val()} method invocation, return the
     * receiver of {@code val()}. Otherwise return {@code expr} unchanged.
     * Used to recover the pointer from the canonical {@code p.val().field}
     * form before passing it to {@code BPF_CORE_READ}.
     */
    private ExpressionTree stripPtrVal(ExpressionTree expr) {
        if (!(expr instanceof MethodInvocationTree mit)) return expr;
        if (!mit.getArguments().isEmpty()) return expr;
        if (!(mit.getMethodSelect() instanceof MemberSelectTree mst)) return expr;
        if (!"val".contentEquals(mst.getIdentifier())) return expr;
        // Confirm the receiver type is Ptr<...>
        var recvType = typeOf(mst.getExpression());
        if (recvType instanceof ClassType ct
                && ct.asElement().getQualifiedName().contentEquals(Ptr.class.getName())) {
            return mst.getExpression();
        }
        return expr;
    }
}
