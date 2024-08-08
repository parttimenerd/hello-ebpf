package me.bechberger.ebpf.bpf.compiler;

import com.sun.source.tree.*;
import com.sun.source.util.*;
import com.sun.source.util.TaskEvent.Kind;
import com.sun.tools.javac.api.BasicJavacTask;
import com.sun.tools.javac.code.Symbol.MethodSymbol;
import com.sun.tools.javac.code.Symbol.TypeSymbol;
import com.sun.tools.javac.code.Type;
import com.sun.tools.javac.code.Type.MethodType;
import com.sun.tools.javac.code.Types;
import com.sun.tools.javac.processing.JavacProcessingEnvironment;
import com.sun.tools.javac.tree.JCTree;
import com.sun.tools.javac.tree.JCTree.*;
import com.sun.tools.javac.tree.TreeMaker;
import com.sun.tools.javac.util.Log;
import com.sun.tools.javac.util.Names;
import jdk.jshell.execution.Util;
import me.bechberger.cast.CAST.Expression;
import me.bechberger.cast.CAST.Operator;
import me.bechberger.cast.CAST.OperatorExpression;
import me.bechberger.cast.CAST.Statement;
import me.bechberger.cast.CAST.Statement.CompoundStatement;
import me.bechberger.cast.CAST.Statement.Define;
import me.bechberger.cast.CAST.Statement.FunctionDeclarationStatement;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFImpl;
import me.bechberger.ebpf.bpf.processor.Processor;
import me.bechberger.ebpf.type.TypeUtils;
import org.jetbrains.annotations.Nullable;

import javax.annotation.processing.ProcessingEnvironment;
import javax.lang.model.element.Modifier;
import javax.lang.model.element.TypeElement;
import javax.lang.model.type.DeclaredType;
import javax.lang.model.type.TypeMirror;
import javax.tools.Diagnostic;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.function.BiFunction;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static me.bechberger.ebpf.bpf.compiler.NullHelpers.callIfNonNull;

/**
 * Plugin to process the inner code of {@link BPFFunction} annotated methods
 * in BPF programs already processed by the {@link Processor}
 */
public class CompilerPlugin implements Plugin {

    Log logger;
    JavacTask task;
    TypeUtils typeUtils;
    Trees trees;
    TreeMaker treeMaker;
    Names names;
    MethodTemplateCache methodTemplateCache;
    Types types;

    private final Map<MethodType, FuncDeclStatementResult> methodElementToCode = new HashMap<>();
    private final Map<Type.ClassType, Integer> classToMethodCountToImplement = new HashMap<>();

    @Override
    public String getName() {
        return "BPFCompilerPlugin";
    }

    private boolean hasAnnotation(TreePath path, ModifiersTree modifiersTree, Class<?> annotation) {
        return modifiersTree.getAnnotations().stream().anyMatch(a -> isSameType(path, a.getAnnotationType(),
                annotation));
    }

    /**
     * Gets all methods in the class that are annotated with {@link BPFFunction}
     */
    private List<TypedTreePath<MethodTree>> getBPFFunctionsForClass(CompilationUnitTree tree) {
        return Objects.requireNonNullElse(tree.accept(new PathCollectingScanner<MethodTree>(tree) {

                                                          @Override
                                                          public List<TypedTreePath<MethodTree>> visitClass(ClassTree node, Object o) {
                                                              return super.visitClass(node, o);
                                                          }

                                                          @Override
                                                          public List<TypedTreePath<MethodTree>> visitMethod(MethodTree node, Object o) {
                                                              return visitWrapped(node, (path, methodTree) -> {
                                                                  if (shouldProcessMethod(new TypedTreePath<>(path))) {
                                                                      classToMethodCountToImplement.merge((Type.ClassType) trees.getTypeMirror(path.getParentPath()), 1, Integer::sum);
                                                                      List<TypedTreePath<MethodTree>> usedMethods = new ArrayList<>();
                                                                      usedMethods.add(new TypedTreePath<>(path));
                                                                      super.visitMethod(methodTree, o);
                                                                      return usedMethods;
                                                                  }
                                                                  return Collections.emptyList();
                                                              });
                                                          }

                                                          @Override
                                                          public List<TypedTreePath<MethodTree>> visitMethodInvocation(MethodInvocationTree node, Object p) {
                                                              var calledMethod = node.getMethodSelect();
                                                              var methodTree = (JCMethodInvocation) node;
                                                              MethodSymbol symbol = switch (methodTree.meth) {
                                                                  case JCFieldAccess access -> (MethodSymbol) access.sym;
                                                                  case JCIdent ident -> (MethodSymbol) ident.sym;
                                                                  default -> null;
                                                              };
                                                              if (symbol != null && symbol.getAnnotation(BPFFunction.class) != null) {
                                                                  // problem: method might be compiled, therefore no
                                                                  // tree available
                                                                  // possible solution: for every method that we process, add
                                                                  // an annotation with the code
                                                                  // then capture the annotations here
                                                                  // problem transitive: this method might call another method
                                                                  // so this annotation should also contain the name/method/signature of all
                                                                  // called methods -> transitive hull is added here then
                                                                  // + stored code and header
                                                                  //return List.of(new TypedTreePath<>(curPath));
                                                              }
                                                              return List.of();
                                                          }
                                                      }
                , null), Collections.emptyList());
    }

    private List<TypedTreePath<ClassTree>> getBPFProgramImpls(CompilationUnitTree compilationUnitTree) {
        return Objects.requireNonNullElse(compilationUnitTree.accept(new PathCollectingScanner<ClassTree>(compilationUnitTree) {
            @Override
            public List<TypedTreePath<ClassTree>> visitClass(ClassTree node, Object ignored) {
                return visitWrapped(node, (path, classTree) -> {
                    var result = super.visitClass(classTree, ignored);
                    if (hasAnnotation(path, classTree.getModifiers(), BPFImpl.class)) {
                        return reduce(List.of(new TypedTreePath<>(path)), result);
                    }
                    return result;
                });
            }
        }, null), Collections.emptyList());
    }

    public record TypedTreePath<T extends Tree>(TreePath path) {

        @Override
        public TreePath path() {
            return path;
        }

        @SuppressWarnings("unchecked")
        T leaf() {
            return (T) path.getLeaf();
        }

        TreePath path(Tree subPath) {
            return TreePath.getPath(path, subPath);
        }

        CompilationUnitTree root() {
            return path.getCompilationUnit();
        }
    }

    @Override
    public void init(JavacTask task, String... args) {
        var context = ((BasicJavacTask) task).getContext();
        this.logger = Log.instance(context);
        this.task = task;
        this.typeUtils = new TypeUtils(task.getTypes(), task.getElements());
        this.trees = Trees.instance(task);
        this.treeMaker = TreeMaker.instance(context);
        this.names = Names.instance(context);
        this.methodTemplateCache = new MethodTemplateCache(this);
        this.types = Types.instance(context);
        var types = task.getTypes();
        List<CompilerPlugin.TypedTreePath<MethodTree>> funcs = new ArrayList<>();
        task.addTaskListener(new TaskListener() {

            @Override
            public void finished(TaskEvent e) {
                if (e.getKind() == Kind.PARSE) {
                    e.getCompilationUnit().accept(new TreeScanner<>() {
                        @Override
                        public Object visitMethod(MethodTree node, Object o) {
                            return super.visitMethod(node, o);
                        }
                    }, null);
                    return;
                }
                if (e.getKind() != TaskEvent.Kind.ANALYZE) { // we do need all information
                    return;
                }
                funcs.addAll(getBPFFunctionsForClass(e.getCompilationUnit()));
                var impls = getBPFProgramImpls(e.getCompilationUnit());
                if (impls.isEmpty()) {
                    return;
                }
                funcs.forEach(CompilerPlugin.this::processBPFFunction);
                funcs.clear();
                impls.forEach(CompilerPlugin.this::processBPFProgramImpls);
            }
        });
    }

    private boolean onlyThrowsExceptions(MethodTree method) {
        if (method.getBody() == null) {
            return false;
        }
        if (method.getBody().getStatements().size() != 1) {
            return false;
        }
        return method.getBody().getStatements().getFirst() instanceof ThrowTree;
    }

    private boolean shouldProcessMethod(CompilerPlugin.TypedTreePath<MethodTree> path) {
        var ann = getAnnotationOfMethodOrSuper((MethodSymbol) trees.getElement(path.path()), BPFFunction.class);
        return ann != null &&
                !path.leaf().getModifiers().getFlags().contains(Modifier.ABSTRACT) &&
                path.leaf().getBody() != null &&
                !onlyThrowsExceptions(path.leaf());
    }

    @Nullable
    <T extends Annotation> T getAnnotationOfMethodOrSuper(MethodSymbol method, Class<T> annotation) {
        if (method.getAnnotation(annotation) != null) {
            return method.getAnnotation(annotation);
        }

        var parentMethod = method.implemented((TypeSymbol) method.getEnclosingElement(), types);
        if (parentMethod == null) {
            return null;
        }
        return parentMethod.getAnnotation(annotation);
    }

    void logError(TypedTreePath<?> path, Tree element, String message) {
        createProcessingEnvironment().getMessager().printMessage(Diagnostic.Kind.ERROR, message,
                trees.getElement(path.path(element)));
    }

    /**
     * Process a BPFFunction and store its code in a field named {@code BPF_FUNCTION_CODE_$NAME}
     * <p>
     * Fills the {@link #methodElementToCode} map with the method and its code too
     */
    private boolean processBPFFunction(CompilerPlugin.TypedTreePath<MethodTree> path) {
        var function = path.leaf();
        assert shouldProcessMethod(path);
        logger.printRawLines("Processing BPFFunction " + function);
        // we could have two cases:
        // 1. the method body only consists of String assignment followed by a throw;
        //    then we can just use the string
        // 2. else, then we need to process the method body and generate the code
        var method = (MethodType) trees.getElement(path.path()).asType();
        var kind = getFunctionKind(path);
        if (kind == FunctionKind.ERROR) {
            return false;
        }
        var code = kind == FunctionKind.RAW ?
                processBPFFunctionWithAssignment(path) :
                processBPFFunctionWithCode(path);
        if (code == null) {
            // log error
            logError(path, function, "Error processing BPFFunction " + function);
            return false;
        }
        methodElementToCode.put(method, code);
        return true;
    }

    private TypeMirror getTypeMirror(CompilerPlugin.TypedTreePath<?> path, Tree typeTree) {
        return task.getTypeMirror(path.path(typeTree));
    }

    private TypeMirror getTypeMirror(TreePath path, Tree typeTree) {
        return trees.getTypeMirror(new TreePath(path, typeTree));
    }


    boolean isSameType(TypedTreePath<?> methodPath, Tree typeTree, Class<?> type) {
        return isSameType(methodPath.path(), typeTree, type);
    }

    private boolean isSameType(TreePath path, Tree typeTree, Class<?> type) {
        return task.getTypes().isSameType(getTypeMirror(path, typeTree), typeUtils.getTypeMirror(type));
    }

    enum FunctionKind {
        FUNCTION,
        RAW,
        ERROR
    }

    private FunctionKind getFunctionKind(TypedTreePath<MethodTree> methodPath) {
        var function = methodPath.leaf();
        var statements = function.getBody().getStatements();
        if (statements.size() != 2) {
            return FunctionKind.FUNCTION;
        }
        if (!(statements.get(1) instanceof ThrowTree)) {
            return FunctionKind.FUNCTION;
        }
        if (statements.getFirst() instanceof JCVariableDecl declStatement) {
            if (declStatement.init instanceof JCLiteral literal && isSameType(methodPath, declStatement.getType(),
                    String.class)) {
                return FunctionKind.RAW;
            }
        }
        logError(methodPath, function, "Raw method body must consist of a single string variable assignment and a " +
                "throw");
        return FunctionKind.ERROR;
    }

    private @Nullable FuncDeclStatementResult processBPFFunctionWithAssignment(TypedTreePath<MethodTree> function) {
        var variableDecl = (JCVariableDecl) function.leaf().getBody().getStatements().getFirst();
        var literal = (JCLiteral) variableDecl.init;
        var code = literal.getValue().toString();
        Translator translator = new Translator(this, function);
        var decl = translator.translateIgnoringBody();
        if (decl == null) {
            return null;
        }
        var newBody = new ArrayList<Statement>(decl.body().statements());
        newBody.addFirst(Statement.verbatim(code));
        return new FuncDeclStatementResult(
                new FunctionDeclarationStatement(decl.declarator(), new CompoundStatement(newBody),
                        decl.annotations()), Set.of());
    }

    record FuncDeclStatementResult(FunctionDeclarationStatement decl, Set<Define> requiredDefines) {
    }

    private @Nullable FuncDeclStatementResult processBPFFunctionWithCode(TypedTreePath<MethodTree> methodPath) {
        var translator = new Translator(this, methodPath);
        return callIfNonNull(translator.translate(), decl -> {
            var requiredDefines = translator.getRequiredDefines();
            return new FuncDeclStatementResult(decl, requiredDefines);
        });
    }

    private void processBPFProgramImpls(TypedTreePath<ClassTree> programPath) {
        var bpfProgram = programPath.leaf();
        var bpfProgramTypeElement = (TypeElement) trees.getElement(programPath.path);
        logger.printRawLines("Processing BPF program " + bpfProgram.getSimpleName());
        // now get all BPFFunctions in the class (and its superclasses)
        // but only include the ones that are actually implemented
        // and don't just throw an exception
        if (bpfProgram.getExtendsClause() == null) {
            throw new IllegalStateException("BPF program implementation must extend a class");
        }
        var superClassType = bpfProgramTypeElement.getSuperclass();

        if (!(superClassType instanceof DeclaredType declaredSuperClass)) {
            throw new AssertionError("Superclass must be a declared type for " + bpfProgram.getSimpleName());
        }
        TypeElement superClassElement = (TypeElement) declaredSuperClass.asElement();

        var methods = task.getElements().getAllMembers(superClassElement).stream()
                .filter(m -> m instanceof MethodSymbol)
                .toList();

        var toImplement = classToMethodCountToImplement.get((Type.ClassType) superClassType);

        if (toImplement == null) {
            return;
        }

        if (methods.isEmpty()) {
            return; // we don't have to do anything
        }

        var declsWithDefines =
                methods.stream().map(m -> task.getTypes().asMemberOf((DeclaredType) superClassElement.asType(), m))
                .filter(m -> m instanceof MethodType)
                .map(m -> (MethodType) m)
                .map(methodElementToCode::get)
                .filter(Objects::nonNull)
                .toList();

        var defines = declsWithDefines.stream().flatMap(r -> r.requiredDefines().stream()).collect(Collectors.toSet());
        var decls = declsWithDefines.stream().map(FuncDeclStatementResult::decl).toList();

        if (decls.size() < toImplement) {
            logError(programPath, bpfProgram, "Not all methods have been processed");
            return;
        }

        // get value of CODE field in the bpfProgram
        var codeField = getMember(bpfProgram, "CODE");
        var code = (String) ((LiteralTree) codeField.getInitializer()).getValue();
        var newCode = combineCode(code, decls, defines);

        // write the C code in a file close to the source file
        var cFile =
                Path.of(programPath.root().getSourceFile().toUri().getPath()).getParent().resolve(bpfProgram.getSimpleName() + ".c");
        try {
            Files.writeString(cFile, newCode);
        } catch (IOException e) {
            logError(programPath, bpfProgram, "Could not write C code to " + cFile);
        }

        var compiledCode = compile(newCode, cFile);
        // adding fields would be easier, but this doesn't seem to work

        // inline small byte codes and put it in a string
        for (var member : bpfProgram.getMembers()) {
            if (member instanceof JCMethodDecl methodDecl) {
                var name = methodDecl.name;
                if (name.contentEquals("getByteCodeBytesStatic")) {

                    var compiledCodeBytes = compiledCode.encode();

                    // problem: we can't just put the byte code in a string, because it might be too large
                    // solution: split into expressions of 2 << 16 bytes, concatenated
                    // problem: the analysis of the tree already ran, so type and operator of
                    // the binary trees are not set
                    // solution: set them manually by taking them from the return statement

                    var returnStatement = (JCReturn) methodDecl.body.getStatements().getLast();

                    var returnBin = (JCBinary)returnStatement.expr;

                    // split into expressions of 2 << 16 bytes, concatenated
                    var byteCodeString = new ArrayList<JCExpression>();
                    var partSize = 2 << 16;
                    var partNum = (compiledCodeBytes.length() + partSize - 1) / partSize;
                    var parts = IntStream.range(0, partNum).mapToObj(i -> {
                        var start = i * partSize;
                        var end = Math.min((i + 1) * partSize, compiledCodeBytes.length());
                        var part = compiledCodeBytes.substring(start, end);
                        return (JCExpression) treeMaker.Literal(part);
                    }).toList();
                    var concat = parts.stream().reduce((a, b) -> {
                        var bin = treeMaker.Binary(JCTree.Tag.PLUS, a, b);
                        bin.operator = returnBin.operator;
                        bin.type = returnBin.type;
                        return bin;
                    });
                    returnStatement.expr = concat.orElseThrow();
                } else if (name.contentEquals("getCodeStatic")) {
                    ((JCReturn) methodDecl.body.getStatements().getLast()).expr = treeMaker.Literal(newCode);
                } else if (name.contentEquals("getByteCodeResourceName")) {
                    ((JCReturn) methodDecl.body.getStatements().getLast()).expr = null;
                }
            }
        }
    }

    private Processor.CompileResult compile(String code, Path file) {
        return Processor.compileAndEncode(createProcessingEnvironment(), code, file);
    }

    VariableTree getMember(ClassTree klass, String name) {
        return klass.getMembers().stream()
                .filter(m -> m instanceof VariableTree)
                .map(m -> (VariableTree) m)
                .filter(m -> m.getName().contentEquals(name))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(name + " field not found in " + klass.getSimpleName()));
    }

    String combineCode(String code, List<FunctionDeclarationStatement> decls, Set<Define> defines) {
        var requiredDefines = defines.stream().filter(d -> !code.contains(d.toPrettyString()))
                .sorted(Comparator.comparing(Define::name)).toList();
        return Stream.concat(Stream.concat(Stream.of(code),
                                requiredDefines.stream().map(Define::toPrettyString)),
                        decls.stream().map(FunctionDeclarationStatement::toPrettyString))
                .filter(s -> !s.isEmpty()).collect(Collectors.joining("\n\n"));
    }

    ProcessingEnvironment createProcessingEnvironment() {
        return JavacProcessingEnvironment.instance(((BasicJavacTask) task).getContext());
    }

    private static class PathCollectingScanner<T extends Tree> extends TreeScanner<List<TypedTreePath<T>>, Object> {

        private final CompilationUnitTree compilationUnitTree;
        TreePath curPath;

        public PathCollectingScanner(CompilationUnitTree compilationUnitTree) {
            this.compilationUnitTree = compilationUnitTree;
            curPath = null;
        }

        private TreePath createPath(@Nullable TreePath parent, Tree tree) {
            if (parent == null) {
                return TreePath.getPath(compilationUnitTree, tree);
            }
            return new TreePath(parent, tree);
        }

        @Override
        public List<TypedTreePath<T>> visitClass(ClassTree node, Object o) {
            var prevPath = curPath;
            curPath = createPath(curPath, node);
            List<TypedTreePath<T>> result = super.visitClass(node, o);
            curPath = prevPath;
            return result;
        }

        public List<TypedTreePath<T>> visitWrapped(T node, BiFunction<TreePath, T, List<TypedTreePath<T>>> process) {
            var prevPath = curPath;
            curPath = createPath(curPath, node);
            List<TypedTreePath<T>> result = process.apply(curPath, node);
            curPath = prevPath;
            return result;
        }

        @Override
        public List<TypedTreePath<T>> reduce(List<TypedTreePath<T>> r1, List<TypedTreePath<T>> r2) {
            if (r1 == null || r1.isEmpty()) {
                return r2;
            }
            if (r2 == null || r2.isEmpty()) {
                return r1;
            }
            List<TypedTreePath<T>> result = new ArrayList<>(r1);
            result.addAll(r2);
            return result;
        }
    }
}
