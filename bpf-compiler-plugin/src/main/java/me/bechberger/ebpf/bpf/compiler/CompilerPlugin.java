package me.bechberger.ebpf.bpf.compiler;

import com.sun.source.tree.*;
import com.sun.source.util.*;
import com.sun.tools.javac.api.BasicJavacTask;
import com.sun.tools.javac.api.JavacTaskImpl;
import com.sun.tools.javac.code.Attribute;
import com.sun.tools.javac.code.Symbol;
import com.sun.tools.javac.code.Symbol.MethodSymbol;
import com.sun.tools.javac.code.Symbol.TypeSymbol;
import com.sun.tools.javac.code.Type;
import com.sun.tools.javac.code.Type.MethodType;
import com.sun.tools.javac.code.Types;
import com.sun.tools.javac.file.JavacFileManager;
import com.sun.tools.javac.processing.JavacProcessingEnvironment;
import com.sun.tools.javac.tree.JCTree.*;
import com.sun.tools.javac.tree.TreeMaker;
import com.sun.tools.javac.util.Log;
import com.sun.tools.javac.util.Names;
import com.sun.tools.javac.util.Pair;
import me.bechberger.cast.CAST;
import me.bechberger.cast.CAST.Statement;
import me.bechberger.cast.CAST.Statement.CompoundStatement;
import me.bechberger.cast.CAST.Statement.Define;
import me.bechberger.cast.CAST.Statement.FunctionDeclarationStatement;
import me.bechberger.ebpf.annotations.bpf.*;
import me.bechberger.ebpf.annotations.bpf.Properties;
import me.bechberger.ebpf.bpf.processor.AnnotationUtils;
import me.bechberger.ebpf.bpf.processor.Processor;
import me.bechberger.ebpf.bpf.processor.TypeProcessor;
import me.bechberger.ebpf.shared.KernelFeatures;
import me.bechberger.ebpf.shared.Util;
import me.bechberger.ebpf.type.TypeUtils;
import org.jetbrains.annotations.Nullable;

import javax.annotation.processing.ProcessingEnvironment;
import javax.lang.model.element.Modifier;
import javax.lang.model.element.TypeElement;
import javax.lang.model.type.DeclaredType;
import javax.lang.model.type.TypeMirror;
import javax.tools.Diagnostic;
import javax.tools.JavaFileManager;
import javax.tools.StandardLocation;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.stream.Collectors;
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

    /**
     * Field-name → resolved C carrier expression for {@code @BPFAbstraction} fields whose
     * carrier was auto-allocated ({@code <auto>}) or otherwise needed processor-time resolution.
     * Key: {@code "qualifiedClassName.fieldName"}.
     * Populated lazily from the impl class's {@code ABSTRACTION_CARRIERS} field.
     */
    Map<String, String> abstractionFieldCarrierOverrides = new HashMap<>();

    /**
     * dumpC option from {@code -Xplugin:"BPFCompilerPlugin dumpC=true|false|<path>"}.
     * Default "true" (write .c file next to source). Set to "false" to suppress.
     */
    private String dumpCArg = "true";

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
                                                              var sym = switch (methodTree.meth) {
                                                                  case JCFieldAccess access -> access.sym;
                                                                  case JCIdent ident -> ident.sym;
                                                                  default -> null;
                                                              };
                                                              if (!(sym instanceof MethodSymbol)) {
                                                                 return List.of();
                                                              }
                                                              var symbol = (MethodSymbol) sym;
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

    private List<TypedTreePath<ClassTree>> getBPFInterfaces(CompilationUnitTree compilationUnitTree) {
        return Objects.requireNonNullElse(compilationUnitTree.accept(new PathCollectingScanner<ClassTree>(compilationUnitTree) {
            @Override
            public List<TypedTreePath<ClassTree>> visitClass(ClassTree node, Object ignored) {
                return visitWrapped(node, (path, classTree) -> {
                    var result = super.visitClass(classTree, ignored);
                    if (hasAnnotation(path, classTree.getModifiers(), BPFInterface.class)) {
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
        // Parse plugin args: dumpC=true|false|<path>
        for (String arg : args) {
            if (arg.startsWith("dumpC=")) {
                this.dumpCArg = arg.substring("dumpC=".length());
            }
        }
        var types = task.getTypes();
        List<CompilerPlugin.TypedTreePath<MethodTree>> funcs = new ArrayList<>();
        task.addTaskListener(new TaskListener() {

            @Override
            public void finished(TaskEvent e) {
                if (e.getKind() != TaskEvent.Kind.ANALYZE) { // we do need all information
                    return;
                }
                e.getCompilationUnit().accept(new TreeScanner<Void, Void>() {
                    @Override
                    public Void visitLambdaExpression(LambdaExpressionTree node, Void unused) {
                        // This is the original lambda
                        System.out.println("Found lambda: " + node);
                        System.out.println("Body: " + node.getBody());
                        System.out.println("Parameters: " + node.getParameters());
                        return super.visitLambdaExpression(node, unused);
                    }
                }, null);
                funcs.addAll(getBPFFunctionsForClass(e.getCompilationUnit()));
                var impls = getBPFProgramImpls(e.getCompilationUnit());
                var interfaces = getBPFInterfaces(e.getCompilationUnit());
                if (impls.isEmpty() && interfaces.isEmpty() && funcs.isEmpty()) {
                    return;
                }
                funcs.forEach(CompilerPlugin.this::processBPFFunction);
                funcs.clear();
                interfaces.forEach(CompilerPlugin.this::processBPFInterface);
                impls.forEach(CompilerPlugin.this::processBPFProgramImpl);
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
        var ann = getEffectiveBPFFunction((MethodSymbol) trees.getElement(path.path()));
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

    /**
     * Returns the effective {@link BPFFunction} for a method, synthesizing one from
     * shorthand attach annotations ({@link Kprobe}, {@link Kretprobe}, {@link Fentry},
     * {@link Fexit}, {@link RawTracepoint}, {@link Tracepoint}, {@link Ksyscall}) when
     * {@link BPFFunction} itself is absent.
     */
    @Nullable
    BPFFunction getEffectiveBPFFunction(MethodSymbol method) {
        var direct = getAnnotationOfMethodOrSuper(method, BPFFunction.class);
        if (direct != null) return direct;
        return synthesizeBPFFunction(method);
    }

    /** Synthesises a {@link BPFFunction} proxy from a shorthand attach annotation, or null. */
    @Nullable
    private BPFFunction synthesizeBPFFunction(MethodSymbol method) {
        String section = null;
        String headerTemplate = "$name";
        String lastStatement = "";

        var kprobe = getAnnotationOfMethodOrSuper(method, Kprobe.class);
        if (kprobe != null) { section = "kprobe/" + kprobe.value(); }

        var kretprobe = getAnnotationOfMethodOrSuper(method, Kretprobe.class);
        if (kretprobe != null) { section = "kretprobe/" + kretprobe.value(); }

        var fentry = getAnnotationOfMethodOrSuper(method, Fentry.class);
        if (fentry != null) { section = "fentry/" + fentry.value(); }

        var fexit = getAnnotationOfMethodOrSuper(method, Fexit.class);
        if (fexit != null) { section = "fexit/" + fexit.value(); }

        var rawTp = getAnnotationOfMethodOrSuper(method, RawTracepoint.class);
        if (rawTp != null) {
            section = "raw_tracepoint/" + rawTp.value();
            headerTemplate = "int BPF_PROG($name, $params)";
            lastStatement = "return 0;";
        }

        var tp = getAnnotationOfMethodOrSuper(method, Tracepoint.class);
        if (tp != null) {
            section = "tp/" + tp.category() + "/" + tp.name();
            headerTemplate = "int $name($params)";
        }

        var ksyscall = getAnnotationOfMethodOrSuper(method, Ksyscall.class);
        if (ksyscall != null) { section = "ksyscall/" + ksyscall.value(); }

        var uprobe = getAnnotationOfMethodOrSuper(method, Uprobe.class);
        if (uprobe != null) {
            var ref = uprobe.symbol().isEmpty()
                    ? uprobe.path() + ":" + uprobe.offset()
                    : uprobe.path() + ":" + uprobe.symbol();
            section = "uprobe/" + ref;
        }

        var uretprobe = getAnnotationOfMethodOrSuper(method, Uretprobe.class);
        if (uretprobe != null) {
            var ref = uretprobe.symbol().isEmpty()
                    ? uretprobe.path() + ":" + uretprobe.offset()
                    : uretprobe.path() + ":" + uretprobe.symbol();
            section = "uretprobe/" + ref;
        }

        var lsm = getAnnotationOfMethodOrSuper(method, LSM.class);
        if (lsm != null) {
            section = "lsm/" + lsm.value();
            headerTemplate = "int BPF_PROG($name, $params)";
            // Do NOT set lastStatement: LSM hooks use their return value as the security
            // decision; replacing explicit returns with "return 0;" would silently eat denials.
        }

        if (section == null) return null;

        final String finalSection = section;
        final String finalHeaderTemplate = headerTemplate;
        final String finalLastStatement = lastStatement;
        return (BPFFunction) Proxy.newProxyInstance(
                BPFFunction.class.getClassLoader(),
                new Class[]{BPFFunction.class},
                (proxy, m, args) -> switch (m.getName()) {
                    case "callTemplate" -> "$name";
                    case "headerTemplate" -> finalHeaderTemplate;
                    case "lastStatement" -> finalLastStatement;
                    case "section" -> finalSection;
                    case "autoAttach" -> true;
                    case "name" -> "";
                    case "addDefinition" -> true;
                    case "inline" -> false; // entry points are not inlined
                    case "annotationType" -> BPFFunction.class;
                    default -> m.getDefaultValue();
                });
    }

    void logError(TypedTreePath<?> path, Tree element, String message) {
        var elPath = path.path(element);
        var el = elPath == null ? null : trees.getElement(elPath);
        if (el == null) el = trees.getElement(path.path()); // fall back to enclosing method
        createProcessingEnvironment().getMessager().printMessage(Diagnostic.Kind.ERROR, message, el);
    }

    void logWarning(TypedTreePath<?> path, Tree element, String message) {
        var elPath = path.path(element);
        var el = elPath == null ? null : trees.getElement(elPath);
        if (el == null) el = trees.getElement(path.path()); // fall back to enclosing method
        createProcessingEnvironment().getMessager().printMessage(Diagnostic.Kind.WARNING, message, el);
    }

    /**
     * Process a BPFFunction and store its code in a field named {@code BPF_FUNCTION_CODE_$NAME}
     * <p>
     * Fills the {@link #methodElementToCode} map with the method and its code too
     */
    private boolean processBPFFunction(CompilerPlugin.TypedTreePath<MethodTree> path) {
        var function = path.leaf();
        assert shouldProcessMethod(path);
        logger.printRawLines("Processing BPFFunction " + function.getName());
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
        // Persist code to @InternalMethodDefinition on the method symbol so that downstream
        // compilations (e.g. bpf-samples compiling a subclass of SchedulerBase) can inject
        // these inherited implementations without needing the source in the current unit.
        var methodSymbol = (MethodSymbol) trees.getElement(path.path());
        if (methodSymbol != null && !(methodSymbol.owner instanceof Symbol.ClassSymbol ownerClass && ownerClass.isInterface())) {
            // Prepend any required #define lines so the injected snippet is self-contained.
            var definesPrefix = code.requiredDefines().stream()
                    .map(d -> d.toPrettyString())
                    .collect(java.util.stream.Collectors.joining("\n"));
            var codeStr = definesPrefix.isBlank()
                    ? code.decl.toPrettyString()
                    : definesPrefix + "\n" + code.decl.toPrettyString();
            storeInternalMethodDefinition(methodSymbol, codeStr);
        }
        return true;
    }

    private void storeInternalMethodDefinition(MethodSymbol methodSymbol, String codeStr) {
        try {
            var internalMethodValueSymbol = (Symbol.MethodSymbol) ((Type.ClassType) typeUtils.getTypeMirror(InternalMethodDefinition.class))
                    .asElement().getEnclosedElements().stream()
                    .filter(e -> e instanceof MethodSymbol m && m.getSimpleName().toString().equals("value"))
                    .findFirst().orElseThrow();
            var methodMeta = methodSymbol.getMetadata();
            var methodAttributesField = methodMeta.getClass().getDeclaredField("attributes");
            methodAttributesField.setAccessible(true);
            var methodAttributes = (com.sun.tools.javac.util.List<Attribute>) methodAttributesField.get(methodMeta);
            methodAttributes = methodAttributes.append(new Attribute.Compound(
                    (Type.ClassType) typeUtils.getTypeMirror(InternalMethodDefinition.class),
                    com.sun.tools.javac.util.List.of(new Pair<>(internalMethodValueSymbol,
                            new Attribute.Constant((Type.ClassType) typeUtils.getTypeMirror(String.class), codeStr)))));
            methodAttributesField.set(methodMeta, methodAttributes);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
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
        /** A string field named code and an optional return which is ignored */
        RAW,
        ERROR
    }

    private FunctionKind getFunctionKind(TypedTreePath<MethodTree> methodPath) {
        var function = methodPath.leaf();
        var statements = function.getBody().getStatements();
        if (statements.size() > 2 || statements.isEmpty()) { // surely this is just a function
            return FunctionKind.FUNCTION;
        }
        if (statements.getFirst() instanceof JCVariableDecl declStatement) {
            if (declStatement.init instanceof JCLiteral literal && isSameType(methodPath, declStatement.getType(),
                    String.class) && declStatement.getName().toString().toLowerCase().equals("code")) {
                return FunctionKind.RAW;
            }
        }
        return FunctionKind.FUNCTION;
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
                        decl.annotations()), Set.of(), translator.addDefinition());
    }

    record FuncDeclStatementResult(FunctionDeclarationStatement decl, Set<Define> requiredDefines, boolean addDefine,
                                   List<FunctionDeclarationStatement> syntheticFunctions,
                                   Map<String, String> calledKFuncs) {
        FuncDeclStatementResult(FunctionDeclarationStatement decl, Set<Define> requiredDefines, boolean addDefine) {
            this(decl, requiredDefines, addDefine, List.of(), Map.of());
        }
        FuncDeclStatementResult(FunctionDeclarationStatement decl, Set<Define> requiredDefines, boolean addDefine,
                                List<FunctionDeclarationStatement> syntheticFunctions) {
            this(decl, requiredDefines, addDefine, syntheticFunctions, Map.of());
        }
    }

    private @Nullable FuncDeclStatementResult processBPFFunctionWithCode(TypedTreePath<MethodTree> methodPath) {
        // Shared per-method analysis context — populated by each pass, consumed by Translator.
        var ctx = new me.bechberger.ebpf.bpf.compiler.flow.AnalysisContext();
        new SuppressionScan(ctx).scan(methodPath.leaf());
        new JavaIsmsRejectPass(this, methodPath, ctx).analyze();
        new MapIdiomLintPass(this, methodPath, ctx).analyze();
        new UnboundedLoopPass(this, methodPath, ctx).analyze();
        new ProbeReadSizeZeroPass(this, methodPath, ctx).analyze();
        new MissingCoreReadPass(this, methodPath, ctx).analyze();
        new ConstantPropagator(methodPath, ctx).analyze();
        new RegionAnalyzer(this, methodPath, ctx).analyze();
        new PtrCoercionInference(this, methodPath, ctx).analyze();
        new CaptureAnalyzer(this, methodPath, ctx).analyze();
        new NullabilityAnalyzer(this, methodPath, ctx).analyze();
        new BoundsCheckPass(this, methodPath, ctx).analyze();
        new MapValueIndexBoundsPass(this, methodPath, ctx).analyze();
        new StackBudgetPass(this, methodPath, ctx).analyze();
        new HelperContextPass(this, methodPath, ctx).analyze();
        new ArenaAccessCheckPass(this, methodPath, ctx).analyze();
        var calledKFuncs = new KFuncCollectPass(this, methodPath).analyze();
        var translator = new Translator(this, methodPath, ctx);
        return callIfNonNull(translator.translate(), decl -> {
            var requiredDefines = translator.getRequiredDefines();
            return new FuncDeclStatementResult(decl, requiredDefines, translator.addDefinition(),
                    List.copyOf(translator.getSyntheticFunctions()), calledKFuncs);
        });
    }

    @SuppressWarnings("unchecked")
    private void processBPFInterface(TypedTreePath<ClassTree> programPath) {
        // idea:
        // Collect all method implementations in the interface,
        // then add a new @InternalBody annotation to the interface with the code

        var bpfInterface = programPath.leaf();
        var bpfInterfaceTypeElement = (TypeElement) trees.getElement(programPath.path);
        logger.printRawLines("Processing BPF interface " + bpfInterface.getSimpleName());
        // now get all BPFFunctions in the class (and its superclasses)
        // but only include the ones that are actually implemented
        // and don't just throw an exception
        if (bpfInterface.getExtendsClause() != null) {
            throw new IllegalStateException("BPF interface implementation must not extend another interface");
        }

        var declsWithDefines = task.getElements().getAllMembers(bpfInterfaceTypeElement).stream()
                .filter(m -> m instanceof MethodSymbol)
                .filter(m -> ((MethodSymbol) m).getEnclosingElement().asType().equals(bpfInterfaceTypeElement.asType()))
                .map(m -> Map.entry(m.toString(), task.getTypes().asMemberOf((DeclaredType) bpfInterfaceTypeElement.asType(), (MethodSymbol) m)))
                .filter(e -> e.getValue() instanceof MethodType)
                .map(e -> Map.entry(e.getKey(), (MethodType) e.getValue()))
                .filter(e -> methodElementToCode.containsKey(e.getValue()))
                .map(e -> Map.entry(e.getKey(), methodElementToCode.get(e.getValue())))
                .toList();

        var defines = declsWithDefines.stream().flatMap(e -> e.getValue().requiredDefines().stream()).collect(Collectors.toSet());
        var functionHeaders = declsWithDefines.stream().map(Map.Entry::getValue).filter(d -> d.addDefine).map(d -> d.decl.declarator()).toList();
        var functionImplementations = declsWithDefines.stream().collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue().decl.toPrettyString()));
        // Synthetic lambdas lifted via $funcN belong with the interface body so they're
        // visible to consumers that paste the interface body into their own C code.
        var syntheticFnsCode = declsWithDefines.stream()
                .flatMap(e -> e.getValue().syntheticFunctions().stream())
                .map(CAST::toPrettyString)
                .collect(Collectors.joining("\n\n"));

        var result = new TypeProcessor(this.createProcessingEnvironment()).processBPFTypeRecords(bpfInterfaceTypeElement);
        if (result == null) {
            logError(programPath, bpfInterface, "Error processing BPF interface " + bpfInterface.getSimpleName());
            return;
        }

        // get BPFInterface annotation
        var bpfInterfaceAnnotation = bpfInterfaceTypeElement.getAnnotation(BPFInterface.class);

        var combinedCode = combineCode("", functionHeaders, List.of(), defines, result.definingStatements(), result.mapDefinitions(),
                result.globalVariableDefinitions(), new TypeProcessor.InterfaceAdditions(List.of(), List.of(), List.of()));
        if (!syntheticFnsCode.isBlank()) {
            combinedCode = combinedCode.isBlank() ? syntheticFnsCode : combinedCode + "\n\n" + syntheticFnsCode;
        }

        if (combinedCode.isBlank() && functionImplementations.isEmpty()) {
            return; // nothing changed
        }

        var beforeSymbol = (Symbol.MethodSymbol) ((Type.ClassType)typeUtils.getTypeMirror(InternalBody.class))
                .asElement().getEnclosedElements().stream()
                .filter(e -> e instanceof MethodSymbol m && m.getSimpleName().toString().equals("value"))
                .findFirst().orElseThrow();

        var meta = ((Symbol.ClassSymbol) bpfInterfaceTypeElement).getMetadata();
        Field attributesField;
        try {
            // we have to jump through some hoops to add the annotation
            attributesField = meta.getClass().getDeclaredField("attributes");
            attributesField.setAccessible(true);
            var attributes = (com.sun.tools.javac.util.List<Attribute>)attributesField.get(meta);
            attributes = attributes.append(new Attribute.Compound((Type.ClassType)typeUtils.getTypeMirror(InternalBody.class),
                    com.sun.tools.javac.util.List.of(
                            new Pair<>(beforeSymbol,
                                    new Attribute.Constant((Type.ClassType)typeUtils.getTypeMirror(String.class),
                                            combinedCode)))));
            for (var entry : functionImplementations.entrySet()) {
                var methodSymbol = (MethodSymbol) bpfInterfaceTypeElement.getEnclosedElements().stream()
                        .filter(e -> e instanceof MethodSymbol m && m.toString().equals(entry.getKey()))
                        .findFirst().orElse(null);
                if (methodSymbol == null) {
                    continue;
                }
                var methodMeta = methodSymbol.getMetadata();
                var methodAttributesField = methodMeta.getClass().getDeclaredField("attributes");
                methodAttributesField.setAccessible(true);
                var methodAttributes = (com.sun.tools.javac.util.List<Attribute>)methodAttributesField.get(methodMeta);
                methodAttributes = methodAttributes.append(new Attribute.Compound((Type.ClassType)typeUtils.getTypeMirror(InternalMethodDefinition.class),
                        com.sun.tools.javac.util.List.of(
                                new Pair<>(beforeSymbol,
                                        new Attribute.Constant((Type.ClassType)typeUtils.getTypeMirror(String.class),
                                                entry.getValue())))));
                methodAttributesField.set(methodMeta, methodAttributes);
            }
            attributesField.set(meta, attributes);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    private Set<String> getRequiredKernelFeatures(TypeElement klass) {
        Set<String> requirements = new HashSet<>();
        var ann = klass.getAnnotation(Requires.class);
        if (ann != null) {
            requirements.addAll(KernelFeatures.getRequiredKernelFeatures(ann));
        }
        for (var iface : klass.getInterfaces()) {
            requirements.addAll(getRequiredKernelFeatures((TypeElement) ((Type.ClassType)iface).asElement()));
        }
        return requirements;
    }

    @SuppressWarnings("unchecked")
    private <T extends Annotation, S extends Annotation> List<T> getAnnotationValues(TypeElement klass,
                                                               Class<T> annotationClass,
                                                               @Nullable Class<S> multiAnnotationClass,
                                                               boolean breadthFirst) {
        List<T> annotations = new ArrayList<>();
        ArrayDeque<TypeElement> toVisit = new ArrayDeque<>(List.of(klass));
        Set<TypeElement> visited = new HashSet<>();

        Method multiAnnMethod = null;
        if (multiAnnotationClass != null) {
            try {
                multiAnnMethod = multiAnnotationClass.getMethod("value");
            } catch (NoSuchMethodException e) {
                throw new RuntimeException(e);
            }
        }

        final Method multiAnnMethodFinal = multiAnnMethod;

        Consumer<TypeElement> add = iface -> {
            if (iface == null) {
                return;
            }
            var ann = iface.getAnnotation(annotationClass);
            if (ann != null) {
                annotations.add(ann);
            }
            if (multiAnnotationClass != null) {
                try {
                    var multiAnn = iface.getAnnotation(multiAnnotationClass);
                    if (multiAnn != null) {
                        var values = (T[]) multiAnnMethodFinal.invoke(multiAnn);
                        annotations.addAll(Arrays.asList(values));
                    }
                } catch (IllegalAccessException | InvocationTargetException e) {
                    throw new RuntimeException(e);
                }
            }
        };
        add.accept(klass);
        visited.add(klass);
        while (!toVisit.isEmpty()) {
            var current = toVisit.poll();
            List<TypeElement> otherClasses = current.getInterfaces().stream().map(i -> (TypeElement) ((Type.ClassType)i).asElement())
                    .filter(Objects::nonNull)
                    .filter(e -> !visited.contains(e))
                    .collect(Collectors.toList());
            if (current.getSuperclass() != null) {
                var s = (TypeElement) ((Type) current.getSuperclass()).asElement();
                if (s != null && !visited.contains(s)) {
                    otherClasses.add(s);
                }
            }
            if (breadthFirst) {
                otherClasses.forEach(add);
                otherClasses.forEach(visited::add);
                toVisit.addAll(otherClasses);
            } else {
                add.accept(current);
                visited.add(current);
                toVisit.addAll(otherClasses.stream().filter(e -> !visited.contains(e)).toList());
            }
        }
        return annotations;
    }

    /** Collect the {@link PropertyDefinition} instances and */
    private Map<String, PropertyDefinition> getPropertyDefinitions(TypedTreePath<ClassTree> path, TypeElement klass) {
        var anns = getAnnotationValues(klass, PropertyDefinition.class, PropertyDefinitions.class, true);
        // log error if there are multiple definitions for the same property
        var definitions = new HashMap<String, PropertyDefinition>();
        for (var ann : anns) {
            if (definitions.containsKey(ann.name())) {
                logError(path, path.leaf(), "Multiple definitions for property " + ann.name());
            }
            definitions.put(ann.name(), ann);
        }
        return definitions;
    }

    private Map<String, String> getPropertyValues(TypedTreePath<ClassTree> path, TypeElement klass) {
        var anns = getAnnotationValues(klass, Property.class, Properties.class, true);
        var values = new HashMap<String, String>();
        for (var ann : anns) {
            if (values.containsKey(ann.name())) {
                logError(path, path.leaf(), "Multiple values for property " + ann.name());
            }
            values.put(ann.name(), ann.value());
        }
        return values;
    }

    /**
     * Get all specified properties (error if property is not defined)
     * and all other defined properties with default values
     */
    private Map<String, String> getAllPropertyValues(TypedTreePath<ClassTree> path, TypeElement klass) {
        var definitions = getPropertyDefinitions(path, klass);
        var values = getPropertyValues(path, klass);

        var properties = new HashMap<String, String>();
        for (var definition : definitions.values()) {
            var name = definition.name();
            var value = definition.defaultValue();
            if (values.containsKey(name)) {
                var regexp = definitions.get(name).regexp();
                if (!values.get(name).matches(regexp)) {
                    logError(path, path.leaf(), "Value of property " + name + " does not match regular expression " + regexp + ": " + values.get(name));
                }

                value = values.get(name);
                values.remove(name);
            }
            properties.put(name, value);
        }

        if (!values.isEmpty()) {
            logError(path, path.leaf(), values.size() + " properties without definition found");
        }
        for (var name : values.keySet()) {
            // find closest definition
            var closest = Util.getClosestString(name, definitions.keySet());
            logError(path, path.leaf(), "Property " + name + " is not defined, maybe you meant " + closest);
        }
        return properties;
    }

    private void processBPFProgramImpl(TypedTreePath<ClassTree> programPath) {
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

        var missingKernelFeatures = KernelFeatures.getMissingFeatures(getRequiredKernelFeatures(superClassElement));
        if (!missingKernelFeatures.isEmpty()) {
            logWarning(programPath, bpfProgram, "Can't compile, missing kernel features in the current kernel: "
                    + String.join(", ", missingKernelFeatures));
            return;
        }

        var methods = task.getElements().getAllMembers(superClassElement).stream()
                .filter(m -> m instanceof MethodSymbol && ((MethodSymbol) m).getEnclosingElement().equals(superClassElement))
                .toList();

        var toImplement = classToMethodCountToImplement.getOrDefault((Type.ClassType) superClassType, 0);

        // Build declsWithDefines while tracking each method's Java name for prologue injection.
        var declsWithDefines = new ArrayList<FuncDeclStatementResult>();
        // Parallel list: declJavaNames[i] is the Java method simple-name for declsWithDefines[i].
        var declJavaNames = new ArrayList<String>();
        for (var m : methods) {
            var mt = task.getTypes().asMemberOf((DeclaredType) superClassElement.asType(), m);
            if (!(mt instanceof MethodType methodType)) continue;
            var result = methodElementToCode.get(methodType);
            if (result == null) continue;
            declsWithDefines.add(result);
            declJavaNames.add(m.getSimpleName().toString());
        }

        var defines = declsWithDefines.stream().flatMap(r -> r.requiredDefines().stream()).collect(Collectors.toSet());
        var decls = declsWithDefines.stream().map(d -> new FuncDecl(d.decl, d.addDefine)).toList();

        // Collect @BPFAbstraction field prologues from the @BPF super-class and prepend
        // them to the target methods (typically init()) in the decls list.
        // Load carrier overrides into the plugin-level map keyed by "superClassName.fieldName".
        var carriers = readAbstractionCarriers((JCClassDecl) bpfProgram);
        var superClassName = superClassElement.getQualifiedName().toString();
        carriers.forEach((fieldName, carrier) ->
                abstractionFieldCarrierOverrides.put(superClassName + "." + fieldName, carrier));
        // Emit #define NAME value for any auto-id carriers so field references that were
        decls = injectAbstractionPrologues(decls, declJavaNames, (JCClassDecl) bpfProgram);
        // Synthetic top-level functions (e.g. lambdas lifted for bpf_loop / bpf_for_each_map_elem).
        // These come BEFORE the main function decls in declarator-emission order so that the
        // helper that takes their address has a forward declaration in scope.
        var syntheticDecls = declsWithDefines.stream()
                .flatMap(d -> d.syntheticFunctions().stream())
                .map(s -> new FuncDecl(s, true))
                .toList();

        if (decls.size() < toImplement) {
            logError(programPath, bpfProgram, "Not all methods have been processed");
            return;
        }

        // get value of CODE field in the bpfProgram
        var codeField = getMember(bpfProgram, "CODE");
        var code = evalStringTree(codeField.getInitializer());

        // Emit #define NAME value for any auto-id carriers so field references that were
        // translated before the carrier map was populated (fallback placeholder = fieldName_DSQ_ID).
        if (!carriers.isEmpty()) {
            var autoDefines = carriers.entrySet().stream()
                    .map(e -> "#define " + e.getKey() + "_DSQ_ID " + e.getValue())
                    .collect(java.util.stream.Collectors.joining("\n"));
            code = autoDefines + "\n" + code;
        }

        // now get the "body" value of all BPFInterface annotations of all interfaces of the super class
        var bpfInterfaceBodies = superClassElement.getInterfaces().stream()
                .map(i -> {
                    var ann = i.getAnnotation(InternalBody.class);
                    if (ann == null && i instanceof Type.ClassType klass && klass.tsym != null) {
                        ann = klass.tsym.getAnnotation(InternalBody.class);
                    }
                    return ann;
                })
                .filter(Objects::nonNull).map(InternalBody::value).filter(b -> !b.isEmpty()).toList();

        // add the code of the interfaces to the code
        var interfaceCode = bpfInterfaceBodies.stream().collect(Collectors.joining("\n\n"));

        // now add every method for which we have a InternalMethodDefinition annotation in an interface
        // but have no implementation in the class itself

        // first: collect all methods of interfaces with InternalMethodDefinition

        Map<MethodSymbol, String> defaultCodeForMethod = getInterfaceMethodsWithDefaultCode((Symbol.ClassSymbol) superClassElement);

        // second: take all methods that are not implemented (or not available in this compilation)
        // and add the default code

        // Methods whose source IS available in this compilation run (their code is in methodElementToCode)
        var implementedMethodStrings = methods.stream()
                .filter(m -> {
                    var t = task.getTypes().asMemberOf((DeclaredType) superClassElement.asType(), m);
                    return t instanceof MethodType && methodElementToCode.containsKey((MethodType) t);
                })
                .map(Object::toString)
                .collect(Collectors.toSet());

        var defaultCode = defaultCodeForMethod.entrySet().stream()
                .filter(e -> !implementedMethodStrings.contains(e.getKey().toString()))
                .map(Map.Entry::getValue)
                .collect(Collectors.joining("\n\n"));

        if (!defaultCode.isBlank()) {
            if (!code.isBlank()) {
                interfaceCode = interfaceCode + "\n\n";
            }
            interfaceCode = interfaceCode + defaultCode;
        }

        if (!interfaceCode.isBlank()) {
            code = interfaceCode + "\n\n" + code;
        }

        var implAnn = bpfProgramTypeElement.getAnnotation(BPFImpl.class);
        if (implAnn == null) {
            logError(programPath, bpfProgram, "BPF program implementation must have a BPFImpl annotation");
            return;
        }

        code = implAnn.before() + code;

        // Aggregate __ksym forward decls for all kfuncs called transitively from
        // any @BPFFunction in this program. Each kfunc's C signature comes from
        // the @KFunc annotation on its Java stub (emitted by bpf-gen from BTF
        // DECL_TAG "bpf_kfunc"). Deduped by kfunc name; insertion-ordered.
        // Skip kfuncs already declared in the program's `before=` block (or any
        // earlier interface code) — duplicate decls with mismatched type names
        // (BTF produces `_Bool`/`long long unsigned int`, hand-written decls
        // use `bool`/`u64`) cause libbpf to reject the load with EINVAL.
        var kfuncDecls = new java.util.LinkedHashMap<String, String>();
        for (var d : declsWithDefines) {
            kfuncDecls.putAll(d.calledKFuncs());
        }
        if (!kfuncDecls.isEmpty()) {
            var existing = code;
            var kfuncProlog = kfuncDecls.entrySet().stream()
                    .filter(e -> !existing.contains(e.getValue() + " __ksym;"))
                    .map(e -> e.getValue() + " __ksym;")
                    .collect(Collectors.joining("\n"));
            if (!kfuncProlog.isEmpty()) {
                code = kfuncProlog + "\n\n" + code;
            }
        }

        var properties = getAllPropertyValues(programPath, superClassElement);

        var newCode = replaceProperties(combineCode(code, syntheticDecls, decls, defines) + "\n\n" + implAnn.after(), properties);

        // Define __arena (clang AS1 qualifier) when the program references
        // it but no header has supplied the define. Kernel selftests provide
        // this via bpf_arena_common.h; we inline the same definition so
        // generated programs compile without an external dependency.
        StringBuilder arenaPrelude = new StringBuilder();
        if (newCode.contains("__arena") && !newCode.contains("#define __arena")) {
            arenaPrelude.append("#ifndef __arena\n#define __arena __attribute__((address_space(1)))\n#endif\n");
        }
        if (arenaPrelude.length() > 0) {
            int insertAt = 0;
            String[] lines = newCode.split("\n", -1);
            int offset = 0;
            for (String line : lines) {
                String trimmed = line.trim();
                if (trimmed.startsWith("#include") || trimmed.isEmpty()) {
                    offset += line.length() + 1;
                    insertAt = offset;
                } else {
                    break;
                }
            }
            newCode = newCode.substring(0, insertAt) + arenaPrelude + newCode.substring(insertAt);
        }

        // write the C code in a file close to the source file (controlled by dumpC plugin arg)
        var cFile =
                Path.of(programPath.root().getSourceFile().toUri().getPath()).getParent().resolve(bpfProgram.getSimpleName() + ".c");
        if (!"false".equalsIgnoreCase(dumpCArg)) {
            Path dumpTarget = "true".equalsIgnoreCase(dumpCArg)
                    ? cFile
                    : Path.of(dumpCArg).resolve(bpfProgram.getSimpleName() + ".c");
            try {
                if (!dumpTarget.equals(cFile)) Files.createDirectories(dumpTarget.getParent());
                Files.writeString(dumpTarget, newCode);
            } catch (IOException e) {
                logError(programPath, bpfProgram, "Could not write C code to " + dumpTarget);
            }
        }

        var compiledCode = compile(newCode, cFile);
        // adding fields would be easier, but this doesn't seem to work

        if (compiledCode.encode().length() < 2 << 15) { // strings can only be 2^16 bytes long, so stay below that
        // inline small byte codes and put it in a string
        for (var member : bpfProgram.getMembers()) {
            if (member instanceof JCMethodDecl methodDecl) {
                var name = methodDecl.name;
                if (name.contentEquals("getByteCodeBytesStatic")) {
                    ((JCReturn) methodDecl.body.getStatements().getLast()).expr = treeMaker.Literal(compiledCode.encode());
                } else if (name.contentEquals("getCodeStatic")) {
                    ((JCReturn) methodDecl.body.getStatements().getLast()).expr = treeMaker.Literal(newCode);
                } else if (name.contentEquals("getByteCodeResourceName")) {
                    ((JCReturn) methodDecl.body.getStatements().getLast()).expr = treeMaker.Literal("");
                }
            }
        }
        } else {
            var resourceName = bpfProgramTypeElement.getQualifiedName() + ".o";
            var fileManager = ((JavacTaskImpl) CompilerPlugin.this.task).getContext().get(JavaFileManager.class);
            Path outPath;
            try {
                 outPath = Path.of(fileManager.getFileForOutput(StandardLocation.CLASS_OUTPUT, "", resourceName, null).toUri().getPath());
            } catch (IOException e) {
                logError(programPath, bpfProgram, "No output folder found");
                return;
            }

            try {
                Files.write(outPath, compiledCode.gzip());
            } catch (IOException e) {
                logError(programPath, bpfProgram, "Could not write byte code to " + outPath);
            }
            for (var member : bpfProgram.getMembers()) {
                if (member instanceof JCMethodDecl methodDecl) {
                    var name = methodDecl.name;
                    if (name.contentEquals("getByteCodeBytesStatic")) {
                        ((JCReturn) methodDecl.body.getStatements().getLast()).expr = treeMaker.Literal("");
                    } else if (name.contentEquals("getCodeStatic")) {
                        ((JCReturn) methodDecl.body.getStatements().getLast()).expr = treeMaker.Literal(newCode);
                    } else if (name.contentEquals("getByteCodeResourceName")) {
                        ((JCReturn) methodDecl.body.getStatements().getLast()).expr = treeMaker.Literal(resourceName);
                    }
                }
            }
        }
    }

    private Map<MethodSymbol, String> getInterfaceMethodsWithDefaultCode(Symbol.ClassSymbol superClassElement) {
        var result = new HashMap<MethodSymbol, String>();
        // Collect @BPFFunction implementations from concrete superclasses first (highest priority).
        // These are stored via @InternalMethodDefinition on the class method by processBPFFunction.
        // Walk from the most-derived class upward; the first (most-derived) definition wins.
        var current = superClassElement;
        while (current != null && !current.getQualifiedName().toString().equals("java.lang.Object")) {
            for (var e : current.getEnclosedElements()) {
                if (!(e instanceof MethodSymbol ms)) continue;
                var ann = ms.getAnnotation(InternalMethodDefinition.class);
                if (ann == null) continue;
                // Only add if not already covered by a more-derived class entry.
                var alreadyPresent = result.keySet().stream()
                        .anyMatch(existing -> existing.getSimpleName().equals(ms.getSimpleName())
                                && existing.asType().toString().equals(ms.asType().toString()));
                if (!alreadyPresent) {
                    result.put(ms, ann.value());
                }
            }
            var sc = current.getSuperclass();
            current = (sc instanceof Type.ClassType ct) ? (Symbol.ClassSymbol) ct.asElement() : null;
        }
        // Collect default implementations from interfaces (@InternalMethodDefinition on interface methods)
        // as fallback — only when no concrete superclass provided an implementation.
        for (var m : getInterfaceMethods(superClassElement)) {
            var ann = m.getAnnotation(InternalMethodDefinition.class);
            if (ann == null) continue;
            var alreadyPresent = result.keySet().stream()
                    .anyMatch(existing -> existing.getSimpleName().equals(m.getSimpleName())
                            && existing.asType().toString().equals(m.asType().toString()));
            if (!alreadyPresent) {
                result.put(m, ann.value());
            }
        }
        return result;
    }

    /**
     * Prepends {@code @BPFAbstraction} constructor side-effects to the matching BPF function.
     * Prologues are read from the {@code ABSTRACTION_PROLOGUES} field of the generated impl class.
     *
     * @param javaMethodNames parallel list of Java method simple-names for {@code decls} (same indices)
     * @param bpfProgram the generated impl class (JCClassDecl) being compiled
     */
    private List<FuncDecl> injectAbstractionPrologues(List<FuncDecl> decls,
                                                      List<String> javaMethodNames,
                                                      JCClassDecl bpfProgram) {
        var prologues = readAbstractionPrologues(bpfProgram);
        if (prologues.isEmpty()) {
            return decls;
        }
        var modified = new ArrayList<>(decls);
        for (int i = 0; i < modified.size(); i++) {
            // Match by Java method name (constructorPrependTo refers to Java names, not C names).
            var javaName = i < javaMethodNames.size() ? javaMethodNames.get(i) : null;
            if (javaName == null) continue;
            var stmts = prologues.get(javaName);
            if (stmts == null || stmts.isEmpty()) continue;
            var fd = modified.get(i);
            // Prepend prologue statements to the body
            var existingStatements = new ArrayList<>(fd.decl().body().statements());
            var prologueStatements = stmts.stream()
                    .map(s -> (CAST.Statement) CAST.Statement.verbatim(s))
                    .toList();
            var newStatements = new ArrayList<>(prologueStatements);
            newStatements.addAll(existingStatements);
            var newBody = new CAST.Statement.CompoundStatement(newStatements);
            var newDecl = new FunctionDeclarationStatement(fd.decl().declarator(), newBody,
                    fd.decl().annotations());
            modified.set(i, new FuncDecl(newDecl, fd.addDefine()));
        }
        return modified;
    }

    /** Evaluate a compile-time string constant tree (handles single literals and + concatenations). */
    private static String evalStringTree(ExpressionTree tree) {
        if (tree instanceof LiteralTree lit) return (String) lit.getValue();
        if (tree instanceof BinaryTree bin && bin.getKind() == Tree.Kind.PLUS)
            return evalStringTree(bin.getLeftOperand()) + evalStringTree(bin.getRightOperand());
        throw new IllegalArgumentException("Cannot evaluate string tree: " + tree.getKind());
    }

    /**
     * Parses the {@code ABSTRACTION_PROLOGUES} field from the generated impl class.
     * Format: each line is {@code "methodName\tstatement"}.
     */
    private Map<String, List<String>> readAbstractionPrologues(JCClassDecl bpfProgram) {
        var prologuesField = getMemberOptional(bpfProgram, "ABSTRACTION_PROLOGUES");
        if (prologuesField == null) return Map.of();
        var raw = evalStringTree(prologuesField.getInitializer());
        if (raw.isBlank()) return Map.of();
        var result = new java.util.LinkedHashMap<String, List<String>>();
        for (var line : raw.split("\n")) {
            int tab = line.indexOf('\t');
            if (tab < 0) continue;
            var method = line.substring(0, tab);
            var stmt = line.substring(tab + 1);
            result.computeIfAbsent(method, k -> new ArrayList<>()).add(stmt);
        }
        return result;
    }

    /**
     * Parses the {@code ABSTRACTION_CARRIERS} field from the generated impl class.
     * Format: each line is {@code "fieldName\tcarrierExpr"}.
     */
    private Map<String, String> readAbstractionCarriers(JCClassDecl bpfProgram) {
        var carriersField = getMemberOptional(bpfProgram, "ABSTRACTION_CARRIERS");
        if (carriersField == null) return Map.of();
        var raw = evalStringTree(carriersField.getInitializer());
        if (raw.isBlank()) return Map.of();
        var result = new java.util.LinkedHashMap<String, String>();
        for (var line : raw.split("\n")) {
            int tab = line.indexOf('\t');
            if (tab < 0) continue;
            result.put(line.substring(0, tab), line.substring(tab + 1));
        }
        return result;
    }

    private List<MethodSymbol> getInterfaceMethods(Symbol.ClassSymbol element) {
        return element.getInterfaces().stream().flatMap(i -> {
            return Stream.concat(i.asElement().getEnclosedElements().stream().filter(m -> m instanceof MethodSymbol).map(m -> (MethodSymbol)m), getInterfaceMethods((Symbol.ClassSymbol) i.asElement()).stream());
        }).toList();
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

    @Nullable
    VariableTree getMemberOptional(ClassTree klass, String name) {
        return klass.getMembers().stream()
                .filter(m -> m instanceof VariableTree)
                .map(m -> (VariableTree) m)
                .filter(m -> m.getName().contentEquals(name))
                .findFirst()
                .orElse(null);
    }

    record FuncDecl(FunctionDeclarationStatement decl, boolean addDefine) {
    }

    boolean canEmitDeclaratorFor(FuncDecl decl) {
        return decl.addDefine && !decl.decl.declarator().toPrettyString().matches(".* [A-Z0-9_]+\\([a-z0-9A-Z_]+,.*\\).*");
    }

    String combineCode(String code, List<FuncDecl> decls, Set<Define> defines) {
        return combineCode(code, List.of(), decls, defines);
    }

    /**
     * Variant that accepts {@code syntheticDecls} — top-level functions lifted from
     * {@code $funcN} lambda placeholders (see {@code Translator#promoteLambda}). These
     * are emitted alongside the main declarations and (forward-declared) before all
     * other functions so callers like {@code bpf_loop(__bpf_lambda_..., ...)} resolve.
     */
    String combineCode(String code, List<FuncDecl> syntheticDecls, List<FuncDecl> decls, Set<Define> defines) {
        var allDecls = new ArrayList<>(syntheticDecls);
        allDecls.addAll(decls);
        return combineCode(code, List.of(), allDecls, defines, List.of(), List.of(), List.of(),
                new TypeProcessor.InterfaceAdditions(List.of(), List.of(), List.of()));
    }

    String combineCode(String code, List<CAST.Declarator.FunctionHeader> functionHeaders, List<FuncDecl> decls, Set<Define> defines,
                       List<Statement> typeDecls, List<TypeProcessor.MapDefinition> mapDefinitions,
                       List<TypeProcessor.GlobalVariableDefinition> globals, TypeProcessor.InterfaceAdditions additions) {
        var requiredDefines = defines.stream().filter(d -> !code.contains(d.toPrettyString()))
                .sorted(Comparator.comparing(Define::name)).toList();

        List<String> result = new ArrayList<>(additions.before());
        result.add(code);
        result.addAll(prettyPrint(requiredDefines));
        result.addAll(prettyPrint(typeDecls));
        result.addAll(prettyPrint(mapDefinitions.stream().map(TypeProcessor.MapDefinition::structDefinition).toList()));
        result.addAll(prettyPrint(globals.stream().map(TypeProcessor.GlobalVariableDefinition::globalVariable).toList()));
        result.addAll(decls.stream().filter(this::canEmitDeclaratorFor).map(d -> d.decl.declarator().toStatement().toPrettyString()).toList());
        result.addAll(prettyPrint(functionHeaders.stream().map(CAST::toStatement).toList()));
        result.addAll(prettyPrint(decls.stream().map(FuncDecl::decl).toList()));
        result.addAll(additions.after());
        return moveIncludesToTheFront(result.stream().filter(s -> !s.isEmpty()).collect(Collectors.joining("\n\n")));
    }

    private static String replaceProperties(String code, Map<String, String> properties) {
        for (var entry : properties.entrySet()) {
            code = code.replace("__property_" + entry.getKey(), entry.getValue());
        }
        return code;
    }

    public static String moveIncludesToTheFront(String code) {
        Predicate<String> isInclude = s -> s.startsWith("#include ");
        // Also hoist SEC(".data") global variable declarations so they precede any
        // injected function bodies that reference them (e.g. _exitCode from SchedulerBase).
        // Only hoist primitive-typed globals: globals that reference a user-defined
        // struct/union type must stay below the type declarations (they need the
        // struct definition to be visible first — see testUsingInterfaceWithStruct2).
        Predicate<String> isSecData = s -> s.matches(".*SEC\\s*\\(\".data\"\\)\\s*;.*") && !s.strip().startsWith("//");
        Predicate<String> isPrimitiveSecData = isSecData.and(s -> {
            var t = s.strip();
            return !t.startsWith("struct ") && !t.startsWith("union ");
        });
        var includes = code.lines().filter(isInclude).toList();
        var secDataLines = code.lines().filter(isPrimitiveSecData).toList();
        var rest = code.lines().filter(isInclude.negate()).filter(isPrimitiveSecData.negate())
                .collect(Collectors.joining("\n")).strip();
        var preamble = new ArrayList<String>(includes);
        if (!secDataLines.isEmpty()) {
            preamble.add("");
            preamble.addAll(secDataLines);
        }
        return String.join("\n", preamble) + "\n\n" + rest;
    }

    private List<String> prettyPrint(List<? extends CAST> statements) {
        return statements.stream().map(CAST::toPrettyString).toList();
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
