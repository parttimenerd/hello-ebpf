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

import me.bechberger.ebpf.bpf.compiler.passes.ArenaAssociationPass;
import me.bechberger.ebpf.bpf.compiler.structops.JavaToCTypeRenderer;
import me.bechberger.ebpf.bpf.compiler.structops.StructOpsDiscovery;
import me.bechberger.ebpf.bpf.compiler.structops.StructOpsLayout;
import me.bechberger.ebpf.bpf.compiler.structops.StructOpsSynthesizer;
import me.bechberger.ebpf.bpf.compiler.structops.StructOpsValidator;

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
     * Side-channel populated during translation: for each translated method, the set of
     * arena-field names it directly dereferences (via {@code @InArena Ptr<T>}).
     * Collected by {@link Translator}; consumed by {@code ArenaAssociationPass} in Task B.
     */
    final Map<MethodSymbol, Set<String>> directArenaRefs = new HashMap<>();

    /**
     * Fields for which an "unresolvable @InArena initializer" compile-error has already
     * been emitted (by {@link Translator#maybeRecordArenaDeref}).  Deduplicated across
     * all method translations so each offending field produces exactly one error.
     */
    final Set<com.sun.tools.javac.code.Symbol.VarSymbol> erroredArenaFields = new HashSet<>();

    /**
     * Side-channel populated during translation: for each translated method, the set of
     * other {@code @BPFFunction} method symbols it directly calls (in the same class).
     * Collected by {@link Translator}; consumed by {@code ArenaAssociationPass} in Task B.
     */
    final Map<MethodSymbol, Set<MethodSymbol>> callGraph = new HashMap<>();

    /**
     * Test hook: when non-null, the plugin instance that most recently finished processing
     * a BPF program class is stored here. Tests that drive javac in-process can read the
     * side-channel maps via {@link #getDirectArenaRefs()} / {@link #getCallGraph()}.
     * <p>
     * Not written in production builds; the field is only set when the plugin is running
     * inside an in-process javac invocation that opts in (see {@code ArenaAssociationPassTest}).
     */
    public static final ThreadLocal<CompilerPlugin> LAST_PLUGIN = new ThreadLocal<>();

    /**
     * The last C code string produced by {@link #processBPFProgramImpl}.
     * Set just before {@link #LAST_PLUGIN} is populated so that in-process tests can
     * retrieve the generated C output alongside the side-channel maps.
     */
    String lastGeneratedCode = "";

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

    /**
     * Per-{@code @BPF} class memoization of struct-ops discovery / validation / synthesis.
     * Keyed by qualified class name (not {@link TypeElement} reference) because the symbol
     * object for the same class can differ between annotation-processing rounds, so using
     * a TypeElement reference as key would cause cache misses when the @BPFImpl class is
     * compiled in a later round.
     */
    private final Map<String, StructOpsSynthesizer.Result> structOpsCache = new HashMap<>();

    /**
     * Guard against emitting the {@code META-INF/ebpf-struct-ops/<userClass>.json} resource more
     * than once per compilation unit. {@link javax.annotation.processing.Filer#createResource}
     * throws {@link javax.annotation.processing.FilerException} on the second call for the same
     * path, which would otherwise surface as a spurious compile error under incremental builds.
     */
    private final Set<String> emittedManifestFqns = new HashSet<>();

    /**
     * Renders {@code t} as its JVM binary name (e.g. {@code p.Outer$Inner} for a
     * nested type), matching {@code Class.getName()} — so runtime lookups using
     * {@code Class.getName()} round-trip against the manifest resource path.
     */
    private static String binaryName(TypeElement t) {
        StringBuilder sb = new StringBuilder();
        javax.lang.model.element.Element e = t;
        while (e instanceof TypeElement te) {
            if (sb.length() == 0) sb.append(te.getSimpleName());
            else sb.insert(0, te.getSimpleName() + "$");
            e = te.getEnclosingElement();
        }
        if (e instanceof javax.lang.model.element.PackageElement pe && !pe.isUnnamed()) {
            sb.insert(0, pe.getQualifiedName() + ".");
        }
        return sb.toString();
    }

    @Override
    public String getName() {
        return "BPFCompilerPlugin";
    }

    /** Returns the accumulated direct-arena-ref side-channel collected during translation. */
    public Map<MethodSymbol, Set<String>> getDirectArenaRefs() {
        return java.util.Collections.unmodifiableMap(directArenaRefs);
    }

    /** Returns the accumulated inter-{@code @BPFFunction} call-graph side-channel collected during translation. */
    public Map<MethodSymbol, Set<MethodSymbol>> getCallGraph() {
        return java.util.Collections.unmodifiableMap(callGraph);
    }

    /** Returns the last C source string produced by {@link #processBPFProgramImpl}, or empty string. */
    public String getLastGeneratedCode() {
        return lastGeneratedCode;
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
                funcs.addAll(getBPFFunctionsForClass(e.getCompilationUnit()));
                var impls = getBPFProgramImpls(e.getCompilationUnit());
                var interfaces = getBPFInterfaces(e.getCompilationUnit());
                // Eagerly trigger struct-ops synthesis for any @BPF class so that
                // string/integer literals are resolved while the Trees API still
                // has the current round's ASTs. Without this, the generated
                // @BPFImpl class is compiled in a later round, at which point
                // Trees.getTree() returns null for the prior round's methods.
                eagerlyPrimeStructOpsCacheForBPFClasses(e.getCompilationUnit());
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

    /**
     * Walks all classes in the compilation unit and eagerly populates the
     * struct-ops synthesis cache for any class annotated {@code @BPF}. Called
     * in the ANALYZE phase so the Trees API still has the current-round ASTs;
     * when the generated {@code @BPFImpl} class is later compiled in a fresh
     * round, {@link #getStructOpsSynthesis} returns the cached result without
     * needing to re-read method bodies.
     */
    private void eagerlyPrimeStructOpsCacheForBPFClasses(CompilationUnitTree cu) {
        cu.accept(new com.sun.source.util.TreeScanner<Void, Void>() {
            @Override
            public Void visitClass(com.sun.source.tree.ClassTree node, Void p) {
                var path = com.sun.source.util.TreePath.getPath(cu, node);
                var el = trees.getElement(path);
                if (el instanceof TypeElement te && te.getAnnotation(BPF.class) != null) {
                    // Calling getStructOpsSynthesis here (while trees are live)
                    // populates the cache; any @BPFImpl-triggered call later gets
                    // a cache hit without needing the AST.
                    getStructOpsSynthesis(te);
                }
                return super.visitClass(node, p);
            }
        }, null);
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
    public BPFFunction getEffectiveBPFFunction(MethodSymbol method) {
        var direct = getAnnotationOfMethodOrSuper(method, BPFFunction.class);
        if (direct != null) return direct;
        // @StructOps override method? Look up (and lazily compute) the per-class synthesis.
        // First try the method's direct enclosing class (fast path, works when the method is
        // declared directly on the @BPF class).
        var enclosing = method.getEnclosingElement();
        if (enclosing instanceof TypeElement te) {
            var synth = getStructOpsSynthesis(te);
            for (var sf : synth.functions()) {
                if (sf.method().equals(method)) return sf.bpfFunction();
            }
        }
        // Slow path: the method may be inherited from an intermediate abstract class
        // (e.g. PerCpuSchedulerBase.init overrides Scheduler.init, but the @BPF class is
        // PerCpuSchedulerSample). Walk all cached syntheses to find a match.
        for (var synth : structOpsCache.values()) {
            for (var sf : synth.functions()) {
                if (sf.method().equals(method)) return sf.bpfFunction();
            }
        }
        return synthesizeBPFFunction(method);
    }

    /**
     * Lazily discovers, validates, and synthesizes {@code @StructOps} interfaces implemented
     * by {@code bpfClass}. Result is memoized per class so that method-level BTF validation
     * errors are printed exactly once, not once per {@link #getEffectiveBPFFunction} call.
     */
    StructOpsSynthesizer.Result getStructOpsSynthesis(TypeElement bpfClass) {
        // @BPFImpl classes are generated from a @BPF class. Synthesis must use the
        // parent @BPF class's cached result so we don't re-synthesize in round 2
        // when Trees are unavailable for the original source's method bodies.
        if (bpfClass.getAnnotation(BPFImpl.class) != null) {
            var superMirror = bpfClass.getSuperclass();
            if (superMirror instanceof javax.lang.model.type.DeclaredType dt) {
                bpfClass = (TypeElement) dt.asElement();
            }
        }
        String key = bpfClass.getQualifiedName().toString();
        var cached = structOpsCache.get(key);
        if (cached != null) return cached;
        var env = createProcessingEnvironment();
        var kinds = StructOpsDiscovery.discover(bpfClass, env);
        if (kinds.isEmpty()) {
            var empty = new StructOpsSynthesizer.Result(List.of(), List.of());
            structOpsCache.put(key, empty);
            return empty;
        }
        // Validate every overridden interface method against its pre-dumped BTF layout.
        // Errors are surfaced as javac diagnostics at the method's source position; we
        // continue past them so multiple problems surface in one compile pass.
        var renderer = new JavaToCTypeRenderer();
        for (var kind : kinds) {
            StructOpsLayout layout;
            try {
                layout = StructOpsLayout.load(kind.kernelName());
            } catch (RuntimeException ex) {
                env.getMessager().printMessage(Diagnostic.Kind.ERROR, ex.getMessage(), kind.iface());
                continue;
            }
            for (var m : kind.overriddenMethods()) {
                String fieldName = StructOpsValidator.camelToSnake(m.getSimpleName().toString());
                // Skip utility methods on the interface that have no matching kernel field
                // (e.g. runSchedulerLoop, attachScheduler, getSchedulerName).
                if (!layout.hasField(fieldName)) continue;
                try {
                    StructOpsValidator.validateFieldExists(layout, fieldName);
                    var field = layout.field(fieldName);
                    // Only function fields carry args/return; data fields are literal-initialized.
                    if (!"data".equals(field.kind())) {
                        StructOpsValidator.validateArgCount(field, m.getParameters().size(), fieldName);
                        // @Unsigned is TYPE_USE-scoped on the return type; TypeMirror.toString()
                        // prefixes the FQN annotation ("@me...Unsigned int") which JavaToCTypeRenderer
                        // can't parse. Read the annotation off the return-type mirror and strip
                        // any leading "@Foo " tokens so the renderer sees the bare Java type.
                        boolean retUnsigned = false;
                        for (var a : m.getReturnType().getAnnotationMirrors()) {
                            String fqn = ((javax.lang.model.element.TypeElement)
                                    a.getAnnotationType().asElement())
                                    .getQualifiedName().toString();
                            if (fqn.equals(me.bechberger.ebpf.annotations.Unsigned.class.getName())) {
                                retUnsigned = true;
                            }
                        }
                        String retTypeStr = m.getReturnType().toString().replaceAll("@\\S+\\s+", "");
                        String ret = renderer.renderWithAnnotation(retTypeStr, retUnsigned);
                        StructOpsValidator.validateReturnType(field, ret, fieldName);
                        for (int i = 0; i < m.getParameters().size(); i++) {
                            var p = m.getParameters().get(i);
                            // @Unsigned is TYPE_USE-scoped, so it appears on the type mirror,
                            // not as an element-scope annotation on the parameter. Fall back
                            // to element-scope for compilers that mirror it there.
                            boolean unsigned = p.getAnnotation(me.bechberger.ebpf.annotations.Unsigned.class) != null;
                            if (!unsigned) {
                                for (var a : p.asType().getAnnotationMirrors()) {
                                    String fqn = ((javax.lang.model.element.TypeElement)
                                            a.getAnnotationType().asElement())
                                            .getQualifiedName().toString();
                                    if (fqn.equals(me.bechberger.ebpf.annotations.Unsigned.class.getName())) {
                                        unsigned = true;
                                        break;
                                    }
                                }
                            }
                            // Strip TYPE_USE annotations (e.g. "@Unsigned int") from the type string.
                            String argTypeStr = p.asType().toString().replaceAll("@\\S+\\s+", "");
                            String rArg = renderer.renderWithAnnotation(argTypeStr, unsigned);
                            StructOpsValidator.validateArgType(field.args().get(i), rArg, i, fieldName);
                        }
                    }
                } catch (StructOpsValidator.ValidationException ex) {
                    env.getMessager().printMessage(Diagnostic.Kind.ERROR, ex.getMessage(), m);
                }
            }
        }
        var result = new StructOpsSynthesizer(env, trees).synthesize(bpfClass, kinds);
        structOpsCache.put(key, result);
        return result;
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
            storeInternalMethodDefinition(methodSymbol, buildInternalMethodCode(code, List.of()));
        }
        return true;
    }

    /**
     * Serialize a {@link FuncDeclStatementResult} into the self-contained C snippet persisted
     * via {@link InternalMethodDefinition} so a downstream compilation (a {@code @BPF} subclass
     * inheriting this method) can inject it verbatim.
     *
     * <p>Order of the emitted string: {@code [extraDefines]} then {@code [requiredDefines]} then
     * {@code [synthetic lambda defs]} then {@code [main body]}.
     * <ul>
     *   <li>{@code extraDefines} — carrier {@code #define}s (e.g. {@code FRAMEWORK_DSQ_ID}) that
     *       are only known at program-impl time; supplied when re-storing (GAP 2).</li>
     *   <li>synthetic lambda defs — lambdas lifted to top-level C functions (e.g.
     *       {@code __bpf_lambda_dispatch_0}); emitted before the main body so the body's call
     *       sites see them already defined. They are self-contained {@code static __always_inline}
     *       defs. Identical defs are deduped (GAP 1).</li>
     * </ul>
     * The subclass-side reader synthesises a forward prototype from the FIRST function in the
     * string only; leading {@code #define} lines are skipped by {@code extractFunctionPrototype}.
     */
    private String buildInternalMethodCode(FuncDeclStatementResult code, List<String> extraDefines) {
        var parts = new ArrayList<String>();
        // Carrier #defines that could only be resolved at program-impl time, deduped against
        // the method's own requiredDefines below to avoid emitting the same macro twice.
        var definesPrefix = code.requiredDefines().stream()
                .map(d -> d.toPrettyString())
                .collect(java.util.stream.Collectors.joining("\n"));
        for (var d : extraDefines) {
            if (d != null && !d.isBlank() && (definesPrefix.isBlank() || !definesPrefix.contains(d))) {
                parts.add(d);
            }
        }
        if (!definesPrefix.isBlank()) parts.add(definesPrefix);
        var syntheticDefs = code.syntheticFunctions().stream()
                .map(FunctionDeclarationStatement::toPrettyString)
                .distinct()
                .collect(java.util.stream.Collectors.joining("\n\n"));
        if (!syntheticDefs.isBlank()) parts.add(syntheticDefs);
        parts.add(code.decl.toPrettyString());
        return String.join("\n", parts);
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
        var functionImplementations = declsWithDefines.stream().collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue().decl.toPrettyString(), (a, b) -> a, LinkedHashMap::new));
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
        // Parallel list: declMethodSymbols[i] is the MethodSymbol for declsWithDefines[i].
        var declMethodSymbols = new ArrayList<MethodSymbol>();
        for (var m : methods) {
            var mt = task.getTypes().asMemberOf((DeclaredType) superClassElement.asType(), m);
            if (!(mt instanceof MethodType methodType)) continue;
            var result = methodElementToCode.get(methodType);
            if (result == null) continue;
            declsWithDefines.add(result);
            declJavaNames.add(m.getSimpleName().toString());
            declMethodSymbols.add((MethodSymbol) m);
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
        // GAP 2: carrier #define ride-along. The numeric carrier id (e.g. FRAMEWORK_DSQ_ID) is
        // only minted at THIS program-impl compile, so it was not available when
        // processBPFFunction persisted each @BPFFunction body. Re-store the
        // @InternalMethodDefinition for every base method whose body references a carrier
        // placeholder, prepending the matching #define so it rides along with the inherited
        // body when a subclass injects it. Without this, a subclass inheriting a body that
        // references FRAMEWORK_DSQ_ID gets no #define and clang fails with an undeclared id.
        if (!carriers.isEmpty()) {
            for (int i = 0; i < declMethodSymbols.size(); i++) {
                var methodSymbol = declMethodSymbols.get(i);
                var result = declsWithDefines.get(i);
                var bodyText = buildInternalMethodCode(result, List.of());
                var extraDefines = carriers.entrySet().stream()
                        .filter(e -> bodyText.contains(e.getKey() + "_DSQ_ID"))
                        .map(e -> "#define " + e.getKey() + "_DSQ_ID " + e.getValue())
                        .distinct()
                        .toList();
                if (!extraDefines.isEmpty()) {
                    storeInternalMethodDefinition(methodSymbol, buildInternalMethodCode(result, extraDefines));
                }
            }
        }
        // Emit #define NAME value for any auto-id carriers so field references that were
        decls = injectAbstractionPrologues(decls, declJavaNames, (JCClassDecl) bpfProgram);
        // Arena association pass: inject per-arena helper calls into struct_ops entry handlers
        // that transitively dereference an @InArena pointer.  The helpers ensure that each
        // struct_ops prog contains a BPF_PSEUDO_MAP_FD ldimm64 for each arena it uses, which
        // is required for the verifier to set prog->aux->arena.
        var arenaPassResult = new ArenaAssociationPass().apply(this, declMethodSymbols, decls);
        decls = arenaPassResult.updatedDecls();
        // NOTE (arena-association across module boundaries — KNOWN GAP): the pass above
        // injects `bpf_arena_associate_<N>();` into this program's OWN struct_ops entries
        // and emits the per-arena helper, so a @BPF program compiled WITH its arena-using
        // sources in the current unit loads correctly. A cross-module @BPF SUBCLASS that
        // inherits an arena-reaching struct_ops entry as a raw-C @InternalMethodDefinition
        // body does NOT get the association call/helper: this program-impl phase runs in a
        // LATER annotation-processing round than the base source, so re-storing the
        // post-pass body onto the base method symbol here cannot reach the already-written
        // base .class file. Fixing this requires persisting per-entry arena reachability in
        // the base source round and injecting into the inherited bodies at subclass compile
        // time. Until then, a subclass that inherits an arena-using struct_ops entry is
        // rejected by the verifier with "addr_space_cast ... has an associated arena".
        // Synthetic top-level functions (e.g. lambdas lifted for bpf_loop / bpf_for_each_map_elem).
        // These come BEFORE the main function decls in declarator-emission order so that the
        // helper that takes their address has a forward declaration in scope.
        var syntheticDecls = new ArrayList<FuncDecl>();
        // Arena association helpers are emitted first so they are in scope when the
        // entry bodies (and any lambda helpers) call them.
        for (var helper : arenaPassResult.helperDecls()) {
            syntheticDecls.add(new FuncDecl(helper, false));
        }
        declsWithDefines.stream()
                .flatMap(d -> d.syntheticFunctions().stream())
                .map(s -> new FuncDecl(s, true))
                .forEach(syntheticDecls::add);

        if (decls.size() < toImplement) {
            logError(programPath, bpfProgram, "Not all methods have been processed");
            return;
        }

        // get value of CODE field in the bpfProgram
        var codeField = getMember(bpfProgram, "CODE");
        var code = evalStringTree(codeField.getInitializer());

        // Emit #define NAME value for any auto-id carriers so field references that were
        // translated before the carrier map was populated (fallback placeholder = fieldName_DSQ_ID).
        // Only emit the define when the placeholder actually appears in the translated body —
        // otherwise the field name leaks into the C output as a stray macro and confuses tests
        // that check the field is fully erased from C.
        if (!carriers.isEmpty()) {
            String body = code;
            var autoDefines = carriers.entrySet().stream()
                    .filter(e -> body.contains(e.getKey() + "_DSQ_ID"))
                    .map(e -> "#define " + e.getKey() + "_DSQ_ID " + e.getValue())
                    .collect(java.util.stream.Collectors.joining("\n"));
            if (!autoDefines.isEmpty()) {
                code = autoDefines + "\n" + code;
            }
        }

        // now get the "body" value of all BPFInterface annotations of all interfaces of the super class
        // Walk transitively so that cross-module interfaces (loaded from a pre-compiled jar) whose
        // @InternalBody lives on a transitive superinterface are also discovered.
        var bpfInterfaceBodies = collectInternalBodies(superClassElement);

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

        var defaultCodeBodies = defaultCodeForMethod.entrySet().stream()
                .filter(e -> !implementedMethodStrings.contains(e.getKey().toString()))
                .sorted(Map.Entry.comparingByKey(Comparator.comparing(MethodSymbol::toString)))
                .map(Map.Entry::getValue)
                .toList();

        // The inherited bodies above are raw C strings that never pass through `decls`,
        // so they get no forward declarations. When one inherited body calls another
        // whose definition sorts LATER alphabetically (e.g. fillQueuedCtx -> incStat),
        // clang fails with "use of undeclared identifier". Synthesise a C prototype for
        // each inherited function definition and emit the block of prototypes BEFORE the
        // bodies so inter-body calls resolve regardless of ordering.
        var prototypes = defaultCodeBodies.stream()
                .map(this::extractFunctionPrototype)
                .filter(p -> p != null && !p.isBlank())
                .distinct()
                .collect(Collectors.joining("\n"));

        var defaultCode = defaultCodeBodies.stream().collect(Collectors.joining("\n\n"));

        // The inherited bodies reference this program's struct/map/#define block (e.g.
        // `struct DispatchedTaskCtx`, the `frameworkPids` map, `FRAMEWORK_DSQ`). That block
        // is emitted by combineCode AFTER `code`, so prepending the bodies into `code` puts
        // them BEFORE their own type/map/define declarations — clang then rejects them with
        // "incomplete definition" / "use of undeclared identifier". Emit the forward
        // prototypes early (into `code`, so any own-code call resolves) but append the
        // inherited body DEFINITIONS at the very end of the program (after structs/maps/
        // defines and this program's own decls) via `deferredInheritedBodies`.
        if (!prototypes.isBlank()) {
            if (!interfaceCode.isBlank()) {
                interfaceCode = interfaceCode + "\n\n";
            }
            // The prototypes reference struct tags (e.g. `struct QueuedTaskCtx *`) whose
            // full definitions are emitted LATER by combineCode (in the type-decl block,
            // after `code`). A prototype that mentions an as-yet-undeclared struct tag
            // declares a fresh prototype-scoped incomplete type; when the matching body
            // is defined later against the real file-scope struct, clang rejects it with
            // "conflicting types". Emit file-scope forward declarations (`struct X;`) for
            // every struct tag used in the prototypes FIRST so the prototype and the
            // eventual definition refer to the same incomplete-then-completed tag.
            var structForwardDecls = extractStructForwardDecls(prototypes);
            if (!structForwardDecls.isBlank()) {
                interfaceCode = interfaceCode + structForwardDecls + "\n\n";
            }
            interfaceCode = interfaceCode + prototypes;
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

        // @StructOps: append the SEC(".struct_ops.link") instance snippets (one per
        // implemented @StructOps interface) and emit a META-INF/ebpf-struct-ops JSON
        // manifest resource so the runtime knows what to attach without reflection.
        // The instance block references the SEC("struct_ops/...") entry-point
        // functions by identifier ((void *)ssthresh, …), so it must be spliced
        // AFTER combineCode has emitted the function bodies — hence we defer
        // the append until after `newCode` is built.
        var structOpsSynth = getStructOpsSynthesis(superClassElement);
        String structOpsInstanceBlock = "";
        if (!structOpsSynth.instances().isEmpty()) {
            structOpsInstanceBlock = structOpsSynth.instances().stream()
                    .map(StructOpsSynthesizer.SynthInstance::cSource)
                    .collect(Collectors.joining("\n\n"));

            var layoutsByKind = new HashMap<String, StructOpsLayout>();
            boolean layoutLoadFailed = false;
            for (var inst : structOpsSynth.instances()) {
                try {
                    layoutsByKind.put(inst.kernelName(), StructOpsLayout.load(inst.kernelName()));
                } catch (RuntimeException ex) {
                    logError(programPath, bpfProgram,
                            "failed to load layout for " + inst.kernelName()
                                    + " during manifest emission: " + ex.getMessage());
                    layoutLoadFailed = true;
                }
            }
            if (layoutLoadFailed) return;
            String userBinaryName = binaryName(superClassElement);
            String resourcePath = "META-INF/ebpf-struct-ops/" + userBinaryName + ".json";
            if (emittedManifestFqns.add(resourcePath)) {
                // Build JSON payload: { "userClass": "p.Foo$Bar",
                //                        "entries": [ {"kernelName":"tcp_congestion_ops",
                //                                       "mapName":"HelloCcSample",
                //                                       "since":"5.6"} ] }
                java.util.Map<String, Object> root = new java.util.LinkedHashMap<>();
                root.put("userClass", userBinaryName);
                java.util.List<Object> entries = new java.util.ArrayList<>();
                for (var inst : structOpsSynth.instances()) {
                    java.util.Map<String, Object> e = new java.util.LinkedHashMap<>();
                    e.put("kernelName", inst.kernelName());
                    e.put("mapName",    inst.mapName());
                    e.put("since",      layoutsByKind.get(inst.kernelName()).since());
                    entries.add(e);
                }
                root.put("entries", entries);
                String json = me.bechberger.util.json.PrettyPrinter.prettyPrint(root);
                try (var w = createProcessingEnvironment().getFiler()
                        .createResource(javax.tools.StandardLocation.CLASS_OUTPUT,
                                        "", resourcePath, superClassElement)
                        .openWriter()) {
                    w.write(json);
                } catch (javax.annotation.processing.FilerException fe) {
                    // Manifest already exists (incremental compile) — that's expected and safe.
                    logWarning(programPath, bpfProgram,
                            "skipping struct-ops manifest emission (already generated): " + fe.getMessage());
                } catch (IOException e) {
                    logError(programPath, bpfProgram,
                            "failed to write " + resourcePath + ": " + e.getMessage());
                }
            }
        }

        var newCode = replaceProperties(combineCode(code, syntheticDecls, decls, defines)
                + (defaultCode.isBlank() ? "" : "\n\n" + defaultCode)
                + "\n\n" + implAnn.after()
                + (structOpsInstanceBlock.isEmpty() ? "" : "\n\n" + structOpsInstanceBlock), properties);

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
        // Expose this plugin instance for test code that drives javac in-process.
        lastGeneratedCode = newCode;
        LAST_PLUGIN.set(this);
    }

    private Map<MethodSymbol, String> getInterfaceMethodsWithDefaultCode(Symbol.ClassSymbol superClassElement) {
        var result = new LinkedHashMap<MethodSymbol, String>();
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

    /**
     * Transitively collect all non-blank {@link InternalBody#value()} strings from the
     * interface hierarchy of {@code element} (including superclass interfaces) so that
     * cross-module {@code @BPFInterface} types whose {@code @InternalBody} lives on a
     * transitive superinterface (loaded from a pre-compiled jar) are also discovered.
     */
    private List<String> collectInternalBodies(TypeElement element) {
        var result = new ArrayList<String>();
        collectInternalBodiesInto(element, new java.util.LinkedHashSet<>(), result);
        return result;
    }

    private void collectInternalBodiesInto(TypeElement element, java.util.Set<String> seen, List<String> out) {
        for (TypeMirror iface : element.getInterfaces()) {
            var ifaceElem = (TypeElement) ((DeclaredType) iface).asElement();
            var qualName = ifaceElem.getQualifiedName().toString();
            if (!seen.add(qualName)) continue;
            InternalBody ann = ifaceElem.getAnnotation(InternalBody.class);
            if (ann == null && iface instanceof Type.ClassType klass && klass.tsym != null) {
                ann = klass.tsym.getAnnotation(InternalBody.class);
            }
            if (ann != null && !ann.value().isBlank()) {
                out.add(ann.value());
            }
            collectInternalBodiesInto(ifaceElem, seen, out);
        }
        // Also walk superclasses so that interfaces declared on abstract parent classes are found.
        var superClass = element.getSuperclass();
        if (superClass instanceof DeclaredType dt && dt.asElement() instanceof TypeElement superElem
                && !superElem.getQualifiedName().toString().equals("java.lang.Object")) {
            var qualName = superElem.getQualifiedName().toString();
            if (seen.add(qualName)) {
                collectInternalBodiesInto(superElem, seen, out);
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

    @Nullable
    VariableTree getMemberOptional(ClassTree klass, String name) {
        return klass.getMembers().stream()
                .filter(m -> m instanceof VariableTree)
                .map(m -> (VariableTree) m)
                .filter(m -> m.getName().contentEquals(name))
                .findFirst()
                .orElse(null);
    }

    public record FuncDecl(FunctionDeclarationStatement decl, boolean addDefine) {
    }

    boolean canEmitDeclaratorFor(FuncDecl decl) {
        return decl.addDefine && !decl.decl.declarator().toPrettyString().matches(".* [A-Z0-9_]+\\([a-z0-9A-Z_]+,.*\\).*");
    }

    /**
     * Synthesise a C forward-declaration (prototype) from a stored inherited
     * {@code @BPFFunction} body string. These bodies are injected verbatim for
     * {@code @BPF} subclasses (via {@code @InternalMethodDefinition}); without a
     * prototype an inherited body that calls another inherited function defined
     * later in the emitted text fails to compile ("use of undeclared identifier").
     *
     * <p>The signature is everything from the function's return type/attributes up
     * to the first {@code {} that opens the body; we return that substring trimmed
     * with a trailing {@code ;}. A stored string may be prefixed with one or more
     * {@code #define} lines (each on its own line) — those are skipped for the
     * prototype (they stay with the body block). Entries that are not plain function
     * definitions (no {@code {}, or a macro-style ALL_CAPS(a,...) call signature
     * mirroring {@link #canEmitDeclaratorFor}'s guard) get no prototype.
     *
     * @return the prototype string (without the {@code #define} prefix), or
     *         {@code null} if no safe prototype can be synthesised
     */
    @Nullable
    String extractFunctionPrototype(String body) {
        if (body == null) return null;
        // Strip any leading #define lines; the actual signature starts at the first
        // non-#define, non-blank line.
        var lines = body.lines().toList();
        int start = 0;
        while (start < lines.size()) {
            var t = lines.get(start).strip();
            if (t.startsWith("#define") || t.isEmpty()) {
                start++;
            } else {
                break;
            }
        }
        if (start >= lines.size()) return null;
        var funcText = String.join("\n", lines.subList(start, lines.size()));
        int brace = funcText.indexOf('{');
        if (brace < 0) return null;                     // not a function definition
        var signature = funcText.substring(0, brace).stripTrailing();
        if (signature.isBlank()) return null;
        // Skip kernel entry-points wrapped in SEC(...)/BPF_PROG(...)/BPF_STRUCT_OPS(...):
        // these macros themselves expand into a full declaration, so emitting a separate
        // prototype collides ("redefinition of 'sched_init'"). Such entry-points are called
        // by the kernel, never by other inherited bodies, so a prototype is never needed.
        if (signature.contains("SEC(") || signature.matches("(?s).*\\bBPF_(PROG|STRUCT_OPS|KPROBE|KRETPROBE|KSYSCALL)\\s*\\(.*")) {
            return null;
        }
        // Mirror canEmitDeclaratorFor: skip macro-expanded entries whose signature
        // looks like an ALL_CAPS(name,...) call rather than a normal declarator.
        if (signature.matches("(?s).* [A-Z0-9_]+\\([a-z0-9A-Z_]+,.*\\).*")) return null;
        return signature + ";";
    }

    /**
     * Collect file-scope {@code struct X;} forward declarations for every struct tag
     * referenced in the synthesised inherited-function prototypes.
     *
     * <p>When a subclass re-emits inherited bodies, their prototypes are placed above
     * the struct/map/#define block that {@code combineCode} appends after {@code code}.
     * A prototype mentioning an undeclared {@code struct QueuedTaskCtx} would otherwise
     * introduce a fresh prototype-scoped incomplete type, causing a "conflicting types"
     * error once the real file-scope struct is defined and the body is emitted. Emitting
     * {@code struct QueuedTaskCtx;} first pins the tag to file scope so prototype and
     * definition agree.
     *
     * @param prototypes the joined prototype block
     * @return a newline-joined block of {@code struct X;} declarations (may be empty)
     */
    String extractStructForwardDecls(String prototypes) {
        if (prototypes == null || prototypes.isBlank()) return "";
        var matcher = java.util.regex.Pattern.compile("\\bstruct\\s+([A-Za-z_][A-Za-z0-9_]*)").matcher(prototypes);
        var names = new java.util.LinkedHashSet<String>();
        while (matcher.find()) {
            names.add(matcher.group(1));
        }
        return names.stream().map(n -> "struct " + n + ";").collect(Collectors.joining("\n"));
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
