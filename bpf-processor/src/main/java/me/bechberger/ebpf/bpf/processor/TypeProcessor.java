package me.bechberger.ebpf.bpf.processor;

import com.squareup.javapoet.FieldSpec;
import com.sun.tools.javac.code.Attribute.Constant;
import com.sun.tools.javac.code.Symbol.MethodSymbol;
import com.sun.tools.javac.code.Type.ClassType;
import com.sun.tools.javac.tree.JCTree;
import com.sun.tools.javac.tree.JCTree.JCExpression;
import com.sun.tools.javac.tree.JCTree.JCNewClass;
import com.sun.tools.javac.tree.JCTree.JCTypeApply;
import com.sun.tools.javac.tree.JCTree.JCVariableDecl;
import me.bechberger.cast.CAST;
import me.bechberger.cast.CAST.PrimaryExpression.CAnnotation;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFInterface;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.bpf.processor.AnnotationUtils.AnnotationValues;
import me.bechberger.ebpf.bpf.processor.AnnotationUtils.AnnotationValues.AnnotationKind;
import me.bechberger.ebpf.bpf.processor.BPFTypeLike.*;
import me.bechberger.ebpf.bpf.processor.BPFTypeLike.VerbatimBPFOnlyType.PrefixKind;
import me.bechberger.ebpf.bpf.processor.DefinedTypes.BPFName;
import me.bechberger.ebpf.bpf.processor.DefinedTypes.JavaName;
import me.bechberger.ebpf.bpf.processor.DefinedTypes.SpecFieldName;
import me.bechberger.ebpf.type.*;
import me.bechberger.ebpf.type.BPFType.*;
import me.bechberger.ebpf.type.BPFType.BPFStructType.SourceClassKind;
import me.bechberger.ebpf.type.Enum;
import me.bechberger.ebpf.type.Typedef;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.annotation.processing.ProcessingEnvironment;
import javax.lang.model.element.*;
import javax.lang.model.type.*;
import java.util.*;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import com.sun.tools.javac.processing.JavacProcessingEnvironment;

import static me.bechberger.cast.CAST.Expression.*;
import static me.bechberger.cast.CAST.Statement.*;
import static me.bechberger.ebpf.NameUtil.toConstantCase;
import static me.bechberger.ebpf.bpf.processor.AnnotationUtils.*;

/**
 * Handles {@code @Type} annotated records
 */
public class TypeProcessor {

    public final static String TYPE_ANNOTATION = "me.bechberger.ebpf.annotations.Type";
    public final static String BPF_PACKAGE = "me.bechberger.ebpf.type";
    public final static String BPF_TYPE = "me.bechberger.ebpf.type.BPFType";
    public final static String BPF_MAP_DEFINITION = "me.bechberger.ebpf.annotations.bpf.BPFMapDefinition";
    public final static String SHARED_FROM_ANNOTATION = "me.bechberger.ebpf.annotations.bpf.SharedFrom";
    public final static String BPF_MAP_CLASS = "me.bechberger.ebpf.annotations.bpf.BPFMapClass";

    private final ProcessingEnvironment processingEnv;
    private final boolean allowUnsizedStrings;
    private final TypeUtils typeUtils;
    /** only use this where necessary because it is not part of the public API */
    private final JavacProcessingEnvironment javacProcessingEnv;
    private TypeElement outerTypeElement;
    private DefinedTypes definedTypes;
    private Map<JavaName, BPFTypeLike<?>> alreadyDefinedTypes;
    private Set<JavaName> currentlyDefining;
    private List<TypeElement> processedTypes;
    /** For generating the C code later */
    private List<CustomBPFType<?>> usedCustomBPFTypes;

    /**
     * Creates a new TypeProcessor
     *
     * @param processingEnv environment to use
     * @param allowUnsizedStrings allow Strings without {@link me.bechberger.ebpf.annotations.Size} annotation,
     *                            useful for code translation
     */
    public TypeProcessor(ProcessingEnvironment processingEnv, boolean allowUnsizedStrings) {
        this.processingEnv = processingEnv;
        this.typeUtils = new TypeUtils(processingEnv.getTypeUtils(), processingEnv.getElementUtils());
        this.javacProcessingEnv = (JavacProcessingEnvironment) processingEnv;
        this.allowUnsizedStrings = allowUnsizedStrings;
    }

    public TypeProcessor(ProcessingEnvironment processingEnv) {
        this(processingEnv, false);
    }

    /** Returns all records annotated with {@code @Type} and types specified in the {@link me.bechberger.ebpf.annotations.bpf.BPF} annotation */
    private List<TypeElement> getRequiredBPFTypeElements(TypeElement typeElement) {
        return Stream.concat(getInnerBPFTypeElements(typeElement).stream(), getBPFSpecifiedTypeElements(typeElement).stream()).toList();
    }

    private List<TypeElement> getInnerBPFTypeElements(TypeElement typeElement) {
        return typeElement.getEnclosedElements().stream().filter(this::isTypeAnnotatedRecord).map(e -> (TypeElement) e).toList();
    }

    private boolean isTypeAnnotatedRecord(Element element) {
        if (getAnnotationMirror(element, TYPE_ANNOTATION).isPresent()) {
           return isValidDataType(element) != DataTypeKind.NONE;
        }
        return false;
    }

    public enum DataTypeKind {
        STRUCT,
        UNION,
        TYPEDEF,
        ENUM,
        NONE
    }

    private boolean isNotUsableInJava(TypeElement element) {
        return hasAnnotation(element, "me.bechberger.ebpf.annotations.bpf.NotUsableInJava");
    }

    private TypeProcessor.DataTypeKind isValidDataType(Element element) {
        return isValidDataType(element, true);
    }

    public TypeProcessor.DataTypeKind isValidDataType(Element element, boolean log) {
        boolean implementsTypedef = typeUtils.implementsInterfaceIgnoringTypeParameters(element, Typedef.class);
        if (element.getKind() == ElementKind.ENUM) {
            if (implementsTypedef) {
                if (log) {
                    this.processingEnv.getMessager().printError("Class " + element.getSimpleName() + " is an enum but implements the Typedef interface", element);
                }
                return DataTypeKind.NONE;
            }
            if (!typeUtils.implementsInterfaceIgnoringTypeParameters(element, Enum.class)) {
                if (log) {
                    this.processingEnv.getMessager().printError("Enum " + element + " must implement the Enum interface", element);
                }
                return DataTypeKind.NONE;
            }
            return DataTypeKind.ENUM;
        }
        if (element.getKind() == ElementKind.RECORD) {
            // check that it has no super class
            if (((TypeElement) element).getSuperclass().getKind() != TypeKind.NONE && !((TypeElement) element).getSuperclass().toString().equals("java.lang.Record")){
                if (log) {
                    this.processingEnv.getMessager().printError("Class " + element.getSimpleName() + " is a record but has a super class", element);
                }
                return DataTypeKind.NONE;
            }
            // check that it has no generic type parameters
            if (!((TypeElement) element).getTypeParameters().isEmpty()) {
                if (log) {
                    var params = ((TypeElement) element).getTypeParameters().stream()
                            .map(tp -> tp.getSimpleName().toString())
                            .collect(Collectors.joining(", "));
                    this.processingEnv.getMessager().printError(
                            "@Type record " + element.getSimpleName() + " must not declare generic type parameters " +
                            "(BPF/C cannot represent type variables). Found: <" + params + ">", element);
                }
                return DataTypeKind.NONE;
            }
            if (implementsTypedef) {
                return DataTypeKind.TYPEDEF;
            }
            return DataTypeKind.STRUCT;
        }
        if (element.getKind() == ElementKind.CLASS) {
            // check that it is a static class
            if (!element.getModifiers().contains(Modifier.STATIC)) {
                if (log) {
                    this.processingEnv.getMessager().printError("Class " + element.getSimpleName() + " is a class but not static", element);
                }
                return DataTypeKind.NONE;
            }
            // check if it is a union
            if (typeUtils.hasSuperClass(element, Union.class)) {
                if (implementsTypedef) {
                    if (log) {
                        this.processingEnv.getMessager().printError("Class " + element + " is a union and must not implement the Typedef interface", element);
                    }
                }
                return DataTypeKind.UNION;
            }
            if (typeUtils.hasSameSuperclassIgnoringTypeParameters(element, TypedefBase.class)) {
                if (implementsTypedef && log) {
                    this.processingEnv.getMessager().printError("Class " + element + " is a typedef and must not extend also TypedefBase", element);
                }
                return DataTypeKind.TYPEDEF;
            }
            // check if it either extends Object or Struct, so it can be a struct
            if (!typeUtils.hasSuperClass(element, Object.class) && !typeUtils.hasSuperClass(element, Struct.class) && ((TypeElement)element).getSuperclass().getKind() != TypeKind.NONE) {
                if (log) {
                    this.processingEnv.getMessager().printError("Class " + element + " is a class but does not extend Object, Union or Struct", element);
                }
            }
            return DataTypeKind.STRUCT;
        }
        return DataTypeKind.NONE;
    }

    private boolean isCustomTypeAnnotatedRecord(Element element) {
        return getAnnotationMirror(element, "me.bechberger.ebpf.annotations.CustomType").isPresent();
    }

    /** Returns all types specified in the {@link me.bechberger.ebpf.annotations.bpf.BPF} annotation */
    private List<TypeElement> getBPFSpecifiedTypeElements(TypeElement typeElement) {
        var annotation = getAnnotationMirror(typeElement, "me.bechberger.ebpf.annotations.bpf.BPF");
        if (annotation.isEmpty()) {
            return List.of();
        }
        var specifiedClasses = AnnotationUtils.getAnnotationValue(annotation.get(), "includeTypes", List.of());
        return specifiedClasses.stream().map(c -> {
            String klass = c.toString().substring(0, c.toString().length() - ".class".length());
            return processingEnv.getElementUtils().getTypeElement(klass);
        }).toList();
    }

    /**
     * Per-method prologue statements collected from {@code @BPFAbstraction} field initialisers.
     * Key = target method name (from {@code @BPFAbstraction#constructorPrependTo}),
     * value = ordered list of C side-effect statements to prepend to that method's body.
     * {@code abstractionFieldCarriers}: field name → resolved C carrier expression (for {@code <auto>} DSQ ids).
     */
    public record TypeProcessorResult(List<FieldSpec> fields, List<Define> defines, List<CAST.Statement> definingStatements,
                               @Nullable Statement licenseDefinition, List<MapDefinition> mapDefinitions,
                               List<GlobalVariableDefinition> globalVariableDefinitions, InterfaceAdditions additions,
                               Map<String, List<String>> abstractionFieldPrologues,
                               Map<String, String> abstractionFieldCarriers) {
        /** Back-compat constructor for call-sites that don't supply abstractionFieldPrologues/Carriers. */
        public TypeProcessorResult(List<FieldSpec> fields, List<Define> defines, List<CAST.Statement> definingStatements,
                                   @Nullable Statement licenseDefinition, List<MapDefinition> mapDefinitions,
                                   List<GlobalVariableDefinition> globalVariableDefinitions, InterfaceAdditions additions) {
            this(fields, defines, definingStatements, licenseDefinition, mapDefinitions, globalVariableDefinitions,
                    additions, Map.of(), Map.of());
        }
        /** Back-compat constructor without carriers. */
        public TypeProcessorResult(List<FieldSpec> fields, List<Define> defines, List<CAST.Statement> definingStatements,
                                   @Nullable Statement licenseDefinition, List<MapDefinition> mapDefinitions,
                                   List<GlobalVariableDefinition> globalVariableDefinitions, InterfaceAdditions additions,
                                   Map<String, List<String>> abstractionFieldPrologues) {
            this(fields, defines, definingStatements, licenseDefinition, mapDefinitions, globalVariableDefinitions,
                    additions, abstractionFieldPrologues, Map.of());
        }
    }

    boolean shouldGenerateCCode(TypeElement innerElement) {
        if (innerElement.getEnclosingElement().getKind() == ElementKind.INTERFACE && outerTypeElement.getKind() != ElementKind.INTERFACE) {
            return false;
        }
        return !getAnnotationMirror(innerElement, TYPE_ANNOTATION).map(a -> getAnnotationValue(a, "noCCodeGeneration", false)).orElse(false);
    }

    boolean isTypedefedType(TypeElement innerElement) {
        return getAnnotationMirror(innerElement, TYPE_ANNOTATION).map(a -> getAnnotationValue(a, "typedefed", false)).orElse(false);
    }

    /**
     * Process the records annotated with {@code @Type} in the given class
     *
     * @param outerTypeElement the class to process that contains the records
     * @return a list of field specs that define the related {@code BPFStructType} instances
     */
    public @Nullable TypeProcessorResult processBPFTypeRecords(TypeElement outerTypeElement) {
        this.outerTypeElement = outerTypeElement;
        List<TypeElement> predefinedTypeElements = getRequiredBPFTypeElements(outerTypeElement);
        // we initialize the defined types with the predefined types
        definedTypes = getDefinedTypes(predefinedTypeElements);

        alreadyDefinedTypes = new HashMap<>();
        // detect recursion
        currentlyDefining = new HashSet<>();

        processedTypes = new ArrayList<>();

        usedCustomBPFTypes = new ArrayList<>();

        Function<BPFTypeLike<?>, SpecFieldName> typeToSpecField = t -> t.getSpecFieldName(definedTypes);

        while (true) {
            var unprocessed = predefinedTypeElements.stream().filter(e -> !processedTypes.contains(e)).toList();
            if (unprocessed.isEmpty()) {
                break;
            }
            var type = processBPFTypeRecord(unprocessed.getFirst());
            if (type.isEmpty()) {
                return new TypeProcessorResult(List.of(), List.of(), List.of(), null, List.of(), createGlobalVariableDefinitions(outerTypeElement, typeToSpecField),
                        new InterfaceAdditions(List.of(), List.of(), List.of()));
            }
            alreadyDefinedTypes.put(type.get().getJavaName(), type.get());
            processedTypes.add(unprocessed.getFirst());
        }

        var mapDefinitions = processDefinedMaps(outerTypeElement,
                field -> getBPFTypeForJavaName(definedTypes.bpfNameToName(definedTypes.specFieldNameToName(field))),
                type -> definedTypes.getSpecFieldName(type.getBPFName()).get());

        var globals = createGlobalVariableDefinitions(outerTypeElement, typeToSpecField);

        var defines = createDefineStatements(outerTypeElement);

        List<FieldSpec> fields = new ArrayList<>();
        List<CAST.Statement> definingStatements = new ArrayList<>();

        // add custom type definitions
        usedCustomBPFTypes.stream().map(CustomBPFType::toCDeclaration)
                .forEach(c -> c.ifPresent(definingStatements::add));

        for (var processedType : processedTypes) {
            if (isCustomTypeAnnotatedRecord(processedType)) {
                continue;
            }
            var name = getTypeRecordBpfName(processedType);
            var type = alreadyDefinedTypes.get(new JavaName(processedType));
            var fieldSpecName = definedTypes.getSpecFieldName(name).get().name();
            assert type instanceof BPFTypeLike.TypeBackedBPFTypeLike<?>;
            var actualType = ((TypeBackedBPFTypeLike<?>) type).type;
            var spec = actualType.toFieldSpecGenerator().get().apply(fieldSpecName,
                    t -> t.toJavaFieldSpecUse(t2 -> typeToSpecField.apply(BPFTypeLike.of(t2)).name()));
            fields.add(spec);
            if (shouldGenerateCCode(processedType)) {
                actualType.toCDeclarationStatement().ifPresent(definingStatements::add);
            }
        }
        // Emit C global-variable declarations for @InArena class fields.
        processInArenaFields(outerTypeElement, definingStatements);
        var additions = getInterfaceAdditions(outerTypeElement.asType());
        if (additions == null) {
            return null;
        }
        var abstractionResult = collectAbstractionFieldPrologues(outerTypeElement);
        return new TypeProcessorResult(fields, defines, definingStatements,
                getLicenseDefinitionStatement(outerTypeElement), mapDefinitions,
                globals,
                additions,
                abstractionResult.prologues(),
                abstractionResult.carriers());
    }

    private static final String IN_ARENA_ANNOTATION = "me.bechberger.ebpf.annotations.InArena";
    private static final String PTR_CLASS = "me.bechberger.ebpf.type.Ptr";

    /**
     * Scans {@code outerTypeElement}'s fields for {@code @InArena Ptr<T>} declarations
     * and appends a {@code __arena T *fieldName;} C global-variable statement for each.
     *
     * <p>These globals must appear after the struct/type declarations (which the caller
     * has already added) so clang can resolve the pointed-to type.
     */
    private void processInArenaFields(TypeElement outerTypeElement, List<CAST.Statement> definingStatements) {
        for (var enclosed : outerTypeElement.getEnclosedElements()) {
            if (enclosed.getKind() != ElementKind.FIELD) continue;
            var field = (VariableElement) enclosed;
            // Check @InArena annotation (SOURCE retention — visible to processors)
            if (!hasAnnotation(field, IN_ARENA_ANNOTATION)) continue;
            var fieldType = field.asType();
            if (!(fieldType instanceof DeclaredType declaredType)) continue;
            // Must be Ptr<T>
            var erasure = processingEnv.getTypeUtils().erasure(fieldType);
            if (!erasure.toString().equals(PTR_CLASS)) continue;
            var typeArgs = declaredType.getTypeArguments();
            if (typeArgs.isEmpty()) continue;
            var pointedTo = typeArgs.get(0);
            // Resolve the pointed-to type's BPF/C name
            String cTypeName = resolveCNameForArenaPointee(pointedTo);
            if (cTypeName == null) {
                processingEnv.getMessager().printWarning(
                        "@InArena field '" + field.getSimpleName() + "': could not resolve C type for "
                                + pointedTo + "; skipping global declaration", field);
                continue;
            }
            var fieldName = field.getSimpleName().toString();
            definingStatements.add(CAST.Statement.verbatim("__arena " + cTypeName + " *" + fieldName + ";"));
        }
    }

    /**
     * Given the {@code TypeMirror} of the pointee type in an {@code @InArena Ptr<T>}
     * field, returns the C type name (the BPF struct name), or {@code null} if unknown.
     */
    private @Nullable String resolveCNameForArenaPointee(TypeMirror pointedTo) {
        if (!(pointedTo instanceof DeclaredType declaredPointee)) return null;
        var element = (TypeElement) declaredPointee.asElement();
        var javaName = new JavaName(element);
        var found = alreadyDefinedTypes.get(javaName);
        if (found != null) {
            return found.getBPFNameWithStructPrefixIfNeeded();
        }
        // Fall back to simple name (covers @Type records whose name equals simpleClass name)
        return element.getSimpleName().toString();
    }

    private static final String BPF_ABSTRACTION_ANNOTATION = "me.bechberger.ebpf.annotations.bpf.BPFAbstraction";
    private static final String BUILTIN_BPF_FUNCTION_ANNOTATION = "me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction";

    public record GlobalVariableDefinition(Statement globalVariable, String name, String typeField, String initializer) {}

    /**
     * Scans {@code outerTypeElement}'s fields for those whose declared type is annotated
     * with {@code @BPFAbstraction}.  For each such field whose constructor carries a
     * non-empty {@code @BuiltinBPFFunction#value()} side-effect, records that statement
     * (with {@code $arg1…} placeholders resolved against the constructor arguments) keyed
     * by the abstraction's {@code constructorPrependTo} method name.
     *
     * @return map from target-method-name → ordered list of prologue C statements
     */
    /** Base value for auto-allocated DSQ ids: 0x1_0000_0000 (above user-id range). */
    private static final long AUTO_DSQ_ID_BASE = 0x1_0000_0000L;

    private record AbstractionPrologueResult(Map<String, List<String>> prologues, Map<String, String> carriers) {}

    private AbstractionPrologueResult collectAbstractionFieldPrologues(TypeElement outerTypeElement) {
        var prologues = new LinkedHashMap<String, List<String>>();
        var carriers = new LinkedHashMap<String, String>();
        int autoIdCounter = 0;
        for (var enclosed : outerTypeElement.getEnclosedElements()) {
            if (enclosed.getKind() != ElementKind.FIELD) continue;
            var field = (VariableElement) enclosed;
            if (field.getModifiers().contains(Modifier.STATIC)) continue;
            var fieldType = field.asType();
            if (!(fieldType instanceof DeclaredType declaredType)) continue;
            var typeElem = (TypeElement) declaredType.asElement();
            var abstractionMirror = getAnnotationMirror(typeElem, BPF_ABSTRACTION_ANNOTATION);
            if (abstractionMirror.isEmpty()) continue;

            // @BPFAbstraction(constructorPrependTo = ?) — default "init"
            var prependTo = getAnnotationValue(abstractionMirror.get(), "constructorPrependTo", "init");

            // field must be final
            if (!field.getModifiers().contains(Modifier.FINAL)) {
                processingEnv.getMessager().printError(
                        "@BPFAbstraction field '" + field.getSimpleName() + "' must be final", field);
                continue;
            }

            // inspect the field initializer in the AST
            var classTree = javacProcessingEnv.getElementUtils().getTree(outerTypeElement);
            JCVariableDecl varDecl = null;
            if (classTree instanceof JCTree.JCClassDecl classDecl) {
                for (var member : classDecl.getMembers()) {
                    if (member instanceof JCVariableDecl vd
                            && vd.getName().contentEquals(field.getSimpleName())) {
                        varDecl = vd;
                        break;
                    }
                }
            }
            if (varDecl == null || !(varDecl.init instanceof JCNewClass newClass)) {
                continue;
            }

            // find the matching constructor on the abstraction class
            MethodSymbol ctor = findMatchingConstructor(typeElem, newClass);
            if (ctor == null) continue;

            var builtinAnn = getAnnotationMirror(ctor, BUILTIN_BPF_FUNCTION_ANNOTATION);
            if (builtinAnn.isEmpty()) continue;

            // Resolve the carrier (needed for <auto> substitution)
            var carrierTemplate = AnnotationUtils.getAnnotationValue(builtinAnn.get(), "carrier", "");
            var fieldName = field.getSimpleName().toString();
            String resolvedCarrier = null;
            if (carrierTemplate.contains("<auto>")) {
                // Mint a unique u64 id for this field, stable within the class.
                var autoId = "0x" + Long.toHexString(AUTO_DSQ_ID_BASE + autoIdCounter++) + "ULL";
                resolvedCarrier = autoId;
                carriers.put(fieldName, resolvedCarrier);
            } else if (!carrierTemplate.isBlank()) {
                resolvedCarrier = resolvePlaceholders(carrierTemplate, newClass.getArguments());
                carriers.put(fieldName, resolvedCarrier);
            }

            var sideEffect = AnnotationUtils.getAnnotationValue(builtinAnn.get(), "value", "");
            if (sideEffect.isBlank() || prependTo.isBlank()) continue; // no side effect or disabled

            // resolve $arg1, $arg2, … and <auto> in the side-effect template
            String resolved;
            if (sideEffect.contains("<auto>") && resolvedCarrier != null) {
                resolved = resolvePlaceholders(sideEffect, newClass.getArguments())
                        .replace("<auto>", resolvedCarrier);
            } else {
                resolved = resolvePlaceholders(sideEffect, newClass.getArguments());
            }
            if (!resolved.endsWith(";")) resolved = resolved + ";";
            prologues.computeIfAbsent(prependTo, k -> new ArrayList<>()).add(resolved);
        }
        return new AbstractionPrologueResult(prologues, carriers);
    }

    /** Return the resolved constructor from the javac-typed {@code newClass} node. */
    @Nullable
    private MethodSymbol findMatchingConstructor(TypeElement abstractionClass, JCNewClass newClass) {
        // javac has already resolved the constructor; use the resolved symbol directly.
        if (newClass.constructor instanceof com.sun.tools.javac.code.Symbol.MethodSymbol ms) {
            return ms;
        }
        // Fallback: match by arity, preferring constructors where the parameter type matches the arg's type.
        int arity = newClass.getArguments().size();
        MethodSymbol firstMatch = null;
        for (var enc : abstractionClass.getEnclosedElements()) {
            if (enc.getKind() != ElementKind.CONSTRUCTOR) continue;
            var ctor = (javax.lang.model.element.ExecutableElement) enc;
            if (ctor.getParameters().size() != arity) continue;
            if (firstMatch == null) firstMatch = (MethodSymbol) enc;
            if (arity == 1) {
                var paramType = ctor.getParameters().get(0).asType().toString();
                // Prefer long param over int param
                if (paramType.equals("long") || paramType.contains("long")) {
                    return (MethodSymbol) enc;
                }
            }
        }
        return firstMatch;
    }

    /**
     * Replace {@code $arg1}, {@code $arg2}, … in {@code template} with the string
     * representation of the corresponding constructor call arguments.
     */
    private String resolvePlaceholders(String template, com.sun.tools.javac.util.List<JCExpression> args) {
        var result = template;
        for (int i = 0; i < args.size(); i++) {
            result = result.replace("$arg" + (i + 1), renderArg(args.get(i)));
        }
        return result;
    }

    private String renderArg(JCExpression arg) {
        return arg.toString();
    }

    private List<GlobalVariableDefinition> createGlobalVariableDefinitions(TypeElement outerTypeElement, Function<BPFTypeLike<?>, SpecFieldName> typeToSpecField) {
        var result = new ArrayList<GlobalVariableDefinition>();
        var seenNames = new java.util.HashSet<String>();
        TypeElement current = outerTypeElement;
        while (current != null && !current.getQualifiedName().toString().equals("java.lang.Object")) {
            for (var e : current.getEnclosedElements()) {
                if (e.getKind() != ElementKind.FIELD) continue;
                var field = (VariableElement) e;
                if (!typeUtils.hasClassIgnoringTypeParameters(field, "me.bechberger.ebpf.bpf.GlobalVariable")) continue;
                if (!seenNames.add(field.getSimpleName().toString())) continue;
                var def = processGlobalVariable(field, typeToSpecField);
                if (def != null) result.add(def);
            }
            var superMirror = current.getSuperclass();
            var superElem = (superMirror != null && superMirror.getKind() != javax.lang.model.type.TypeKind.NONE)
                    ? processingEnv.getTypeUtils().asElement(superMirror) : null;
            current = (superElem instanceof TypeElement te) ? te : null;
        }
        return result;
    }


    private @Nullable GlobalVariableDefinition processGlobalVariable(VariableElement field, Function<BPFTypeLike<?>, SpecFieldName> typeToSpecField) {
        // check that the field is final
        if (!field.getModifiers().contains(Modifier.FINAL)) {
            this.processingEnv.getMessager().printError("Global variable field " + field.getSimpleName() + " must be final", field);
            return null;
        }
        // check that field is not static
        if (field.getModifiers().contains(Modifier.STATIC)) {
            this.processingEnv.getMessager().printError("Global variable field " + field.getSimpleName() + " must not be static", field);
            return null;
        }
        // get the type from the type parameter
        var type = ((DeclaredType) field.asType()).getTypeArguments().getFirst();
        var bpfTypeMirror = processBPFTypeRecordMemberType(field, getAnnotationValuesForRecordMember(type), type);
        if (type instanceof ClassType classType && typeUtils.hasClassIgnoringTypeParameters(classType.asElement(), Box.class.getName())) {
            this.processingEnv.getMessager().printError("Global variable field " + field.getSimpleName() + " must not be a Box and you don't need this wrapper here", field);
            return null;
        }
        if (bpfTypeMirror.isEmpty()) {
            return null;
        }
        var bpfType = bpfTypeMirror.get().toBPFType(this::getBPFTypeForJavaName);
        var typeField = bpfType.toCustomType().toJavaFieldSpecUse(t -> typeToSpecField.apply(BPFTypeLike.of(t)).name());

        String initializer = "";
        var tree = javacProcessingEnv.getElementUtils().getTree(field);
        if (tree instanceof JCVariableDecl varDecl) {
            var init = varDecl.init;
            if (init == null) {
                this.processingEnv.getMessager().printError("Global variable field " + field.getSimpleName() + " must have an initializer", field);
                return null;
            }
            if (!(init instanceof JCNewClass) || !((JCTypeApply) ((JCNewClass) init).clazz).getType().toString().equals("GlobalVariable")) {
                this.processingEnv.getMessager().printError("Global variable field " + field.getSimpleName() + " must be initialized with a new GlobalVariable", field);
                return null;
            }
            var args = ((JCNewClass) init).getArguments();
            assert args.size() == 1;
            initializer = args.getFirst().toString();
        }
        // If tree is null (field from a compiled superclass jar), we emit the C declaration
        // and leave the initializer empty — initGlobals() only needs g.name() and g.typeField().
        var definition = variableDefinition(bpfType.toCustomType().cUse().get(),
                variable(field.getSimpleName().toString(),
                        CAnnotation.sec(".data")));
        return new GlobalVariableDefinition(definition, field.getSimpleName().toString(), typeField, initializer);
    }

    private BPFTypeLike<?> getBPFTypeForJavaName(JavaName name) {
        Objects.requireNonNull(name);
        if (alreadyDefinedTypes.containsKey(name)) {
            return alreadyDefinedTypes.get(name);
        }
        if (currentlyDefining.contains(name)) {
            this.processingEnv.getMessager().printError("Recursion detected for type " + name, outerTypeElement);
            throw new IllegalStateException("Recursion detected for type " + name);
        }
        currentlyDefining.add(name);
        var bpfName = definedTypes.nameToBPFName(name);
        var typeElementOpt = definedTypes.getTypeElement(bpfName);
        if (typeElementOpt.isEmpty()) {
            this.processingEnv.getMessager().printError("Type " + name + " not defined", outerTypeElement);
            return null;
        }
        var typeElement = typeElementOpt.get();
        var type = processBPFTypeRecord(typeElement);
        if (type.isEmpty()) {
            this.processingEnv.getMessager().printError("Type " + name + " could not be processed", outerTypeElement);
            return null;
        }
        alreadyDefinedTypes.put(name, type.get());
        currentlyDefining.remove(name);
        processedTypes.add(typeElement);
        return type.get();
    }

    private @Nullable Statement getLicenseDefinitionStatement(TypeElement outerTypeElement) {
        var annotation = getAnnotationMirror(outerTypeElement, "me.bechberger.ebpf.annotations.bpf.BPF");
        if (annotation.isEmpty()) {
            return null;
        }
        var license = AnnotationUtils.getAnnotationValue(annotation.get(), "license", "");
        if (license.isEmpty()) {
            return null;
        }
        // char _license[] SEC ("license") = "GPL";
        return variableDefinition(Declarator.array(Declarator.identifier("char"), null), variable("_license", CAnnotation.sec("license")), constant(license));
    }

    public record InterfaceAdditions(List<String> includes, List<String> before, List<String> after) {}

    private InterfaceAdditions getInterfaceAdditions(TypeMirror outerType) {
        List<String> includes = new ArrayList<>();
        var outerTypeElement = (TypeElement) ((DeclaredType) outerType).asElement();
        var annotation = outerTypeElement.getAnnotation(BPF.class);
        if (annotation != null) {
            includes.addAll(List.of(annotation.includes()));
        }
        includes.addAll(getIncludesOfInterface(outerType));
        List<String> before = new ArrayList<>();
        List<String> after = new ArrayList<>();

        boolean hadError = false;

        for (var inter : getInterfaces(outerType)) {
            var interElement = ((ClassType) inter).asElement();
            var interAnnotation = interElement.getAnnotation(BPFInterface.class);
            if (interAnnotation == null) {
                continue;
            }
            var beforeLine = interAnnotation.before();
            if (!beforeLine.isEmpty()) {
                before.add(beforeLine.strip());
            }
            var afterLine = interAnnotation.after();
            if (!afterLine.isEmpty()) {
                after.add(afterLine.strip());
            }
            for (var include : getIncludesOfInterface(inter)) {
                if (!includes.contains(include)) {
                    includes.add(include);
                }
            }
        }
        if (hadError) {
            return null;
        }
        return new InterfaceAdditions(includes, before, after);
    }

    private List<TypeMirror> getInterfaces(TypeMirror outerType) {
        var outerTypeElement = (TypeElement) ((DeclaredType) outerType).asElement();
        var interfaces = new ArrayList<TypeMirror>();
        outerTypeElement.getInterfaces().forEach(t -> {
            interfaces.add(t);
            interfaces.addAll(getInterfaces(t));
        });
        return interfaces;
    }

    private List<String> getIncludesOfInterface(TypeMirror outerType) {
        var annotation = getAnnotationMirror(((ClassType)outerType).asElement(), "me.bechberger.ebpf.annotations.Includes");
        return annotation.map(annotationMirror -> AnnotationUtils.getAnnotationValue(annotationMirror, "value", List.of())
                .stream().map(v -> (String)((Constant)v).getValue()).toList()).orElse(List.of());
    }

    public @Nullable CAST.Statement.Define processField(VariableElement field) {
        // check that the field is static, final and of type boolean, ..., int, long, float, double or String
        // create a #define statement for the field
        // return the #define statement
        if (!field.getModifiers().contains(Modifier.STATIC) || !field.getModifiers().contains(Modifier.FINAL) || field.getSimpleName().toString().equals("EBPF_PROGRAM")) {
            return null;
        }
        if (getAnnotationMirror(field, "me.bechberger.ebpf.annotations.bpf.JavaOnly").isPresent()) {
            return null;
        }
        TypeMirror type = field.asType();
        return switch (type.toString()) {
            case "boolean" ->
                    define(field.getSimpleName().toString(), constant(field.getConstantValue().equals(true) ? "1" : "0"));
            case "byte", "short", "int", "long", "float", "double" ->
                    new Define(field.getSimpleName().toString(), constant(field.getConstantValue()));
            case "java.lang.String" ->
                    new Define(field.getSimpleName().toString(), constant(field.getConstantValue().toString()));
            default -> null;
        };
    }

    private List<Define> createDefineStatements(TypeElement typeElement) {
        // idea: find all static final fields with type boolean, ..., int, long, float, double or String of the typeElement
        // create a #define statement for each of them (name is the field name)
        // return the list of #define statements
        return typeElement.getEnclosedElements().stream().filter(e -> e.getKind() == ElementKind.FIELD).map(e -> (VariableElement) e).map(this::processField).filter(Objects::nonNull).toList();
    }

    /**
     * Obtains the name from the Type annotation, if not present uses the simple name of the type
     */
    BPFName getTypeRecordBpfName(TypeElement typeElement) {
        var annotation = getAnnotationMirror(typeElement, "me.bechberger.ebpf.annotations.Type");
        if (annotation.isEmpty()) {
            annotation = getAnnotationMirror(typeElement, "me.bechberger.ebpf.annotations.CustomType");
        }
        return new BPFName(annotation.flatMap(a -> Optional.ofNullable(getAnnotationValue(a, "name", (String)null)))
                .orElse(typeElement.getSimpleName().toString()));
    }

    private Optional<? extends TypeBackedBPFTypeLike<?>> processBPFTypeRecord(TypeElement typeElement) {
        String className = typeElement.getQualifiedName().toString().replace("$", ".");
        var name = getTypeRecordBpfName(typeElement);

        var t = isValidDataType(typeElement);
        return switch (t) {
            case STRUCT -> processBPFTypeStruct(typeElement, className, name);
            case UNION -> processBPFTypeUnion(typeElement, className, name);
            case TYPEDEF -> processBPFTypeTypedef(typeElement, className, name);
            case ENUM -> processBPFTypeEnum(typeElement, className, name);
            case NONE -> Optional.empty();
        };
    }

    private Optional<TypeBackedBPFEnumType<?>> processBPFTypeEnum(TypeElement typeElement, String className, BPFName name) {
        var elementTypeParameter = typeElement.getInterfaces().stream()
                .filter(t -> t.toString().startsWith(TypedEnum.class.getCanonicalName())).findFirst().map(
                        t -> ((DeclaredType) t).getTypeArguments().get(1)
                ).flatMap(t -> processBPFTypeRecordMemberType(typeElement, getAnnotationValuesForRecordMember(t), t));

        var enumMembers = typeElement.getEnclosedElements().stream().filter(e -> e.getKind() == ElementKind.ENUM_CONSTANT).map(e -> (VariableElement) e).toList();
        var members = new ArrayList<BPFEnumMember>();
        long currentValue = 0;
        Map<String, Element> cNames = new HashMap<>();
        for (var member : enumMembers) {
            long value = getAnnotationMirror(member, "me.bechberger.ebpf.annotations.EnumMember")
                    .map(a -> getAnnotationValue(a, "value", -1L)).orElse(currentValue);
            if (value == -1L) {
                value = currentValue;
            }
            var memberName = member.getSimpleName().toString();
            var memberCNameValue = getAnnotationMirror(member, "me.bechberger.ebpf.annotations.EnumMember")
                    .map(a -> getAnnotationValue(a, "name", "")).orElse("");
            if (memberCNameValue.isEmpty()) {
                memberCNameValue = toConstantCase(name.name() + "_" + memberName);
            }
            if (cNames.containsKey(memberCNameValue)) {
                this.processingEnv.getMessager().printError("Enum member " + member.getSimpleName() + " has a duplicate name, " + typeElement.getSimpleName() + "::" + cNames.get(memberCNameValue) + " has the same C name", member);
                return Optional.empty();
            }
            cNames.put(memberCNameValue, member);
            members.add(new BPFEnumMember(memberName, memberCNameValue, value));
            currentValue = value + 1;
        }
        BPFType.AnnotatedClass annotatedClass = new BPFType.AnnotatedClass(className, List.of());
        if (elementTypeParameter.isEmpty()) {
            return Optional.of(new TypeBackedBPFEnumType<>(new BPFType.BPFEnumType<>(name.name(), members, annotatedClass, null)));
        }
        return Optional.of(new TypeBackedBPFEnumType<>(new BPFType.BPFEnumType<>(name.name(), elementTypeParameter.orElseThrow().toBPFType(this::getBPFTypeForJavaName).toCustomType(), members, annotatedClass, null)));
    }

    @SuppressWarnings({"unchecked"})
    private Optional<TypeBackedBPFTypedef<?, ?>> processBPFTypeTypedef(TypeElement typeElement, String className, BPFName name) {
        TypeMirror typeParameter;
        if (typeElement.getKind() == ElementKind.RECORD) {
            // find the extended Typedef interface and get its type parameter
            typeParameter = ((DeclaredType) typeElement.getInterfaces().stream()
                    .filter(t -> t.toString().startsWith(Typedef.class.getCanonicalName())).findFirst().orElseThrow()
            ).getTypeArguments().getFirst();
        } else {
            assert typeElement.getKind() == ElementKind.CLASS;
            // find the extended TypedefBase class and get its type parameter
            typeParameter = ((DeclaredType) typeElement.getSuperclass()).getTypeArguments().getFirst();
        }
        var innerType = processBPFTypeRecordMemberType(typeElement, getAnnotationValuesForRecordMember(typeParameter), typeParameter);
        if (innerType.isEmpty()) {
            return Optional.empty();
        }

        BPFType.AnnotatedClass annotatedClass = new BPFType.AnnotatedClass(className, List.of());
        return Optional.of(new TypeBackedBPFTypedef<>((BPFTypedef<?, ? extends Typedef<?>>) new BPFTypedef<>(name.name(),
                innerType.get().toBPFType(this::getBPFTypeForJavaName).toCustomType(), annotatedClass, null)));
    }

    record StructProcResult(Optional<List<BPFType.UBPFStructMember<?, ?>>> members, SourceClassKind kind) {}

    @SuppressWarnings({"unchecked", "rawtypes"})
    private Optional<TypeBackedBPFStructType<?>> processBPFTypeStruct(TypeElement typeElement, String className, BPFName name) {
        StructProcResult result;
        if (typeElement.getKind() == ElementKind.RECORD) {
            result = processBPFTypeRecordStruct(typeElement, className, name);
        } else {
            result = processBPFTypeClassStruct(typeElement, className, name);
        }

        if (result.members.isEmpty()) {
            return Optional.empty();
        }

        BPFType.AnnotatedClass annotatedClass = new BPFType.AnnotatedClass(className, List.of());

        return Optional.of(new TypeBackedBPFStructType<>(BPFType.BPFStructType.autoLayout(name.name(),
                (List<BPFType.UBPFStructMember<Object, ?>>) (List) result.members.get(),
                annotatedClass, null, result.kind, isTypedefedType(typeElement))));
    }

    private StructProcResult processBPFTypeRecordStruct(TypeElement typeElement, String className, BPFName name) {
        var constructors =
                typeElement.getEnclosedElements().stream().filter(e -> e.getKind() == ElementKind.CONSTRUCTOR).toList();
        if (constructors.size() != 1) {
            this.processingEnv.getMessager().printError("Record " + typeElement.getSimpleName() + " must have " +
                    "exactly" + " one " + "constructor", typeElement);
            return new StructProcResult(Optional.empty(), null);
        }
        var constructor = (ExecutableElement) constructors.getFirst();
        return new StructProcResult(
                processBPFTypeRecordMembers(constructor.getParameters(), className, true, SourceClassKind.RECORD), SourceClassKind.RECORD);
    }

    private StructProcResult processBPFTypeClassStruct(TypeElement typeElement, String className, BPFName name) {
        var constructors =
                typeElement.getEnclosedElements().stream().filter(e -> e.getKind() == ElementKind.CONSTRUCTOR).toList();

        // has default constructor
        boolean hasDefaultConstructor = constructors.stream().anyMatch(e -> ((ExecutableElement) e).getParameters().isEmpty());

        // get fields
        var fields = typeElement.getEnclosedElements().stream().filter(e -> e.getKind() == ElementKind.FIELD).map(e -> (VariableElement) e).toList();

        boolean hasConstructorWithFieldsInOrder = constructors.stream().anyMatch(e -> {
            var constructor = (ExecutableElement) e;
            var constructorFields = constructor.getParameters();

            return fields.size() == constructorFields.size() &&
                    IntStream.range(0, fields.size())
                            .allMatch(i -> this.processingEnv.getTypeUtils().isSameType(constructorFields.get(i).asType(), fields.get(i).asType()));
        });

        if (!hasDefaultConstructor && !hasConstructorWithFieldsInOrder) {
            this.processingEnv.getMessager().printError("Class " + typeElement.getSimpleName() + " must have " +
                    "either a default constructor or a constructor with fields in order", typeElement);
            return new StructProcResult(Optional.empty(), null);
        }

        var kind = hasConstructorWithFieldsInOrder ? SourceClassKind.CLASS_WITH_CONSTRUCTOR : SourceClassKind.CLASS;
        return new StructProcResult(
                processBPFTypeRecordMembers(fields, className, true, kind), kind);
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private Optional<TypeBackedBPFUnionType<?>> processBPFTypeUnion(TypeElement typeElement, String className, BPFName name) {
        var constructors =
                typeElement.getEnclosedElements().stream().filter(e -> e.getKind() == ElementKind.CONSTRUCTOR).toList();
        if (constructors.size() != 1 || !((ExecutableElement)constructors.getFirst()).getParameters().isEmpty()) {
            this.processingEnv.getMessager().printError("Union class " + typeElement.getSimpleName() + " must only have the default constructor",
                    typeElement);
            return Optional.empty();
        }
        var constructor = (ExecutableElement) constructors.getFirst();
        Optional<List<BPFType.UBPFStructMember<?, ?>>> membersOpt =
                processBPFTypeRecordMembers(typeElement.getEnclosedElements().stream().filter(e -> e.getKind() == ElementKind.FIELD).map(e -> (VariableElement) e).toList(), className, false, SourceClassKind.CLASS);
        if (membersOpt.isEmpty()) {
            return Optional.empty();
        }

        var members = membersOpt.get();

        BPFType.AnnotatedClass annotatedClass = new BPFType.AnnotatedClass(className, List.of());

        return Optional.of(new TypeBackedBPFUnionType<>(new BPFType.BPFUnionType<>(name.name(),
                (List<BPFUnionMember<Union,?>>) (List) members.stream().map(m -> new BPFUnionMember<>(m.name(), m.type(), null)).toList(), annotatedClass, null,
                 isTypedefedType(typeElement))));
    }

    private boolean hasInitializer(VariableElement element) {
        var tree = javacProcessingEnv.getElementUtils().getTree(element);
        if (tree instanceof JCVariableDecl) {
            return ((JCVariableDecl) tree).init != null;
        }
        return element.getConstantValue() != null;
    }

    private boolean checkThatNoMemberHasAnInitializer(List<? extends VariableElement> recordMembers) {
        var membersWithInitializer = recordMembers.stream().filter(this::hasInitializer).toList();
        for (var member : membersWithInitializer) {
            this.processingEnv.getMessager().printError(member.getEnclosingElement().getSimpleName() + "." + member.getSimpleName() + " must not have an initializer", member);
        }
        return membersWithInitializer.isEmpty();
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private Optional<List<BPFType.UBPFStructMember<?, ?>>> processBPFTypeRecordMembers(List<? extends VariableElement> recordMembers, String className, boolean allowInlineUnionAnnotation, SourceClassKind kind) {
        var list = recordMembers.stream().map(this::processBPFTypeRecordMember).toList();

        if (list.stream().anyMatch(Optional::isEmpty) || !checkThatNoMemberHasAnInitializer(recordMembers)) {
            return Optional.empty();
        }

        var cleanedList = list.stream().map(Optional::orElseThrow).toList();
        // problem: cleanedList potentially contains struct members annotated with @InlineUnion
        if (cleanedList.stream().noneMatch(m -> m.inlineUnionId().isPresent())) {
            return Optional.of((List<BPFType.UBPFStructMember<?, ?>>)(List) cleanedList.stream().map(UBPFStructMemberPotentiallyInlineUnion::member).toList());
        }

        if (!allowInlineUnionAnnotation) {
            this.processingEnv.getMessager().printError("InlineUnion annotation is only allowed for records", IntStream.range(0, recordMembers.size()).mapToObj(i -> cleanedList.get(i).inlineUnionId.isPresent() ? recordMembers.get(i) : null).filter(Objects::nonNull).findFirst().orElseThrow());
            return Optional.empty();
        }

        List<UBPFStructMember<?, ?>> result = new ArrayList<>();
        Set<Integer> previousInlineUnionIds = new HashSet<>();
        @Nullable Integer curId = null;
        Optional<Integer> curOffset = Optional.empty();
        List<UBPFStructMember<?, ?>> memberForCurrentInlineUnion = new ArrayList<>();
        BiConsumer<Integer, Optional<Integer>> addCurrentInlineUnion = (id, offset) -> {
            List<BPFInlineUnionMember<Object, Object>> inlineMembers = (List<BPFInlineUnionMember<Object, Object>>) (List)memberForCurrentInlineUnion.stream().map(m -> new BPFInlineUnionMember<>(m.name(), m.type(), null)).toList();
            var type = new BPFType.BPFInlineUnionType<>("__union" + id, (List<BPFInlineUnionMember<Object,?>>) (List) inlineMembers, new AnnotatedClass(className, List.of()), kind);
            result.add(new UBPFStructMember<Object, Object>("__union" + id, (BPFType) type, null, null, offset));
            memberForCurrentInlineUnion.clear();
        };
        int count = 0;
        for (var member : cleanedList) {
            if (member.inlineUnionId().isEmpty()) { // everything as normal
                result.add(member.member());
                if (curId != null) {
                    previousInlineUnionIds.add(curId);
                    addCurrentInlineUnion.accept(curId, curOffset);
                    curId = null;
                    curOffset = null;
                }
                continue;
            }
            var inlineUnionId = member.inlineUnionId().get();
            var realMember = member.member();
            if (previousInlineUnionIds.contains(inlineUnionId)) {
                this.processingEnv.getMessager().printError("Members with the same InlineUnion annotation id have to follow each other", recordMembers.get(count));
                return Optional.empty();
            }
            if (curId != null && !curId.equals(member.inlineUnionId().get())) {
                previousInlineUnionIds.add(curId);
                addCurrentInlineUnion.accept(curId, curOffset);
                curId = null;
            }
            if (curId == null) {
                curOffset = member.member().offset();
            } else {
                if (!curOffset.equals(member.member().offset())) {
                    this.processingEnv.getMessager().printError("Members with the same InlineUnion annotation id have to have the same offset", recordMembers.get(count));
                    return Optional.empty();
                }
            }
            curId = member.inlineUnionId().get();
            memberForCurrentInlineUnion.add(realMember);
            count++;
        }
        if (curId != null) {
            addCurrentInlineUnion.accept(curId, curOffset);
        }
        return Optional.of(result);
    }

    record UBPFStructMemberPotentiallyInlineUnion(UBPFStructMember<?, ?> member, Optional<Integer> inlineUnionId) {}

    private Optional<UBPFStructMemberPotentiallyInlineUnion> processBPFTypeRecordMember(VariableElement element) {
        AnnotationValues annotations = getAnnotationValuesForRecordMember(element);
        Optional<Integer> inlineUnionId = Optional.ofNullable(getAnnotationMirror(element.asType(), "me.bechberger.ebpf.annotations.InlineUnion")
                .map(a -> AnnotationUtils.<Integer>getAnnotationValue(a, "value", null)).orElse(null));
        TypeMirror type = element.asType();
        if (annotations.kptr()) {
            boolean isPtr = type instanceof DeclaredType
                    && processingEnv.getTypeUtils().erasure(type).toString().equals(PTR_CLASS);
            if (!isPtr) {
                processingEnv.getMessager().printError(
                        "@Kptr can only be applied to fields of type Ptr<T> (got " + type + ")",
                        element);
                return Optional.empty();
            }
        }
        var bpfType = processBPFTypeRecordMemberType(element, annotations.dropOffset(), type);
        return bpfType.map(t -> {

            var bt = t.toBPFType(this::getBPFTypeForJavaName);
            if (bt == null) {
                processingEnv.getMessager().printError("Could not process type " + type + " for member " + element, element);
                return null;
            }
            return new UBPFStructMemberPotentiallyInlineUnion(new BPFType.UBPFStructMember<>(element.getSimpleName().toString(),
                    bt.toCustomType(), null, null, annotations.offset(), annotations.kptr()), inlineUnionId);
        });
    }

    private static final Set<String> integerTypes = Set.of("int", "long", "short", "byte", "char", "boolean");

    private static String lastPart(String s) {
        return s.substring(s.lastIndexOf(" ") + 1);
    }

    static final Map<String, String> boxedToUnboxedIntegerType = Map.of(
            "java.lang.Integer", "int",
            "java.lang.Long", "long",
            "java.lang.Short", "short",
            "java.lang.Byte", "byte",
            "java.lang.Character", "char",
            "java.lang.Float", "float",
            "java.lang.Double", "double",
            "java.lang.Boolean", "boolean"
    );

    private boolean isIntegerType(TypeMirror type) {
        var typeName = lastPart(type.toString());
        return (type instanceof PrimitiveType p && integerTypes.contains(typeName)) ||
                (boxedToUnboxedIntegerType.containsKey(typeName) || boxedToUnboxedIntegerType.containsKey("java.lang." + typeName));
    }

    private boolean isStringType(TypeMirror type) {
        // comparing strings isn't pretty, but it works without additional module exports
        // maybe revisit loter
        var lastPart = lastPart(type.toString());
        return lastPart.equals("String") || lastPart.equals("java.lang.String");
    }

    public Optional<BPFTypeMirror> processBPFTypeRecordMemberType(Element element, AnnotationValues annotations,
                                                                  TypeMirror type) {
        return processBPFTypeRecordMemberType(element, annotations, type, true);
    }

    /**
     * Process the type of a record member, allowing the {@link Box} type (and unwrapping it)
     * @param element the element of the record member
     * @param annotations the annotations of the record member
     * @param type the type of the record member
     * @return the BPFTypeMirror for the record member
     */
    public Optional<BPFTypeMirror> processBPFTypeRecordMemberTypeWithBox(Element element, AnnotationValues annotations,
                                                                  TypeMirror type) {
        return processBPFTypeRecordMemberType(element, annotations, type, true);
    }

    private Optional<BPFTypeMirror> processBPFTypeRecordMemberType(Element element, AnnotationValues annotations,
                                                                  TypeMirror type, boolean allowBox) {
        if (type.getKind() == TypeKind.DECLARED && typeUtils.hasClassIgnoringTypeParameters(element, Box.class.getName())) {
            if (!allowBox) {
                this.processingEnv.getMessager().printError("Box is not allowed here", element);
                return Optional.empty();
            }
            if (!(element.asType() instanceof ClassType classType)) {
                this.processingEnv.getMessager().printError("Box type has to be a class", element);
                return Optional.empty();
            }
            var genericTypes = classType.getTypeArguments();
            if (genericTypes.size() != 1) {
                this.processingEnv.getMessager().printError("Box type must have exactly one type argument", element);
                return Optional.empty();
            }
            var genericType = genericTypes.getFirst();
            return processBPFTypeRecordMemberType(genericType.asElement(), getAnnotationValuesForRecordMember(genericType), genericType);
        }
        if (type.getKind() == TypeKind.ARRAY) {
            return processArrayType(element,
                    annotations,
                    (ArrayType)type);
        }

        if (isIntegerType(type)) {
            return processIntegerType(element, annotations, type).map(tp -> (t -> BPFTypeLike.of(tp)));
        }
        if (isStringType(type)) {
            return processStringType(element, annotations, type);
        }

        var typeElem = processingEnv.getTypeUtils().asElement(type);

        if (typeElem == null) {
            return Optional.of(t -> BPFTypeLike.of(BPFType.VOID));
        }

        if (!(typeElem instanceof TypeElement typeElement)) {
            this.processingEnv.getMessager().printError("Unsupported type " + type + " in " + element, element);
            return Optional.empty();
        }

        if (isPointerType(typeElement)) {
            return processPointerType(element, annotations, type);
        }

        if (isCustomTypeAnnotatedRecord(typeElement)) {
            return processCustomType(element, annotations, type);
        }
        var t = isValidDataType(typeElement);
        if (t != DataTypeKind.NONE) {
            return processDefinedDataType(element, annotations, type, t);
        }
        this.processingEnv.getMessager().printError("Unsupported type " + type, element);
        return Optional.empty();
    }

    private boolean isPointerType(TypeElement typeElement) {
        return typeElement.getQualifiedName().toString().equals(Ptr.class.getCanonicalName());
    }

    private Optional<BPFTypeMirror> processPointerType(Element element, AnnotationValues annotations, TypeMirror type) {
        if (!annotations.checkSupportedAnnotations(m -> this.processingEnv.getMessager().printError(m, element))) {
            return Optional.empty();
        }
        var genericTypes = ((DeclaredType)type).getTypeArguments();
        if (genericTypes.size() != 1) {
            this.processingEnv.getMessager().printError("Pointer type must have exactly one type argument", element);
            return Optional.empty();
        }
        var genericType = genericTypes.getFirst();
        // Pointers to @KernelBTF types are opaque to user-space layout: the
        // kernel struct's offsets are relocated by libbpf at load time via
        // CO-RE, so descending into the kernel type's fields here is both
        // unnecessary and dangerous (kernel structs often hold self-referential
        // helpers like llist_node that trip the recursion guard). The C side
        // still needs the proper kernel struct name (e.g. `struct task_struct`),
        // which we render via VerbatimBPFOnlyType.
        if (genericType instanceof DeclaredType dt) {
            var elem = dt.asElement();
            if (elem != null && elem.getAnnotation(me.bechberger.ebpf.annotations.KernelBTF.class) != null) {
                var typeAnn = elem.getAnnotation(Type.class);
                String cType = typeAnn != null && !typeAnn.cType().isEmpty()
                        ? typeAnn.cType()
                        : ("struct " + elem.getSimpleName());
                String bareName = cType.startsWith("struct ")
                        ? cType.substring("struct ".length())
                        : cType.startsWith("union ")
                                ? cType.substring("union ".length())
                                : cType;
                PrefixKind kind = cType.startsWith("struct ")
                        ? PrefixKind.STRUCT
                        : cType.startsWith("union ")
                                ? PrefixKind.UNION
                                : PrefixKind.NORMAL;
                // Build an inner CustomBPFType that:
                //   - emits the proper kernel struct name in C (cUse + bpfName),
                //   - uses the actual kernel struct's Java name in generics, so
                //     Ptr<task_struct> in user code matches the generated spec
                //     (UBPFStructMember accessor compatibility),
                //   - emits "null" as its Java spec value, so the wrapping
                //     BPFPointerType.toJavaFieldSpecUse renders as
                //     `new BPFPointerType<task_struct>(null)` — opaque user-space
                //     pointer; CO-RE handles offsets at load time.
                String javaUseInGenerics = elem instanceof TypeElement te
                        ? te.getQualifiedName().toString()
                        : elem.getSimpleName().toString();
                final var inner = new VerbatimBPFOnlyType<>(bareName, kind).toCustomType();
                final var innerWithSpec = new BPFType.CustomBPFType<>(
                        javaUseInGenerics,
                        javaUseInGenerics,
                        javaUseInGenerics,
                        inner.bpfName(),
                        inner.cUse(),
                        typeToSpec -> "null",
                        () -> Optional.empty());
                return Optional.of(nameToCustomType -> new TypeBackedBPFTypeLike<>(
                        new BPFType.BPFPointerType<>(innerWithSpec)));
            }
        }
        var innerType = processBPFTypeRecordMemberType(element, getAnnotationValuesForRecordMember(genericType), genericType);
        if (innerType.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(nameToCustomType -> new TypeBackedBPFTypeLike<>(new BPFType.BPFPointerType<>(
                innerType.get().toBPFType(nameToCustomType).toCustomType())));
    }

    private Optional<BPFTypeMirror> processArrayType(Element element, AnnotationValues annotations, ArrayType type) {
        if (annotations.size().isEmpty()) {
            this.processingEnv.getMessager().printError("Size annotation required for array types", element);
            if (type.getComponentType().getKind() == TypeKind.ARRAY) {
                int depth = 1;
                var innerType = type.getComponentType();
                while (innerType.getKind() == TypeKind.ARRAY) {
                    depth++;
                    innerType = ((ArrayType)innerType).getComponentType();
                }
                String example = "@Size(...) " + innerType + "[] " + IntStream.range(0, depth - 1).mapToObj(i -> " @Size(...) []").collect(Collectors.joining());
                this.processingEnv.getMessager().printError("This might be due to misplaced annotations, use: " + example, element);
            }
            return Optional.empty();
        }
        var innerType = processBPFTypeRecordMemberType(element, annotations.dropSize(), type.getComponentType());
        if (innerType.isEmpty()) {
            return Optional.empty();
        }

        return Optional.of(nameToCustomType -> new TypeBackedBPFTypeLike<>(BPFType.BPFArrayType.of(
                innerType.get().toBPFType(nameToCustomType).toCustomType(), annotations.size().getFirst())));
    }

    @FunctionalInterface
    public interface BPFTypeMirror {

        BPFTypeLike<?> toBPFType(Function<JavaName, BPFTypeLike<?>> nameToCustomType);
    }

    private Optional<BPFType<?>> processIntegerType(Element element, AnnotationValues annotations, TypeMirror type) {
        if (!annotations.checkSupportedAnnotations(m -> this.processingEnv.getMessager().printError(m, element),
                AnnotationKind.UNSIGNED)) {
            return Optional.empty();
        }
        boolean unsigned = annotations.unsigned();
        var typeName = lastPart(type.toString());
        var numberName = boxedToUnboxedIntegerType.getOrDefault(typeName,
                boxedToUnboxedIntegerType.getOrDefault("java.lang." + typeName, typeName));
        return switch (numberName) {
            case "boolean" -> Optional.of(BPFType.BPFIntType.BOOL);
            case "int" -> Optional.of(unsigned ? BPFType.BPFIntType.UINT32 : BPFType.BPFIntType.INT32);
            case "long" -> Optional.of(unsigned ? BPFType.BPFIntType.UINT64 : BPFType.BPFIntType.INT64);
            case "short" -> Optional.of(unsigned ? BPFType.BPFIntType.UINT16 : BPFType.BPFIntType.INT16);
            case "byte" -> Optional.of(unsigned ? BPFType.BPFIntType.UINT8 : BPFType.BPFIntType.INT8);
            case "char" -> {
                if (unsigned) {
                    this.processingEnv.getMessager().printError("Unsigned char not supported", element);
                    yield  Optional.empty();
                }
                yield Optional.of(BPFType.BPFIntType.CHAR);
            }
            default -> {
                this.processingEnv.getMessager().printError("Unsupported integer type " + type, element);
                yield Optional.empty();
            }
        };
    }

    private Optional<BPFTypeMirror> processStringType(Element element, AnnotationValues annotations, TypeMirror type) {
        if (!annotations.checkSupportedAnnotations(m -> this.processingEnv.getMessager().printError(m, element),
                AnnotationValues.AnnotationKind.SIZE)) {
            return Optional.empty();
        }
        if (annotations.size().isEmpty() && !allowUnsizedStrings) {
            this.processingEnv.getMessager().printError("Size annotation required for string types", element);
            return Optional.empty();
        }
        return Optional.of(t -> BPFTypeLike.of(new BPFType.StringType(annotations.size().isEmpty() ? -1 : annotations.size().getFirst())));
    }

    private Optional<BPFTypeMirror> processDefinedDataType(Element element, AnnotationValues annotations, TypeMirror type, DataTypeKind kind) {
        if (!checkAnnotatedType(element, annotations)) {
            return Optional.empty();
        }
        TypeElement typeElement = (TypeElement) processingEnv.getTypeUtils().asElement(type);
        if (this.definedTypes == null) { // used from the compiler plugin
            var annotation = typeElement.getAnnotation(Type.class);
            if (annotation == null) {
                this.processingEnv.getMessager().printError("Type " + typeElement.getSimpleName() + " must be annotated with @Type", element);
                return Optional.empty();
            }
            String cType = annotation.cType();
            return getVerbatimBPFTypeName(cType, kind, typeElement);
        }
        SpecFieldName fieldName = definedTypes.getOrCreateFieldName(typeElement);
        var typeName = definedTypes.bpfNameToName(definedTypes.specFieldNameToName(fieldName));
        return Optional.of(t -> t.apply(typeName));
    }

    private @NotNull Optional<BPFTypeMirror> getVerbatimBPFTypeName(String cType, DataTypeKind kind, TypeElement typeElement) {
        if (cType.isEmpty()) {
            var name = getTypeRecordBpfName(typeElement).name();
            var parts = name.split("\\$");
            var properName = parts[parts.length - 1];
            return Optional.of(t -> new VerbatimBPFOnlyType<>(properName, switch (kind) {
                case STRUCT -> PrefixKind.STRUCT;
                case UNION -> PrefixKind.UNION;
                case ENUM -> PrefixKind.ENUM;
                case NONE -> PrefixKind.NORMAL;
                default -> throw new IllegalStateException("Unexpected value: " + kind);
            }));
        }
        return Optional.of(t -> new VerbatimBPFOnlyType<>(cType, PrefixKind.NORMAL));
    }

    private boolean checkAnnotatedType(Element element, AnnotationValues annotations) {
        return annotations.checkSupportedAnnotations(m -> this.processingEnv.getMessager().printError(m, element));
    }

    private Optional<BPFTypeMirror> processCustomType(Element element, AnnotationValues annotations, TypeMirror type) {
        if (!checkAnnotatedType(element, annotations)) {
            return Optional.empty();
        }
        TypeElement typeElement = (TypeElement) processingEnv.getTypeUtils().asElement(type);
        if (!definedTypes.isTypeDefined(typeElement)) {
            var info = getCustomTypeInfo(typeElement);
            if (info == null) {
                return Optional.empty();
            }
            addCustomType(info);
        }
        Optional<SpecFieldName> fieldName = definedTypes.getFieldName(typeElement);
        if (fieldName.isEmpty()) {
           return Optional.empty();
        }
        var typeName = definedTypes.bpfNameToName(definedTypes.specFieldNameToName(fieldName.get()));
        return Optional.of(t -> {
            var customType = usedCustomBPFTypes.stream().filter(ut -> ut.javaName().equals(typeName.name())).findFirst().orElseThrow();
            return new TypeBackedBPFCustomType<>(customType);
        });
    }

    public @Nullable CustomTypeInfo getCustomTypeInfo(TypeElement typeElement) {
        var optAnn = getAnnotationMirror(typeElement, "me.bechberger.ebpf.annotations.CustomType");
        if (optAnn.isEmpty()) {
            return null;
        }
        var javaName = new JavaName(typeElement);
        var bpfName = new BPFName(getAnnotationValue(optAnn.get(), "name", typeElement.getSimpleName().toString()));
        var fieldNameString = getAnnotationValue(optAnn.get(), "specFieldName", "").replace("$class", javaName.name());
        if (typeElement.getEnclosingElement() instanceof TypeElement outerClass) {
            fieldNameString = fieldNameString.replace("$outerClass", outerClass.getQualifiedName().toString().replace('$', '.'));
        }
        var fieldName = new SpecFieldName(fieldNameString);
        if (!fieldNameString.contains(".")) {
            // probably a field of the current class
            this.processingEnv.getMessager().printError("specFieldName must be set", typeElement);
            return null;
        }
        var isStruct = getAnnotationValue(optAnn.get(), "isStruct", false);
        var cCode = getAnnotationValue(optAnn.get(), "cCode", "").replace("$name", bpfName.name());

        return new CustomTypeInfo(typeElement, javaName, bpfName, fieldName, isStruct, cCode);
    }

   public record CustomTypeInfo(TypeElement typeElement, JavaName javaName, BPFName bpfName, SpecFieldName fieldName, boolean isStruct, String cCode) {}

   private void addCustomType(CustomTypeInfo customType) {
       definedTypes.insertType(customType.typeElement, customType.bpfName, customType.fieldName);
       usedCustomBPFTypes.add(new CustomBPFType<>(customType.javaName.name(), customType.javaName.name(), customType.javaName.name(), customType.bpfName.name(), () -> {
           return customType.isStruct ? Declarator.structIdentifier(variable(customType.bpfName.name())) : Declarator.identifier(customType.bpfName.name());
       },  f -> customType.fieldName.name(), () -> customType.cCode.isEmpty() ? Optional.<Statement>empty() : Optional.of(Statement.verbatim(customType.cCode))));
   }

    private DefinedTypes getDefinedTypes(List<TypeElement> innerTypeElements) {
        return new DefinedTypes(this, innerTypeElements, this::typeToFieldName);
    }

    /**
     * Field name is camel-case and upper-case version of simple type name
     */
    private SpecFieldName typeToFieldName(TypeElement typeElement) {
        String name;
        if (typeElement.getEnclosingElement().equals(outerTypeElement)) {
            name = typeElement.getSimpleName().toString();
        } else {
            name = typeElement.getQualifiedName().toString().replace(".", "__");
        }
        return new SpecFieldName(toConstantCase(name));
    }

    /**
     * Information attached to a map field annotated with
     * {@link me.bechberger.ebpf.annotations.bpf.SharedFrom @SharedFrom}.
     *
     * @param producerFqn        fully-qualified name of the producer {@code @BPF} class
     * @param producerSimpleName simple class name of the producer (used to name the
     *                           generated impl-class constructor parameter)
     * @param mapName            name of the map field on the producer
     */
    public record SharedFromInfo(String producerFqn, String producerSimpleName, String mapName) {}

    /**
     * Combines the C and the Java code to construct a map
     * @param javaFieldInitializer code that initializes a map field in the constructor of the BPFProgram implementation
     * @param structDefinition the C struct definition of the map
     * @param sharedFrom non-null when the field is annotated with {@code @SharedFrom}
     */
    public record MapDefinition(String javaFieldName, String javaFieldInitializer, Statement structDefinition,
                                @Nullable SharedFromInfo sharedFrom) {
        public MapDefinition(String javaFieldName, String javaFieldInitializer, Statement structDefinition) {
            this(javaFieldName, javaFieldInitializer, structDefinition, null);
        }
    }

    List<MapDefinition> processDefinedMaps(TypeElement outerElement, Function<SpecFieldName, BPFTypeLike<?>> fieldToType,
                                           Function<BPFTypeLike<?>, SpecFieldName> typeToSpecFieldName) {
        // take all @BPFMapDefinition annotated fields
        return outerElement.getEnclosedElements().stream().filter(e -> e.getKind() == ElementKind.FIELD).map(e -> (VariableElement) e)
                .filter(e -> getAnnotationMirror(e.asType(), BPF_MAP_DEFINITION).isPresent())
                .map(f -> processMapDefiningField(f, fieldToType, typeToSpecFieldName)).filter(Objects::nonNull).toList();
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Nullable MapDefinition processMapDefiningField(VariableElement field,
                                                    Function<SpecFieldName, BPFTypeLike<?>> fieldToType,
                                                    Function<BPFTypeLike<?>, SpecFieldName> typeToSpecFieldName) {
        // create a FieldSpec for the field
        // create a #define statement for the field
        // return the FieldSpec and the #define statement
        var annotation = getAnnotationMirror(field.asType(), BPF_MAP_DEFINITION);
        assert annotation.isPresent();
        var maxEntries = getAnnotationValue(annotation.get(), "maxEntries", 0);
        if (maxEntries == 0) {
            this.processingEnv.getMessager().printError("maxEntries must be set and larger than 0", field);
            return null;
        }
        var type = field.asType();
        if (!(type instanceof DeclaredType declaredType)) {
            this.processingEnv.getMessager().printError("Field must be a declared type", field);
            return null;
        }
        // get generic type members
        var typeParams = declaredType.getTypeArguments().stream()
                .map(t -> processBPFTypeRecordMemberType(field, getAnnotationValuesForRecordMember(t), t)
                        .map(m -> m.toBPFType(mt -> fieldToType.apply(definedTypes.nameToSpecFieldName(definedTypes.nameToBPFName(mt)))))
                ).toList();
        if (typeParams.stream().anyMatch(Optional::isEmpty)) {
            List<? extends TypeMirror> problematicFields = IntStream.range(0, typeParams.size()).filter(i -> typeParams.get(i).isEmpty()).mapToObj(i -> declaredType.getTypeArguments().get(i)).toList();
            this.processingEnv.getMessager().printError("Type parameters must be valid: " + problematicFields.stream().map(TypeMirror::toString).collect(Collectors.joining(", ")) + " is not, maybe you missed an @Type annotation", field);
            return null;
        }
        List<BPFTypeLike<?>> typeParameters = (List<BPFTypeLike<?>>) (List) typeParams.stream().map(Optional::get).toList();

        // now we just have to get the annotation of the fields map type

        var mapType = processingEnv.getTypeUtils().asElement(type);

        var mapClassAnnotation = getAnnotationMirror(processingEnv.getTypeUtils().asElement(type), BPF_MAP_CLASS);
        if (mapClassAnnotation.isEmpty()) {
            this.processingEnv.getMessager().printError("Only BPFMapClass annotated classes can be used for map definitions, " +
                    "please annotate " + mapType + " directly", field);
            return null;
        }

        var cTemplate = getAnnotationValue(mapClassAnnotation.get(), "cTemplate", "");
        if (cTemplate.isEmpty()) {
            this.processingEnv.getMessager().printError("cTemplate must be set for class", mapType);
            return null;
        }
        var javaTemplate = getAnnotationValue(mapClassAnnotation.get(), "javaTemplate", "");
        if (javaTemplate.isEmpty()) {
            this.processingEnv.getMessager().printError("javaTemplate must be set for class", mapType);
            return null;
        }
        var fieldName = field.getSimpleName().toString();
        var className = mapType.toString();

        SharedFromInfo sharedFrom = processSharedFromIfPresent(field, fieldName, declaredType, mapType, maxEntries);

        return new MapDefinition(field.getSimpleName().toString(),
                processBPFClassJavaTemplate(field, javaTemplate, typeParameters, maxEntries, fieldName, className, typeToSpecFieldName),
                processBPFClassCTemplate(field, cTemplate, typeParameters, maxEntries, fieldName, className, typeToSpecFieldName),
                sharedFrom);
    }

    /**
     * If {@code field} is annotated with {@code @SharedFrom}, validate that the
     * producer declares a compatible map and return a {@link SharedFromInfo}
     * describing it. Otherwise return {@code null}.
     *
     * <p>Compatibility checks (each emits a printError on the field with a
     * helpful message; first failure returns {@code null} so the caller treats
     * the map as unshared):
     * <ol>
     *   <li>The producer class is loadable and is a {@code @BPF} class.</li>
     *   <li>The producer declares a {@code @BPFMapDefinition} field with the
     *       requested map name.</li>
     *   <li>The producer's map class (e.g. {@code BPFHashMap}) matches the
     *       consumer's.</li>
     *   <li>Each generic type parameter is structurally compatible with the
     *       producer's: same {@link TypeElement}, or both framework-known
     *       primitives with the same BPF name, or two distinct {@code @Type}
     *       classes with byte-identical layout (walked field-by-field).</li>
     *   <li>{@code maxEntries} matches.</li>
     * </ol>
     */
    private @Nullable SharedFromInfo processSharedFromIfPresent(VariableElement field, String fieldName,
                                                                DeclaredType consumerMapType, Element consumerMapClass,
                                                                int consumerMaxEntries) {
        var sharedAnn = getAnnotationMirror(field, SHARED_FROM_ANNOTATION);
        if (sharedAnn.isEmpty()) return null;

        // 1) Resolve the producer class.
        TypeMirror producerMirror = getAnnotationValue(sharedAnn.get(), "value", null);
        if (producerMirror == null || !(producerMirror instanceof DeclaredType producerDecl)) {
            this.processingEnv.getMessager().printError(
                    "@SharedFrom: 'value' must reference a @BPF class", field);
            return null;
        }
        TypeElement producerType = (TypeElement) producerDecl.asElement();
        if (!hasAnnotation(producerType, "me.bechberger.ebpf.annotations.bpf.BPF")) {
            this.processingEnv.getMessager().printError(
                    "@SharedFrom: " + producerType.getQualifiedName()
                            + " is not annotated with @BPF — only @BPF classes can be referenced", field);
            return null;
        }

        // 2) Resolve the producer's map field.
        String requestedMapName = getAnnotationValue(sharedAnn.get(), "mapName", "");
        if (requestedMapName.isEmpty()) requestedMapName = fieldName;

        VariableElement producerField = null;
        var producerMapFields = new java.util.ArrayList<String>();
        for (var enc : producerType.getEnclosedElements()) {
            if (enc.getKind() != ElementKind.FIELD) continue;
            VariableElement vf = (VariableElement) enc;
            // @BPFMapDefinition is @Target(TYPE_USE) — sits on the field's type.
            if (!hasAnnotation(vf.asType(), BPF_MAP_DEFINITION)) continue;
            producerMapFields.add(vf.getSimpleName().toString());
            if (vf.getSimpleName().toString().equals(requestedMapName)) {
                producerField = vf;
            }
        }
        if (producerField == null) {
            this.processingEnv.getMessager().printError(
                    "@SharedFrom: producer class " + producerType.getQualifiedName()
                            + " has no @BPFMapDefinition field '" + requestedMapName + "'."
                            + " Producer fields: " + producerMapFields, field);
            return null;
        }

        // 3) Compare raw map class (BPFHashMap vs BPFLRUHashMap, etc.).
        TypeMirror producerFieldType = producerField.asType();
        if (!(producerFieldType instanceof DeclaredType producerMapDecl)) {
            this.processingEnv.getMessager().printError(
                    "@SharedFrom: producer's '" + requestedMapName + "' field has unexpected type", field);
            return null;
        }
        Element producerMapClass = producerMapDecl.asElement();
        if (!consumerMapClass.toString().equals(producerMapClass.toString())) {
            this.processingEnv.getMessager().printError(
                    "@SharedFrom: field " + fieldName + " is " + consumerMapClass
                            + " but producer's '" + requestedMapName + "' is " + producerMapClass + ".", field);
            return null;
        }

        // 4) Walk type parameters.
        var consumerArgs = consumerMapType.getTypeArguments();
        var producerArgs = producerMapDecl.getTypeArguments();
        if (consumerArgs.size() != producerArgs.size()) {
            this.processingEnv.getMessager().printError(
                    "@SharedFrom: type parameter count differs between consumer (" + consumerArgs.size()
                            + ") and producer (" + producerArgs.size() + ")", field);
            return null;
        }
        for (int i = 0; i < consumerArgs.size(); i++) {
            if (!sharedFromTypesCompatible(field, requestedMapName, i,
                    consumerArgs.get(i), producerArgs.get(i),
                    producerType.getQualifiedName().toString())) {
                return null;
            }
        }

        // 5) Compare maxEntries.
        var producerMapAnn = getAnnotationMirror(producerField.asType(), BPF_MAP_DEFINITION).orElse(null);
        if (producerMapAnn != null) {
            int producerMaxEntries = getAnnotationValue(producerMapAnn, "maxEntries", 0);
            if (producerMaxEntries != consumerMaxEntries) {
                this.processingEnv.getMessager().printError(
                        "@SharedFrom: maxEntries mismatch on '" + requestedMapName
                                + "': consumer declares " + consumerMaxEntries
                                + ", producer " + producerType.getQualifiedName()
                                + " declares " + producerMaxEntries
                                + ". Pinned reuse requires identical sizing.", field);
                return null;
            }
        }

        return new SharedFromInfo(
                producerType.getQualifiedName().toString(),
                producerType.getSimpleName().toString(),
                requestedMapName);
    }

    /**
     * Compare two type-parameter mirrors for {@code @SharedFrom} compatibility.
     * Returns {@code true} if compatible; otherwise emits a printError and returns
     * {@code false}.
     */
    private boolean sharedFromTypesCompatible(VariableElement field, String mapName, int paramIndex,
                                              TypeMirror consumerArg, TypeMirror producerArg,
                                              String producerFqn) {
        // Same TypeElement? Trivially OK (consumer used producer's @Type directly).
        if (processingEnv.getTypeUtils().isSameType(consumerArg, producerArg)) {
            return true;
        }
        // Try framework type comparison via toString.
        // (Both Long/Integer/etc. and @Type classes have stable toString forms.)
        String c = consumerArg.toString();
        String p = producerArg.toString();
        if (c.equals(p)) return true;

        // Distinct @Type classes — check structural equivalence.
        Element ce = processingEnv.getTypeUtils().asElement(consumerArg);
        Element pe = processingEnv.getTypeUtils().asElement(producerArg);
        if (ce instanceof TypeElement consumerTE
                && pe instanceof TypeElement producerTE
                && hasAnnotation(consumerTE, TYPE_ANNOTATION)
                && hasAnnotation(producerTE, TYPE_ANNOTATION)) {
            return checkStructuralEquivalence(field, mapName, paramIndex, consumerTE, producerTE, producerFqn);
        }

        this.processingEnv.getMessager().printError(
                "@SharedFrom: type-parameter " + paramIndex + " on '" + mapName
                        + "' differs: consumer is " + c + ", producer " + producerFqn + " is " + p
                        + ". Use the producer's @Type directly to share the definition "
                        + "(e.g. " + producerFqn + "." + simpleName(p) + ").", field);
        return false;
    }

    private static String simpleName(String fqn) {
        int dot = fqn.lastIndexOf('.');
        return dot < 0 ? fqn : fqn.substring(dot + 1);
    }

    /**
     * Walk fields of two {@code @Type} classes and verify byte-identical layout.
     * Reports the first offending field and returns {@code false}.
     */
    private boolean checkStructuralEquivalence(VariableElement field, String mapName, int paramIndex,
                                               TypeElement consumerType, TypeElement producerType,
                                               String producerFqn) {
        Map<String, TypeMirror> producerFields = new LinkedHashMap<>();
        for (var enc : producerType.getEnclosedElements()) {
            if (enc.getKind() != ElementKind.FIELD) continue;
            VariableElement v = (VariableElement) enc;
            if (v.getModifiers().contains(Modifier.STATIC)) continue;
            producerFields.put(v.getSimpleName().toString(), v.asType());
        }
        Map<String, TypeMirror> consumerFields = new LinkedHashMap<>();
        for (var enc : consumerType.getEnclosedElements()) {
            if (enc.getKind() != ElementKind.FIELD) continue;
            VariableElement v = (VariableElement) enc;
            if (v.getModifiers().contains(Modifier.STATIC)) continue;
            consumerFields.put(v.getSimpleName().toString(), v.asType());
        }
        // Missing on producer side?
        for (var fn : consumerFields.keySet()) {
            if (!producerFields.containsKey(fn)) {
                this.processingEnv.getMessager().printError(
                        "@SharedFrom: type " + consumerType.getSimpleName() + " on '" + mapName
                                + "' has field '" + fn + "' but producer " + producerFqn + "'s "
                                + producerType.getSimpleName() + " does not."
                                + " Use " + producerFqn + "." + producerType.getSimpleName()
                                + " directly to share the definition.", field);
                return false;
            }
        }
        // Extra on producer side?
        for (var fn : producerFields.keySet()) {
            if (!consumerFields.containsKey(fn)) {
                this.processingEnv.getMessager().printError(
                        "@SharedFrom: producer " + producerFqn + "'s " + producerType.getSimpleName()
                                + " on '" + mapName + "' has field '" + fn
                                + "' but consumer " + consumerType.getSimpleName() + " is missing it."
                                + " Use " + producerFqn + "." + producerType.getSimpleName()
                                + " directly to share the definition.", field);
                return false;
            }
        }
        // Field types differ?
        for (var entry : consumerFields.entrySet()) {
            TypeMirror ct = entry.getValue();
            TypeMirror pt = producerFields.get(entry.getKey());
            if (!ct.toString().equals(pt.toString())) {
                this.processingEnv.getMessager().printError(
                        "@SharedFrom: type-parameter " + paramIndex + " on '" + mapName
                                + "' — field '" + entry.getKey() + "' has type '" + ct + "' here but '"
                                + pt + "' in " + producerFqn + "." + producerType.getSimpleName() + "."
                                + " Use BPFHashMap with " + producerFqn + "." + producerType.getSimpleName()
                                + " to share the definition.", field);
                return false;
            }
        }
        return true;
    }


    String processBPFClassJavaTemplate(VariableElement field, String javaTemplate,
                                       List<BPFTypeLike<?>> typeParams, Integer maxEntries,
                                       String fieldName, String className,
                                       Function<BPFTypeLike<?>, SpecFieldName> typeToSpecFieldName) {
        return "this." + field.getSimpleName() + " = recordMap(" + processBPFClassTemplate(javaTemplate, typeParams,
                 maxEntries, fieldName, className, typeToSpecFieldName).strip() + ")";
    }



    Statement processBPFClassCTemplate(VariableElement field, String cTemplate, List<BPFTypeLike<?>> typeParameters,
                                       Integer maxEntries, String fieldName, String className,
                                       Function<BPFTypeLike<?>, SpecFieldName> typeToSpecFieldName) {
        String raw = processBPFClassTemplate(cTemplate, typeParameters,
                maxEntries, fieldName, className, typeToSpecFieldName);
        return new VerbatimStatement(raw);
    }

    String processBPFClassTemplate(String template, List<BPFTypeLike<?>> typeParams, int maxEntries, String fieldName,
                                   String className, Function<BPFTypeLike<?>, SpecFieldName> typeToSpecFieldName) {
        var classNames = typeParams.stream().map(BPFTypeLike::getJavaName).map(JavaName::toString).toList();
        var cTypeNames = typeParams.stream().map(BPFTypeLike::getBPFNameWithStructPrefixIfNeeded).toList();
        var bFields = typeParams.stream().map(t -> t.toJavaFieldSpecUse(tm -> typeToSpecFieldName.apply(BPFTypeLike.of(tm)).name())).toList();
        String res = template;
        for (int i = typeParams.size(); i > 0; i--) {
            res = res.replace("$c" + i, cTypeNames.get(i - 1))
                    .replace("$j" + i, classNames.get(i - 1))
                    .replace("$b" + i, bFields.get(i - 1));
        }
        return res.replace("$maxEntries", Integer.toString(maxEntries))
                .replace("$field", fieldName)
                .replace("$class", className)
                .replace("$fd", "getMapDescriptorByName(" + CAST.toStringLiteral(fieldName) + ")");
    }
}