package me.bechberger.ebpf.bpf.processor;

import com.squareup.javapoet.FieldSpec;
import me.bechberger.cast.CAST;
import me.bechberger.cast.CAST.PrimaryExpression.CAnnotation;
import me.bechberger.ebpf.type.BPFType;
import me.bechberger.ebpf.type.BPFType.AnnotatedClass;
import org.jetbrains.annotations.Nullable;

import javax.annotation.processing.ProcessingEnvironment;
import javax.lang.model.AnnotatedConstruct;
import javax.lang.model.element.*;
import javax.lang.model.type.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.stream.Collectors;

import static me.bechberger.cast.CAST.Expression.constant;
import static me.bechberger.cast.CAST.Expression.variable;
import static me.bechberger.cast.CAST.Statement.*;

/**
 * Handles {@code @Type} annotated records
 */
class TypeProcessor {

    public final static String SIZE_ANNOTATION = "me.bechberger.ebpf.annotations.Size";
    public final static String UNSIGNED_ANNOTATION = "me.bechberger.ebpf.annotations.Unsigned";
    public final static String TYPE_ANNOTATION = "me.bechberger.ebpf.annotations.bpf.Type";
    public final static String BPF_PACKAGE = "me.bechberger.ebpf.type";
    public final static String BPF_TYPE = "me.bechberger.ebpf.type.BPFType";
    public final static String BPF_MAP_DEFINITION = "me.bechberger.ebpf.annotations.bpf.BPFMapDefinition";
    public final static String BPF_MAP_CLASS = "me.bechberger.ebpf.annotations.bpf.BPFMapClass";

    record SpecFieldName(String name) {}

    record BPFName(String name) {}

    record JavaName(String name) {
        JavaName(TypeElement clazz) {
            this(clazz.getQualifiedName().toString());
        }

        JavaName(BPFType<?> type) {
            this(type.javaClass().klass());
        }
    }

    /**
     * Helper class to keep track of defined types
     */
    private class DefinedTypes {

        private final Map<JavaName, BPFName> nameToBPFName;
        private final Map<BPFName, JavaName> bpfNameToName;
        private final Map<TypeElement, SpecFieldName> typeToFieldName;
        private final Map<BPFName, SpecFieldName> nameToSpecFieldName;
        private final Map<SpecFieldName, BPFName> specFieldNameToName;
        private final Map<BPFName, TypeElement> nameToTypeElement;

        DefinedTypes(Map<TypeElement, SpecFieldName> typeToFieldName) {
            this.nameToBPFName = new HashMap<>();
            this.bpfNameToName = new HashMap<>();
            this.typeToFieldName = typeToFieldName;
            this.nameToSpecFieldName = new HashMap<>();
            this.specFieldNameToName = new HashMap<>();
            this.nameToTypeElement = new HashMap<>();
            this.typeToFieldName.forEach((k, v) -> {
                var name = getTypeRecordBpfName(k);
                this.nameToSpecFieldName.put(name, v);
                this.specFieldNameToName.put(v, name);
                this.nameToTypeElement.put(name, k);
                var javaName = new JavaName(k);
                this.nameToBPFName.put(javaName, name);
                this.bpfNameToName.put(name, javaName);
            });
        }

        public boolean isTypeDefined(TypeElement typeElement) {
            return this.typeToFieldName.containsKey(typeElement);
        }

        public boolean isNameDefined(BPFName name) {
            return this.nameToSpecFieldName.containsKey(name);
        }

        public boolean isNameDefined(SpecFieldName name) {
            return this.specFieldNameToName.containsKey(name);
        }

        public boolean isNameDefined(JavaName name) {
            return this.nameToTypeElement.containsKey(name);
        }

        public Optional<SpecFieldName> getFieldName(TypeElement typeElement) {
            return Optional.ofNullable(this.typeToFieldName.get(typeElement));
        }

        public Optional<SpecFieldName> getSpecFieldName(BPFName name) {
            return Optional.ofNullable(this.nameToSpecFieldName.get(name));
        }

        public Optional<TypeElement> getTypeElement(BPFName name) {
            return Optional.ofNullable(this.nameToTypeElement.get(name));
        }

        @Override
        public String toString() {
            return this.typeToFieldName.toString();
        }

        public BPFName specFieldNameToName(SpecFieldName field) {
            if (this.specFieldNameToName.containsKey(field)) {
                return this.specFieldNameToName.get(field);
            } else {
                throw new IllegalArgumentException("Field " + field + " not defined");
            }
        }

        public SpecFieldName nameToSpecFieldName(BPFName name) {
            if (this.nameToSpecFieldName.containsKey(name)) {
                return this.nameToSpecFieldName.get(name);
            } else {
                throw new IllegalArgumentException("Name " + name + " not defined");
            }
        }

        public JavaName bpfNameToName(BPFName name) {
            if (this.bpfNameToName.containsKey(name)) {
                return this.bpfNameToName.get(name);
            } else {
                throw new IllegalArgumentException("Name " + name + " not defined");
            }
        }

        public BPFName nameToBPFName(JavaName name) {
            if (this.nameToBPFName.containsKey(name)) {
                return this.nameToBPFName.get(name);
            } else {
                throw new IllegalArgumentException("Name " + name + " not defined");
            }
        }
    }

    private final ProcessingEnvironment processingEnv;

    private DefinedTypes definedTypes;

    TypeProcessor(ProcessingEnvironment processingEnv) {
        this.processingEnv = processingEnv;
    }

    /**
     * Get a specific annotation which is present on the element (if not present returns {@code Optional.empty()})
     */
    static Optional<? extends AnnotationMirror> getAnnotationMirror(AnnotatedConstruct element,
                                                                     String annotationName) {
        return element.getAnnotationMirrors().stream().filter(a -> a.getAnnotationType().asElement().toString().equals(annotationName)).findFirst();
    }

    static Map<String, Object> getAnnotationValues(AnnotationMirror annotation) {
        return annotation.getElementValues().entrySet().stream().collect(Collectors.toMap(e -> e.getKey().toString(), Map.Entry::getValue));
    }

    @SuppressWarnings("unchecked")
    static  <T> T getAnnotationValue(AnnotationMirror annotation, String name, T defaultValue) {
        return annotation.getElementValues().entrySet().stream().filter(e -> e.getKey().getSimpleName().toString().equals(name)).map(e -> (T)e.getValue().getValue()).findFirst().orElse(defaultValue);
    }

    static boolean hasAnnotation(AnnotatedConstruct element, String annotationName) {
        return getAnnotationMirror(element, annotationName).isPresent();
    }

    private List<TypeElement> getInnerBPFTypeElements(TypeElement typeElement) {
        record Pair(Optional<? extends AnnotationMirror> a, Element e) {
        }
        return typeElement.getEnclosedElements().stream().map(e -> {
            var annotation = getAnnotationMirror(e, TYPE_ANNOTATION);
            return new Pair(annotation, e);
        }).filter(p -> p.a.isPresent()).map(e -> {
            // check that it's a record
            if (e.e.getKind() != ElementKind.RECORD) {
                this.processingEnv.getMessager().printError("Inner class " + e.e.getSimpleName() + " is annotated " + "with " + "Type but is not a record", e.e);
                return null;
            }
            return (TypeElement) e.e;
        }).filter(Objects::nonNull).toList();
    }

    record TypeProcessorResult(List<FieldSpec> fields, List<Define> defines, List<CAST.Statement> definingStatements,
                               @Nullable Statement licenseDefinition, List<MapDefinition> mapDefinitions) {

        String toCCodeWithoutDefines() {
            return definingStatements.stream().map(CAST.Statement::toPrettyString).collect(Collectors.joining("\n"));
        }
    }

    boolean shouldGenerateCCode(TypeElement innerElement) {
        return !getAnnotationMirror(innerElement, TYPE_ANNOTATION).map(a -> getAnnotationValue(a, "noCCodeGeneration", false)).orElse(false);
    }

    /**
     * Process the records annotated with {@code @Type} in the given class
     *
     * @param outerTypeElement the class to process that contains the records
     * @return a list of field specs that define the related {@code BPFStructType} instances
     */
    TypeProcessorResult processBPFTypeRecords(TypeElement outerTypeElement) {
        List<TypeElement> innerTypeElements = getInnerBPFTypeElements(outerTypeElement);
        definedTypes = getDefinedTypes(innerTypeElements);

        Map<JavaName, BPFType<?>> alreadyDefinedTypes = new HashMap<>();
        // detect recursion
        Set<JavaName> currentlyDefining = new HashSet<>();

        List<TypeElement> processedTypes = new ArrayList<>();

        // bpf name to type
        AtomicReference<Function<JavaName, BPFType<?>>> obtainType = new AtomicReference<>();
        obtainType.set(name -> {
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
            var type = processBPFTypeRecord(typeElement, obtainType.get());
            if (type.isEmpty()) {
                this.processingEnv.getMessager().printError("Type " + name + " could not be processed", outerTypeElement);
                return null;
            }
            alreadyDefinedTypes.put(name, type.get());
            currentlyDefining.remove(name);
            processedTypes.add(typeElement);
            return type.get();
        });

        Function<BPFType<?>, SpecFieldName> typeToSpecField = t -> {
            if (t instanceof BPFType.BPFStructType<?> structType) {
                return definedTypes.getSpecFieldName(new BPFName(structType.bpfName())).get();
            }
            return null;
        };

        while (processedTypes.size() < innerTypeElements.size()) {
            var unprocessed = innerTypeElements.stream().filter(e -> !processedTypes.contains(e)).toList();
            var type = processBPFTypeRecord(unprocessed.getFirst(), obtainType.get());
            if (type.isEmpty()) {
                return new TypeProcessorResult(List.of(), List.of(), List.of(), null, List.of());
            }
            alreadyDefinedTypes.put(new JavaName(type.get()), type.get());
            processedTypes.add(unprocessed.getFirst());
        }

        var mapDefinitions = processDefinedMaps(outerTypeElement,
                field -> obtainType.get().apply(definedTypes.bpfNameToName(definedTypes.specFieldNameToName(field))),
                type -> definedTypes.getSpecFieldName(new BPFName(type.bpfName())).get());

        List<FieldSpec> fields = new ArrayList<>();
        List<CAST.Statement> definingStatements = new ArrayList<>();

        for (var processedType : processedTypes) {
            var name = getTypeRecordBpfName(processedType);
            var type = alreadyDefinedTypes.get(new JavaName(processedType));
            var fieldSpecName = definedTypes.getSpecFieldName(name).get().name;
            var spec = type.toFieldSpecGenerator().get().apply(fieldSpecName,
                    t -> t.toJavaFieldSpecUse(t2 -> typeToSpecField.apply(t2).name()));
            fields.add(spec);
            if (shouldGenerateCCode(processedType)) {
                type.toCDeclarationStatement().ifPresent(definingStatements::add);
            }
        }
        return new TypeProcessorResult(fields, createDefineStatements(outerTypeElement), definingStatements,
                getLicenseDefinitionStatement(outerTypeElement), mapDefinitions);
    }

    private @Nullable Statement getLicenseDefinitionStatement(TypeElement outerTypeElement) {
        var annotation = getAnnotationMirror(outerTypeElement, "me.bechberger.ebpf.annotations.bpf.BPF");
        if (annotation.isEmpty()) {
            return null;
        }
        var license = getAnnotationValue(annotation.get(), "license", "");
        if (license.isEmpty()) {
            return null;
        }
        // char _license[] SEC ("license") = "GPL";
        return variableDefinition(Declarator.array(Declarator.identifier("char"), null), variable("_license", CAnnotation.sec("license")), constant(license));
    }

    private @Nullable CAST.Statement.Define processField(VariableElement field) {
        // check that the field is static, final and of type boolean, ..., int, long, float, double or String
        // create a #define statement for the field
        // return the #define statement
        if (!field.getModifiers().contains(Modifier.STATIC) || !field.getModifiers().contains(Modifier.FINAL) || field.getSimpleName().toString().equals("EBPF_PROGRAM")) {
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
    private BPFName getTypeRecordBpfName(TypeElement typeElement) {
        var annotation = getAnnotationMirror(typeElement, "me.bechberger.ebpf.annotations.bpf.Type");
        assert annotation.isPresent();
        var name =
                annotation.get().getElementValues().entrySet().stream().filter(e -> e.getKey().getSimpleName().toString().equals("name")).findFirst();
        return name.map(entry -> new BPFName(entry.getValue().getValue().toString()))
                .orElseGet(() -> new BPFName(typeElement.getSimpleName().toString()));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private Optional<BPFType.BPFStructType<?>> processBPFTypeRecord(TypeElement typeElement, Function<JavaName, BPFType<?>> nameToCustomType) {
        String className = typeElement.getQualifiedName().toString();
        var name = getTypeRecordBpfName(typeElement);
        var constructors =
                typeElement.getEnclosedElements().stream().filter(e -> e.getKind() == ElementKind.CONSTRUCTOR).toList();
        if (constructors.size() != 1) {
            this.processingEnv.getMessager().printError("Record " + typeElement.getSimpleName() + " must have " +
                    "exactly" + " one " + "constructor", typeElement);
            return Optional.empty();
        }
        var constructor = (ExecutableElement) constructors.getFirst();
        Optional<List<BPFType.UBPFStructMember<?, ?>>> members =
                processBPFTypeRecordMembers(constructor.getParameters(), nameToCustomType);
        if (members.isEmpty()) {
            return Optional.empty();
        }

        BPFType.AnnotatedClass annotatedClass = new BPFType.AnnotatedClass(className, List.of());

        return Optional.of(BPFType.BPFStructType.autoLayout(name.name(),
                (List<BPFType.UBPFStructMember<Object, ?>>)(List)members.get(),
                annotatedClass, null));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private Optional<List<BPFType.UBPFStructMember<?, ?>>> processBPFTypeRecordMembers(List<? extends VariableElement> recordMembers, Function<JavaName, BPFType<?>> nameToCustomType) {
        var list = recordMembers.stream().map(m -> processBPFTypeRecordMember(m, nameToCustomType)).toList();
        if (list.stream().anyMatch(Optional::isEmpty)) {
            return Optional.empty();
        }
        return Optional.of((List<BPFType.UBPFStructMember<?, ?>>)(List)list.stream().map(Optional::get).toList());
    }

    record AnnotationValues(boolean unsigned, Optional<Integer> size) {
    }

    private AnnotationValues getAnnotationValuesForRecordMember(VariableElement element) {
        return getAnnotationValuesForRecordMember(element.asType());
    }

    private AnnotationValues getAnnotationValuesForRecordMember(AnnotatedConstruct element) {
        boolean unsigned = hasAnnotation(element, UNSIGNED_ANNOTATION);
        Optional<Integer> size = Optional.empty();
        Optional<String> bpfType = Optional.empty();
        var sizeAnnotation = getAnnotationMirror(element, SIZE_ANNOTATION);
        if (sizeAnnotation.isPresent()) {
            var value = sizeAnnotation.get().getElementValues().entrySet().stream().findFirst();
            if (value.isPresent()) {
                size = Optional.of((Integer) value.get().getValue().getValue());
            }
        }
        return new AnnotationValues(unsigned, size);
    }

    private Optional<BPFType.UBPFStructMember<?, ?>> processBPFTypeRecordMember(VariableElement element,
                                                                                Function<JavaName, BPFType<?>> nameToCustomType) {
        AnnotationValues annotations = getAnnotationValuesForRecordMember(element);
        TypeMirror type = element.asType();
        var bpfType = processBPFTypeRecordMemberType(element, annotations, type);
        return bpfType.map(t -> new BPFType.UBPFStructMember<>(element.getSimpleName().toString(),
                t.toBPFType(nameToCustomType), null, null));
    }

    private static final Set<String> integerTypes = Set.of("int", "long", "short", "byte", "char");

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
                boxedToUnboxedIntegerType.containsKey(typeName);
    }

    private boolean isStringType(TypeMirror type) {
        // comparing strings isn't pretty, but it works without additional module exports
        // maybe revisit loter
        var lastPart = lastPart(type.toString());
        return lastPart.equals("String") || lastPart.equals("java.lang.String");
    }

    private Optional<BPFTypeMirror> processBPFTypeRecordMemberType(Element element, AnnotationValues annotations,
                                                                   TypeMirror type) {
        if (isIntegerType(type)) {
            return processIntegerType(element, annotations, type).map(tp -> (t -> tp));
        }
        if (isStringType(type)) {
            return processStringType(element, annotations, type);
        }
        if (definedTypes.isTypeDefined((TypeElement) processingEnv.getTypeUtils().asElement(type))) {
            return processDefinedType(element, annotations, type);
        }
        this.processingEnv.getMessager().printError("Unsupported type " + type, element);
        return Optional.empty();
    }

    @FunctionalInterface
    interface BPFTypeMirror {

        BPFType<?> toBPFType(Function<JavaName, BPFType<?>> nameToCustomType);
    }

    private Optional<BPFType<?>> processIntegerType(Element element, AnnotationValues annotations, TypeMirror type) {
        if (annotations.size().isPresent()) {
            // annotation not supported for integer types and log
            this.processingEnv.getMessager().printError("Size annotation not supported for integer types", element);
            return Optional.empty();
        }
        boolean unsigned = annotations.unsigned;
        var typeName = lastPart(type.toString());
        var numberName = boxedToUnboxedIntegerType.getOrDefault(typeName, typeName);
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
        if (annotations.size().isEmpty()) {
            this.processingEnv.getMessager().printError("Size annotation required for string types", element);
            return Optional.empty();
        }
        if (annotations.unsigned) {
            this.processingEnv.getMessager().printError("Unsigned annotation not supported for string types", element);
            return Optional.empty();
        }
        return Optional.of(t -> new BPFType.StringType(annotations.size().get()));
    }

    private Optional<BPFTypeMirror> processDefinedType(Element element, AnnotationValues annotations, TypeMirror type) {
        if (annotations.size().isPresent()) {
            this.processingEnv.getMessager().printError("Size annotation not supported for defined types", element);
            return Optional.empty();
        }
        if (annotations.unsigned) {
            this.processingEnv.getMessager().printError("Unsigned annotation not supported for defined types", element);
            return Optional.empty();
        }
        TypeElement typeElement = (TypeElement) processingEnv.getTypeUtils().asElement(type);
        Optional<SpecFieldName> fieldName = definedTypes.getFieldName(typeElement);
        if (fieldName.isEmpty()) {
            this.processingEnv.getMessager().printError("Type " + typeElement.getSimpleName() + " not defined",
                    element);
            return Optional.empty();
        }
        var typeName = definedTypes.bpfNameToName(definedTypes.specFieldNameToName(fieldName.get()));
        return Optional.of(t -> t.apply(typeName));
    }

    private DefinedTypes getDefinedTypes(List<TypeElement> innerTypeElements) {
        return new DefinedTypes(innerTypeElements.stream().collect(Collectors.toMap(e -> e, this::typeToFieldName)));
    }

    /**
     * Field name is camel-case and upper-case version of simple type name
     */
    private SpecFieldName typeToFieldName(TypeElement typeElement) {
        return new SpecFieldName(toSnakeCase(typeElement.getSimpleName().toString()).toUpperCase());
    }

    /**
     * Convert a name to snake case
     * <p>
     * Example: "HelloWorld" -> "hello_world"
     */
    private static String toSnakeCase(String name) {
        return name.replaceAll("([a-z0-9])([A-Z])", "$1_$2");
    }

    /**
     * Combines the C and the Java code to construct a map
     * @param javaFieldInitializer code that initializes a map field in the constructor of the BPFProgram implementation
     * @param structDefinition the C struct definition of the map
     */
    record MapDefinition(String javaFieldName, String javaFieldInitializer, Statement structDefinition) {
    }

    List<MapDefinition> processDefinedMaps(TypeElement outerElement, Function<SpecFieldName, BPFType<?>> fieldToType,
                                           Function<BPFType<?>, SpecFieldName> typeToSpecFieldName) {
        // take all @BPFMapDefinition annotated fields
        return outerElement.getEnclosedElements().stream().filter(e -> e.getKind() == ElementKind.FIELD).map(e -> (VariableElement) e)
                .filter(e -> getAnnotationMirror(e.asType(), BPF_MAP_DEFINITION).isPresent())
                .map(f -> processMapDefiningField(f, fieldToType, typeToSpecFieldName)).filter(Objects::nonNull).toList();
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Nullable MapDefinition processMapDefiningField(VariableElement field,
                                                    Function<SpecFieldName, BPFType<?>> fieldToType,
                                                    Function<BPFType<?>, SpecFieldName> typeToSpecFieldName) {
        // create a FieldSpec for the field
        // create a #define statement for the field
        // return the FieldSpec and the #define statement
        var annotation = getAnnotationMirror(field.asType(), BPF_MAP_DEFINITION);
        assert annotation.isPresent();
        var maxEntries = getAnnotationValue(annotation.get(), "maxEntries", 0);
        if (maxEntries == 0) {
            this.processingEnv.getMessager().printError("maxEntries must be set and larger than 0", field);
        }

        var type = field.asType();
        if (!(type instanceof DeclaredType declaredType)) {
            this.processingEnv.getMessager().printError("Field must be a declared type", field);
            return null;
        }
        // get generic type members
        var typeParams = declaredType.getTypeArguments().stream()
                .map(t -> processBPFTypeRecordMemberType(field, getAnnotationValuesForRecordMember(t), t)
                        .map(m -> m.toBPFType(mt -> fieldToType.apply(definedTypes.nameToSpecFieldName(definedTypes.nameToBPFName(mt)))))).toList();
        if (typeParams.stream().anyMatch(Optional::isEmpty)) {
            this.processingEnv.getMessager().printError("Type parameters must be valid", field);
            return null;
        }
        List<BPFType<?>> typeParameters = (List<BPFType<?>>) (List) typeParams.stream().map(Optional::get).toList();

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

        return new MapDefinition(field.getSimpleName().toString(),
                processBPFClassJavaTemplate(field, javaTemplate, typeParameters, maxEntries, fieldName, className, typeToSpecFieldName),
                processBPFClassCTemplate(field, cTemplate, typeParameters, maxEntries, fieldName, className, typeToSpecFieldName));
    }

    String processBPFClassJavaTemplate(VariableElement field, String javaTemplate,
                                       List<BPFType<?>> typeParams, Integer maxEntries,
                                       String fieldName, String className,
                                       Function<BPFType<?>, SpecFieldName> typeToSpecFieldName) {
        return "this." + field.getSimpleName() + " = recordMap(" + processBPFClassTemplate(javaTemplate, typeParams,
                 maxEntries, fieldName, className, typeToSpecFieldName).strip() + ")";
    }



    Statement processBPFClassCTemplate(VariableElement field, String cTemplate, List<BPFType<?>> typeParameters,
                                       Integer maxEntries, String fieldName, String className,
                                       Function<BPFType<?>, SpecFieldName> typeToSpecFieldName) {
        String raw = processBPFClassTemplate(cTemplate, typeParameters,
                maxEntries, fieldName, className, typeToSpecFieldName);
        return new VerbatimStatement(raw);
    }

    String processBPFClassTemplate(String template, List<BPFType<?>> typeParams, int maxEntries, String fieldName,
                                   String className, Function<BPFType<?>, SpecFieldName> typeToSpecFieldName) {
        var classNames = typeParams.stream().map(BPFType::javaClass).map(AnnotatedClass::toString).toList();
        var cTypeNames = typeParams.stream().map(BPFType::bpfName).toList();
        var bFields = typeParams.stream().map(t -> t.toJavaFieldSpecUse(tm -> typeToSpecFieldName.apply(tm).name)).toList();
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