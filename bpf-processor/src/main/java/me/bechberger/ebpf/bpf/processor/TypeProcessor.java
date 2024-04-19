package me.bechberger.ebpf.bpf.processor;

import com.squareup.javapoet.FieldSpec;
import me.bechberger.cast.CAST;
import me.bechberger.cast.CAST.PrimaryExpression.CAnnotation;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.bpf.processor.AnnotationUtils.AnnotationValues;
import me.bechberger.ebpf.bpf.processor.DefinedTypes.BPFName;
import me.bechberger.ebpf.bpf.processor.DefinedTypes.JavaName;
import me.bechberger.ebpf.bpf.processor.DefinedTypes.SpecFieldName;
import me.bechberger.ebpf.bpf.processor.BPFTypeLike.TypeBackedBPFStructType;
import me.bechberger.ebpf.type.BPFType;
import me.bechberger.ebpf.type.BPFType.CustomBPFType;
import org.jetbrains.annotations.Nullable;

import javax.annotation.processing.ProcessingEnvironment;
import javax.lang.model.element.*;
import javax.lang.model.type.*;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Stream;

import static me.bechberger.cast.CAST.Expression.constant;
import static me.bechberger.cast.CAST.Expression.variable;
import static me.bechberger.cast.CAST.Statement.*;
import static me.bechberger.ebpf.bpf.processor.AnnotationUtils.*;

/**
 * Handles {@code @Type} annotated records
 */
class TypeProcessor {

    public final static String TYPE_ANNOTATION = "me.bechberger.ebpf.annotations.bpf.Type";
    public final static String BPF_PACKAGE = "me.bechberger.ebpf.type";
    public final static String BPF_TYPE = "me.bechberger.ebpf.type.BPFType";
    public final static String BPF_MAP_DEFINITION = "me.bechberger.ebpf.annotations.bpf.BPFMapDefinition";
    public final static String BPF_MAP_CLASS = "me.bechberger.ebpf.annotations.bpf.BPFMapClass";

    private final ProcessingEnvironment processingEnv;
    private TypeElement outerTypeElement;
    private DefinedTypes definedTypes;
    private Map<JavaName, BPFTypeLike<?>> alreadyDefinedTypes;
    private Set<JavaName> currentlyDefining;
    private List<TypeElement> processedTypes;
    /** For generating the C code later */
    private List<CustomBPFType<?>> usedCustomBPFTypes;

    TypeProcessor(ProcessingEnvironment processingEnv) {
        this.processingEnv = processingEnv;
    }

    /** Returns all records annotated with {@code @Type} and types specified in the {@link me.bechberger.ebpf.annotations.bpf.BPF} annotation */
    private List<TypeElement> getRequiredBPFTypeElements(TypeElement typeElement) {
        return Stream.concat(getInnerBPFTypeElements(typeElement).stream(), getBPFSpecifiedTypeElements(typeElement).stream()).toList();
    }

    private List<TypeElement> getInnerBPFTypeElements(TypeElement typeElement) {
        record Pair(Optional<? extends AnnotationMirror> a, Element e) {
        }
        return typeElement.getEnclosedElements().stream().filter(this::isTypeAnnotatedRecord).map(e -> (TypeElement) e).toList();
    }

    private boolean isTypeAnnotatedRecord(Element element) {
        if (getAnnotationMirror(element, TYPE_ANNOTATION).isPresent()) {
            if (element.getKind() != ElementKind.RECORD) {
                this.processingEnv.getMessager().printError("Inner class " + element.getSimpleName() + " is annotated " + "with Type but is not a record", element);
                return false;
            }
            return true;
        }
        return false;
    }

    private boolean isCustomTypeAnnotatedRecord(Element element) {
        return getAnnotationMirror(element, "me.bechberger.ebpf.annotations.bpf.CustomType").isPresent();
    }

    /** Returns all types specified in the {@link me.bechberger.ebpf.annotations.bpf.BPF} annotation */
    private List<TypeElement> getBPFSpecifiedTypeElements(TypeElement typeElement) {
        var annotation = getAnnotationMirror(typeElement, "me.bechberger.ebpf.annotations.bpf.BPF");
        assert annotation.isPresent();
        var specifiedClasses = AnnotationUtils.getAnnotationValue(annotation.get(), "includeTypes", List.of());
        return specifiedClasses.stream().map(c -> {
            String klass = c.toString().substring(0, c.toString().length() - ".class".length());
            return processingEnv.getElementUtils().getTypeElement(klass);
        }).toList();
    }

    record TypeProcessorResult(List<FieldSpec> fields, List<Define> defines, List<CAST.Statement> definingStatements,
                               @Nullable Statement licenseDefinition, List<MapDefinition> mapDefinitions) {
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
                return new TypeProcessorResult(List.of(), List.of(), List.of(), null, List.of());
            }
            alreadyDefinedTypes.put(type.get().getJavaName(), type.get());
            processedTypes.add(unprocessed.getFirst());
        }

        var mapDefinitions = processDefinedMaps(outerTypeElement,
                field -> getBPFTypeForJavaName(definedTypes.bpfNameToName(definedTypes.specFieldNameToName(field))),
                type -> definedTypes.getSpecFieldName(type.getBPFName()).get());

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
            assert type instanceof BPFTypeLike.TypeBackedBPFStructType<?>;
            var actualType = ((TypeBackedBPFStructType<?>) type).type;
            var spec = actualType.toFieldSpecGenerator().get().apply(fieldSpecName,
                    t -> t.toJavaFieldSpecUse(t2 -> typeToSpecField.apply(BPFTypeLike.of(t2)).name()));
            fields.add(spec);
            if (shouldGenerateCCode(processedType)) {
                actualType.toCDeclarationStatement().ifPresent(definingStatements::add);
            }
        }

        return new TypeProcessorResult(fields, createDefineStatements(outerTypeElement), definingStatements,
                getLicenseDefinitionStatement(outerTypeElement), mapDefinitions);
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
    BPFName getTypeRecordBpfName(TypeElement typeElement) {
        var annotation = getAnnotationMirror(typeElement, "me.bechberger.ebpf.annotations.bpf.Type");
        if (annotation.isEmpty()) {
            annotation = getAnnotationMirror(typeElement, "me.bechberger.ebpf.annotations.bpf.CustomType");
        }
        assert annotation.isPresent();
        return new BPFName(getAnnotationValue(annotation.get(), "name", typeElement.getSimpleName().toString()));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private Optional<TypeBackedBPFStructType<?>> processBPFTypeRecord(TypeElement typeElement) {
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
                processBPFTypeRecordMembers(constructor.getParameters());
        if (members.isEmpty()) {
            return Optional.empty();
        }

        BPFType.AnnotatedClass annotatedClass = new BPFType.AnnotatedClass(className, List.of());

        return Optional.of(new TypeBackedBPFStructType<>(BPFType.BPFStructType.autoLayout(name.name(),
                (List<BPFType.UBPFStructMember<Object, ?>>)(List)members.get(),
                annotatedClass, null)));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private Optional<List<BPFType.UBPFStructMember<?, ?>>> processBPFTypeRecordMembers(List<? extends VariableElement> recordMembers) {
        var list = recordMembers.stream().map(this::processBPFTypeRecordMember).toList();
        if (list.stream().anyMatch(Optional::isEmpty)) {
            return Optional.empty();
        }
        return Optional.of((List<BPFType.UBPFStructMember<?, ?>>)(List)list.stream().map(Optional::get).toList());
    }

    private Optional<BPFType.UBPFStructMember<?, ?>> processBPFTypeRecordMember(VariableElement element) {
        AnnotationValues annotations = getAnnotationValuesForRecordMember(element);
        TypeMirror type = element.asType();
        var bpfType = processBPFTypeRecordMemberType(element, annotations, type);
        return bpfType.map(t -> new BPFType.UBPFStructMember<>(element.getSimpleName().toString(),
                t.toBPFType(this::getBPFTypeForJavaName).toCustomType(), null, null));
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
            return processIntegerType(element, annotations, type).map(tp -> (t -> BPFTypeLike.of(tp)));
        }
        if (isStringType(type)) {
            return processStringType(element, annotations, type);
        }
        var typeElement = (TypeElement) processingEnv.getTypeUtils().asElement(type);

        System.out.println("Type " + typeElement.getSimpleName());
         if (isTypeAnnotatedRecord(typeElement)) {
            return processDefinedType(element, annotations, type);
        }
        if (isCustomTypeAnnotatedRecord(typeElement)) {
            return processCustomType(element, annotations, type);
        }
        this.processingEnv.getMessager().printError("Unsupported type " + type, element);
        return Optional.empty();
    }

    @FunctionalInterface
    interface BPFTypeMirror {

        BPFTypeLike<?> toBPFType(Function<JavaName, BPFTypeLike<?>> nameToCustomType);
    }

    private Optional<BPFType<?>> processIntegerType(Element element, AnnotationValues annotations, TypeMirror type) {
        if (annotations.size().isPresent()) {
            // annotation not supported for integer types and log
            this.processingEnv.getMessager().printError("Size annotation not supported for integer types", element);
            return Optional.empty();
        }
        boolean unsigned = annotations.unsigned();
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
        if (annotations.unsigned()) {
            this.processingEnv.getMessager().printError("Unsigned annotation not supported for string types", element);
            return Optional.empty();
        }
        return Optional.of(t -> BPFTypeLike.of(new BPFType.StringType(annotations.size().get())));
    }

    private Optional<BPFTypeMirror> processDefinedType(Element element, AnnotationValues annotations, TypeMirror type) {
        if (!checkAnnotatedType(element, annotations)) {
            return Optional.empty();
        }
        TypeElement typeElement = (TypeElement) processingEnv.getTypeUtils().asElement(type);
        SpecFieldName fieldName = definedTypes.getOrCreateFieldName(typeElement);
        var typeName = definedTypes.bpfNameToName(definedTypes.specFieldNameToName(fieldName));
        return Optional.of(t -> t.apply(typeName));
    }

    private boolean checkAnnotatedType(Element element, AnnotationValues annotations) {
        if (annotations.size().isPresent()) {
            this.processingEnv.getMessager().printError("Size annotation not supported for defined types", element);
            return false;
        }
        if (annotations.unsigned()) {
            this.processingEnv.getMessager().printError("Unsigned annotation not supported for defined types", element);
            return false;
        }
        return true;
    }

    private Optional<BPFTypeMirror> processCustomType(Element element, AnnotationValues annotations, TypeMirror type) {
        if (!checkAnnotatedType(element, annotations)) {
            return Optional.empty();
        }
        TypeElement typeElement = (TypeElement) processingEnv.getTypeUtils().asElement(type);
        if (!definedTypes.isTypeDefined(typeElement)) {
            addCustomType(typeElement);
        }
        Optional<SpecFieldName> fieldName = definedTypes.getFieldName(typeElement);
        if (fieldName.isEmpty()) {
           return Optional.empty();
        }
        var typeName = definedTypes.bpfNameToName(definedTypes.specFieldNameToName(fieldName.get()));
        return Optional.of(t -> t.apply(typeName));
    }

    private void addCustomType(TypeElement typeElement) {
        var optAnn = getAnnotationMirror(typeElement, "me.bechberger.ebpf.annotations.bpf.CustomType");
        assert optAnn.isPresent();
        var javaName = new JavaName(typeElement);
        var bpfName = new BPFName(getAnnotationValue(optAnn.get(), "name", typeElement.getSimpleName().toString()));
        var fieldNameString = getAnnotationValue(optAnn.get(), "specFieldName", "").replace("$class", javaName.name());
        if (typeElement.getEnclosingElement() instanceof TypeElement outerClass) {
            fieldNameString = fieldNameString.replace("$outerClass", outerClass.getQualifiedName().toString());
        }
        var fieldName = new SpecFieldName(fieldNameString);
        if (!fieldNameString.contains(".")) {
            // probably a field of the current class
            this.processingEnv.getMessager().printError("specFieldName must be set", typeElement);
            return;
        }
        var isStruct = getAnnotationValue(optAnn.get(), "isStruct", false);
        var cCode = getAnnotationValue(optAnn.get(), "cCode", "").replace("$name", bpfName.name());
        definedTypes.insertType(typeElement, bpfName, fieldName);
        usedCustomBPFTypes.add(new CustomBPFType<>(javaName.name(), bpfName.name(), () -> {
            return isStruct ? Declarator.structIdentifier(variable(bpfName.name())) : Declarator.identifier(bpfName.name());
        },  f -> fieldName.name(), () -> cCode.isEmpty() ? Optional.<Statement>empty() : Optional.of(verbatim(cCode))));
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
        return new SpecFieldName(toSnakeCase(name).toUpperCase());
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

        return new MapDefinition(field.getSimpleName().toString(),
                processBPFClassJavaTemplate(field, javaTemplate, typeParameters, maxEntries, fieldName, className, typeToSpecFieldName),
                processBPFClassCTemplate(field, cTemplate, typeParameters, maxEntries, fieldName, className, typeToSpecFieldName));
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
        var cTypeNames = typeParams.stream().map(BPFTypeLike::getBPFName).toList();
        var bFields = typeParams.stream().map(t -> t.toJavaFieldSpecUse(tm -> typeToSpecFieldName.apply(BPFTypeLike.of(tm)).name())).toList();
        String res = template;
        for (int i = typeParams.size(); i > 0; i--) {
            res = res.replace("$c" + i, cTypeNames.get(i - 1).name())
                    .replace("$j" + i, classNames.get(i - 1))
                    .replace("$b" + i, bFields.get(i - 1));
        }
        return res.replace("$maxEntries", Integer.toString(maxEntries))
                .replace("$field", fieldName)
                .replace("$class", className)
                .replace("$fd", "getMapDescriptorByName(" + CAST.toStringLiteral(fieldName) + ")");
    }
}