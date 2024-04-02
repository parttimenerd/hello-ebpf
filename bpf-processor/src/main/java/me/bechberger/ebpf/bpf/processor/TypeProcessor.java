package me.bechberger.ebpf.bpf.processor;

import com.squareup.javapoet.FieldSpec;
import me.bechberger.cast.CAST;
import me.bechberger.cast.CAST.Statement.Define;
import me.bechberger.ebpf.type.BPFType;
import org.jetbrains.annotations.Nullable;

import javax.annotation.processing.ProcessingEnvironment;
import javax.lang.model.AnnotatedConstruct;
import javax.lang.model.element.*;
import javax.lang.model.type.PrimitiveType;
import javax.lang.model.type.TypeMirror;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.stream.Collectors;

import static me.bechberger.cast.CAST.Expression.constant;
import static me.bechberger.cast.CAST.Statement.define;

/**
 * Handles {@code @Type} annotated records
 */
public class TypeProcessor {

    public final static String SIZE_ANNOTATION = "me.bechberger.ebpf.annotations.Size";
    public final static String UNSIGNED_ANNOTATION = "me.bechberger.ebpf.annotations.Unsigned";
    public final static String TYPE_ANNOTATION = "me.bechberger.ebpf.annotations.bpf.Type";
    public final static String BPF_PACKAGE = "me.bechberger.ebpf.type";
    public final static String BPF_TYPE = "me.bechberger.ebpf.type.BPFType";
    /**
     * Helper class to keep track of defined types
     */
    private class DefinedTypes {

        private final Map<TypeElement, String> typeToFieldName;
        private final Map<String, String> nameToSpecFieldName;

        private final Map<String, TypeElement> nameToTypeElement;

        DefinedTypes(Map<TypeElement, String> typeToFieldName) {
            this.typeToFieldName = typeToFieldName;
            this.nameToSpecFieldName = new HashMap<>();
            this.nameToTypeElement = new HashMap<>();
            this.typeToFieldName.forEach((k, v) -> {
                var name = getTypeRecordBpfName(k);
                this.nameToSpecFieldName.put(name, v);
                this.nameToTypeElement.put(name, k);
            });
        }

        public boolean isTypeDefined(TypeElement typeElement) {
            return this.typeToFieldName.containsKey(typeElement);
        }

        public boolean isNameDefined(String name) {
            return this.nameToSpecFieldName.containsKey(name);
        }

        public Optional<String> getFieldName(TypeElement typeElement) {
            return Optional.ofNullable(this.typeToFieldName.get(typeElement));
        }

        public Optional<String> getSpecFieldName(String name) {
            return Optional.ofNullable(this.nameToSpecFieldName.get(name));
        }

        public Optional<TypeElement> getTypeElement(String name) {
            return Optional.ofNullable(this.nameToTypeElement.get(name));
        }

        @Override
        public String toString() {
            return this.typeToFieldName.toString();
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
    private Optional<? extends AnnotationMirror> getAnnotationMirror(AnnotatedConstruct element,
                                                                     String annotationName) {
        return element.getAnnotationMirrors().stream().filter(a -> a.getAnnotationType().asElement().toString().equals(annotationName)).findFirst();
    }

    private Map<String, Object> getAnnotationValues(AnnotationMirror annotation) {
        return annotation.getElementValues().entrySet().stream().collect(Collectors.toMap(e -> e.getKey().toString(), Map.Entry::getValue));
    }

    @SuppressWarnings("unchecked")
    private <T> T getAnnotationValue(AnnotationMirror annotation, String name, T defaultValue) {
        return annotation.getElementValues().entrySet().stream().filter(e -> e.getKey().getSimpleName().toString().equals(name)).map(e -> (T)e.getValue().getValue()).findFirst().orElse(defaultValue);
    }

    private boolean hasAnnotation(AnnotatedConstruct element, String annotationName) {
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

    record TypeProcessorResult(List<FieldSpec> fields, List<Define> defines, List<CAST.Statement> definingStatements) {

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

        Map<String, BPFType<?>> alreadyDefinedTypes = new HashMap<>();
        // detect recursion
        Set<String> currentlyDefining = new HashSet<>();

        List<TypeElement> processedTypes = new ArrayList<>();

        AtomicReference<Function<String, BPFType<?>>> obtainType = new AtomicReference<>();
        obtainType.set(name -> {
            if (alreadyDefinedTypes.containsKey(name)) {
                return alreadyDefinedTypes.get(name);
            }
            if (currentlyDefining.contains(name)) {
                this.processingEnv.getMessager().printError("Recursion detected for type " + name, outerTypeElement);
                throw new IllegalStateException("Recursion detected for type " + name);
            }
            currentlyDefining.add(name);
            var typeElement = definedTypes.getTypeElement(name).get();
            var type = processBPFTypeRecord(typeElement, obtainType.get());
            if (type.isEmpty()) {
                return null;
            }
            alreadyDefinedTypes.put(name, type.get());
            currentlyDefining.remove(name);
            processedTypes.add(typeElement);
            return type.get();
        });

        Function<BPFType<?>, String> typeToSpecField = t -> {
            if (t instanceof BPFType.BPFStructType<?> structType) {
                return definedTypes.getSpecFieldName(structType.bpfName()).get();
            }
            return null;
        };

        while (processedTypes.size() < innerTypeElements.size()) {
            var unprocessed = innerTypeElements.stream().filter(e -> !processedTypes.contains(e)).toList();
            var type = processBPFTypeRecord(unprocessed.get(0), obtainType.get());
            if (type.isEmpty()) {
                return new TypeProcessorResult(List.of(), List.of(), List.of());
            }
            alreadyDefinedTypes.put(type.get().bpfName(), type.get());
            processedTypes.add(unprocessed.get(0));
        }

        List<FieldSpec> fields = new ArrayList<>();
        List<CAST.Statement> definingStatements = new ArrayList<>();

        for (var processedType : processedTypes) {
            var name = getTypeRecordBpfName(processedType);
            var type = alreadyDefinedTypes.get(getTypeRecordBpfName(processedType));
            var spec = type.toFieldSpecGenerator().get().apply(definedTypes.getSpecFieldName(name).get(),
                    typeToSpecField);
            fields.add(spec);
            if (shouldGenerateCCode(processedType)) {
                type.toCDeclarationStatement().ifPresent(definingStatements::add);
            }
        }
        return new TypeProcessorResult(fields, createDefineStatements(outerTypeElement), definingStatements);
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
    private String getTypeRecordBpfName(TypeElement typeElement) {
        var annotation = getAnnotationMirror(typeElement, "me.bechberger.ebpf.annotations.bpf.Type");
        assert annotation.isPresent();
        var name =
                annotation.get().getElementValues().entrySet().stream().filter(e -> e.getKey().getSimpleName().toString().equals("name")).findFirst();
        if (name.isEmpty()) {
            return typeElement.getSimpleName().toString();
        }
        return name.get().getValue().getValue().toString();
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private Optional<BPFType.BPFStructType<?>> processBPFTypeRecord(TypeElement typeElement, Function<String, BPFType<?>> nameToCustomType) {
        String className = typeElement.getSimpleName().toString();
        String name = getTypeRecordBpfName(typeElement);
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

        return Optional.of(BPFType.BPFStructType.autoLayout(name,
                (List<BPFType.UBPFStructMember<Object, ?>>)(List)members.get(),
                annotatedClass, null));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private Optional<List<BPFType.UBPFStructMember<?, ?>>> processBPFTypeRecordMembers(List<? extends VariableElement> recordMembers, Function<String, BPFType<?>> nameToCustomType) {
        var list = recordMembers.stream().map(m -> processBPFTypeRecordMember(m, nameToCustomType)).toList();
        if (list.stream().anyMatch(Optional::isEmpty)) {
            return Optional.empty();
        }
        return Optional.of((List<BPFType.UBPFStructMember<?, ?>>)(List)list.stream().map(Optional::get).toList());
    }

    record AnnotationValues(boolean unsigned, Optional<Integer> size) {
    }

    private AnnotationValues getAnnotationValuesForRecordMember(VariableElement element) {
        boolean unsigned = hasAnnotation(element.asType(), UNSIGNED_ANNOTATION);
        Optional<Integer> size = Optional.empty();
        Optional<String> bpfType = Optional.empty();
        var sizeAnnotation = getAnnotationMirror(element.asType(), SIZE_ANNOTATION);
        if (sizeAnnotation.isPresent()) {
            var value = sizeAnnotation.get().getElementValues().entrySet().stream().findFirst();
            if (value.isPresent()) {
                size = Optional.of((Integer) value.get().getValue().getValue());
            }
        }
        return new AnnotationValues(unsigned, size);
    }

    private Optional<BPFType.UBPFStructMember<?, ?>> processBPFTypeRecordMember(VariableElement element,
                                                                                Function<String, BPFType<?>> nameToCustomType) {
        AnnotationValues annotations = getAnnotationValuesForRecordMember(element);
        TypeMirror type = element.asType();
        var bpfType = processBPFTypeRecordMemberType(element, annotations, type);
        return bpfType.map(t -> {
            return new BPFType.UBPFStructMember<>(element.getSimpleName().toString(),
                    t.toBPFType(nameToCustomType), null, null);
        });
    }

    private static final Set<String> integerTypes = Set.of("int", "long", "short", "byte", "char");

    private static String lastPart(String s) {
        return s.substring(s.lastIndexOf(" ") + 1);
    }

    private boolean isIntegerType(TypeMirror type) {
        return type instanceof PrimitiveType p && integerTypes.contains(lastPart(p.toString()));
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

        BPFType<?> toBPFType(Function<String, BPFType<?>> nameToCustomType);
    }

    private Optional<BPFType<?>> processIntegerType(Element element, AnnotationValues annotations, TypeMirror type) {
        if (annotations.size().isPresent()) {
            // annotation not supported for integer types and log
            this.processingEnv.getMessager().printError("Size annotation not supported for integer types", element);
            return Optional.empty();
        }
        boolean unsigned = annotations.unsigned;
        return switch (lastPart(type.toString())) {
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
        Optional<String> fieldName = definedTypes.getFieldName(typeElement);
        if (fieldName.isEmpty()) {
            this.processingEnv.getMessager().printError("Type " + typeElement.getSimpleName() + " not defined",
                    element);
            return Optional.empty();
        }
        return Optional.of(t -> t.apply(fieldName.get()));
    }

    private DefinedTypes getDefinedTypes(List<TypeElement> innerTypeElements) {
        return new DefinedTypes(innerTypeElements.stream().collect(Collectors.toMap(e -> e, this::typeToFieldName)));
    }

    /**
     * Field name is camel-case and upper-case version of simple type name
     */
    private String typeToFieldName(TypeElement typeElement) {
        return toSnakeCase(typeElement.getSimpleName().toString()).toUpperCase();
    }

    /**
     * Convert a name to snake case
     * <p>
     * Example: "HelloWorld" -> "hello_world"
     */
    private static String toSnakeCase(String name) {
        return name.replaceAll("([a-z0-9])([A-Z])", "$1_$2");
    }
}