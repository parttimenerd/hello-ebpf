package me.bechberger.ebpf.bpf.processor;

import com.squareup.javapoet.ClassName;
import com.squareup.javapoet.FieldSpec;
import com.squareup.javapoet.ParameterizedTypeName;
import com.squareup.javapoet.TypeName;

import javax.annotation.processing.ProcessingEnvironment;
import javax.lang.model.AnnotatedConstruct;
import javax.lang.model.element.*;
import javax.lang.model.type.PrimitiveType;
import javax.lang.model.type.TypeMirror;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Handles {@code @Type} annotated records
 */
class TypeProcessor {

    private final String SIZE_ANNOTATION = "me.bechberger.ebpf.annotations.Size";
    private final String UNSIGNED_ANNOTATION = "me.bechberger.ebpf.annotations.Unsigned";
    private final String TYPE_ANNOTATION = "me.bechberger.ebpf.annotations.bpf.Type";
    private final String TYPE_MEMBER_ANNOTATION = "me.bechberger.ebpf.annotations.bpf.Type.Member";

    private final String BPF_PACKAGE = "me.bechberger.ebpf.shared";
    private final String BPF_TYPE = "me.bechberger.ebpf.shared.BPFType";
    private final String BPF_INT_TYPE = BPF_TYPE + ".BPFIntType";

    /**
     * Helper class to keep track of defined types
     */
    private record DefinedTypes(Map<TypeElement, String> typeToFieldName) {

        public boolean isTypeDefined(TypeElement typeElement) {
            return this.typeToFieldName.containsKey(typeElement);
        }

        public Optional<String> getFieldName(TypeElement typeElement) {
            return Optional.ofNullable(this.typeToFieldName.get(typeElement));
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

    /**
     * Process the records annotated with {@code @Type} in the given class
     *
     * @param outerTypeElement the class to process that contains the records
     * @return a list of field specs that define the related {@code BPFStructType} instances
     */
    List<FieldSpec> processBPFTypeRecords(TypeElement outerTypeElement) {
        List<TypeElement> innerTypeElements = getInnerBPFTypeElements(outerTypeElement);
        definedTypes = getDefinedTypes(innerTypeElements);
        var list = innerTypeElements.stream().map(this::processBPFTypeRecord).toList();
        if (list.stream().anyMatch(Optional::isEmpty)) {
            return List.of();
        }
        return list.stream().map(Optional::get).toList();
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

    /**
     * Mirrors a generic BPFType instance
     */
    record BPFTypeMirror(String expression) {
    }

    /**
     * Mirrors the BPFStructMember constructor
     */
    record UBPFStructMemberMirror(String name, BPFTypeMirror type, String javaType) {
    }

    /**
     * Mirrors the BPFStructType constructor
     */
    record StructTypeMirror(String bpfName, List<UBPFStructMemberMirror> members, TypeMirror javaClass) {
    }

    private Optional<FieldSpec> processBPFTypeRecord(TypeElement typeElement) {
        String className = typeElement.getSimpleName().toString();
        String name = getTypeRecordBpfName(typeElement);
        String fieldName = typeToFieldName(typeElement);
        var constructors =
                typeElement.getEnclosedElements().stream().filter(e -> e.getKind() == ElementKind.CONSTRUCTOR).toList();
        if (constructors.size() != 1) {
            this.processingEnv.getMessager().printError("Record " + typeElement.getSimpleName() + " must have " +
                    "exactly" + " one " + "constructor", typeElement);
            return Optional.empty();
        }
        var constructor = (ExecutableElement) constructors.getFirst();
        var members = processBPFTypeRecordMembers(constructor.getParameters());
        if (members.isEmpty()) {
            return Optional.empty();
        }
        // now create the BPFStructType instance FieldSpec
        // that we get something like
        /*
        BPFType.BPFStructType<Event> fieldName = BPFStructType.autoLayout("name", List.of(
            new BPFType.UBPFStructMember<>("e_pid", BPFType.BPFIntType.UINT32, Event::pid),
    ), new BPFType.AnnotatedClass(className.class, List.of()), fields -> new Event((int)fields.get(0),
            (String)fields.get(1), (String)fields.get(2)));
         */
        ClassName bpfStructType = ClassName.get(BPF_PACKAGE, "BPFType.BPFStructType");
        TypeName fieldType = ParameterizedTypeName.get(bpfStructType, ClassName.get("", className));
        String memberExpression =
                members.get().stream().map(m -> "new " + BPF_TYPE + ".UBPFStructMember<>(" + "\"" + m.name() + "\", " + m.type().expression() + ", " + className + "::" + m.name() + ")").collect(Collectors.joining(", "));
        ClassName bpfType = ClassName.get(BPF_PACKAGE, "BPFType");
        String creatorExpr =
                members.get().stream().map(m -> "(" + m.javaType + ")fields.get(" + members.get().indexOf(m) + ")").collect(Collectors.joining(", "));
        return Optional.of(FieldSpec.builder(fieldType, fieldName).addModifiers(Modifier.FINAL, Modifier.STATIC,
                Modifier.PUBLIC).initializer("$T.autoLayout($S, java.util.List.of($L), new $T.AnnotatedClass($T" +
                ".class, java.util.List" + ".of()" + "), " + "fields -> new $T($L))", bpfStructType, name,
                memberExpression, bpfType, ClassName.get("", className), ClassName.get("", className), creatorExpr).build());
    }

    private Optional<List<UBPFStructMemberMirror>> processBPFTypeRecordMembers(List<? extends VariableElement> recordMembers) {
        var list = recordMembers.stream().map(this::processBPFTypeRecordMember).toList();
        if (list.stream().anyMatch(Optional::isEmpty)) {
            return Optional.empty();
        }
        return Optional.of(list.stream().map(Optional::get).toList());
    }

    record AnnotationValues(boolean unsigned, Optional<Integer> size, Optional<String> bpfType) {
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
        var typeAnnotation = getAnnotationMirror(element.asType(), TYPE_MEMBER_ANNOTATION);
        if (typeAnnotation.isPresent()) {
            var value = typeAnnotation.get().getElementValues().entrySet().stream().findFirst();
            if (value.isPresent()) {
                bpfType = Optional.of((String) value.get().getValue().getValue());
            }
        }
        return new AnnotationValues(unsigned, size, bpfType);
    }

    private Optional<UBPFStructMemberMirror> processBPFTypeRecordMember(VariableElement element) {
        AnnotationValues annotations = getAnnotationValuesForRecordMember(element);
        TypeMirror type = element.asType();
        var bpfType = processBPFTypeRecordMemberType(element, annotations, type);
        return bpfType.map(bpfTypeMirror -> new UBPFStructMemberMirror(element.getSimpleName().toString(),
                bpfTypeMirror, lastPart(type.toString())));
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
        if (annotations.bpfType().isPresent()) {
            return processCustomType(annotations.bpfType().get(), type);
        }
        if (isIntegerType(type)) {
            return processIntegerType(element, annotations, type);
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

    private Optional<BPFTypeMirror> processCustomType(String bpfType, TypeMirror type) {
        return Optional.of(new BPFTypeMirror(bpfType));
    }

    private Optional<String> getBaseIntegerType(Element element, TypeMirror type) {
        return switch (lastPart(type.toString())) {
            case "int" -> Optional.of("INT32");
            case "long" -> Optional.of("INT64");
            case "short" -> Optional.of("INT16");
            case "byte" -> Optional.of("INT8");
            case "char" -> Optional.of("UINT16");
            default -> {
                this.processingEnv.getMessager().printError("Unsupported integer type " + type, element);
                yield Optional.empty();
            }
        };
    }

    private Optional<BPFTypeMirror> processIntegerType(Element element, AnnotationValues annotations, TypeMirror type) {
        if (annotations.size().isPresent()) {
            // annotation not supported for integer types and log
            this.processingEnv.getMessager().printError("Size annotation not supported for integer types", element);
            return Optional.empty();
        }
        return getBaseIntegerType(element, type).map(s -> new BPFTypeMirror(BPF_INT_TYPE + "." + (annotations.unsigned ? "U" : "") + s));
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
        return Optional.of(new BPFTypeMirror("new " + BPF_TYPE + ".StringType(" + annotations.size().get() + ")"));
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
        return Optional.of(new BPFTypeMirror(fieldName.get()));
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
