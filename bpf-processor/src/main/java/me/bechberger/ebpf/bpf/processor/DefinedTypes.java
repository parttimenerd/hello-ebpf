package me.bechberger.ebpf.bpf.processor;

import me.bechberger.ebpf.type.BPFType;

import javax.lang.model.element.TypeElement;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

/**
 * Helper class to keep track of defined types
 */
public class DefinedTypes {

    /**
     * Name of the BPFType'd field for a specific type
     */
    public record SpecFieldName(String name) {
    }

    /**
     * Name of the BPFType in C code
     */
    public record BPFName(String name) {
    }

    /**
     * Fully qualified name of the Java class
     */
    public record JavaName(String name) {
        JavaName(TypeElement clazz) {
            this(clazz.getQualifiedName().toString());
        }

        JavaName(BPFType<?> type) {
            this(type.javaClass().klass());
        }
    }

    private final TypeProcessor typeProcessor;
    private final Function<TypeElement, SpecFieldName> typeToFieldNameFunction;
    private final Map<JavaName, BPFName> nameToBPFName;
    private final Map<BPFName, JavaName> bpfNameToName;
    private final Map<TypeElement, SpecFieldName> typeToFieldName;
    private final Map<BPFName, SpecFieldName> nameToSpecFieldName;
    private final Map<SpecFieldName, BPFName> specFieldNameToName;
    private final Map<BPFName, TypeElement> nameToTypeElement;

    DefinedTypes(TypeProcessor typeProcessor, List<TypeElement> initialTypes, Function<TypeElement, SpecFieldName> typeToFieldNameFunction) {
        this.typeProcessor = typeProcessor;
        this.typeToFieldNameFunction = typeToFieldNameFunction;
        this.nameToBPFName = new HashMap<>();
        this.bpfNameToName = new HashMap<>();
        this.typeToFieldName = new HashMap<>();
        this.nameToSpecFieldName = new HashMap<>();
        this.specFieldNameToName = new HashMap<>();
        this.nameToTypeElement = new HashMap<>();
        initialTypes.forEach(this::insertType);
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

    public SpecFieldName getOrCreateFieldName(TypeElement typeElement) {
        if (!this.typeToFieldName.containsKey(typeElement)) {
            insertType(typeElement);
        }
        return this.typeToFieldName.get(typeElement);
    }

    public void insertType(TypeElement typeElement, BPFName name, SpecFieldName fieldName) {
        if (this.nameToSpecFieldName.containsKey(name)) {
            throw new IllegalArgumentException("Name " + name + " already defined");
        }
        if (this.specFieldNameToName.containsKey(fieldName)) {
            throw new IllegalArgumentException("Field " + fieldName + " already defined");
        }
        this.typeToFieldName.put(typeElement, fieldName);
        this.nameToSpecFieldName.put(name, fieldName);
        this.specFieldNameToName.put(fieldName, name);
        this.nameToTypeElement.put(name, typeElement);
        var javaName = new JavaName(typeElement);
        this.nameToBPFName.put(javaName, name);
        this.bpfNameToName.put(name, javaName);
    }

    private void insertType(TypeElement typeElement) {
        var name = typeProcessor.getTypeRecordBpfName(typeElement);
        var fieldName = typeToFieldNameFunction.apply(typeElement);
        insertType(typeElement, name, fieldName);
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
