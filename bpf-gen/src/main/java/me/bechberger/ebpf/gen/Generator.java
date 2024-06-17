package me.bechberger.ebpf.gen;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.squareup.javapoet.*;
import me.bechberger.cast.CAST;
import me.bechberger.cast.CAST.Declarator;
import me.bechberger.cast.CAST.Declarator.FunctionDeclarator;
import me.bechberger.cast.CAST.Declarator.FunctionParameter;
import me.bechberger.cast.CAST.Expression;
import me.bechberger.ebpf.annotations.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.Offset;
import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.gen.Generator.Type.*;
import me.bechberger.ebpf.gen.KnownTypes.KnownInt;
import me.bechberger.ebpf.type.*;
import me.bechberger.ebpf.type.Enum;
import me.bechberger.ebpf.type.BPFType.*;
import org.jetbrains.annotations.Nullable;

import javax.lang.model.SourceVersion;
import javax.lang.model.element.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.logging.Logger;
import java.util.stream.IntStream;

import static me.bechberger.ebpf.gen.Generator.JSONObjectWithType.getNameOrNull;

public class Generator {

    private static final Logger logger = Logger.getLogger(Generator.class.getName());

    private final String basePackage;

    public Generator(String basePackage) {
        this.basePackage = basePackage;
    }

    private TypeName createClassName(String name) {
        return ClassName.get("", name);
    }

    private TypeName createClassName(int id) {
        return createClassName("Type" + id);
    }

    public static class UnsupportedTypeKindException extends RuntimeException {
        public UnsupportedTypeKindException(Kind kind) {
            super("Unsupported type kind: " + kind.toString());
        }

        public UnsupportedTypeKindException(String message) {
            super(message);
        }
    }

    /**
     * Type kind
     */
    public enum Kind {
        VOID,
        /**
         * Integer
         */
        INT,
        /**
         * Pointer
         */
        PTR,
        /**
         * Array
         */
        ARRAY,
        /**
         * Struct
         */
        STRUCT,
        /**
         * Union
         */
        UNION,
        /**
         * Enumeration up to 32-bit values
         */
        ENUM,
        /**
         * Forward
         */
        FWD,
        /**
         * Typedef
         */
        TYPEDEF,
        /**
         * Volatile
         */
        VOLATILE,
        /**
         * Const
         */
        CONST,
        /**
         * Restrict
         */
        RESTRICT,
        /**
         * Function
         */
        FUNC,
        /**
         * Function Proto
         */
        FUNC_PROTO,
        /**
         * Variable
         */
        VAR,
        /**
         * Section
         */
        DATASEC,
        /**
         * Floating point
         */
        FLOAT,
        /**
         * Decl Tag
         */
        DECL_TAG,
        /**
         * Type Tag
         */
        TYPE_TAG,
        /**
         * Enumeration up to 64-bit values
         */
        ENUM64,
        VERBATIM,
        ANY
    }

    record JSONObjectWithType(JSONObject jsonObject, Kind kind) {
        JSONObjectWithType(JSONObject jsonObject) {
            this(jsonObject, Kind.valueOf(jsonObject.getString("kind")));
        }

        String getName() {
            return jsonObject.getString("name");
        }

        /**
         * Has name "(anon)"
         */
        boolean hasProperName() {
            return !getName().equals("(anon)");
        }

        int getId() {
            return jsonObject.getInteger("id");
        }

        int getInteger(String field) {
            return jsonObject.getInteger(field);
        }

        long getLong(String field) {
            return jsonObject.getLong(field);
        }

        String getString(String field) {
            return jsonObject.getString(field);
        }

        @Nullable
        String getNameOrNull() {
            String name = getName();
            if (name.equals("(anon)")) {
                return null;
            }
            return name;
        }

        static @Nullable String getNameOrNull(JSONObject jsonObject) {
            String name = jsonObject.getString("name");
            if (name.equals("(anon)")) {
                return null;
            }
            return name;
        }

        void assertKeys(String... keys) {
            var keySet = jsonObject.keySet();
            if (!keySet.containsAll(Arrays.asList(keys))) {
                throw new AssertionError("Expected keys " + Arrays.toString(keys) + " but got " + keySet);
            }
        }
    }

    public void process() {
        try {
            process((JSONArray) BTF.getBTFJSONTypes());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void process(JSONArray types) {
        process(types.stream().map(t -> new JSONObjectWithType((JSONObject) t)).toList());
    }

    private static final List<Class<?>> preimportedClasses = List.of(
            Struct.class,
            Enum.class,
            Offset.class,
            Size.class,
            Unsigned.class,
            me.bechberger.ebpf.annotations.bpf.Type.class,
            TypedefBase.class,
            Ptr.class,
            TypedEnum.class,
            me.bechberger.ebpf.annotations.bpf.EnumMember.class,
            me.bechberger.ebpf.annotations.bpf.InlineUnion.class,
            Union.class,
            Ptr.class,
            BuiltinBPFFunction.class,
            Nullable.class,
            MethodIsBPFRelatedFunction.class
    );

    private static final Set<Class<?>> preimportedClassesSet = new HashSet<>(preimportedClasses);

    /**
     * Create a class name, omit package name if it is in the preimported classes
     */
    static ClassName cts(Class<?> clazz) {
        if (preimportedClassesSet.contains(clazz)) {
            return ClassName.get("", clazz.getSimpleName());
        }
        return ClassName.get(clazz);
    }

    /**
     * Parsed BTF types
     */
    public sealed interface Type {

        Kind kind();

        /**
         * -1 for no id
         */
        int id();

        BPFType<?> bpfType();

        default TypeName toTypeName(Generator gen) {
            return null;
        }

        /**
         * Returns the name used in generics, or {@code null} for wildcards
         */
        default @Nullable TypeName toGenericTypeName(Generator gen) {
            return toTypeName(gen);
        }

        /**
         * Returns the Java type definition, or {@code null} if not applicable
         */
        default @Nullable TypeSpec toTypeSpec(Generator gen, boolean typedefed) {
            return null;
        }

        default @Nullable TypeSpec toTypeSpec(Generator gen) {
            return toTypeSpec(gen, false);
        }

        default List<FieldSpec> toFieldSpecs(Generator gen) {
            return List.of();
        }

        default @Nullable MethodSpec toMethodSpec(Generator gen) {
            return null;
        }

        default @Nullable MethodSpec toMethodSpec(Generator gen, String name, @Nullable String javaDoc) {
            return null;
        }

        default CAST.Declarator toCType() {
            return toCType(false);
        }

        default CAST.Declarator toCType(boolean typedefed) {
            return toCType();
        }

        /**
         * Does this type contain a tag (like const) in its c type?
         */
        boolean shouldAddCast();

        static AnnotationSpec.Builder addTypedefedIfNeeded(AnnotationSpec.Builder builder, boolean typedefed) {
            if (typedefed) {
                builder.addMember("typedefed", "$L", true);
            }
            return builder;
        }

        static AnnotationSpec createAnnotations(boolean typedefed) {
            return addTypedefedIfNeeded(AnnotationSpec.builder(cts(me.bechberger.ebpf.annotations.bpf.Type.class)),
                    typedefed)
                    .addMember("noCCodeGeneration", "$L", true)
                    .build();
        }

        sealed interface NamedType extends Type {
            String name();
        }


        sealed interface PotentiallyNamedType extends NamedType {
            @Nullable
            String name();

            default boolean hasName() {
                assert !Objects.equals(name(), "(anon)");
                return name() != null;
            }

            default TypeName toTypeName(Generator gen) {
                return hasName() ? gen.createClassName(name()) : gen.createClassName(id());
            }
        }

        @FunctionalInterface
        interface TypeRef {
            Type resolve();
        }

        /**
         * {@code void}
         */
        record VoidType() implements Type {
            @Override
            public int id() {
                return 0;
            }

            @Override
            public Kind kind() {
                return Kind.VOID;
            }

            @Override
            public BPFType<?> bpfType() {
                return BPFType.VOID;
            }

            @Override
            public TypeName toTypeName(Generator gen) {
                return ClassName.VOID;
            }

            @Override
            public @Nullable TypeName toGenericTypeName(Generator gen) {
                return null;
            }

            @Override
            public CAST.Declarator toCType() {
                return Declarator._void();
            }

            @Override
            public boolean shouldAddCast() {
                return false;
            }
        }

        /**
         * {@code int, long, ..., float} (singed and unsigned)
         */
        record IntType(int id, KnownInt knownInt) implements Type {

            IntType(KnownInt knownInt) {
                this(-1, knownInt);
            }

            @Override
            public Kind kind() {
                return Kind.INT;
            }

            @Override
            public BPFType<?> bpfType() {
                return knownInt.bpfType();
            }

            int bitWidth() {
                return knownInt.bits();
            }

            boolean isSigned() {
                return knownInt.isSigned();
            }

            @Override
            public TypeName toTypeName(Generator gen) {
                return knownInt.javaType().type();
            }

            @Override
            public @Nullable TypeName toGenericTypeName(Generator gen) {
                return knownInt.javaType().inGenerics();
            }

            @Override
            public CAST.Declarator toCType() {
                return knownInt.toCType();
            }

            @Override
            public boolean shouldAddCast() {
                return false;
            }
        }

        /**
         * {@code T*} represented as {@code Ptr<T>}, {@code char*} is represented as {@code String}
         *
         * @param nullableElements annotate elements with {@link Nullable}
         */
        record PtrType(int id, TypeRef type, boolean nullableElements) implements Type {

            public PtrType(Type type) {
                this(-1, () -> type, false);
            }

            public PtrType(Type type, boolean nullableElements) {
                this(-1, () -> type, nullableElements);
            }

            @Override
            public Kind kind() {
                return Kind.PTR;
            }

            public Type resolvedPointee() {
                return type.resolve();
            }

            public Type resolvedPointeeSkippingMirrorTypes() {
                var t = type.resolve();
                while (t instanceof MirrorType mirrorType) {
                    t = mirrorType.type.resolve();
                }
                return t;
            }

            @Override
            public BPFType<?> bpfType() {
                // might be problematic with circular references
                return new BPFPointerType<>(resolvedPointee().bpfType());
            }

            @Override
            public String toString() {
                return "PtrType[id=" + id + "]";
            }

            @Override
            public TypeName toTypeName(Generator gen) {
                if (resolvedPointeeSkippingMirrorTypes() instanceof IntType intType && intType.knownInt.cName().equals("char")) {
                    return ClassName.get(String.class);
                }
                var pointeeType = resolvedPointee().toGenericTypeName(gen);
                var inner = Objects.requireNonNullElseGet(pointeeType, () -> WildcardTypeName.subtypeOf(Object.class));
                if (nullableElements) {
                    inner = inner.annotated(AnnotationSpec.builder(cts(Nullable.class)).build());
                }
                return ParameterizedTypeName.get(cts(Ptr.class), inner);
            }

            @Override
            public @Nullable MethodSpec toMethodSpec(Generator gen, String name, @Nullable String javaDoc) {
                if (resolvedPointee() instanceof FuncProtoType funcProtoType) {
                    return funcProtoType.toMethodSpec(gen, name, javaDoc);
                }
                return null;
            }

            @Override
            public CAST.Declarator toCType() {
                return Declarator.pointer(resolvedPointee().toCType());
            }

            @Override
            public boolean shouldAddCast() {
                return resolvedPointee().shouldAddCast();
            }
        }

        /**
         * {@code T[N]} represented as {@code @Size(N) T[]}
         *
         * @param nullableElements annotate elements with {@link Nullable}
         */
        record ArrayType(int id, TypeRef elementType, int length, boolean nullableElements) implements Type {

            public ArrayType(int id, Type elementType, int length) {
                this(id, () -> elementType, length, false);
            }

            public ArrayType(Type elementType, int length) {
                this(-1, () -> elementType, length, false);
            }

            public ArrayType(Type elementType, int length, boolean nullableElements) {
                this(-1, () -> elementType, length, nullableElements);
            }

            @Override
            public Kind kind() {
                return Kind.ARRAY;
            }

            @Override
            public BPFType<?> bpfType() {
                var innerBPFType = elementType.resolve().bpfType();
                return new BPFArrayType<>(innerBPFType.bpfName() + "[" + length + "]", innerBPFType, length);
            }

            @Override
            public TypeName toTypeName(Generator gen) {
                var arr = ArrayTypeName.of(elementType.resolve().toTypeName(gen));
                if (length == -1) {
                    return arr;
                }
                var res =
                        arr.annotated(AnnotationSpec.builder(cts(Size.class)).addMember("value", "$L", length).build());
                if (nullableElements) {
                    return res.annotated(AnnotationSpec.builder(cts(Nullable.class)).build());
                }
                return res;
            }

            @Override
            public CAST.Declarator toCType() {
                if (length != -1) {
                    return Declarator.array(elementType.resolve().toCType(), Expression.constant(length));
                }
                return Declarator.array(elementType.resolve().toCType(), null);
            }

            @Override
            public boolean shouldAddCast() {
                return true;
            }
        }

        /**
         * Member of a struct or union
         */
        record TypeMember(@Nullable String name, TypeRef type, int bitsOffset /* 0 for unions */) {

            public TypeMember(String name, Type type, int bitsOffset) {
                this(name, () -> type, bitsOffset);
            }

            public TypeMember {
                if (bitsOffset % 8 != 0) {
                    throw new UnsupportedTypeKindException("Bit offset must be a multiple of 8");
                }
            }

            List<FieldSpec> toFieldSpecs(Generator gen) {
                int byteOffset = bitsOffset / 8;
                if (name == null && type.resolve() instanceof UnionType unionType && !unionType.hasName()) {
                    // inline unions, so generate a field for every union member annotated with @InlineUnion(type.id)
                    return unionType.members.stream().map(m -> FieldSpec.builder(m.type.resolve().toTypeName(gen),
                                    Objects.requireNonNull(m.name))
                            .addModifiers(Modifier.PUBLIC)
                            .addAnnotation(AnnotationSpec.builder(cts(Offset.class)).addMember("value", "$L",
                                    byteOffset).build())
                            .addAnnotation(AnnotationSpec.builder(cts(me.bechberger.ebpf.annotations.bpf.InlineUnion.class))
                                    .addMember("value", unionType.id + "")
                                    .build()).build()).toList();
                }
                if (name == null) {
                    throw new UnsupportedTypeKindException("Anonymous member in struct of type " + this.type().resolve());
                }
                return List.of(FieldSpec.builder(type.resolve().toTypeName(gen), name)
                        .addModifiers(Modifier.PUBLIC)
                        .addAnnotation(AnnotationSpec.builder(cts(Offset.class)).addMember("value", "$L", byteOffset).build())
                        .build());
            }
        }

        record StructType(int id, @Nullable String name, List<TypeMember> members) implements PotentiallyNamedType {

            public StructType(@Nullable String name, List<TypeMember> members) {
                this(-1, name, members);
            }

            @Override
            public Kind kind() {
                return Kind.STRUCT;
            }

            @Override
            @SuppressWarnings({"unchecked", "rawtypes"})
            public BPFType<?> bpfType() {
                return new BPFStructType(name,
                        (List<BPFStructMember>) (List) members.stream().map(m -> new BPFStructMember<>(m.name,
                                m.type.resolve().bpfType(), m.bitsOffset / 8, null)).toList(), null, null);
            }

            private static TypeSpec create(Generator gen, PotentiallyNamedType type, List<TypeMember> members,
                                           boolean typedefed, Class<?> superClass) {
                var typeName = type.toTypeName(gen);
                assert typeName instanceof ClassName;
                var builder = TypeSpec.classBuilder(((ClassName) typeName).simpleName())
                        .addModifiers(Modifier.PUBLIC, Modifier.STATIC)
                        .addAnnotation(createAnnotations(typedefed))
                        .superclass(cts(superClass));
                for (var member : members) {
                    for (var field : member.toFieldSpecs(gen)) {
                        builder.addField(field);
                    }
                }
                return builder.build();
            }

            @Override
            public TypeSpec toTypeSpec(Generator gen, boolean typedefed) {
                return create(gen, this, members, typedefed, Struct.class);
            }

            @Override
            public Declarator toCType(boolean typedefed) {
                if (name == null) {
                    throw new UnsupportedTypeKindException("Anonymous struct can't be transformed to C type");
                }
                if (typedefed) {
                    return Declarator.identifier(name);
                }
                return Declarator.structIdentifier(Expression.variable(name));
            }

            @Override
            public boolean shouldAddCast() {
                return false;
            }
        }

        record UnionType(int id, @Nullable String name, List<TypeMember> members) implements PotentiallyNamedType {

            public UnionType(@Nullable String name, List<TypeMember> members) {
                this(-1, name, members);
            }

            @Override
            public Kind kind() {
                return Kind.UNION;
            }

            @Override
            @SuppressWarnings({"unchecked", "rawtypes"})
            public BPFType<?> bpfType() {
                return new BPFUnionType(name,
                        (List<BPFStructMember>) (List) members.stream().map(m -> new BPFStructMember<>(m.name,
                                m.type.resolve().bpfType(), m.bitsOffset, null)).toList(), null, null);
            }

            @Override
            public TypeSpec toTypeSpec(Generator gen, boolean typedefed) {
                return StructType.create(gen, this, members, typedefed, Union.class);
            }

            @Override
            public Declarator toCType(boolean typedefed) {
                if (name == null) {
                    throw new UnsupportedTypeKindException("Anonymous union can't be transformed to C type");
                }
                if (typedefed) {
                    return Declarator.identifier(name);
                }
                return Declarator.unionIdentifier(Expression.variable(name));
            }

            @Override
            public boolean shouldAddCast() {
                return false;
            }
        }

        record EnumMember(String name, long value) {

            /**
             * Generate something like {@code  @EnumMember(value = 23, name = "KIND_A") B}
             */
            TypeSpec toEnumFieldContant(Generator gen) {
                return TypeSpec.anonymousClassBuilder("")
                        .addAnnotation(AnnotationSpec.builder(cts(me.bechberger.ebpf.annotations.bpf.EnumMember.class))
                                .addMember("value", "$L", value)
                                .addMember("name", "$S", name)
                                .build())
                        .build();
            }

            /**
             * Generate something like {@code public static final int KIND_A = 23;}
             */
            FieldSpec toConstantFieldSpec(Generator gen, KnownInt valueType) {
                return FieldSpec.builder(valueType.javaType().type(), name)
                        .addModifiers(Modifier.PUBLIC, Modifier.STATIC, Modifier.FINAL)
                        .initializer("$L", value)
                        .build();
            }
        }

        /**
         * An enum if named, else just a set of fields
         *
         * @param id
         * @param name
         * @param byteSize
         * @param unsigned
         * @param members
         */
        record EnumType(int id, @Nullable String name, int byteSize, boolean unsigned,
                        List<EnumMember> members) implements PotentiallyNamedType {

            public EnumType(@Nullable String name, int byteSize, boolean unsigned, List<EnumMember> members) {
                this(-1, name, byteSize, unsigned, members);
            }

            @Override
            public Kind kind() {
                return Kind.ENUM;
            }

            @Override
            public BPFType<?> bpfType() {
                return null;
            }

            @Override
            public TypeName toTypeName(Generator gen) {
                return hasName() ? gen.createClassName(name()) : null;
            }

            private KnownInt valueType() {
                return KnownTypes.getKnownInt(byteSize * 8, !unsigned).orElseThrow();
            }

            @Override
            public TypeSpec toTypeSpec(Generator gen, boolean typedefed) {
                if (!hasName()) {
                    return null;
                }
                var valueType = valueType();
                assert name() != null;
                var builder = TypeSpec.enumBuilder(name())
                        .addModifiers(Modifier.PUBLIC, Modifier.STATIC)
                        .addAnnotation(createAnnotations(typedefed))
                        .addSuperinterface(ParameterizedTypeName.get(cts(Enum.class), gen.createClassName(name())))
                        .addSuperinterface(ParameterizedTypeName.get(cts(TypedEnum.class),
                                gen.createClassName(name()), valueType.javaType().inGenerics()));
                for (var member : members) {
                    builder.addEnumConstant(member.name(), member.toEnumFieldContant(gen));
                }
                return builder.build();
            }

            @Override
            public List<FieldSpec> toFieldSpecs(Generator gen) {
                if (!hasName()) {
                    return members.stream().filter(m -> !m.name.equals("true") && !m.name.equals("false")).map(m -> m.toConstantFieldSpec(gen, valueType())).toList();
                }
                return List.of();
            }

            @Override
            public Declarator toCType(boolean typedefed) {
                if (name == null) {
                    throw new UnsupportedTypeKindException("Anonymous enum can't be transformed to C type");
                }
                if (typedefed) {
                    return Declarator.identifier(name);
                }
                return Declarator.enumIdentifier(Expression.variable(name));
            }

            @Override
            public boolean shouldAddCast() {
                return false;
            }
        }

        record UnsupportedType(int id, Kind kind) implements Type {

            public UnsupportedType(Kind kind) {
                this(-1, kind);
            }

            @Override
            public BPFType<?> bpfType() {
                throw new UnsupportedTypeKindException(kind);
            }

            @Override
            public TypeName toTypeName(Generator gen) {
                throw new UnsupportedTypeKindException(kind);
            }

            @Override
            public @Nullable TypeName toGenericTypeName(Generator gen) {
                throw new UnsupportedTypeKindException(kind);
            }

            @Override
            public @Nullable TypeSpec toTypeSpec(Generator gen, boolean typedefed) {
                throw new UnsupportedTypeKindException(kind);
            }

            @Override
            public List<FieldSpec> toFieldSpecs(Generator gen) {
                throw new UnsupportedTypeKindException(kind);
            }

            @Override
            public CAST.Declarator toCType() {
                throw new UnsupportedTypeKindException(kind);
            }

            @Override
            public boolean shouldAddCast() {
                return false;
            }
        }

        record TypeDefType(int id, String name, TypeRef type) implements NamedType {

            public TypeDefType(int id, String name, Type type) {
                this(id, name, () -> type);
            }

            public TypeDefType(String name, Type type) {
                this(-1, name, () -> type);
            }

            @Override
            public Kind kind() {
                return Kind.TYPEDEF;
            }

            @Override
            public BPFType<?> bpfType() {
                return new BPFTypedef<>(name, type.resolve().bpfType(), null, null);
            }

            @Override
            public TypeName toTypeName(Generator gen) {
                return gen.createClassName(name);
            }

            @Override
            public TypeSpec toTypeSpec(Generator gen, boolean typedefed) {
                var t = type.resolve();
                if (t instanceof MirrorType mirrorType) {
                    return mirrorType.type.resolve().toTypeSpec(gen, true);
                }
                if (t instanceof StructType || t instanceof UnionType || t instanceof EnumType) {
                    return t.toTypeSpec(gen, true);
                }
                return TypeSpec.classBuilder(name)
                        .addModifiers(Modifier.PUBLIC, Modifier.STATIC)
                        .addAnnotation(createAnnotations(typedefed))
                        .superclass(ParameterizedTypeName.get(cts(TypedefBase.class), t.toGenericTypeName(gen)))
                        .addMethod(MethodSpec.constructorBuilder()
                                .addModifiers(Modifier.PUBLIC)
                                .addParameter(Objects.requireNonNullElse(t.toGenericTypeName(gen),
                                        ClassName.get(Object.class)), "val")
                                .addStatement("super(val)")
                                .build())
                        .build();
            }

            @Override
            public @Nullable MethodSpec toMethodSpec(Generator gen) {
                return type.resolve().toMethodSpec(gen, name, null);
            }

            @Override
            public CAST.Declarator toCType(boolean typedefed) {
                return type.resolve().toCType(true);
            }

            @Override
            public boolean shouldAddCast() {
                return true;
            }
        }

        /**
         * Types that effectively mirrors of other types, e.g. volatile, const, restrict
         */
        record MirrorType(Kind kind, int id, TypeRef type) implements Type {

            public MirrorType(Kind kind, Type type) {
                this(kind, -1, () -> type);
            }

            @Override
            public BPFType<?> bpfType() {
                return type.resolve().bpfType();
            }

            @Override
            public TypeName toTypeName(Generator gen) {
                return type.resolve().toTypeName(gen);
            }

            @Override
            public @Nullable TypeName toGenericTypeName(Generator gen) {
                return type.resolve().toGenericTypeName(gen);
            }

            @Override
            public @Nullable TypeSpec toTypeSpec(Generator gen, boolean typedefed) {
                return type.resolve().toTypeSpec(gen, typedefed);
            }

            @Override
            public @Nullable TypeSpec toTypeSpec(Generator gen) {
                return type.resolve().toTypeSpec(gen);
            }

            @Override
            public List<FieldSpec> toFieldSpecs(Generator gen) {
                return type.resolve().toFieldSpecs(gen);
            }

            @Override
            public CAST.Declarator toCType() {
                return toCType(false);
            }

            @Override
            public CAST.Declarator toCType(boolean typedefed) {
                switch (kind) {
                    case VOLATILE -> {
                        return Declarator.tagged("volatile", type.resolve().toCType(typedefed));
                    }
                    case CONST -> {
                        return Declarator.tagged("const", type.resolve().toCType(typedefed));
                    }
                    case RESTRICT -> {
                        return Declarator.tagged("restrict", type.resolve().toCType(typedefed));
                    }
                    default -> throw new UnsupportedTypeKindException(kind);
                }
            }

            @Override
            public boolean shouldAddCast() {
                return true;
            }
        }

        record FuncType(int id, String name, FuncProtoType impl, @Nullable String javaDoc) implements NamedType {

            public FuncType(String name, FuncProtoType impl, @Nullable String javaDoc) {
                this(-1, name, impl, null);
            }

            public FuncType(int id, String name, FuncProtoType impl) {
                this(id, name, impl, null);
            }

            public FuncType(String name, FuncProtoType impl) {
                this(-1, name, impl, null);
            }

            @Override
            public Kind kind() {
                return Kind.FUNC;
            }

            @Override
            public BPFType<?> bpfType() {
                return null;
            }

            @Override
            public MethodSpec toMethodSpec(Generator gen) {
                return impl.toMethodSpec(gen, name, javaDoc);
            }

            @Override
            public CAST.Declarator toCType() {
                return impl.toCType(name);
            }

            @Override
            public boolean shouldAddCast() {
                return false;
            }

            public FuncType setJavaDoc(String javaDoc) {
                return new FuncType(id, name, impl, javaDoc);
            }
        }

        /**
         * Assigns a name to a {@link FuncProtoType}
         */
        record FuncParameter(@Nullable String name, Type type) {

            private String escapeName(String name) {
                if (SourceVersion.isName(name, SourceVersion.latest())) {
                    return name;
                }
                return "_" + name;
            }

            private ParameterSpec toParameterSpec(Generator gen, int index, TypeName typeName) {

                return ParameterSpec.builder(typeName, name == null ? "param" + index : escapeName(name)).build();
            }

            public ParameterSpec toParameterSpec(Generator gen, int index) {
                return toParameterSpec(gen, index, type.toTypeName(gen));
            }
        }

        record FuncProtoType(int id, List<FuncParameter> parameters, Type returnType,
                             boolean variadic) implements Type {

            public FuncProtoType(List<FuncParameter> parameters, Type returnType, boolean variadic) {
                this(-1, parameters, returnType, variadic);
            }

            FuncProtoType(int id, List<FuncParameter> parameters, Type returnType) {
                this(id, parameters, returnType, false);
            }

            FuncProtoType(List<FuncParameter> parameters, Type returnType) {
                this(-1, parameters, returnType, false);
            }

            @Override
            public Kind kind() {
                return Kind.FUNC_PROTO;
            }

            @Override
            public BPFType<?> bpfType() {
                return null;
            }

            @Override
            public MethodSpec toMethodSpec(Generator gen, String name, @Nullable String javaDoc) {
                var builder = MethodSpec.methodBuilder(name)
                        .addModifiers(Modifier.PUBLIC, Modifier.STATIC)
                        .addAnnotation(AnnotationSpec.builder(cts(BuiltinBPFFunction.class)).addMember("value", "$S",
                                toBPFFunctionConversionString(name)).build())
                        .returns(returnType.toTypeName(gen)).varargs(variadic);
                for (int i = 0; i < parameters.size(); i++) {
                    builder.addParameter(parameters.get(i).toParameterSpec(gen, i));
                }
                builder.addCode("throw new $T();", cts(MethodIsBPFRelatedFunction.class));
                if (javaDoc != null) {
                    builder.addJavadoc(javaDoc);
                }
                return builder.build();
            }

            @Override
            public CAST.Declarator toCType() {
                throw new UnsupportedTypeKindException("Function prototype can't be transformed to C type");
            }

            public FunctionDeclarator toCType(String name) {
                return new FunctionDeclarator(Expression.variable(name), returnType.toCType(),
                        parameters.stream().map(p -> new FunctionParameter(Expression.variable(p.name),
                                p.type().toCType())).toList());
            }

            public boolean returnsVoid() {
                return returnType instanceof VoidType;
            }

            /**
             * Convert to a string that can be used in the {@link BuiltinBPFFunction} annotation
             */
            public String toBPFFunctionConversionString(String name) {
                var params = IntStream.range(0, parameters.size()).mapToObj(i -> {
                    var param = parameters.get(i);
                    if (param.type.shouldAddCast() && (!variadic || i < parameters.size() - 1)) {
                        return "(" + param.type.toCType().toPrettyString() + ")$arg" + (i + 1);
                    }
                    return "$arg" + (i + 1);
                }).toList();
                var anyConversion = params.stream().anyMatch(a -> a.contains("(") || a.contains(")"));
                String call = anyConversion ? name + "(" + String.join(", ", params) + ")" : name;
                return returnsVoid() || !returnType.shouldAddCast() ? call :
                        "((" + returnType.toCType().toPrettyString() + ")" + call + ")";
            }

            @Override
            public boolean shouldAddCast() {
                return true;
            }
        }

        /**
         * A defined global variable
         */
        record VarType(int id, String name, Type type) implements NamedType {

            public VarType(String name, Type type) {
                this(-1, name, type);
            }

            @Override
            public Kind kind() {
                return Kind.VAR;
            }

            @Override
            public BPFType<?> bpfType() {
                return null;
            }

            @Override
            public List<FieldSpec> toFieldSpecs(Generator gen) {
                return List.of(FieldSpec.builder(type.toTypeName(gen), name)
                        .addModifiers(Modifier.PUBLIC, Modifier.STATIC)
                        .build());
            }

            @Override
            public boolean shouldAddCast() {
                return false;
            }
        }

        record VerbatimType(String cName, String javaName) implements Type {
            @Override
            public Kind kind() {
                return Kind.VERBATIM;
            }

            @Override
            public int id() {
                return 1;
            }

            @Override
            public BPFType<?> bpfType() {
                throw new UnsupportedOperationException("Verbatim type");
            }

            @Override
            public TypeName toTypeName(Generator gen) {
                return ClassName.get("", javaName);
            }

            @Override
            public CAST.Declarator toCType() {
                var parts = cName.split(" ");
                if (parts.length == 1) {
                    return Declarator.identifier(cName);
                }
                return switch (parts[1]) {
                    case "struct" -> Declarator.structIdentifier(Expression.variable(parts[1]));
                    case "union" -> Declarator.unionIdentifier(Expression.variable(parts[1]));
                    case "enum" -> Declarator.enumIdentifier(Expression.variable(parts[1]));
                    default -> Declarator.identifier(cName);
                };
            }

            @Override
            public boolean shouldAddCast() {
                return false;
            }
        }

        /**
         * Represent any type, used for {@code bpf_printk}
         */
        record AnyType() implements Type {
            @Override
            public Kind kind() {
                return Kind.ANY;
            }

            @Override
            public int id() {
                return -1;
            }

            @Override
            public BPFType<?> bpfType() {
                throw new UnsupportedOperationException("Any type");
            }

            @Override
            public TypeName toTypeName(Generator gen) {
                return ClassName.get(Object.class);
            }

            @Override
            public CAST.Declarator toCType() {
                return Declarator.identifier("void");
            }

            @Override
            public boolean shouldAddCast() {
                return false;
            }
        }
    }

    private final ArrayList<@Nullable Type> types = new ArrayList<>(List.of((Type) new VoidType()));
    private final List<Type> additionalTypes = new ArrayList<>();

    void put(Type type) {
        if (type.id() == -1) {
            throw new AssertionError("Type must have an id");
        }
        if (type.id() < types.size() && types.get(type.id()) != null) {
            throw new AssertionError("Type already exists with the given id " + type.getClass().getSimpleName() + " " + types.get(type.id()));
        }
        types.ensureCapacity(type.id() + 1);
        while (type.id() > types.size() - 1) {
            types.add(null);
        }
        types.set(type.id(), type);
    }

    private Type get(int id) {
        // TODO: later we can add a check for null
        if (id >= types.size()) {
            return null;
        }
        var type = types.get(id);
        if (type instanceof UnsupportedType) {
            throw new UnsupportedTypeKindException(((UnsupportedType) type).kind);
        }
        return types.get(id);
    }

    private IntType getIntType(int id) {
        var type = get(id);
        if (type == null || type.kind() != Kind.INT) {
            throw new AssertionError("Expected int type but got " + type);
        }
        return (IntType) type;
    }

    private void process(List<JSONObjectWithType> rawTypes) {
        for (var rawType : rawTypes) {
            processRawType(rawType);
        }
    }

    private void processRawType(JSONObjectWithType rawType) {
        int typeId = rawType.getId();
        try {
            switch (rawType.kind) {
                case VOID -> throw new AssertionError("Unexpected void type");
                case INT -> put(processIntType(typeId, rawType));
                case PTR -> put(processPtrType(typeId, rawType));
                case ARRAY -> put(processArrayType(typeId, rawType));
                case STRUCT -> put(processStructType(typeId, rawType));
                case UNION -> put(processUnionType(typeId, rawType));
                case ENUM -> put(processEnumType(typeId, rawType));
                case FWD, DATASEC, DECL_TAG -> put(new UnsupportedType(typeId, rawType.kind));
                case TYPEDEF -> put(processTypeDefType(typeId, rawType));
                case VOLATILE, CONST, RESTRICT, TYPE_TAG -> put(processMirrorType(rawType.kind, typeId, rawType));
                case FUNC -> put(processFuncType(typeId, rawType));
                case FUNC_PROTO -> put(processFuncProtoType(typeId, rawType));
                case VAR -> put(processVarType(typeId, rawType));
                case FLOAT -> put(processFloatType(typeId, rawType));
                case ENUM64 -> put(processEnum64Type(typeId, rawType));
                default -> throw new IllegalStateException("Unexpected value: " + rawType.kind);
            }
        } catch (UnsupportedTypeKindException e) {
            put(new UnsupportedType(typeId, rawType.kind));
        }
    }

    private IntType processIntType(int id, JSONObjectWithType rawType) {
        var name = rawType.getName();
        var size = rawType.getInteger("nr_bits");
        var encoding = rawType.getString("encoding");
        var knownInt = KnownTypes.getKnownInt(name, size, encoding).orElseThrow(() -> new IllegalArgumentException(
                "Unknown int type: " + name));
        return new IntType(id, knownInt);
    }

    private TypeRef ref(int id) {
        return new TypeRef() {
            Type resolved = null;

            @Override
            public Type resolve() {
                if (resolved == null) {
                    resolved = get(id);
                }
                return resolved;
            }
        };
    }

    /**
     * Process a pointer type
     * <p>
     * From e.g. {@code {"kind":"PTR","type_id":100387,"name":"(anon)","id":100422}}
     */
    private PtrType processPtrType(int id, JSONObjectWithType rawType) {
        rawType.assertKeys("type_id", "name", "id", "kind");
        if (rawType.hasProperName()) {
            throw new AssertionError("Expected pointer type to have name '(anon)' but got " + rawType.getName());
        }
        var pointee = rawType.getInteger("type_id");
        return new PtrType(id, () -> get(pointee), false);
    }

    /**
     * Process an array type
     * <p>
     * From e.g. {@code {"kind":"ARRAY","type_id":2633,"name":"(anon)","id":100360,"nr_elems":34,"index_type_id":8}}
     */
    private ArrayType processArrayType(int id, JSONObjectWithType rawType) {
        rawType.assertKeys("type_id", "name", "id", "kind", "nr_elems", "index_type_id");
        if (rawType.hasProperName()) {
            throw new AssertionError("Expected array type to have name '(anon)' but got " + rawType.getName());
        }
        var indexType = getIntType(rawType.getInteger("index_type_id"));
        if (indexType.knownInt.bits() != 32) {
            throw new AssertionError("Expected 32-bit index type but got " + indexType);
        }
        var length = rawType.getInteger("nr_elems");
        var elementType = rawType.getInteger("type_id");
        return new ArrayType(id, ref(elementType), length, false);
    }

    private TypeMember processTypeMember(JSONObject rawMember) {
        var name = getNameOrNull(rawMember);
        var type = ref(rawMember.getInteger("type_id"));
        var bitsOffset = rawMember.getInteger("bits_offset");
        return new TypeMember(name, type, bitsOffset);
    }

    private List<TypeMember> processTypeMembers(JSONArray members) {
        return members.stream().map(m -> processTypeMember((JSONObject) m)).toList();
    }

    /**
     * Process a struct type
     * <p>
     * From e.g. {@code
     * {
     * "size":16,
     * "kind":"STRUCT",
     * "members":[
     * {
     * "bits_offset":0,
     * "type_id":54,
     * "name":"entries"
     * }
     * ],
     * "name":"of_changeset",
     * "vlen":1,
     * "id":22908
     * }
     * }
     */
    private StructType processStructType(int id, JSONObjectWithType rawType) {
        rawType.assertKeys("name", "id", "kind", "members");
        return new StructType(id, rawType.getNameOrNull(), processTypeMembers(rawType.jsonObject.getJSONArray(
                "members")));
    }

    private UnionType processUnionType(int id, JSONObjectWithType rawType) {
        rawType.assertKeys("name", "id", "kind", "members");
        return new UnionType(id, rawType.getNameOrNull(), processTypeMembers(rawType.jsonObject.getJSONArray("members"
        )));
    }

    private EnumType processEnumType(int id, JSONObjectWithType rawType) {
        rawType.assertKeys("name", "id", "kind", "values", "size", "vlen", "encoding");
        return new EnumType(id, rawType.getNameOrNull(), rawType.getInteger("size"),
                rawType.getString("encoding").equals("UNSIGNED"),
                rawType.jsonObject.getJSONArray("values").stream().map(m -> new EnumMember(((JSONObject) m).getString("name"), ((JSONObject) m).getInteger("val"))).toList());
    }

    private TypeDefType processTypeDefType(int id, JSONObjectWithType rawType) {
        rawType.assertKeys("name", "id", "kind", "type_id");
        var name = rawType.getName();
        var type = ref(rawType.getInteger("type_id"));
        return new TypeDefType(id, name, type);
    }

    private MirrorType processMirrorType(Kind kind, int id, JSONObjectWithType rawType) {
        rawType.assertKeys("name", "id", "kind", "type_id");
        var type = ref(rawType.getInteger("type_id"));
        return new MirrorType(kind, id, type);
    }

    private FuncType processFuncType(int id, JSONObjectWithType rawType) {
        rawType.assertKeys("name", "id", "kind", "type_id");
        var name = rawType.getName();
        var impl = (FuncProtoType) get(rawType.getInteger("type_id"));
        return new FuncType(id, name, impl);
    }

    private List<FuncParameter> processFuncParameters(JSONArray params) {
        return params.stream().map(p -> {
            var param = (JSONObject) p;
            return new FuncParameter(getNameOrNull(param), get(param.getInteger("type_id")));
        }).toList();
    }

    private FuncProtoType processFuncProtoType(int id, JSONObjectWithType rawType) {
        rawType.assertKeys("name", "id", "kind", "params", "vlen", "ret_type_id");
        return new FuncProtoType(id, processFuncParameters(rawType.jsonObject.getJSONArray("params")),
                get(rawType.getInteger("ret_type_id")));
    }

    private VarType processVarType(int id, JSONObjectWithType rawType) {
        rawType.assertKeys("name", "id", "kind", "type_id");
        var name = rawType.getName();
        var type = get(rawType.getInteger("type_id"));
        return new VarType(id, name, type);
    }

    private IntType processFloatType(int id, JSONObjectWithType rawType) {
        rawType.assertKeys("name", "id", "kind", "size");
        return new IntType(id,
                KnownTypes.getKnownInt(rawType.getName(), rawType.getInteger("size") * 8, "(none)").orElseThrow(() -> new IllegalArgumentException("Unknown float type: " + rawType.getName())));
    }

    private EnumType processEnum64Type(int id, JSONObjectWithType rawType) {
        rawType.assertKeys("name", "id", "kind", "values", "size", "vlen", "encoding");
        return new EnumType(id, rawType.getNameOrNull(), rawType.getInteger("size"),
                rawType.getString("encoding").equals("UNSIGNED"),
                rawType.jsonObject.getJSONArray("values").stream().map(m -> new EnumMember(((JSONObject) m).getString("name"), ((JSONObject) m).getLong("val"))).toList());
    }

    public record Result<T>(T result, int unsupportedTypes, int supportedTypes) {
    }

    public Result<TypeSpec> generateTypeSpec(String className, String description) {
        var specBuilder =
                TypeSpec.classBuilder(className).addModifiers(Modifier.PUBLIC, Modifier.FINAL).addJavadoc(description);
        List<@Nullable Type> actualTypes = types;
        if (!additionalTypes.isEmpty()) {
            actualTypes = new ArrayList<>(types);
            actualTypes.addAll(additionalTypes);
        }
        var unsupportedTypes = 0;
        var supportedTypes = 0;
        for (var type : actualTypes) {
            if (type != null && !(type instanceof UnsupportedType)) {
                try {
                    var typeSpec = type.toTypeSpec(this);
                    if (typeSpec != null) {
                        specBuilder.addType(typeSpec);
                    }
                    for (var field : type.toFieldSpecs(this)) {
                        specBuilder.addField(field);
                    }
                    var method = type.toMethodSpec(this);
                    if (method != null) {
                        specBuilder.addMethod(method);
                    }
                    supportedTypes++;
                } catch (Exception e) {
                    unsupportedTypes++;
                }
            } else {
                unsupportedTypes++;
            }
        }
        return new Result<>(specBuilder.build(), unsupportedTypes, supportedTypes);
    }

    public Result<String> generateJavaFile(String className, String description) {
        var importStrings = preimportedClasses.stream().map(c -> "import " + c.getName() + ";").sorted().toList();
        var typeRes = generateTypeSpec(className, description);
        return new Result<>("""
                /** Auto-generated */
                package %s;
                
                %s
                
                %s
                """.formatted(basePackage, String.join("\n", importStrings), typeRes.result.toString().trim()),
                typeRes.unsupportedTypes, typeRes.supportedTypes);
    }

    /**
     * Store the generated Java file in the package in the given folder
     */
    public Result<String> storeInFolder(Path folder) {
        return storeInFolder(folder, "BPFRuntime", "BPF runtime functions and types");
    }

    Result<String> storeInFolder(Path folder, String className, String description) {
        var javaFile = generateJavaFile(className, description);
        var path = folder.resolve(basePackage.replace('.', '/') + "/" + className + ".java");
        if (!Files.exists(path.getParent())) {
            try {
                Files.createDirectories(path.getParent());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        try {
            Files.writeString(path, javaFile.result);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return javaFile;
    }

    public void addAdditionalType(Type type) {
        additionalTypes.add(type);
    }
}
