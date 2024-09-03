package me.bechberger.ebpf.gen;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.squareup.javapoet.*;
import me.bechberger.cast.CAST;
import me.bechberger.cast.CAST.Declarator;
import me.bechberger.cast.CAST.Declarator.*;
import me.bechberger.cast.CAST.Expression;
import me.bechberger.ebpf.annotations.*;
import me.bechberger.ebpf.annotations.EnumMember;
import me.bechberger.ebpf.annotations.InlineUnion;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
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
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static me.bechberger.ebpf.gen.Generator.JSONObjectWithType.getNameOrNull;
import static me.bechberger.ebpf.gen.SystemCallProcessor.toCamelCase;

public class Generator {

    private static final Logger logger = Logger.getLogger(Generator.class.getName());

    private final String basePackage;
    private static final boolean markAllCombinedTypesAsNotUsableInJava = true;
    private static final boolean dontEmitTypeDefs = true;
    private static final boolean ignoreBitOffset = true;

    public Generator(String basePackage) {
        this.basePackage = basePackage;
    }

    private TypeName createClassName(String name) {
        return ClassName.get("", escapeName(name));
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

    private static String escapeName(String name) {
        if (SourceVersion.isName(name, SourceVersion.latest())) {
            return name;
        }
        return "_" + name;
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
        ENUM64, VERBATIM, ANY
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
            process(BTF.getBTFJSONTypes());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void process(JSONArray types) {
        process(types.stream().map(t -> new JSONObjectWithType((JSONObject) t)).toList());
    }

    private static final List<Class<?>> preimportedClasses = List.of(Struct.class, Enum.class, Offset.class,
            Size.class, Unsigned.class, me.bechberger.ebpf.annotations.Type.class, TypedefBase.class, Ptr.class,
            TypedEnum.class, EnumMember.class,
            InlineUnion.class, Union.class, Ptr.class, BuiltinBPFFunction.class,
            Nullable.class, MethodIsBPFRelatedFunction.class, NotUsableInJava.class, OriginalName.class);

    private static final Set<Class<?>> preimportedClassesSet = new HashSet<>(preimportedClasses);

    /**
     * Create a class name, omit package name if it is in the preimported classes
     */
    static ClassName cts(Class<?> clazz) {
        if (preimportedClassesSet.contains(clazz) || clazz.getPackageName().equals("java.lang")) {
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

        default @Nullable TypeName toTypeName(Generator gen) {
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

        default Set<TypeName> collectUsedTypes(Generator gen, Predicate<TypeName> goIntoStructOrUnion) {
            var set = new HashSet<TypeName>();
            collectUsedTypes(gen, goIntoStructOrUnion, set);
            return set;
        }

        /**
         * Collect all used types in this type
         */
        void collectUsedTypes(Generator gen, Predicate<TypeName> goIntoStructOrUnion, Set<TypeName> typeNames);

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

        static AnnotationSpec createAnnotations(boolean typedefed, @Nullable Declarator declarator) {
            var builder =
                    addTypedefedIfNeeded(AnnotationSpec.builder(cts(me.bechberger.ebpf.annotations.Type.class)),
                            typedefed).addMember("noCCodeGeneration", "$L", true);
            if (declarator != null) {
                builder.addMember("cType", "$S", declarator.toPrettyString().replaceAll("\\s+", " "));
            }
            return builder.build();
        }

        sealed interface NamedType extends Type {
            String name();

            String javaName();
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

            @Override
            public void collectUsedTypes(Generator gen, Predicate<TypeName> goIntoStructOrUnion,
                                         Set<TypeName> typeNames) {
                // nothing to do
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

            @Override
            public void collectUsedTypes(Generator gen, Predicate<TypeName> goIntoStructOrUnion,
                                         Set<TypeName> typeNames) {
                typeNames.add(toTypeName(gen));
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
                var skipping = resolvedPointeeSkippingMirrorTypes();
                if (skipping instanceof IntType intType && (intType.knownInt.cName().equals("char") || intType.knownInt.cName().equals("u8"))) {
                    return cts(String.class);
                }
                var skippingMore = resolvedPointeeSkippingMirrorTypesAndTypedef();
                if (skippingMore instanceof FwdType fwdType) {
                    return ParameterizedTypeName.get(cts(Ptr.class), WildcardTypeName.subtypeOf(Object.class)).annotated(AnnotationSpec.builder(cts(OriginalName.class)).addMember("value", "$S", fwdType.toCType().toPrettyString()).build());
                }

                // unpack typedefs
                var pointeeType = resolvedPointee().toGenericTypeName(gen);
                TypeName inner = pointeeType;
                if (inner == null || skippingMore instanceof FuncProtoType funcProtoType) {
                    inner = WildcardTypeName.subtypeOf(Object.class);
                }
                if (nullableElements) {
                    inner = inner.annotated(AnnotationSpec.builder(cts(Nullable.class)).build());
                }
                return ParameterizedTypeName.get(cts(Ptr.class), inner);
            }

            private Type resolvedPointeeSkippingMirrorTypesAndTypedef() {
                var t = resolvedPointeeSkippingMirrorTypes();
                while (t instanceof TypeDefType typedefType) {
                    t = typedefType.type.resolve();
                }
                return t;
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

            @Override
            public void collectUsedTypes(Generator gen, Predicate<TypeName> goIntoStructOrUnion,
                                         Set<TypeName> typeNames) {
                if (!typeNames.add(toTypeName(gen))) { // already added
                    return;
                }
                resolvedPointee().collectUsedTypes(gen, goIntoStructOrUnion, typeNames);
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

            @Override
            public void collectUsedTypes(Generator gen, Predicate<TypeName> goIntoStructOrUnion,
                                         Set<TypeName> typeNames) {
                typeNames.add(toTypeName(gen));
                elementType.resolve().collectUsedTypes(gen, goIntoStructOrUnion, typeNames);
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
                if (bitsOffset % 8 != 0 && !ignoreBitOffset) {
                    throw new UnsupportedTypeKindException("Bit offset must be a multiple of 8");
                }
            }

            public @Nullable String name(int index) {
                if (name == null && type.resolve() instanceof UnionType unionType && !unionType.hasName()) {
                    return null;
                }
                return name == null ? "anon" + index : name;
            }

            List<FieldSpec> toFieldSpecs(Generator gen, int index) {
                int byteOffset = bitsOffset / 8;
                if (name == null && type.resolve() instanceof UnionType unionType) {
                    // inline unions, so generate a field for every union member annotated with @InlineUnion(type.id)
                    var startName = "anon" + index;
                    return IntStream.range(0, unionType.members.size()).mapToObj(i -> {
                        var m = unionType.members.get(i);
                        var builder = FieldSpec.builder(Objects.requireNonNull(m.type.resolve().toTypeName(gen)),
                                escapeName(m.name() == null ? startName + "$" + i : m.name())).addModifiers(Modifier.PUBLIC);
                        if (!ignoreBitOffset) {
                            builder.addAnnotation(AnnotationSpec.builder(cts(Offset.class)).addMember("value", "$L",
                                    byteOffset).build());
                        }
                        return builder.addAnnotation(AnnotationSpec.builder(cts(InlineUnion.class)).addMember("value", unionType.id + "").build()).build();
                    }).toList();
                }
                var properName = name(index);
                if (properName == null) {
                    return List.of();
                }
                var typeName = type.resolve().toTypeName(gen);
                if (typeName == null) {
                    return List.of();
                }
                var builder =
                        FieldSpec.builder(Objects.requireNonNull(typeName), escapeName(properName)).addModifiers(Modifier.PUBLIC);
                if (!ignoreBitOffset) {
                    builder.addAnnotation(AnnotationSpec.builder(cts(Offset.class)).addMember("value", "$L",
                            byteOffset).build());
                }
                return List.of(builder.build());
            }

            void collectUsedTypes(Generator gen, Predicate<TypeName> goIntoStructOrUnion, Set<TypeName> typeNames) {
                type.resolve().collectUsedTypes(gen, goIntoStructOrUnion, typeNames);
            }
        }

        sealed abstract class NameSettable implements PotentiallyNamedType {
            @Nullable
            String name;
            @Nullable
            String javaName;

            boolean hasOriginalName;

            public NameSettable(@Nullable String name) {
                this.name = name;
                this.javaName = name;
                this.hasOriginalName = name != null;
            }

            public void setJavaName(String name) {
                this.javaName = name;
            }

            @Override
            public boolean hasName() {
                assert !Objects.equals(javaName, "(anon)");
                return javaName != null;
            }

            @Override
            public TypeName toTypeName(Generator gen) {
                return hasName() ? gen.createClassName(javaName) : gen.createClassName(id());
            }

            @Override
            public String name() {
                return name;
            }

            @Override
            public String javaName() {
                return javaName;
            }
        }

        final class StructType extends NameSettable {
            private final int id;
            private final List<TypeMember> members;

            public StructType(int id, @Nullable String name, List<TypeMember> members) {
                super(name);
                this.id = id;
                this.members = members;
            }

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
                var builder = TypeSpec.classBuilder(((ClassName) typeName).simpleName()).addModifiers(Modifier.PUBLIC
                        , Modifier.STATIC).addAnnotation(createAnnotations(typedefed, type.toCType(typedefed))).superclass(cts(superClass));
                if (markAllCombinedTypesAsNotUsableInJava) {
                    builder.addAnnotation(cts(NotUsableInJava.class));
                }
                for (int i = 0; i < members.size(); i++) {
                    for (var field : members.get(i).toFieldSpecs(gen, i)) {
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
                    return new StructDeclarator(null,
                            members.stream().map(m -> Declarator.structMember(m.type.resolve().toCType(),
                                    Expression.variable(m.name()))).toList());
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

            @Override
            public int id() {
                return id;
            }

            @Override
            public @Nullable String name() {
                return name;
            }

            public List<TypeMember> members() {
                return members;
            }

            @Override
            public boolean equals(Object obj) {
                if (obj == this) return true;
                if (obj == null || obj.getClass() != this.getClass()) return false;
                var that = (StructType) obj;
                return this.id == that.id && Objects.equals(this.name, that.name) && Objects.equals(this.members,
                        that.members);
            }

            @Override
            public int hashCode() {
                return Objects.hash(id, name, members);
            }

            @Override
            public String toString() {
                return "StructType[" + "id=" + id + ", " + "name=" + name + ", " + "members=" + members + ']';
            }

            @Override
            public void collectUsedTypes(Generator gen, Predicate<TypeName> goIntoStructOrUnion,
                                         Set<TypeName> typeNames) {
                var typeName = toTypeName(gen);
                typeNames.add(typeName);
                if (goIntoStructOrUnion.test(typeName)) {
                    members.forEach(m -> m.collectUsedTypes(gen, goIntoStructOrUnion, typeNames));
                }
            }
        }

        final class UnionType extends NameSettable {
            private final int id;
            private final List<TypeMember> members;

            public UnionType(int id, @Nullable String name, List<TypeMember> members) {
                super(name);
                this.id = id;
                this.members = members;
            }

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
                    return new UnionDeclarator(null,
                            members.stream().map(m -> Declarator.unionMember(m.type.resolve().toCType(),
                                    Expression.variable(m.name()))).toList());
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

            public int id() {
                return id;
            }

            public @Nullable String name() {
                return name;
            }

            public List<TypeMember> members() {
                return members;
            }

            @Override
            public boolean equals(Object obj) {
                if (obj == this) return true;
                if (obj == null || obj.getClass() != this.getClass()) return false;
                var that = (UnionType) obj;
                return this.id == that.id && Objects.equals(this.name, that.name) && Objects.equals(this.members,
                        that.members);
            }

            @Override
            public int hashCode() {
                return Objects.hash(id, name, members);
            }

            @Override
            public String toString() {
                return "UnionType[" + "id=" + id + ", " + "name=" + name + ", " + "members=" + members + ']';
            }

            @Override
            public void collectUsedTypes(Generator gen, Predicate<TypeName> goIntoStructOrUnion,
                                         Set<TypeName> typeNames) {
                var typeName = toTypeName(gen);
                typeNames.add(typeName);
                if (goIntoStructOrUnion.test(typeName)) {
                    members.forEach(m -> m.collectUsedTypes(gen, goIntoStructOrUnion, typeNames));
                }
            }
        }

        record EnumMember(String name, long value) {

            /**
             * Generate something like {@code  @EnumMember(value = 23, name = "KIND_A") B}
             */
            TypeSpec toEnumFieldContant(Generator gen) {
                return TypeSpec.anonymousClassBuilder("").addAnnotation(AnnotationSpec.builder(cts(me.bechberger.ebpf.annotations.EnumMember.class)).addMember("value", "$LL", value).addMember("name", "$S", name).build()).addJavadoc("{@code $L = $L}", name, value).build();
            }

            /**
             * Generate something like {@code public static final int KIND_A = 23;}
             */
            FieldSpec toConstantFieldSpec(Generator gen, KnownInt valueType) {
                return FieldSpec.builder(valueType.javaType().type(), escapeName(name)).addModifiers(Modifier.PUBLIC,
                        Modifier.STATIC, Modifier.FINAL).initializer("$L" + (valueType.bits() > 32 ? "L" : ""),
                        value).build();
            }
        }

        /**
         * An enum if named, else just a set of fields
         */
        final class EnumType extends NameSettable implements PotentiallyNamedType {
            private final int id;
            private final String synthName;
            private final int byteSize;
            private final boolean unsigned;
            private final List<EnumMember> members;

            public EnumType(int id, @Nullable String name, int byteSize, boolean unsigned, List<EnumMember> members) {
                super(name);
                this.id = id;
                this.name = name;
                this.synthName = name == null ? syntheticName(members) : null;
                this.byteSize = byteSize;
                this.unsigned = unsigned;
                this.members = members;
            }

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
            public String name() {
                return name;
            }

            @Override
            public void setJavaName(String javaName) {
                this.javaName = javaName;
            }

            private static String syntheticName(List<EnumMember> members) {

                var commonPrefix =
                        findLongestCommonPrefix(members.stream().map(EnumMember::name).filter(Objects::nonNull).collect(Collectors.toList()));

                if (commonPrefix.length() > 5 || commonPrefix.endsWith("_")) {
                    return commonPrefix.endsWith("_") ? commonPrefix.substring(0, commonPrefix.length() - 1) :
                            commonPrefix;
                }
                return null;
            }

            private static String findLongestCommonPrefix(List<String> strings) {
                if (strings.isEmpty()) {
                    return "";
                }
                var first = strings.getFirst();
                for (int i = 0; i < first.length(); i++) {
                    char c = first.charAt(i);
                    for (var s : strings) {
                        if (s.length() <= i || s.charAt(i) != c) {
                            return first.substring(0, i);
                        }
                    }
                }
                return first;
            }

            @Override
            public TypeName toTypeName(Generator gen) {
                return javaName() != null ? gen.createClassName(javaName()) : valueType().javaType().type();
            }

            private KnownInt valueType() {
                return KnownTypes.getKnownInt(byteSize * 8, !unsigned).orElseThrow();
            }

            @Override
            public TypeSpec toTypeSpec(Generator gen, boolean typedefed) {
                if (javaName() == null || members.isEmpty()) {
                    return null;
                }
                var valueType = valueType();
                var builder =
                        TypeSpec.enumBuilder(javaName()).addModifiers(Modifier.PUBLIC, Modifier.STATIC).addAnnotation(createAnnotations(typedefed, toCType(typedefed))).addSuperinterface(ParameterizedTypeName.get(cts(Enum.class), gen.createClassName(javaName()))).addSuperinterface(ParameterizedTypeName.get(cts(TypedEnum.class), gen.createClassName(javaName()), valueType.javaType().inGenerics()));
                for (var member : members) {
                    builder.addEnumConstant(escapeName(member.name()), member.toEnumFieldContant(gen));
                }
                return builder.build();
            }

            @Override
            public List<FieldSpec> toFieldSpecs(Generator gen) {
                if (!hasName() || members.isEmpty()) {
                    return members.stream().filter(m -> !m.name.equals("true") && !m.name.equals("false")).map(m -> m.toConstantFieldSpec(gen, valueType())).toList();
                }
                return List.of();
            }

            @Override
            public Declarator toCType(boolean typedefed) {
                if (javaName() == null || members.isEmpty()) {
                    return valueType().toCType();
                }
                if (typedefed) {
                    return Declarator.identifier(javaName());
                }
                return Declarator.enumIdentifier(Expression.variable(javaName()));
            }

            @Override
            public boolean shouldAddCast() {
                return false;
            }

            @Override
            public String javaName() {
                return javaName == null ? synthName : javaName;
            }

            @Override
            public int id() {
                return id;
            }

            public int byteSize() {
                return byteSize;
            }

            public boolean unsigned() {
                return unsigned;
            }

            public List<EnumMember> members() {
                return members;
            }

            @Override
            public boolean equals(Object obj) {
                if (obj == this) return true;
                if (obj == null || obj.getClass() != this.getClass()) return false;
                var that = (EnumType) obj;
                return this.id == that.id && Objects.equals(this.name, that.name) && this.byteSize == that.byteSize && this.unsigned == that.unsigned && Objects.equals(this.members, that.members);
            }

            @Override
            public int hashCode() {
                return Objects.hash(id, name, byteSize, unsigned, members);
            }

            @Override
            public String toString() {
                return "EnumType[" + "id=" + id + ", " + "name=" + name + ", " + "byteSize=" + byteSize + ", " +
                        "unsigned=" + unsigned + ", " + "members=" + members + ']';
            }

            @Override
            public void collectUsedTypes(Generator gen, Predicate<TypeName> goIntoStructOrUnion,
                                         Set<TypeName> typeNames) {
                typeNames.add(toTypeName(gen));
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

            @Override
            public void collectUsedTypes(Generator gen, Predicate<TypeName> goIntoStructOrUnion,
                                         Set<TypeName> typeNames) {
                // nothing to do
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
                return toTypeName(gen, true);
            }

            public TypeName toTypeName(Generator gen, boolean addOriginalName) {
                if (!dontEmitTypeDefs) {
                    return gen.createClassName(name);
                }
                var underly = findUnderlyingTypeName(gen);
                var originalName = gen.createClassName(name);
                if (underly.equals(originalName)) {
                    return originalName;
                }
                if (addOriginalName && (KnownTypes.normalizeNames(name).equals(name) || name.equals("bool")) && !underly.toString().startsWith(name)) {
                    return underly.annotated(AnnotationSpec.builder(cts(OriginalName.class)).addMember("value", "$S",
                            name).build());
                }
                return underly;
            }

            @Override
            public TypeName toGenericTypeName(Generator gen) {
                return toGenericTypeName(gen, true);
            }

            public TypeName toGenericTypeName(Generator gen, boolean addOriginalName) {
                var tn = type.resolve() instanceof TypeDefType t ? t.toGenericTypeName(gen, false) :
                        type.resolve().toGenericTypeName(gen);
                if (tn == null) {
                    return toTypeName(gen);
                }
                if (addOriginalName && (KnownTypes.normalizeNames(name).equals(name) || name.equals("bool")) && !tn.toString().startsWith(name)) {
                    return tn.annotated(AnnotationSpec.builder(cts(OriginalName.class)).addMember("value", "$S",
                            name).build());
                }
                return tn;
            }

            @Override
            public @Nullable TypeSpec toTypeSpec(Generator gen, boolean typedefed) {
                if (dontEmitTypeDefs) {
                    if (findUnderlyingTypeName(gen) != null) {
                        return null;
                    }
                }
                var t = type.resolve();
                if (t instanceof MirrorType mirrorType) {
                    return mirrorType.type.resolve().toTypeSpec(gen, true);
                }
                if (t instanceof StructType || t instanceof UnionType || t instanceof EnumType) {
                    return t.toTypeSpec(gen, true);
                }
                return TypeSpec.classBuilder(name).addModifiers(Modifier.PUBLIC, Modifier.STATIC).addAnnotation(createAnnotations(typedefed, toCType(typedefed))).superclass(ParameterizedTypeName.get(cts(TypedefBase.class), t.toGenericTypeName(gen))).addMethod(MethodSpec.constructorBuilder().addModifiers(Modifier.PUBLIC).addParameter(Objects.requireNonNullElse(t.toGenericTypeName(gen), ClassName.get(Object.class)), "val").addStatement("super(val)").build()).build();
            }

            private TypeName findUnderlyingTypeName(Generator gen) {
                var t = type.resolve();
                while (true) {
                    switch (t) {
                        case TypeDefType typedefType -> {
                            var underly = typedefType.findUnderlyingTypeName(gen);
                            if (underly != null) {
                                return underly;
                            }
                            return typedefType.toTypeName(gen, false);
                        }
                        case MirrorType mirrorType -> t = mirrorType.type.resolve();
                        case EnumType enumType -> {
                            return enumType.toTypeName(gen);
                        }
                        case null, default -> {
                            var underly = t.toTypeName(gen);
                            if (underly != null) {
                                return underly;
                            }
                            return gen.createClassName(name);
                        }
                    }
                }
            }

            @Override
            public @Nullable MethodSpec toMethodSpec(Generator gen) {
                if (type.resolve() instanceof FuncProtoType funcProtoType || (type.resolve() instanceof PtrType ptrType && ptrType.resolvedPointee() instanceof FuncProtoType)) {
                    return null; // don't emit typedefs for function pointers
                }
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

            @Override
            public String javaName() {
                return name;
            }

            @Override
            public void collectUsedTypes(Generator gen, Predicate<TypeName> goIntoStructOrUnion,
                                         Set<TypeName> typeNames) {
                if (dontEmitTypeDefs) {
                    if (findUnderlyingTypeName(gen) != null) {
                        return;
                    }
                }
                typeNames.add(toTypeName(gen));
                type.resolve().collectUsedTypes(gen, goIntoStructOrUnion, typeNames);
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

            @Override
            public void collectUsedTypes(Generator gen, Predicate<TypeName> goIntoStructOrUnion,
                                         Set<TypeName> typeNames) {
                type.resolve().collectUsedTypes(gen, goIntoStructOrUnion, typeNames);
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

            @Override
            public String javaName() {
                return name;
            }

            @Override
            public void collectUsedTypes(Generator gen, Predicate<TypeName> goIntoStructOrUnion,
                                         Set<TypeName> typeNames) {
                impl.collectUsedTypes(gen, goIntoStructOrUnion, typeNames);
            }
        }

        /**
         * Assigns a name to a {@link FuncProtoType}
         */
        record FuncParameter(@Nullable String name, TypeRef type) {

            FuncParameter(String name, Type type) {
                this(name, () -> type);
            }

            private ParameterSpec toParameterSpec(Generator gen, int index, TypeName typeName) {

                return ParameterSpec.builder(typeName, name == null ? "param" + index : escapeName(name)).build();
            }

            public ParameterSpec toParameterSpec(Generator gen, int index) {
                return toParameterSpec(gen, index, type.resolve().toTypeName(gen));
            }

            public void collectUsedTypes(Generator gen, Predicate<TypeName> goIntoStructOrUnion,
                                         Set<TypeName> typeNames) {
                type.resolve().collectUsedTypes(gen, goIntoStructOrUnion, typeNames);
            }
        }

        final class FuncProtoType implements Type {
            private final int id;
            private final List<FuncParameter> parameters;
            private final Type returnType;
            private final boolean variadic;

            public FuncProtoType(int id, List<FuncParameter> parameters, Type returnType, boolean variadic) {
                this.id = id;
                this.variadic = variadic || isVariadic(parameters);
                this.parameters = modifyLastIfVariadic(parameters, this.variadic);
                this.returnType = returnType;
            }

            public FuncProtoType(List<FuncParameter> parameters, Type returnType, boolean variadic) {
                this(-1, parameters, returnType, variadic);
            }

            FuncProtoType(int id, List<FuncParameter> parameters, Type returnType) {
                this(id, parameters, returnType, false);
            }

            FuncProtoType(List<FuncParameter> parameters, Type returnType) {
                this(-1, parameters, returnType, false);
            }

            static boolean isVariadic(List<FuncParameter> parameters) {
                // check if last parameter has void as its type
                return !parameters.isEmpty() && parameters.getLast().type.resolve() instanceof VoidType;
            }

            static List<FuncParameter> modifyLastIfVariadic(List<FuncParameter> parameters, boolean isVariadic) {
                if (isVariadic) {
                    var list = new ArrayList<>(parameters);
                    var lastParam = list.getLast();
                    list.set(parameters.size() - 1, new FuncParameter(lastParam.name, new ArrayType(new AnyType(),
                            -1)));
                    return list;
                }
                return parameters;
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
                var builtinFunctionAnnBuilder = AnnotationSpec.builder(cts(BuiltinBPFFunction.class));
                var funcConversion = toBPFFunctionConversionString(name);
                if (funcConversion != null) {
                    builtinFunctionAnnBuilder.addMember("value", "$S", funcConversion);
                }
                var builtinFunctionAnn = builtinFunctionAnnBuilder.build();
                var builder =
                        MethodSpec.methodBuilder(name).addModifiers(Modifier.PUBLIC, Modifier.STATIC)
                                .addAnnotation(cts(NotUsableInJava.class))
                                .addAnnotation(builtinFunctionAnn).returns(returnType.toTypeName(gen)).varargs(variadic);
                for (int i = 0; i < parameters.size(); i++) {
                    var param = parameters.get(i);
                    if (param.type.resolve() instanceof VoidType) { // this can never be
                        throw new IllegalArgumentException("Void type not allowed in function parameters");
                    }
                    builder.addParameter(param.toParameterSpec(gen, i));
                }
                builder.addCode("throw new $T();", cts(MethodIsBPFRelatedFunction.class));
                if (javaDoc != null) {
                    builder.addJavadoc("$L", javaDoc);
                }
                return builder.build();
            }

            @Override
            public Declarator toCType() {
                return toCType("");
            }

            public FunctionDeclarator toCType(String name) {
                return new FunctionDeclarator(Expression.variable(name), returnType.toCType(),
                        parameters.stream().map(p -> new FunctionParameter(Expression.variable(p.name),
                                p.type().resolve().toCType())).toList());
            }

            public boolean returnsVoid() {
                return returnType instanceof VoidType;
            }

            /**
             * Convert to a string that can be used in the {@link BuiltinBPFFunction} annotation
             */
            public @Nullable String toBPFFunctionConversionString(String name) {
                var params = IntStream.range(0, parameters.size()).mapToObj(i -> {
                    var param = parameters.get(i);
                    if (param.type.resolve().shouldAddCast() && (!variadic || i < parameters.size() - 1)) {
                        var t = param.type.resolve().toCType();
                        return "(" + (t instanceof Pointery ? ((Pointery) t).toPrettyVariableDefinition(null, "") :
                                t.toPrettyString()) + ")$arg" + (i + 1);
                    }
                    if (i == parameters.size() - 1 && variadic) {
                        return "$arg" + (i + 1) + "_";
                    }
                    return "$arg" + (i + 1);
                }).toList();
                var anyConversion = params.stream().anyMatch(a -> a.contains("(") || a.contains(")"));
                String call = anyConversion ? name + "(" + String.join(", ", params) + ")" : name;
                String ret = returnsVoid() || !returnType.shouldAddCast() ? call :
                        "((" + returnType.toCType().toPrettyString() + ")" + call + ")";
                if (ret.equals(name)) {
                    return null;
                }
                return ret;
            }

            @Override
            public boolean shouldAddCast() {
                return true;
            }

            @Override
            public int id() {
                return id;
            }

            public List<FuncParameter> parameters() {
                return parameters;
            }

            public Type returnType() {
                return returnType;
            }

            public boolean variadic() {
                return variadic;
            }

            @Override
            public boolean equals(Object obj) {
                if (obj == this) return true;
                if (obj == null || obj.getClass() != this.getClass()) return false;
                var that = (FuncProtoType) obj;
                return this.id == that.id && Objects.equals(this.parameters, that.parameters) && Objects.equals(this.returnType, that.returnType) && this.variadic == that.variadic;
            }

            @Override
            public int hashCode() {
                return Objects.hash(id, parameters, returnType, variadic);
            }

            @Override
            public String toString() {
                return "FuncProtoType[" + "id=" + id + ", " + "parameters=" + parameters + ", " + "returnType=" + returnType + ", " + "variadic=" + variadic + ']';
            }

            @Override
            public void collectUsedTypes(Generator gen, Predicate<TypeName> goIntoStructOrUnion,
                                         Set<TypeName> typeNames) {
                parameters.forEach(p -> p.collectUsedTypes(gen, goIntoStructOrUnion, typeNames));
                if (returnType != null) {
                    returnType.collectUsedTypes(gen, goIntoStructOrUnion, typeNames);
                }
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
                return List.of(FieldSpec.builder(type.toTypeName(gen), escapeName(name)).addModifiers(Modifier.PUBLIC
                        , Modifier.STATIC).build());
            }

            @Override
            public boolean shouldAddCast() {
                return false;
            }

            @Override
            public String javaName() {
                return name;
            }

            @Override
            public void collectUsedTypes(Generator gen, Predicate<TypeName> goIntoStructOrUnion,
                                         Set<TypeName> typeNames) {
                type.collectUsedTypes(gen, goIntoStructOrUnion, typeNames);
            }
        }

        record VerbatimType(String cName, String javaName, String genericJavaName) implements Type {

            public VerbatimType(String cName, String javaName) {
                this(cName, javaName, javaName);
            }

            public VerbatimType(String cName, VerbatimType javaType) {
                this(cName, javaType.javaName, javaType.genericJavaName);
            }

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
            public TypeName toGenericTypeName(Generator gen) {
                return ClassName.get("", genericJavaName);
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

            @Override
            public void collectUsedTypes(Generator gen, Predicate<TypeName> goIntoStructOrUnion,
                                         Set<TypeName> typeNames) {
                // nothing to do
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

            @Override
            public void collectUsedTypes(Generator gen, Predicate<TypeName> goIntoStructOrUnion,
                                         Set<TypeName> typeNames) {
                // nothing to do
            }
        }

        record FwdType(int id, String name) implements Type {
            public FwdType(String name) {
                this(-1, name);
            }

            @Override
            public Kind kind() {
                return Kind.FWD;
            }

            @Override
            public BPFType<?> bpfType() {
                throw new UnsupportedOperationException("Fwd type");
            }

            @Override
            public TypeName toTypeName(Generator gen) {
                return gen.createClassName(name);
            }

            @Override
            public CAST.Declarator toCType() {
                return Declarator.identifier(name);
            }

            @Override
            public boolean shouldAddCast() {
                return false;
            }

            @Override
            public void collectUsedTypes(Generator gen, Predicate<TypeName> goIntoStructOrUnion,
                                         Set<TypeName> typeNames) {
                typeNames.add(toTypeName(gen));
            }
        }
    }

    private final ArrayList<@Nullable Type> types = new ArrayList<>(List.of((Type) new VoidType()));
    private final Map<String, NamedType> namedTypes = new HashMap<>();
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
        if (type instanceof NamedType namedType) {
            namedTypes.put(namedType.name(), namedType);
        }
    }

    @Nullable NamedType getByName(String name) {
        return namedTypes.get(name);
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
        switch (rawType.kind) {
            case VOID -> throw new AssertionError("Unexpected void type");
            case INT -> put(processIntType(typeId, rawType));
            case PTR -> put(processPtrType(typeId, rawType));
            case ARRAY -> put(processArrayType(typeId, rawType));
            case STRUCT -> put(processStructType(typeId, rawType));
            case UNION -> put(processUnionType(typeId, rawType));
            case ENUM -> put(processEnumType(typeId, rawType));
            case DATASEC, DECL_TAG -> put(new UnsupportedType(typeId, rawType.kind));
            case FWD -> put(processFwdType(typeId, rawType));
            case TYPEDEF -> put(processTypeDefType(typeId, rawType));
            case VOLATILE, CONST, RESTRICT, TYPE_TAG -> put(processMirrorType(rawType.kind, typeId, rawType));
            case FUNC -> put(processFuncType(typeId, rawType));
            case FUNC_PROTO -> put(processFuncProtoType(typeId, rawType));
            case VAR -> put(processVarType(typeId, rawType));
            case FLOAT -> put(processFloatType(typeId, rawType));
            case ENUM64 -> put(processEnum64Type(typeId, rawType));
            default -> throw new IllegalStateException("Unexpected value: " + rawType.kind);
        }
    }

    private IntType processIntType(int id, JSONObjectWithType rawType) {
        var name = switch (rawType.getName()) {
            case "char" -> "u8";
            case "unsigned char" -> "u8";
	     case "signed char" -> "s8";
            default -> rawType.getName();
        };
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
                rawType.jsonObject.getJSONArray("values").stream().map(m -> new Type.EnumMember(((JSONObject) m).getString("name"), ((JSONObject) m).getInteger("val"))).toList());
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
            return new FuncParameter(getNameOrNull(param), ref(param.getInteger("type_id")));
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
                rawType.jsonObject.getJSONArray("values").stream().map(m -> new Type.EnumMember(((JSONObject) m).getString("name"), ((JSONObject) m).getLong("val"))).toList());
    }

    private FwdType processFwdType(int id, JSONObjectWithType rawType) {
        rawType.assertKeys("name", "id", "kind", "fwd_kind");
        return new FwdType(id, rawType.getName());
    }

    public record Result<T>(T result, int unsupportedTypes, int supportedTypes) {
    }

    public static abstract class GeneratorConfig {

        final String baseClassName;

        public GeneratorConfig(String baseClassName) {
            this.baseClassName = baseClassName;
        }

        String classDescription(String className) {
            return classDescription();
        }

        String classDescription() {
            return "";
        }

        List<MethodSpec> createMethodSpec(Generator gen, Type type) {
            var ret = type.toMethodSpec(gen);
            return ret == null ? List.of() : List.of(ret);
        }

        /**
         * Create a type spec builder for the given type,
         * the class name is either the default class or the group for non-default groups
         */
        TypeSpec.Builder createTypeSpecBuilder(Generator gen, String className) {
            var builder =
                    TypeSpec.classBuilder(className).addModifiers(Modifier.PUBLIC, Modifier.FINAL).addAnnotation(AnnotationSpec.builder(SuppressWarnings.class).addMember("value", "$S", "unused").build());
            if (!classDescription(className).isEmpty()) {
                builder.addJavadoc(classDescription(className));
            }
            return builder;
        }

        List<String> additionalImports() {
            return List.of();
        }

        List<Class<?>> preimportedClasses() {
            return List.of(SuppressWarnings.class);
        }

        /**
         * Get the group class part of the type, e.g. "xdp" for "xdp_md", {@code ""} is the default group
         */
        String group(String typeName) {
            return "";
        }

        public String mergedClassName() {
            return "misc";
        }

        public int maxGroupSizeForMerging() {
            return -1;
        }
    }

    /**
     * Set the name of {@link NameSettable} types if they don't have a name
     * <p>
     * Try to use "UsingType$FieldType" if using type is not null
     */
    private void setNamesOfAnonymousIfPossible(List<@Nullable Type> types) {

        Function<TypeMember, @Nullable NameSettable> innerTypeOfMember = m -> {
            // throw away pointer, mirror and typedef types
            var type = m.type().resolve();
            while (true) {
                if (type instanceof NameSettable nameSettable) {
                    return nameSettable;
                }
                if (type instanceof MirrorType mirrorType) {
                    type = mirrorType.type.resolve();
                } else if (type instanceof PtrType ptrType) {
                    type = ptrType.resolvedPointee();
                } else if (type instanceof TypeDefType typedefType) {
                    var resolved = typedefType.type.resolve();
                    if (resolved instanceof NameSettable typedefed && typedefed.javaName() == null) {
                        typedefed.setJavaName(typedefType.name()); // we know the name
                        return null;
                    }
                    type = typedefType.type.resolve();
                } else {
                    return null;
                }
            }
        };

        record Usage(NamedType type, String memberName) {
        }

        Map<NameSettable, List<Usage>> usages = new HashMap<>();

        for (var type : types) {
            if (type instanceof TypeDefType typedefType) {
                var resolved = typedefType.type.resolve();
                if (resolved instanceof NameSettable typedefed && typedefed.javaName() == null) {
                    typedefed.setJavaName(typedefType.name()); // we know the name
                }
            }
        }

        for (var type : types) {
            List<TypeMember> members;
            switch (type) {
                case StructType structType -> members = structType.members();
                case UnionType unionType -> members = unionType.members();
                case TypeDefType typedefType when typedefType.type.resolve() instanceof StructType structType ->
                        members = structType.members();
                case TypeDefType typedefType when typedefType.type.resolve() instanceof UnionType unionType ->
                        members = unionType.members();
                case null, default -> {
                    continue;
                }
            }
            for (var member : members) {
                var innerType = innerTypeOfMember.apply(member);
                if (innerType instanceof NameSettable n && n.javaName == null) {
                    usages.computeIfAbsent(innerType, k -> new ArrayList<>()).add(new Usage((NamedType) type,
                            member.name()));
                }
            }
        }

        Set<NameSettable> withAnonymousParentTypes = new HashSet<>();
        Set<NameSettable> work = new HashSet<>(usages.keySet());
        boolean changed = true;
        while (changed) {
            changed = false;
            withAnonymousParentTypes.clear();
            for (var type : work) {
                var usagesList = usages.get(type);
                var anonymous = usagesList.stream().anyMatch(usage -> usage.type.javaName() == null);
                if (anonymous) {
                    withAnonymousParentTypes.add(type);
                    continue;
                }
                var usageNames = usagesList.stream().map(usage -> (usage.memberName == null ? "anon_member" :
                        usage.memberName) + "_of_" + usage.type.javaName()).distinct().toList();
                if (usageNames.size() == 1) {
                    type.setJavaName(usageNames.getFirst());
                } else {
                    type.setJavaName(usageNames.stream().sorted().limit(3).collect(Collectors.joining("_and_")));
                }
                changed = true;
            }
            work = new HashSet<>(withAnonymousParentTypes);
        }

        for (var type : types) {
            if (type instanceof NameSettable n && n.javaName == null) {
                var cCode = n.toCType().toPrettyString();
                if (!(type instanceof EnumType)) {
                    n.setJavaName("AnonymousType" + Math.abs(cCode.chars().sorted().hashCode()) + "C" + cCode.length());
                }
            }
        }
    }

    private List<TypeGroup> groupTypes(String className, GeneratorConfig config) {
        Map<String, TypeGroup> groups = new HashMap<>();
        List<@Nullable Type> actualTypes = types;
        if (!additionalTypes.isEmpty()) {
            actualTypes = new ArrayList<>(types);
            actualTypes.addAll(additionalTypes);
        }
        setNamesOfAnonymousIfPossible(actualTypes);
        Set<String> alreadyEmitted = new HashSet<>();

        Map<TypeName, Type> typeMap = new HashMap<>();

        // group
        for (var type : actualTypes) {
            if (type != null && !(type instanceof UnsupportedType) && !(type instanceof FwdType)) {
                var name = type instanceof FuncType f ? f.name : Objects.toString(type.toTypeName(this));
                if (alreadyEmitted.contains(name)) {
                    continue;
                }
                boolean emittedSomething =
                        type.toTypeSpec(this) != null || !type.toFieldSpecs(this).isEmpty() || !config.createMethodSpec(this, type).isEmpty();
                if (emittedSomething) {
                    var groupName = escapeName(config.group(name).isEmpty() ? className : config.group(name));
                    var group = groups.computeIfAbsent(groupName, k -> new TypeGroup(this, config, basePackage,
                            className, k, new ArrayList<>()));
                    group.types.add(type);
                    alreadyEmitted.add(name);
                    typeMap.put(type.toTypeName(this), type);
                }
            }
        }

        // for every group check that there is no type with the same name
        // if so, prefix it with "_"
        for (var group : groups.values().stream().toList()) {
            String newName = group.className();
            while (alreadyEmitted.contains(newName)) {
                newName = "_" + newName;
            }
            if (!newName.equals(group.className())) {
                groups.put(newName, new TypeGroup(this, config, basePackage, className, newName, group.types));
                groups.remove(group.className());
            }
        }

        Map<TypeGroup, Integer> sizes = new HashMap<>();
        for (var group : groups.values()) {
            sizes.put(group, group.types.size());
        }

        // find whether there are groups that can be merged
        var mergeableGroups =
                sizes.entrySet().stream().filter(e -> e.getValue() <= config.maxGroupSizeForMerging()).toList();

        // create merged group

        // merge from tiniest to largest, till max group size is reached
        var collectedTypesForMerge = new ArrayList<Type>();
        var mergedGroups = new ArrayList<TypeGroup>();
        for (var group : mergeableGroups) {
            collectedTypesForMerge.addAll(group.getKey().types);
            mergedGroups.add(group.getKey());
        }

        if (mergedGroups.size() > 1) {
            var mergedGroup = new TypeGroup(this, config, basePackage, className, config.mergedClassName(),
                    collectedTypesForMerge);
            groups.put(config.mergedClassName(), mergedGroup);
            // remove merged groups
            mergedGroups.forEach(e -> {
                if (e.className().equals(config.mergedClassName())) {
                    return;
                }
                groups.remove(e.className());
            });
        }

        // now place anonymous types in the correct group
        // for each group: compute all used types in the base group
        // and store for every type in the base group the groups it is used in

        // for each group: compute all used types in the base group
        Map<Type, List<String>> groupsThatUseRuntimeGroup = new HashMap<>();

        for (var groupEntry : groups.entrySet()) {
            if (groupEntry.getKey().equals(className)) {
                continue;
            }
            var usedTypesFromRuntime = new HashSet<TypeName>();
            for (var type : groupEntry.getValue().types) {
                type.collectUsedTypes(this,
                        t -> config.group(t.toString()).isEmpty() || t.equals(type.toTypeName(this)),
                        usedTypesFromRuntime);
            }
            for (var usedType : usedTypesFromRuntime) {
                if (!config.group(usedType.toString()).isEmpty()) {
                    continue;
                }
                if (typeMap.get(usedType) == null) { // non emitting type
                    continue;
                }
                groupsThatUseRuntimeGroup.computeIfAbsent(typeMap.get(usedType), k -> new ArrayList<>()).add(groupEntry.getKey());
            }
        }

        // now we take all types where the groups with only one group usage and move them
        groupsThatUseRuntimeGroup.forEach((type, groupsThatUseIt) -> {
            if (groupsThatUseIt.size() == 1) {
                var group = groups.get(groupsThatUseIt.getFirst());
                group.types.add(type);
                groups.get(className).types.remove(type);
            }
        });

        System.out.println("Generated " + groups.size() + " groups");
        // print max group size and group names
        var maxGroupSize = groups.values().stream().mapToInt(g -> g.types.size()).max().orElse(0);
        System.out.println("Max group size: " + maxGroupSize);
        System.out.println("Types: " + typeMap.size());

        return new ArrayList<>(groups.values());
    }

    private static final class TypeGroup {
        private final Generator gen;
        private final GeneratorConfig config;
        private final String packageName;
        private final String defaultClassName;
        private final String className;
        private final List<Type> types;

        private TypeGroup(Generator gen, GeneratorConfig config, String packageName, String defaultClassName,
                          String className, List<Type> types) {
            this.gen = gen;
            this.config = config;
            this.packageName = packageName;
            this.defaultClassName = defaultClassName;
            this.className = className;
            this.types = types;
        }

        TypeSpec computeType() {
            var typeSpec = config.createTypeSpecBuilder(gen, className);
            for (var type : types) {
                var t = type.toTypeSpec(gen);
                if (t != null) {
                    typeSpec.addType(t);
                }
                for (var field : type.toFieldSpecs(gen)) {
                    typeSpec.addField(field);
                }
                var methods = config.createMethodSpec(gen, type);
                if (!methods.isEmpty()) {
                    methods.forEach(typeSpec::addMethod);
                }
            }
            return typeSpec.build();
        }

        Set<TypeName> usedTypes() {
            var typeNames = new HashSet<TypeName>();
            var ownTypeNames =
                    types.stream().map(t -> t.toTypeName(gen)).filter(Objects::nonNull).collect(Collectors.toSet());
            types.forEach(t -> t.collectUsedTypes(gen, ownTypeNames::contains, typeNames));
            return typeNames;
        }

        Set<String> usedGroupClassNames() {
            var usedTypes = usedTypes();
            return usedTypes.stream().map(Object::toString).map(t -> {
                var g = config.group(t);
                return g.isEmpty() ? defaultClassName : g;
            }).filter(Objects::nonNull).filter(t -> t.equals(className)).collect(Collectors.toSet());
        }

        List<String> createImportLines(List<String> moreImportedClasses) {
            List<String> imports =
                    Stream.concat(config.preimportedClasses().stream(), preimportedClasses.stream()).distinct().map(c -> "import " + c.getName() + ";").collect(Collectors.toList());
            imports.addAll(config.additionalImports());
            for (var t : moreImportedClasses) {
                if (t.equals(className)) {
                    continue;
                }
                imports.add("import static " + packageName + "." + t + ".*;");
            }
            Collections.sort(imports);
            return imports;
        }

        String javaFile(List<String> moreImportedClasses) {
            return """
                    /** Auto-generated */
                    package %s;
                                            
                    %s
                                            
                    %s
                    """.formatted(packageName, String.join("\n", createImportLines(moreImportedClasses)),
                    computeType().toString().trim());
        }

        public Generator gen() {
            return gen;
        }

        public GeneratorConfig config() {
            return config;
        }

        public String packageName() {
            return packageName;
        }

        public String defaultClassName() {
            return defaultClassName;
        }

        public String className() {
            return className;
        }

        public List<Type> types() {
            return types;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == this) return true;
            if (obj == null || obj.getClass() != this.getClass()) return false;
            var that = (TypeGroup) obj;
            return Objects.equals(this.gen, that.gen) && Objects.equals(this.config, that.config) && Objects.equals(this.packageName, that.packageName) && Objects.equals(this.defaultClassName, that.defaultClassName) && Objects.equals(this.className, that.className) && Objects.equals(this.types, that.types);
        }

        @Override
        public int hashCode() {
            return Objects.hash(gen, config, packageName, defaultClassName, className, types);
        }

        @Override
        public String toString() {
            return "TypeGroup[" + "gen=" + gen + ", " + "config=" + config + ", " + "packageName=" + packageName + "," +
                    " " + "defaultClassName=" + defaultClassName + ", " + "className=" + className + ", " + "types=" + types + ']';
        }

    }

    public record TypeJavaFiles(String packageName, Map<String, String> javaFilePerClass) {

        private void storeInFolder(Path folder, String className, String code) {
            var path = folder.resolve(packageName.replace('.', '/') + "/" + className + ".java");
            if (!Files.exists(path.getParent())) {
                try {
                    Files.createDirectories(path.getParent());
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }

            try {
                Files.writeString(path, code);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        void storeInFolder(Path folder) {
            javaFilePerClass.forEach((className, code) -> storeInFolder(folder, className, code));
        }

        List<String> generateStaticImportsForAll() {
            return javaFilePerClass.keySet().stream().map(c -> "import static " + packageName + "." + c + ".*;").sorted().collect(Collectors.toList());
        }
    }

    public TypeJavaFiles generateJavaFiles(GeneratorConfig config) {
        var groups = groupTypes(config.baseClassName, config);
        return new TypeJavaFiles(basePackage, groups.stream().collect(Collectors.toMap(t -> t.className,
                t -> t.javaFile(groups.stream().map(g -> g.className).collect(Collectors.toList())))));
    }

    /**
     * Config for create bpf runtime classes
     */
    public GeneratorConfig createBPFRuntimeConfig() {
        return new GeneratorConfig("runtime") {
            @Override
            public String classDescription(String className) {
                if (className.equals("misc")) {
                    return "Generated class for many BPF runtime types";
                }
                if (className.equals(baseClassName)) {
                    return "Generated class for BPF runtime types that don't fit in other classes";
                }
                return "Generated class for BPF runtime types that start with " + className.replaceAll("Definitions$"
                        , "").toLowerCase();
            }

            @Override
            public List<Class<?>> preimportedClasses() {
                return List.of(NotUsableInJava.class, BuiltinBPFFunction.class, MethodIsBPFRelatedFunction.class);
            }

            @Override
            public String group(String typeName) {
                if (typeName.matches("_*[a-z0-9A-Z]+_[a-z].*")) {
                    // return first [a-z]+ part even with multiple leading _
                    var parts = typeName.split("_+");
                    return toCamelCase(Arrays.stream(parts).filter(s -> !s.isEmpty()).findFirst().orElse("").toLowerCase() + "_definitions");
                }
                return "";
            }

            @Override
            public String mergedClassName() {
                return "misc";
            }

            @Override
            public int maxGroupSizeForMerging() {
                return 10;
            }
        };
    }

    public TypeJavaFiles generateBPFRuntimeJavaFiles() {
        return generateJavaFiles(createBPFRuntimeConfig());
    }

    public void addAdditionalType(Type type) {
        additionalTypes.add(type);
    }

    public List<Type> getAdditionalTypes() {
        return additionalTypes;
    }

    public Set<TypeName> generatedJavaTypeNames() {
        return Stream.concat(types.stream(), additionalTypes.stream()).filter(Objects::nonNull).map(t -> t.toTypeName(this)).filter(Objects::nonNull).collect(Collectors.toSet());
    }

    public static class NameTranslator {

        public static class UnknownTypeException extends RuntimeException {
            public UnknownTypeException(String name) {
                super("Unknown type: " + name);
            }
        }

        record Translation(String javaType, String genericJavaType) {
        }

        private final Map<String, Translation> translations;
        private final Set<String> types;

        private boolean throwUnknownTypeException = false;

        public NameTranslator(Generator gen) {
            this.translations = new HashMap<>();
            this.types = new HashSet<>();
            Stream.concat(gen.types.stream(), gen.additionalTypes.stream()).filter(Objects::nonNull).forEach(t -> {
                if (t instanceof TypeDefType typedef) {
                    types.add(typedef.name());
                    types.add(typedef.toTypeName(gen).toString());
                    if (!translations.containsKey(typedef.name())) {
                        translations.put(typedef.name(), new Translation(typedef.toTypeName(gen).toString(),
                                Objects.requireNonNullElseGet(typedef.toGenericTypeName(gen),
                                        () -> typedef.toTypeName(gen)).toString()));
                    }
                }
                if (t instanceof NamedType) {
                    types.add(((NamedType) t).javaName());
                }
            });
        }

        public VerbatimType translate(String name) {
            if (!KnownTypes.normalizeNames(name).equals(name)) {
                var knownInt = KnownTypes.getKnowIntUnchecked(name);
                return new VerbatimType(knownInt.cName(), knownInt.javaType().type().toString(),
                        knownInt.javaType().inGenerics().toString());
            }
            if (translations.containsKey(name)) {
                var res = translations.get(name);
                return new VerbatimType(name, res.javaType, res.genericJavaType);
            }
            if (types.contains("__kernel_" + name)) {
                return new VerbatimType("__kernel_" + name, "__kernel_" + name);
            }
            if (!types.contains(name) && throwUnknownTypeException) {
                throw new UnknownTypeException(name);
            }
            return new VerbatimType(name, name);
        }

        public NameTranslator put(String name, String javaType, String genericJavaType) {
            this.translations.put(name, new Translation(translate(javaType).javaName,
                    translate(genericJavaType).genericJavaName));
            return this;
        }

        public NameTranslator put(String name, String javaType) {
            this.translations.put(name, new Translation(translate(javaType).javaName,
                    translate(javaType).genericJavaName));
            return this;
        }

        public NameTranslator put(String name, KnownInt knownInt) {
            this.translations.put(name, new Translation(knownInt.javaType().type().toString(),
                    knownInt.javaType().inGenerics().toString()));
            return this;
        }

        public void setThrowUnknownTypeException(boolean doThrow) {
            this.throwUnknownTypeException = doThrow;
        }
    }

    public NameTranslator createNameTranslator() {
        return new NameTranslator(this);
    }

    public String getBasePackage() {
        return basePackage;
    }
}