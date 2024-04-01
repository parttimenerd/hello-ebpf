package me.bechberger.ebpf.type;

import com.squareup.javapoet.ClassName;
import com.squareup.javapoet.FieldSpec;
import com.squareup.javapoet.ParameterizedTypeName;
import com.squareup.javapoet.TypeName;
import me.bechberger.cast.CAST;
import me.bechberger.ebpf.annotations.AnnotationInstances;
import org.jetbrains.annotations.Nullable;

import javax.lang.model.element.Modifier;
import java.lang.annotation.Annotation;
import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.*;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static me.bechberger.cast.CAST.Declarator.identifier;
import static me.bechberger.cast.CAST.Expression.variable;
import static me.bechberger.ebpf.bpf.processor.TypeProcessor.BPF_PACKAGE;
import static me.bechberger.ebpf.bpf.processor.TypeProcessor.BPF_TYPE;
import static me.bechberger.ebpf.type.BPFType.BPFIntType.CHAR;


/**
 * A BPF type, see <a href="https://www.kernel.org/doc/html/latest/bpf/btf.html">Linux BTF documentation</a> for
 * more information
 */
public sealed interface BPFType<T> {

    /**
     * Java class with annotations
     */
    record AnnotatedClass(String klass, List<Annotation> annotations) {

        public AnnotatedClass(Class<?> klass, List<Annotation> annotations) {
            this(klass.getName(), annotations);
        }
    }

    /**
     * Parse a memory segment to return a Java object
     */
    @FunctionalInterface
    interface MemoryParser<T> {
        T parse(MemorySegment segment);
    }

    /**
     * Copy the native representation of a Java object into a passed memory segment
     */
    @FunctionalInterface
    interface MemorySetter<T> {
        void store(MemorySegment segment, T obj);
    }

    /**
     * Name of the type in BPF
     */
    String bpfName();

    MemoryLayout layout();

    MemoryParser<T> parser();

    MemorySetter<T> setter();

    /**
     * Size of the type in bytes
     */
    default long size() {
        return layout().byteSize();
    }

    /**
     * Alignment of the type in bytes
     */
    long alignment();

    private static long padSize(long size, long alignment) {
        return (size + alignment - 1) & -alignment;
    }

    /**
     * Padded size of the type in bytes, use for all array index computations
     */
    default long sizePadded() {
        return padSize(layout().byteSize(), alignment());
    }

    /**
     * Class that represents the type
     */
    AnnotatedClass javaClass();

    default Optional<? extends CAST> toCDeclaration() {
        return Optional.empty(); // for structs already defined in C
    }

    default Optional<? extends CAST.Statement> toCDeclarationStatement() {
        return Optional.empty();
    }

    default CAST.Declarator toCUse() {
        return identifier(bpfName());
    }

    default Optional<BiFunction<String, Function<BPFType<?>, String>, FieldSpec>> toFieldSpecGenerator() {
        return Optional.empty();
    }

    default String toJavaUse() {
        return javaClass().klass;
    }

    default String toJavaUseInGenerics() {
        return toJavaUse();
    }

    String toJavaFieldSpecUse(Function<BPFType<?>, String> typeToSpecFieldName);

    /**
     * Make sure to guarantee type-safety
     */
    default T parseMemory(MemorySegment segment) {
        return parser().parse(segment);
    }

    default void setMemory(MemorySegment segment, T obj) {
        setter().store(segment, obj);
    }

    /** Allocate a memory segment and store the object in it */
    default MemorySegment allocate(Arena arena, T obj) {
        MemorySegment segment = arena.allocate(layout());
        setMemory(segment, obj);
        return segment;
    }

    /** Allocate a memory segment */
    default MemorySegment allocate(Arena arena) {
        return arena.allocate(layout());
    }

    /**
     * Integer
     */
    record BPFIntType<I>(String bpfName, MemoryLayout layout, MemoryParser<I> parser, MemorySetter<I> setter,
                         AnnotatedClass javaClass, int encoding) implements BPFType<I> {
        static final int ENCODING_SIGNED = 1;
        /**
         * used for pretty printing
         */
        static final int ENCODING_CHAR = 2;
        /**
         * used for pretty printing
         */
        static final int ENCODING_BOOL = 4;

        public boolean isSigned() {
            return (encoding & ENCODING_SIGNED) != 0;
        }

        public boolean isChar() {
            return (encoding & ENCODING_CHAR) != 0;
        }

        public boolean isBool() {
            return (encoding & ENCODING_BOOL) != 0;
        }

        @Override
        public long alignment() {
            return size();
        }

        @Override
        public String toJavaUse() {
            return switch (javaClass.klass) {
                case "java.lang.Integer" -> "int";
                case "java.lang.Long" -> "long";
                case "java.lang.Short" -> "short";
                case "java.lang.Byte" -> "byte";
                case "java.lang.Boolean" -> "boolean";
                default -> javaClass().klass;
            };
        }

        @Override
        public String toJavaUseInGenerics() {
            return javaClass.klass;
        }

        @Override
        public String toJavaFieldSpecUse(Function<BPFType<?>, String> typeToSpecFieldName) {
            return getClass().getSimpleName() + "." + Objects.requireNonNull(typeToSpecName.get(this));
        }

        private static final Map<AnnotatedClass, BPFType<?>> registeredTypes = new HashMap<>();
        private static final Map<BPFType<?>, String> typeToSpecName = new IdentityHashMap<>();

        /**
         * Create a new BPFIntType and register it
         */
        private static <T, V extends ValueLayout> BPFIntType<T> createType(String bpfName, String specFieldName,
                                                                           Class<T> klass,
                                                                           V layout,
                                                                           MemoryParser<T> parser,
                                                                           MemorySetter<T> setter, boolean signed) {
            var type = new BPFIntType<>(bpfName, layout, parser, setter, new AnnotatedClass(klass, signed ?
                    List.of(AnnotationInstances.UNSIGNED) : List.of()), signed ? ENCODING_SIGNED : 0);
            if (registeredTypes.containsKey(type.javaClass())) {
                throw new IllegalArgumentException("Type " + type.javaClass() + " already registered as " + registeredTypes.get(type.javaClass()).bpfName());
            }
            registeredTypes.put(type.javaClass(), type);
            typeToSpecName.put(type, specFieldName);
            return type;
        }

        /**
         * <code>bool/u8</code> mapped to {@code boolean}
         */
        public static final BPFIntType<Boolean> BOOL = createType("bool", "BOOL", Boolean.class, ValueLayout.JAVA_BYTE,
                segment -> {
            return segment.get(ValueLayout.JAVA_BYTE, 0) == 1;
        }, (segment, obj) -> {
            segment.set(ValueLayout.JAVA_BYTE, 0, obj ? (byte) 1 : 0);
        }, false);

        /**
         * <code>char</code> mapped to {@code byte} (essentially an unsigned byte)
         */
        public static final BPFIntType<Byte> CHAR = createType("char", "CHAR", Byte.class, ValueLayout.JAVA_BYTE,
                segment -> {
            return segment.get(ValueLayout.JAVA_BYTE, 0);
        }, (segment, obj) -> {
            segment.set(ValueLayout.JAVA_BYTE, 0, obj);
        }, false);

        public static final BPFTypedef<Byte> UINT8 = new BPFTypedef<>("u8", CHAR);

        /**
         * <code>i8</code> mapped to {@code byte}
         */
        public static final BPFIntType<Byte> INT8 = createType("s8", "INT8", Byte.class, ValueLayout.JAVA_BYTE,
                segment -> {
            return segment.get(ValueLayout.JAVA_BYTE, 0);
        }, (segment, obj) -> {
            segment.set(ValueLayout.JAVA_BYTE, 0, obj);
        }, true);

        /**
         * <code>s16</code> mapped to {@code short}
         */
        public static final BPFIntType<Short> INT16 = createType("s16", "INT16", Short.class, ValueLayout.JAVA_SHORT,
                segment -> {
            return segment.get(ValueLayout.JAVA_SHORT, 0);
        }, (segment, obj) -> {
            segment.set(ValueLayout.JAVA_SHORT, 0, obj);
        }, true);

        /**
         * <code>u16</code> mapped to {@code @Unsigned short}
         */
        public static final BPFIntType<Short> UINT16 = createType("u16", "UINT16", Short.class, ValueLayout.JAVA_SHORT,
                segment -> {
            return segment.get(ValueLayout.JAVA_SHORT, 0);
        }, (segment, obj) -> {
            segment.set(ValueLayout.JAVA_SHORT, 0, obj);
        }, false);

        /**
         * <code>s32</code> mapped to {@code int}
         */
        public static final BPFIntType<Integer> INT32 = createType("s32",  "INT32", Integer.class, ValueLayout.JAVA_INT,
                segment -> {
            return segment.get(ValueLayout.JAVA_INT, 0);
        }, (segment, obj) -> {
            segment.set(ValueLayout.JAVA_INT, 0, obj);
        }, true);

        /**
         * <code>u32</code> mapped to {@code @Unsigned int}
         */
        public static final BPFIntType<Integer> UINT32 = createType("u32", "UINT32", Integer.class,
                ValueLayout.JAVA_INT,
                segment -> {
            return segment.get(ValueLayout.JAVA_INT, 0);
        }, (segment, obj) -> {
            segment.set(ValueLayout.JAVA_INT, 0, obj);
        }, false);


        /**
         * <code>s64</code> mapped to {@code long}
         */
        public static final BPFIntType<Long> INT64 = createType("s64", "INT64", Long.class, ValueLayout.JAVA_LONG,
                segment -> {
            return segment.get(ValueLayout.JAVA_LONG, 0);
        }, (segment, obj) -> {
            segment.set(ValueLayout.JAVA_LONG, 0, obj);
        }, true);

        /**
         * <code>u64</code> mapped to {@code @Unsigned long}
         */
        public static final BPFIntType<Long> UINT64 = createType("u64", "UINT64", Long.class, ValueLayout.JAVA_LONG,
                segment -> {
            return segment.get(ValueLayout.JAVA_LONG, 0);
        }, (segment, obj) -> {
            segment.set(ValueLayout.JAVA_LONG, 0, obj);
        }, false);


        /**
         * <code>void*</code>
         */
        public static final BPFType<Long> POINTER = new BPFTypedef<>("void*", BPFIntType.UINT64);
    }

    /**
     * Struct member with manually set offset
     *
     * @param name   name of the member
     * @param type   type of the member
     * @param offset offset from the start of the struct in bytes
     * @param getter function that takes the struct and returns the member
     */
    record BPFStructMember<P, T>(String name, BPFType<T> type, int offset, Function<P, T> getter,
                                 @Nullable String ebpfSize) {

        public BPFStructMember(String name, BPFType<T> type, int offset, Function<P, T> getter) {
            this(name, type, offset, getter, null);
        }

        CAST.Declarator.StructMember toCStructMember() {
            return CAST.Declarator.structMember(type.toCUse(), CAST.Expression.variable(name),
                    ebpfSize == null ? null : CAST.Expression.verbatim(ebpfSize));
        }
    }

    /**
     * Unpositioned struct member
     *
     * @param name   name of the member
     * @param type   type of the member
     * @param getter function that takes the struct and returns the member
     */
    record UBPFStructMember<P, T>(String name, BPFType<T> type, Function<P, T> getter, @Nullable String ebpfSize) {

        public UBPFStructMember(String name, BPFType<T> type, Function<P, T> getter) {
            this(name, type, getter, null);
        }
        public BPFStructMember<P, T> position(int offset) {
            return new BPFStructMember<>(name, type, offset, getter, ebpfSize);
        }
    }

    /**
     * Struct
     */
    final class BPFStructType<T> implements BPFType<T> {
        private final String bpfName;
        private final MemoryLayout layout;

        private final long alignment;
        private final List<BPFStructMember<T, ?>> members;
        private final AnnotatedClass javaClass;
        private final Function<List<Object>, T> constructor;

        /**
         * Create a new struct type with manually set layout,
         * consider using {@link #autoLayout(String, List, AnnotatedClass, Function)}
         * for creating the layout automatically
         *
         * @param bpfName     name of the struct in BPF
         * @param members     members of the struct, order should be the same as in the constructor
         * @param javaClass   class that represents the struct
         * @param constructor constructor that takes the members in the same order as in the constructor
         */
        public BPFStructType(String bpfName, List<BPFStructMember<T, ?>> members, AnnotatedClass javaClass,
                             Function<List<Object>, T> constructor) {
            this.bpfName = bpfName;
            this.layout = createLayout(members);
            this.alignment = members.stream().mapToLong(m -> m.type.alignment()).max().orElse(1);
            this.members = members;
            this.javaClass = javaClass;
            this.constructor = constructor;
        }

        public static <T> BPFStructType<T> autoLayout(String bpfName, List<UBPFStructMember<T, ?>> members,
                                                      AnnotatedClass javaClass, Function<List<Object>, T> constructor) {
            return new BPFStructType<>(bpfName, layoutMembers(members), javaClass, constructor);
        }

        /**
         * Creates the memory layout, inserting padding where neccessary
         */
        private MemoryLayout createLayout(List<BPFStructMember<T, ?>> members) {
            List<MemoryLayout> layouts = new ArrayList<>();
            for (int i = 0; i < members.size(); i++) {
                var member = members.get(i);
                if (i != 0) {
                    var prev = members.get(i - 1);
                    var padding = member.offset - (prev.offset + prev.type.size());
                    if (padding > 0) {
                        layouts.add(MemoryLayout.paddingLayout(padding));
                    }
                }
                layouts.add(member.type.layout().withName(member.name()));
            }
            return MemoryLayout.structLayout(layouts.toArray(new MemoryLayout[0]));
        }

        private static <T> List<BPFStructMember<T, ?>> layoutMembers(List<UBPFStructMember<T, ?>> members) {
            List<BPFStructMember<T, ?>> result = new ArrayList<>();
            long offset = 0;
            for (var member : members) {
                offset = padSize(offset, member.type.alignment());
                result.add(member.position((int) offset));
                offset += member.type.size();
            }
            return result;
        }

        /**
         * Layout that represents the struct, including padding, first level members are properly named
         */
        @Override
        public MemoryLayout layout() {
            return layout;
        }

        public long alignment() {
            return alignment;
        }

        /**
         * Returns the offset of the passed member
         */
        public int getOffsetOfMember(String memberName) {
            return getMember(memberName).offset();
        }

        public BPFStructMember<T, ?> getMember(String memberName) {
            return members.stream().filter(m -> m.name().equals(memberName)).findFirst().orElseThrow();
        }

        @Override
        public long size() {
            return layout.byteSize();
        }

        @Override
        public MemoryParser<T> parser() {
            return segment -> {
                List<Object> args =
                        members.stream().map(member -> (Object) member.type.parseMemory(segment.asSlice(member.offset))).toList();
                return constructor.apply(args);
            };
        }

        @SuppressWarnings("unchecked")
        @Override
        public MemorySetter<T> setter() {
            return (segment, obj) -> {
                for (BPFStructMember<T, ?> member : members) {
                    ((BPFType<Object>) member.type).setMemory(segment.asSlice(member.offset), member.getter.apply(obj));
                }
            };
        }

        @Override
        public String bpfName() {
            return bpfName;
        }

        public List<BPFStructMember<T, ?>> members() {
            return members;
        }

        @Override
        public AnnotatedClass javaClass() {
            return javaClass;
        }

        public Function<List<Object>, T> constructor() {
            return constructor;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == this) return true;
            if (obj == null || obj.getClass() != this.getClass()) return false;
            var that = (BPFStructType<?>) obj;
            return Objects.equals(this.bpfName, that.bpfName) && Objects.equals(this.members, that.members) && Objects.equals(this.javaClass, that.javaClass) && Objects.equals(this.constructor, that.constructor);
        }

        @Override
        public int hashCode() {
            return Objects.hash(bpfName, members, javaClass, constructor);
        }

        @Override
        public String toString() {
            return "BPFStructType[" + "bpfName=" + bpfName + ", " + "members=" + members + ", " + "javaClass=" + javaClass + ", " + "constructor=" + constructor + ']';
        }

        @Override
        public Optional<CAST.Declarator> toCDeclaration() {
            return Optional.of(CAST.Declarator.struct(CAST.Expression.variable(bpfName),
                    members.stream().map(BPFStructMember::toCStructMember).toList()));
        }

        @Override
        public Optional<CAST.Statement> toCDeclarationStatement() {
            return toCDeclaration().map(d -> CAST.Statement.declarationStatement(d, null));
        }

        @Override
        public CAST.Declarator toCUse() {
            return CAST.Declarator.structIdentifier(CAST.Expression.variable(bpfName));
        }

        @Override
        public Optional<BiFunction<String, Function<BPFType<?>, String>, FieldSpec>> toFieldSpecGenerator() {
            return Optional.of((fieldName, typeToSpecName)-> {
                String className = this.javaClass.klass;
                ClassName bpfStructType = ClassName.get(BPF_PACKAGE, "BPFType.BPFStructType");
                TypeName fieldType = ParameterizedTypeName.get(bpfStructType, ClassName.get("", className));
                String memberExpression =
                        members.stream().map(m -> "new " + BPF_TYPE + ".UBPFStructMember<>(" + "\"" + m.name() + "\"," +
                                " " + typeToSpecName.apply(m.type()) + ", " + className + "::" + m.name() +
                                ")").collect(Collectors.joining(", "));
                ClassName bpfType = ClassName.get(BPF_PACKAGE, "BPFType");
                String creatorExpr = IntStream.range(0, members.size()).mapToObj(i -> "(" + members.get(i).type.toJavaUse() + ")" + "fields.get(" + i + ")").collect(Collectors.joining(", "));
                return FieldSpec.builder(fieldType, fieldName).addModifiers(Modifier.FINAL, Modifier.STATIC, Modifier.PUBLIC)
                        .initializer("$T.autoLayout($S, java.util.List.of($L), new $T.AnnotatedClass($T" + ".class, " +
                                "java.util.List" + ".of()" + "), " + "fields -> new $T($L))", bpfStructType, bpfName,
                                memberExpression, bpfType, ClassName.get("", className), ClassName.get("", className), creatorExpr).build();
            });
        }

        @Override
        public String toJavaUse() {
            return javaClass.klass;
        }

        @Override
        public String toJavaFieldSpecUse(Function<BPFType<?>, String> typeToSpecFieldName) {
            return typeToSpecFieldName.apply(this);
        }
    }

    /**
     * Array mapped to {@code List}
     */
    record BPFArrayType<E>(String bpfName, BPFType<E> memberType, int length) implements BPFType<List<E>> {

        @Override
        public MemoryLayout layout() {
            return MemoryLayout.sequenceLayout(length, paddedMemberLayout());
        }

        public MemoryLayout paddedMemberLayout() {
            var padding = memberType.sizePadded() - memberType.size();
            if (padding == 0) {
                return memberType.layout();
            } else {
                return MemoryLayout.structLayout(memberType.layout(), MemoryLayout.paddingLayout(padding));
            }
        }

        @Override
        public MemoryParser<List<E>> parser() {
            return segment -> IntStream.range(0, length).mapToObj(i -> memberType.parseMemory(segment.asSlice(i * memberType.size()))).toList();
        }

        @Override
        public MemorySetter<List<E>> setter() {
            return (segment, list) -> {
                if (list.size() != length) {
                    throw new IllegalArgumentException("Array must have length " + length);
                }
                for (int i = 0; i < length; i++) {
                    memberType.setMemory(segment.asSlice(i * memberType.size()), list.get(i));
                }
            };
        }

        @Override
        public long alignment() {
            return memberType.alignment();
        }

        @Override
        public AnnotatedClass javaClass() {
            return new AnnotatedClass(List.class, List.of(AnnotationInstances.size(length)));
        }

        public long getOffsetAtIndex(int index) {
            return index * memberType.sizePadded();
        }

        public static <E> BPFArrayType<E> of(BPFType<E> memberType, int length) {
            return new BPFArrayType<>(memberType.bpfName() + "[" + length + "]", memberType, length);
        }

        @Override
        public Optional<CAST.Declarator> toCDeclaration() {
            return Optional.empty();
        }

        @Override
        public CAST.Declarator toCUse() {
            return CAST.Declarator.array(memberType.toCUse(), CAST.Expression.constant(length));
        }

        @Override
        public String toJavaUse() {
            return "java.util.List<" + memberType.toJavaUseInGenerics() + ">";
        }

        @Override
        public String toJavaFieldSpecUse(Function<BPFType<?>, String> typeToSpecFieldName) {
            return "new " + BPF_TYPE + ".BPFArrayType<>(\""+ bpfName + "\", " + typeToSpecFieldName.apply(memberType) + ", " + length + ")";
        }
    }

    /**
     * String with max size mapped to {@code char[]}
     * <p>
     * Important: the string is null-terminated, therefore the max length of the string is length-1 ASCII character.
     * The string is truncated if it is longer than length-1.
     */
    record StringType(int length) implements BPFType<String> {

        @Override
        public String bpfName() {
            return "char[" + length + "]";
        }

        @Override
        public MemoryLayout layout() {
            return MemoryLayout.sequenceLayout(length, ValueLayout.JAVA_BYTE);
        }

        @Override
        public MemoryParser<String> parser() {
            return segment -> segment.getUtf8String(0);
        }

        @Override
        public MemorySetter<String> setter() {
            return (segment, obj) -> {
                byte[] bytes = obj.getBytes();
                if (bytes.length + 1 < length) {
                    segment.setUtf8String(0, obj);
                } else {
                    byte[] dest = new byte[length];
                    System.arraycopy(bytes, 0, dest, 0, length - 1);
                    dest[length - 1] = 0;
                    for (int i = 0; i < length; i++) {
                        segment.set(ValueLayout.JAVA_BYTE, i, dest[i]);
                    }
                }
            };
        }

        @Override
        public long alignment() {
            return CHAR.alignment();
        }

        @Override
        public AnnotatedClass javaClass() {
            return new AnnotatedClass(String.class, List.of(AnnotationInstances.size(length)));
        }

        @Override
        public Optional<CAST.Declarator> toCDeclaration() {
            return Optional.empty();
        }

        @Override
        public CAST.Declarator toCUse() {
            return CAST.Declarator.array(CHAR.toCUse(), CAST.Expression.constant(length));
        }

        @Override
        public String toJavaFieldSpecUse(Function<BPFType<?>, String> typeToSpecFieldName) {
            return "new " + BPF_TYPE + ".StringType(" + length + ")";
        }
    }

    /**
     * Type alias
     */
    record BPFTypedef<T>(String bpfName, BPFType<T> wrapped) implements BPFType<T> {

        @Override
        public MemoryLayout layout() {
            return wrapped.layout();
        }

        @Override
        public MemoryParser<T> parser() {
            return wrapped.parser();
        }

        @Override
        public MemorySetter<T> setter() {
            return wrapped.setter();
        }

        @Override
        public long alignment() {
            return wrapped.alignment();
        }

        @Override
        public AnnotatedClass javaClass() {
            return wrapped.javaClass();
        }

        @Override
        public Optional<CAST> toCDeclaration() {
            return Optional.of(CAST.Statement.typedef(wrapped.toCUse(), variable(bpfName)));
        }

        @Override
        public Optional<CAST.Statement> toCDeclarationStatement() {
            return Optional.of(CAST.Statement.typedef(wrapped.toCUse(), variable(bpfName)));
        }

        @Override
        public String toJavaFieldSpecUse(Function<BPFType<?>, String> typeToSpecFieldName) {
            return "new " + BPF_TYPE + ".BPFTypedef<>(" + "\"" + bpfName + "\", " + typeToSpecFieldName.apply(wrapped) + ")";
        }
    }


    record BPFUnionTypeMember(String name, BPFType<?> type) {
    }

    /**
     * Union
     *
     * @param bpfName
     * @param shared  type that is shared between all members
     * @param members members of the union, including the shared type members
     */
    record BPFUnionType<S>(String bpfName, @Nullable BPFType<S> shared,
                           List<BPFUnionTypeMember> members) implements BPFType<BPFUnion<S>> {

        @Override
        public MemoryLayout layout() {
            return MemoryLayout.sequenceLayout(size(), ValueLayout.JAVA_BYTE);
        }

        @Override
        public long size() {
            return members.stream().mapToLong(member -> member.type.size()).max().orElseThrow();
        }

        @Override
        public long alignment() {
            return members.stream().mapToLong(member -> member.type.alignment()).max().orElse(1);
        }

        @Override
        public MemoryParser<BPFUnion<S>> parser() {
            return segment -> {
                Map<String, Object> possibleMembers = new HashMap<>();
                for (var member : members) {
                    // try to parse all members, but only keep the ones that work
                    try {
                        possibleMembers.put(member.name(), member.type.parseMemory(segment));
                    } catch (IllegalArgumentException e) {
                    }
                }
                return new BPFUnionFromMemory<>(shared != null ? shared.parseMemory(segment) : null, possibleMembers);
            };
        }

        /**
         * Return the memory setter, only works if the passed union has a set current member
         */
        @Override
        public MemorySetter<BPFUnion<S>> setter() {
            return (segment, union) -> {
                if (union.current() == null) {
                    throw new IllegalArgumentException("Union must have a current member");
                }
                BPFUnionTypeMember current =
                        members().stream().filter(m -> m.name.equals(union.current())).findFirst().orElseThrow();
                current.type.setMemory(segment, union.get(union.current()));
            };
        }

        @Override
        public AnnotatedClass javaClass() {
            return new AnnotatedClass(BPFUnion.class, List.of());
        }

        @Override
        public String toJavaFieldSpecUse(Function<BPFType<?>, String> typeToSpecFieldName) {
            throw new UnsupportedOperationException();
        }
    }

    interface BPFUnion<S> {
        @Nullable S shared();

        <T> T get(String name);

        <T> void set(String name, T value);

        @Nullable String current();

        void setCurrent(String name);
    }

    final class BPFUnionFromMemory<S> implements BPFUnion<S> {
        private final @Nullable S shared;
        private final Map<String, Object> possibleMembers;

        @Nullable String current = null;

        public BPFUnionFromMemory(@Nullable S shared, Map<String, Object> possibleMembers) {
            this.shared = shared;
            this.possibleMembers = possibleMembers;
        }

        @SuppressWarnings("unchecked")
        @Override
        public <T> T get(String name) {
            return Objects.requireNonNull((T) possibleMembers.get(name));
        }

        @Override
        public <T> void set(String name, T value) {
            possibleMembers.put(name, value);
            setCurrent(name);
        }

        @Override
        public @Nullable S shared() {
            return shared;
        }

        @Override
        public @Nullable String current() {
            return current;
        }

        @Override
        public void setCurrent(String current) {
            if (!possibleMembers.containsKey(current)) {
                throw new IllegalArgumentException("Union does not have member " + current);
            }
            this.current = current;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == this) return true;
            if (obj == null || obj.getClass() != this.getClass()) return false;
            var that = (BPFUnionFromMemory<?>) obj;
            return Objects.equals(this.shared, that.shared) && Objects.equals(this.possibleMembers,
                    that.possibleMembers);
        }
    }
}