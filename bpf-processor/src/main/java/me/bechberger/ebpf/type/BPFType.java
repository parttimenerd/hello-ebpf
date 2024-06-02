package me.bechberger.ebpf.type;

import com.squareup.javapoet.ClassName;
import com.squareup.javapoet.FieldSpec;
import com.squareup.javapoet.ParameterizedTypeName;
import com.squareup.javapoet.TypeName;
import me.bechberger.cast.CAST;
import me.bechberger.cast.CAST.Declarator;
import me.bechberger.cast.CAST.Statement;
import me.bechberger.ebpf.annotations.AnnotationInstances;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.lang.model.element.Modifier;
import java.lang.annotation.Annotation;
import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.math.BigInteger;
import java.util.*;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static me.bechberger.cast.CAST.Declarator.identifier;
import static me.bechberger.cast.CAST.Expression.variable;
import static me.bechberger.ebpf.type.BPFType.BPFIntType.CHAR;
import static me.bechberger.ebpf.type.BPFType.BPFIntType.UINT32;
import static me.bechberger.ebpf.type.BoxHelper.box;
import static me.bechberger.ebpf.type.BoxHelper.unbox;


/**
 * A BPF type, see <a href="https://www.kernel.org/doc/html/latest/bpf/btf.html">Linux BTF documentation</a> for
 * more information
 */
public sealed interface BPFType<T> {

    String BPF_PACKAGE = "me.bechberger.ebpf.type";
    String BPF_TYPE = BPF_PACKAGE + ".BPFType";

    /** Used in the type processor */
    record CustomBPFType<T>(String javaName, String javaUse, String javaUseInGenerics, String bpfName, Supplier<Declarator> cUse, Function<Function<BPFType<?>, String>, String> specFieldNameCreator, Supplier<Optional<? extends Statement>> cDeclaration) implements BPFType<T> {

        @Override
        public MemoryLayout layout() {
            return MemoryLayout.structLayout();
        }

        @Override
        public MemoryParser<T> parser() {
            return null;
        }

        @Override
        public MemorySetter<T> setter() {
            return null;
        }

        @Override
        public long alignment() {
            return 0;
        }

        @Override
        public AnnotatedClass javaClass() {
            return null;
        }

        @Override
        public String toJavaFieldSpecUse(Function<BPFType<?>, String> typeToSpecFieldName) {
           return specFieldNameCreator.apply(typeToSpecFieldName);
        }

        @Override
        public Optional<? extends Statement> toCDeclaration() {
            return cDeclaration.get();
        }

        @Override
        public String toJavaUse() {
            return javaUse;
        }

        @Override
        public String toJavaUseInGenerics() {
            return javaUseInGenerics;
        }

        @Override
        public Declarator toCUse() {
            return cUse.get();
        }
    }

    /**
     * Java class with annotations
     */
    record AnnotatedClass(String klass, List<Annotation> annotations) {

        public AnnotatedClass(Class<?> klass, List<Annotation> annotations) {
            this(klass.getName(), annotations);
        }

        @Override
        public String toString() {
            if (annotations.isEmpty()) {
                return klass;
            }
            return annotations.stream().map(Annotation::toString).collect(Collectors.joining(" ")) + " " + klass;
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

    record WrappedBPFType<T>(BPFType<T> type, long alignment) implements BPFType<T> {

            public WrappedBPFType(BPFType<T> type) {
                this(type, (int) type.alignment());
            }

            public WrappedBPFType<T> alignTo(int bytes) {
                return new WrappedBPFType<>(type, bytes);
            }

            public MemoryLayout layout() {
                return type.layout().withByteAlignment(alignment);
            }

            public MemoryParser<T> parser() {
                return type.parser();
            }

            public MemorySetter<T> setter() {
                return type.setter();
            }

            public long size() {
                return padSize(type.size(), alignment);
            }

            public String bpfName() {
                return type.bpfName();
            }

            public AnnotatedClass javaClass() {
                return type.javaClass();
            }

            public String toJavaUse() {
                return type.toJavaUse();
            }

            public String toJavaUseInGenerics() {
                return type.toJavaUseInGenerics();
            }

            public String toJavaFieldSpecUse(Function<BPFType<?>, String> typeToSpecFieldName) {
                return type.toJavaFieldSpecUse(typeToSpecFieldName);
            }

            public Optional<? extends CAST> toCDeclaration() {
                return type.toCDeclaration();
            }

            public Optional<? extends CAST.Statement> toCDeclarationStatement() {
                return type.toCDeclarationStatement();
            }

            public CAST.Declarator toCUse() {
                return type.toCUse();
            }

            public Optional<BiFunction<String, Function<BPFType<?>, String>, FieldSpec>> toFieldSpecGenerator() {
                return type.toFieldSpecGenerator();
            }
    }

    default WrappedBPFType<T> alignTo(int bytes) {
        return new WrappedBPFType<>(this).alignTo(bytes);
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
                case "java.lang.Character" -> "char";
                case "java.lang.Float" -> "float";
                case "java.lang.Double" -> "double";
                default -> javaClass().klass;
            };
        }

        @Override
        public String toJavaUseInGenerics() {
            return switch (javaClass.klass) {
                case "int" -> "Integer";
                case "long" -> "Long";
                case "short" -> "Short";
                case "byte" -> "Byte";
                case "boolean" -> "Boolean";
                case "char" -> "Character";
                case "float" -> "Float";
                case "double" -> "Double";
                default -> javaClass().klass;
            };
        }

        @Override
        public String toJavaFieldSpecUse(Function<BPFType<?>, String> typeToSpecFieldName) {
            return getClass().getCanonicalName() + "." + Objects.requireNonNull(typeToSpecName.get(this));
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

        public static final BPFInternalTypedef<Byte> UINT8 = new BPFInternalTypedef<>("u8", CHAR);

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
        public static final BPFInternalTypedef<Long> POINTER = new BPFInternalTypedef<>("void*", BPFIntType.UINT64);
    }

    /** A potentially signed integer with a fixed width */
    class FixedWidthInteger extends Number implements Comparable<FixedWidthInteger> {

        private final int width;
        private final boolean signed;
        private final byte[] content;

        public FixedWidthInteger(int width, boolean signed, byte[] content) {
            this.width = width;
            this.content = content;
            this.signed = signed;
        }

        public FixedWidthInteger(int width, boolean signed, String val, int radix) {
            this(width, signed, new BigInteger(val, radix).toByteArray());
        }

        public static FixedWidthInteger fromBigInteger(int width, boolean signed, BigInteger val) {
            return new FixedWidthInteger(width, signed, val.toByteArray());
        }

        public static FixedWidthInteger valueOf(int width, boolean signed, long val) {
            return fromBigInteger(width, signed, BigInteger.valueOf(val));
        }

        public boolean isSigned() {
            return signed;
        }

        public int getWidth() {
            return width;
        }

        public byte[] getContent() {
            return content;
        }

        /** Convert to a {@code BigInteger}, keeping signedness */
        public BigInteger toBigInteger() {
            if (signed) {
                return new BigInteger(content);
            } else {
                return new BigInteger(1, content);
            }
        }

        @Override
        public int compareTo(@NotNull FixedWidthInteger other) {
            return toBigInteger().compareTo(other.toBigInteger());
        }

        @Override
        public int intValue() {
            return toBigInteger().intValue();
        }

        @Override
        public long longValue() {
            return toBigInteger().longValue();
        }

        @Override
        public float floatValue() {
            return toBigInteger().floatValue();
        }

        @Override
        public double doubleValue() {
            return toBigInteger().doubleValue();
        }

        @Override
        public boolean equals(Object obj) {
            return obj instanceof FixedWidthInteger integer && integer.compareTo(this) == 0;
        }
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

        /**
         * Kind of the source class, only important for the generation of Java code
         */
        public enum SourceClassKind {
            /**
             * Class defined via {@code record}
             */
            RECORD,
            /**
             * Class with a default constructor and no field matching constructor
             */
            CLASS,
            /**
             * Class with a field matching constructor
             */
            CLASS_WITH_CONSTRUCTOR
        }

        private final String bpfName;
        private final MemoryLayout layout;

        private final long alignment;
        private final List<BPFStructMember<T, ?>> members;
        private final AnnotatedClass javaClass;
        private final Function<List<Object>, T> constructor;
        private final SourceClassKind sourceClassKind;

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
            this(bpfName, members, javaClass, constructor, SourceClassKind.RECORD);
        }

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
                             Function<List<Object>, T> constructor, SourceClassKind sourceClassKind) {
            this.bpfName = bpfName;
            this.layout = createLayout(members);
            this.alignment = members.stream().mapToLong(m -> m.type.alignment()).max().orElse(1);
            this.members = members;
            this.javaClass = javaClass;
            this.constructor = constructor;
            this.sourceClassKind = sourceClassKind;
        }

        public static <T> BPFStructType<T> autoLayout(String bpfName, List<UBPFStructMember<T, ?>> members,
                                                      AnnotatedClass javaClass, Function<List<Object>, T> constructor) {
            return autoLayout(bpfName, members, javaClass, constructor, SourceClassKind.RECORD);
        }

        public static <T> BPFStructType<T> autoLayout(String bpfName, List<UBPFStructMember<T, ?>> members,
                                                      AnnotatedClass javaClass, Function<List<Object>, T> constructor,
                                                      SourceClassKind sourceClassKind) {
            return new BPFStructType<>(bpfName, layoutMembers(members), javaClass, constructor, sourceClassKind);
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
                    var arr = box(member.getter.apply(obj));
                    ((BPFType<Object>) member.type).setMemory(segment.asSlice(member.offset), arr);
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
            return Optional.of((fieldName, typeToSpecName) -> {
                String className = this.javaClass.klass;
                ClassName bpfStructType = ClassName.get(BPF_PACKAGE, "BPFType.BPFStructType");
                TypeName fieldType = ParameterizedTypeName.get(bpfStructType, ClassName.get("", className));
                Function<BPFStructMember<?, ?>, String> accessor = m -> switch (sourceClassKind) {
                    case RECORD -> className + "::" + m.name();
                    case CLASS, CLASS_WITH_CONSTRUCTOR -> "o -> (" + m.type().toJavaUseInGenerics() + ")(Object)o." + m.name;
                };
                String memberExpression =
                        members.stream().map(m -> "new " + BPF_TYPE + ".UBPFStructMember<" + className + ", " + m.type().toJavaUseInGenerics() + ">(" + "\"" + m.name() + "\"," +
                                " " + typeToSpecName.apply(m.type()) + ", " + accessor.apply(m) +
                                ")").collect(Collectors.joining(", "));

                ClassName bpfType = ClassName.get(BPF_PACKAGE, "BPFType");
                String constructorExpr = switch (sourceClassKind) {
                    case RECORD, CLASS_WITH_CONSTRUCTOR -> {
                        String creatorExpr =
                                IntStream.range(0, members.size()).mapToObj(i -> "(" + members.get(i).type.toJavaUse() + ")" +
                                        "me.bechberger.ebpf.type.BoxHelper.unbox(fields.get(" + i + "), " +
                                        members.get(i).type.toJavaUse() + ".class)").collect(Collectors.joining(", "));
                        yield "new " + className + "(" + creatorExpr + ")";
                    }
                    case CLASS ->
                            "{ var o = new " + className + "(); " + members.stream().map(m -> "o." + m.name() + " = " +
                                    "me.bechberger.ebpf.type.BoxHelper.unbox(fields.get(" + members.indexOf(m) + "), " +
                                    m.type().toJavaUse() + ".class)").collect(Collectors.joining("; ")) + "; return o; }";
                };

                return FieldSpec.builder(fieldType, fieldName).addModifiers(Modifier.FINAL, Modifier.STATIC)
                        .initializer("$T.autoLayout($S, java.util.List.of($L), new $T.AnnotatedClass($T" + ".class, " +
                                        "java.util.List" + ".of()" + "), " + "fields -> $L)", bpfStructType, bpfName,
                                memberExpression, bpfType, ClassName.get("", className), constructorExpr).build();
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
     * Array type
     */
    record BPFArrayType<E>(String bpfName, BPFType<E> memberType, int length) implements BPFType<E[]> {

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

        @SuppressWarnings("unchecked")
        @Override
        public MemoryParser<E[]> parser() {
            return segment -> (E[])IntStream.range(0, length).mapToObj(i ->
                    memberType.parseMemory(segment.asSlice(i * memberType.size()))).toArray();
        }

        @Override
        public MemorySetter<E[]> setter() {
            return (segment, list) -> {
                if (list.length > length) {
                    throw new IllegalArgumentException("Array must have length <= " + length);
                }
                for (int i = 0; i < list.length; i++) {
                    memberType.setMemory(segment.asSlice(i * memberType.sizePadded()), list[i]);
                }
            };
        }

        @Override
        public long alignment() {
            return memberType.alignment();
        }

        @Override
        public AnnotatedClass javaClass() {
            return new AnnotatedClass(memberType.toJavaUse() + "[]", List.of(AnnotationInstances.size(length)));
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
            return memberType.toJavaUse() + "[]";
        }

        @Override
        public String toJavaFieldSpecUse(Function<BPFType<?>, String> typeToSpecFieldName) {
            return "(BPFType)new " + BPF_TYPE + ".BPFArrayType<>(\""+ bpfName + "\", " + memberType.toJavaFieldSpecUse(typeToSpecFieldName) + ", " + length + ")";
        }
    }

    /**
     * Pointer type mapped to {@link Ptr} in Java, and only usable in generated C code for now
     */
    record BPFPointerType<T>(@Nullable BPFType<T> valueType) implements BPFType<Ptr<T>> {

        @Override
        public String bpfName() {
            return (valueType == null ? "void" : valueType.bpfName()) + "*";
        }

        @Override
        public MemoryLayout layout() {
            return ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(0, valueType == null ? JAVA_BYTE : valueType.layout()));
        }

        @SuppressWarnings("unchecked")
        @Override
        public MemoryParser<Ptr<T>> parser() {
            throw new UnsupportedOperationException("Not implemented");
        }

        @Override
        public MemorySetter<Ptr<T>> setter() {
            throw new UnsupportedOperationException("Not implemented");
        }

        @Override
        public long alignment() {
            return layout().byteAlignment();
        }

        @Override
        public AnnotatedClass javaClass() {
            return new AnnotatedClass(Ptr.class, List.of());
        }

        @Override
        public Optional<CAST.Declarator> toCDeclaration() {
            return Optional.empty();
        }

        @Override
        public CAST.Declarator toCUse() {
            return valueType == null ? CAST.Declarator.voidPointer() : CAST.Declarator.pointer(valueType.toCUse());
        }

        @Override
        public String toJavaUse() {
            return Ptr.class.getCanonicalName();
        }

        @Override
        public String toJavaUseInGenerics() {
            return Ptr.class.getCanonicalName() + "<" + (valueType == null ? "?" : valueType.toJavaUseInGenerics()) + ">";
        }

        @Override
        public String toJavaFieldSpecUse(Function<BPFType<?>, String> typeToSpecFieldName) {
            return "new " + BPF_TYPE + ".BPFPointerType<" + (valueType == null ? "" : valueType.toJavaUseInGenerics()) +">(" +
                    (valueType == null ? "null" : valueType.toJavaFieldSpecUse(typeToSpecFieldName)) + ")";
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
            return segment -> segment.getString(0);
        }

        @Override
        public MemorySetter<String> setter() {
            return (segment, obj) -> {
                byte[] bytes = obj.getBytes();
                if (bytes.length + 1 < length) {
                    segment.setString(0, obj);
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
     * Type alias for built-in typedefs
     */
    record BPFInternalTypedef<T>(String bpfName, BPFType<T> wrapped) implements BPFType<T> {

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
            return "new " + BPF_TYPE + ".BPFInternalTypedef<>(" + "\"" + bpfName + "\", " + typeToSpecFieldName.apply(wrapped) + ")";
        }
    }

    /**
     * Type alias
     */
    record BPFTypedef<W, T extends Typedef<W>>(String bpfName, BPFType<W> wrapped, AnnotatedClass javaClass, Function<W, T> constructor, @Nullable Class<?> wrappedClass) implements BPFType<T> {

        public BPFTypedef(String bpfName, BPFType<W> wrapped, AnnotatedClass javaClass, Function<W, T> constructor) {
            this(bpfName, wrapped, javaClass, constructor, null);
        }

        @Override
        public MemoryLayout layout() {
            return wrapped.layout();
        }

        @Override
        public MemoryParser<T> parser() {
            return segment -> constructor.apply(unbox(wrapped.parser().parse(segment), wrappedClass));
        }

        @Override
        public MemorySetter<T> setter() {
            return (segment, obj) -> wrapped.setter().store(segment, box(obj.val()));
        }

        @Override
        public long alignment() {
            return wrapped.alignment();
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
        public long size() {
            return wrapped.size();
        }

        @Override
        public long sizePadded() {
            return wrapped.sizePadded();
        }

        @Override
        public Declarator toCUse() {
            return CAST.Declarator.identifier(bpfName);
        }

        @Override
        public Optional<BiFunction<String, Function<BPFType<?>, String>, FieldSpec>> toFieldSpecGenerator() {
            return Optional.of((fieldName, typeToSpecName) -> {
                String className = this.javaClass.klass;
                ClassName baseType = ClassName.get(BPF_PACKAGE, "BPFType.BPFTypedef");
                TypeName fieldType = ParameterizedTypeName.get(baseType, ClassName.get("", wrapped.toJavaUseInGenerics()), ClassName.get("", className));
                ClassName bpfType = ClassName.get(BPF_PACKAGE, "BPFType");
                String wrappedFieldName = typeToSpecName.apply(wrapped);
                return FieldSpec.builder(fieldType, fieldName).addModifiers(Modifier.FINAL, Modifier.STATIC).initializer("new $T<>($S, $L, new $T.AnnotatedClass($T" + ".class, " + "java.util.List" + ".of()" + "), ($L o) -> new $L(o), $L.class)", baseType, bpfName, wrappedFieldName, bpfType, ClassName.get("", className), wrapped.toJavaUseInGenerics(), className, wrapped.toJavaUse()).build();
            });
        }

        @Override
        public String toJavaUse() {
            return javaClass.klass;
        }

        @Override
        public String toJavaUseInGenerics() {
            return javaClass.klass;
        }

        @Override
        public String toJavaFieldSpecUse(Function<BPFType<?>, String> typeToSpecFieldName) {
            return typeToSpecFieldName.apply(this);
        }
    }

    record BPFUnionMember<P, T>(String name, BPFType<T> type, Function<P, T> getter) {
        CAST.Declarator.UnionMember toCUnionMember() {
            return CAST.Declarator.unionMember(type.toCUse(), CAST.Expression.variable(name));
        }
    }

    /**
     * Union
     *
     * @param bpfName
     * @param members members of the union
     */
    record BPFUnionType<T extends Union>(String bpfName, List<BPFUnionMember<T, ?>> members, AnnotatedClass javaClass,
                                         Function<Map<String, Object>, T> constructor) implements BPFType<T> {

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

        public BPFUnionMember getMember(String memberName) {
            return members.stream().filter(m -> m.name().equals(memberName)).findFirst().orElseThrow();
        }

        @Override
        public MemoryParser<T> parser() {
            return segment -> {
                Map<String, Object> possibleMembers = new HashMap<>();
                for (var member : members) {
                    // try to parse all members, but only keep the ones that work
                    try {
                        possibleMembers.put(member.name(), member.type.parseMemory(segment));
                    } catch (IllegalArgumentException e) {
                    }
                }
                if (possibleMembers.isEmpty()) {
                    throw new IllegalArgumentException("Union must have atleast one member set");
                }
                return constructor.apply(possibleMembers);
            };
        }

        record FieldValueChanged(BPFUnionMember<?, ?> member, Object value, boolean changed) {
        }

        /**
         * Return the memory setter, only works if the passed union has a set current member
         */
        @Override
        @SuppressWarnings("unchecked")
        public MemorySetter<T> setter() {
            return (segment, union) -> {
                // find all members that don't have their original value
                // their original value comes either from the originalValues map (compare via ==)
                // or is the default value of the type (like null for references, 0 for numbers, etc.)
                var membersToSet = members.stream().map(member -> {
                    Object currentValue = box(member.getter.apply(union));
                    if (union.originalValues != null && union.originalValues.containsKey(member.name())) {
                        return new FieldValueChanged(member, currentValue,
                                union.originalValues.get(member.name()) != currentValue);
                    }
                    if (currentValue instanceof Number number) {
                        return new FieldValueChanged(member, currentValue, number.longValue() != 0);
                    }
                    if (currentValue instanceof Boolean bool) {
                        return new FieldValueChanged(member, currentValue, bool);
                    }
                    return new FieldValueChanged(member, currentValue, currentValue != null);
                }).filter(f -> f.changed).toList();
                if (membersToSet.size() > 1) {
                    System.err.println("Union must have exactly one member set of " + union);
                }
                if (membersToSet.isEmpty()) {
                    return;
                }
                var member = membersToSet.getFirst();
                ((BPFType<Object>) member.member.type).setMemory(segment, box(member.value));
            };
        }

        @Override
        public int hashCode() {
            return Objects.hash(bpfName, members, javaClass);
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == this) return true;
            if (obj == null || obj.getClass() != this.getClass()) return false;
            var that = (BPFUnionType<?>) obj;
            return Objects.equals(this.bpfName, that.bpfName) && Objects.equals(this.members, that.members) &&
                    Objects.equals(this.javaClass, that.javaClass);
        }

        @Override
        public Optional<CAST.Declarator> toCDeclaration() {
            return Optional.of(CAST.Declarator.union(CAST.Expression.variable(bpfName),
                    members.stream().map(BPFUnionMember::toCUnionMember).toList()));
        }

        @Override
        public Optional<CAST.Statement> toCDeclarationStatement() {
            return toCDeclaration().map(d -> CAST.Statement.declarationStatement(d, null));
        }

        @Override
        public CAST.Declarator toCUse() {
            return CAST.Declarator.unionIdentifier(CAST.Expression.variable(bpfName));
        }

        @Override
        public Optional<BiFunction<String, Function<BPFType<?>, String>, FieldSpec>> toFieldSpecGenerator() {
            return Optional.of((fieldName, typeToSpecName) -> {
                String className = this.javaClass.klass;
                ClassName baseType = ClassName.get(BPF_PACKAGE, "BPFType.BPFUnionType");
                TypeName fieldType = ParameterizedTypeName.get(baseType, ClassName.get("", className));
                String memberExpression =
                        members.stream().map(m -> "new " + BPF_TYPE + ".BPFUnionMember<" + className + ", " + m.type().toJavaUseInGenerics() + ">(" + "\"" + m.name() + "\"," + " " + typeToSpecName.apply(m.type()) + ", (" + className + " u) -> (" + m.type().toJavaUseInGenerics() + ") (Object)u." + m.name() + ")").collect(Collectors.joining(", "));
                ClassName bpfType = ClassName.get(BPF_PACKAGE, "BPFType");
                return FieldSpec.builder(fieldType, fieldName).addModifiers(Modifier.FINAL, Modifier.STATIC).initializer("new $T<>($S, java.util.List.of($L), new $T.AnnotatedClass($T" + ".class, " + "java.util.List" + ".of()" + "), members -> new $T().init(members))", baseType, bpfName, memberExpression, bpfType, ClassName.get("", className), ClassName.get("", className)).build();
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

    record BPFEnumMember(String name, String cName, int value) {
        CAST.Declarator.EnumMember toCEnumMember() {
            return CAST.Declarator.enumMember(CAST.Expression.variable(cName), value);
        }
    }

    /**
     * Enum
     */
    final class BPFEnumType<T extends Enum<?>> implements BPFType<T> {
        private final String bpfName;
        private final List<BPFEnumMember> members;
        private final AnnotatedClass javaClass;
        private final Function<Integer, T> indexToEnum;
        private final Map<Integer, Integer> memberValueToIndex;

        /**
         * @param members constant members of the enum
         */
        public BPFEnumType(String bpfName, List<BPFEnumMember> members, AnnotatedClass javaClass, Function<Integer,
                T> indexToEnum) {
            this.bpfName = bpfName;
            this.members = members;
            this.javaClass = javaClass;
            this.indexToEnum = indexToEnum;
            this.memberValueToIndex =
                    IntStream.range(0, members.size()).boxed().collect(Collectors.toMap(i -> members.get(i).value(),
                            i -> i));
        }


        @Override
        public MemoryLayout layout() {
            return UINT32.layout();
        }

        @Override
        public long size() {
            return UINT32.size();
        }

        @Override
        public long alignment() {
            return UINT32.alignment();
        }

        public BPFEnumMember getMember(String memberName) {
            return members.stream().filter(m -> m.name().equals(memberName)).findFirst().orElseThrow();
        }

        @Override
        public MemoryParser<T> parser() {
            return segment -> {
                int value = UINT32.parseMemory(segment);
                var index = memberValueToIndex.get(value);
                if (index == null) {
                    throw new RuntimeException("Unknown enum value " + value);
                }
                return indexToEnum.apply(index);
            };
        }

        @Override
        public MemorySetter<T> setter() {
            return (segment, member) -> {
                UINT32.setMemory(segment, members.get(((java.lang.Enum<?>) member).ordinal()).value());
            };
        }

        @Override
        public int hashCode() {
            return Objects.hash(bpfName, members, javaClass);
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == this) return true;
            if (obj == null || obj.getClass() != this.getClass()) return false;
            var that = (BPFEnumType<?>) obj;
            return Objects.equals(this.bpfName, that.bpfName) && Objects.equals(this.members, that.members) &&
                    Objects.equals(this.javaClass, that.javaClass);
        }

        @Override
        public Optional<Declarator> toCDeclaration() {
            return Optional.of(Declarator._enum(variable(bpfName),
                    members.stream().map(BPFEnumMember::toCEnumMember).toList()));
        }

        @Override
        public Optional<Statement> toCDeclarationStatement() {
            return toCDeclaration().map(d -> Statement.declarationStatement(d, null));
        }

        @Override
        public Declarator toCUse() {
            return Declarator.enumIdentifier(variable(bpfName));
        }

        @Override
        public Optional<BiFunction<String, Function<BPFType<?>, String>, FieldSpec>> toFieldSpecGenerator() {
            return Optional.of((fieldName, typeToSpecName) -> {
                String className = this.javaClass.klass;
                ClassName baseType = ClassName.get(BPF_PACKAGE, "BPFType.BPFEnumType");
                TypeName fieldType = ParameterizedTypeName.get(baseType, ClassName.get("", className));
                String memberExpression =
                        members.stream().map(m -> "new " + BPF_TYPE + ".BPFEnumMember(" + "\"" + m.name() + "\", \"" + m.cName() + "\", " + m.value() + ")").collect(Collectors.joining(", "));
                ClassName bpfType = ClassName.get(BPF_PACKAGE, "BPFType");
                return FieldSpec.builder(fieldType, fieldName).addModifiers(Modifier.FINAL, Modifier.STATIC)
                        .initializer("new $T<>($S, java.util.List.of($L), new $T.AnnotatedClass($T" + ".class, " + "java.util.List" + ".of()" + "), index -> $T.values()[index])",
                                baseType, bpfName, memberExpression, bpfType, ClassName.get("", className), ClassName.get("", className)).build();
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

        @Override
        public String bpfName() {
            return bpfName;
        }

        @Override
        public AnnotatedClass javaClass() {
            return javaClass;
        }

        @Override
        public String toString() {
            return "BPFEnumType[" +
                    "bpfName=" + bpfName + ", " +
                    "members=" + members + ", " +
                    "javaClass=" + javaClass + ']';
        }

        /**
         * Get the enum value from the passed value
         */
        public T fromValue(int value) {
            return indexToEnum.apply(memberValueToIndex.get(value));
        }

        /**
         * Get the value of the passed enum
         */
        public int toValue(T value) {
            return members.get(((java.lang.Enum<?>) value).ordinal()).value();
        }
    }

    // just for existing code
    /**
     * Union
     *
     * @param bpfName
     * @param shared  type that is shared between all members
     * @param members members of the union, including the shared type members
     */
    record BPFUnionTypeOld<S>(String bpfName, @Nullable BPFType<S> shared,
                              List<BPFUnionMember<?, ?>> members) implements BPFType<BPFUnion<S>> {

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
                    } catch (IllegalArgumentException _) {
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
                var current =
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