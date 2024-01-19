package me.bechberger.ebpf.bcc;

import me.bechberger.ebpf.annotations.AnnotationInstances;
import org.jetbrains.annotations.Nullable;

import java.lang.annotation.Annotation;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.IntStream;


/**
 * A BPF type, see <a href="https://www.kernel.org/doc/html/latest/bpf/btf.html">Linux BTF documentation</a> for
 * more information
 */
public sealed interface BPFType<T> {

    /**
     * Java class with annotations
     */
    record AnnotatedClass(Class<?> klass, List<Annotation> annotations) {
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
     * Padded size of the type in bytes, use for all array index computations
     */
    default long sizePadded() {
        return PanamaUtil.padSize(layout().byteSize());
    }

    /**
     * Class that represents the type
     */
    AnnotatedClass javaClass();

    /**
     * Make sure to guarantee type-safety
     */
    @SuppressWarnings("unchecked")
    default T parseMemory(MemorySegment segment) {
        return parser().parse(segment);
    }

    default void setMemory(MemorySegment segment, T obj) {
        setter().store(segment, obj);
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

        /**
         * <code>u64</code> mapped to {@code @Unsigned long}
         */
        public static BPFIntType<Long> UINT64 = new BPFIntType<>("u64", ValueLayout.JAVA_LONG, segment -> {
            return segment.get(ValueLayout.JAVA_LONG, 0);
        }, (segment, obj) -> {
            segment.set(ValueLayout.JAVA_LONG, 0, obj);
        }, new AnnotatedClass(long.class, List.of(AnnotationInstances.UNSIGNED)), 0);

        /**
         * <code>u32</code> mapped to {@code @Unsigned int}
         */
        public static BPFIntType<Integer> UINT32 = new BPFIntType<>("u32", ValueLayout.JAVA_INT, segment -> {
            return segment.get(ValueLayout.JAVA_INT, 0);
        }, (segment, obj) -> {
            segment.set(ValueLayout.JAVA_INT, 0, obj);
        }, new AnnotatedClass(int.class, List.of(AnnotationInstances.UNSIGNED)), 0);

        /**
         * <code>s32</code> mapped to {@code int}
         */
        public static BPFIntType<Integer> INT32 = new BPFIntType<>("s32", ValueLayout.JAVA_INT, segment -> {
            return segment.get(ValueLayout.JAVA_INT, 0);
        }, (segment, obj) -> {
            segment.set(ValueLayout.JAVA_INT, 0, obj);
        }, new AnnotatedClass(int.class, List.of()), ENCODING_SIGNED);

        /**
         * <code>char</code> mapped to {@code char}
         */
        public static BPFIntType<Byte> CHAR = new BPFIntType<>("char", ValueLayout.JAVA_BYTE, segment -> {
            return segment.get(ValueLayout.JAVA_BYTE, 0);
        }, (segment, obj) -> {
            segment.set(ValueLayout.JAVA_BYTE, 0, obj);
        }, new AnnotatedClass(byte.class, List.of()), ENCODING_CHAR);

        public static BPFIntType<Byte> UINT8 = new BPFIntType<>("u8", ValueLayout.JAVA_BYTE, segment -> {
            return segment.get(ValueLayout.JAVA_BYTE, 0);
        }, (segment, obj) -> {
            segment.set(ValueLayout.JAVA_BYTE, 0, obj);
        }, new AnnotatedClass(byte.class, List.of()), 0);

        public static BPFIntType<Short> INT16 = new BPFIntType<>("s16", ValueLayout.JAVA_SHORT, segment -> {
            return segment.get(ValueLayout.JAVA_SHORT, 0);
        }, (segment, obj) -> {
            segment.set(ValueLayout.JAVA_SHORT, 0, obj);
        }, new AnnotatedClass(short.class, List.of()), ENCODING_SIGNED);

        public static BPFIntType<Short> UINT16 = new BPFIntType<>("u16", ValueLayout.JAVA_SHORT, segment -> {
            return segment.get(ValueLayout.JAVA_SHORT, 0);
        }, (segment, obj) -> {
            segment.set(ValueLayout.JAVA_SHORT, 0, obj);
        }, new AnnotatedClass(short.class, List.of()), 0);
    }

    /**
     * Struct member
     *
     * @param name   name of the member
     * @param type   type of the member
     * @param offset offset from the start of the struct in bytes
     * @param getter function that takes the struct and returns the member
     */
    record BPFStructMember<P, T>(String name, BPFType<T> type, int offset, Function<P, T> getter) {
    }

    /**
     * Struct
     *
     * @param bpfName     name of the struct in BPF
     * @param members     members of the struct, order should be the same as in the constructor
     * @param javaClass   class that represents the struct
     * @param constructor constructor that takes the members in the same order as in the constructor
     */
    record BPFStructType<T>(String bpfName, List<BPFStructMember<T, ?>> members, AnnotatedClass javaClass,
                         Function<List<Object>, T> constructor) implements BPFType<T> {

        @Override
        public MemoryLayout layout() {
            return MemoryLayout.sequenceLayout(size(), ValueLayout.JAVA_BYTE);
        }

        @Override
        public long size() {
            return members.stream().mapToLong(member -> member.type.size() + member.offset).max().orElseThrow();
        }

        @Override
        public MemoryParser<T> parser() {
            return segment -> {
                List<Object> args = members.stream().map(member -> (Object)member.type.parseMemory(segment.asSlice(member.offset))).toList();
                return constructor.apply(args);
            };
        }

        @SuppressWarnings("unchecked")
        @Override
        public MemorySetter<T> setter() {
            return (segment, obj) -> {
                for (BPFStructMember<T, ?> member : members) {
                    ((BPFType<Object>)member.type).setMemory(segment.asSlice(member.offset),
                            member.getter.apply(obj));
                }
            };
        }
    }

    /**
     * Array mapped to {@code List}
     */
    record BPFArrayType<E>(String bpfName, BPFType<E> memberType, int length) implements BPFType<List<E>> {

        @Override
        public MemoryLayout layout() {
            return MemoryLayout.sequenceLayout(length, memberType.layout());
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
        public AnnotatedClass javaClass() {
            return new AnnotatedClass(List.class, List.of(AnnotationInstances.size(length)));
        }

        public static <E> BPFArrayType<E> of(BPFType<E> memberType, int length) {
            return new BPFArrayType<>(memberType.bpfName() + "[" + length + "]",
                    memberType, length);
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
        public AnnotatedClass javaClass() {
            return new AnnotatedClass(String.class, List.of(AnnotationInstances.size(length)));
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
        public AnnotatedClass javaClass() {
            return wrapped.javaClass();
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
    record BPFUnionType<S>(String bpfName, @Nullable BPFType<S> shared, List<BPFUnionTypeMember> members) implements BPFType<BPFUnion<S>> {

        @Override
        public MemoryLayout layout() {
            return MemoryLayout.sequenceLayout(size(), ValueLayout.JAVA_BYTE);
        }

        @Override
        public long size() {
            return members.stream()
                    .mapToLong(member -> member.type.size())
                    .max()
                    .orElseThrow();
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
                BPFUnionTypeMember current = members().stream().filter(m -> m.name.equals(union.current())).findFirst().orElseThrow();
                current.type.setMemory(segment, union.get(union.current()));
            };
        }

        @Override
        public AnnotatedClass javaClass() {
            return new AnnotatedClass(BPFUnion.class, List.of());
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
            return Objects.equals(this.shared, that.shared) &&
                    Objects.equals(this.possibleMembers, that.possibleMembers);
        }
    }
}
