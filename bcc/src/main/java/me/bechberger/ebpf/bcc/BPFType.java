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
public sealed interface BPFType {

    /**
     * Java class with annotations
     */
    record AnnotatedClass(Class<?> klass, List<Annotation> annotations) {
    }

    /**
     * Parse a memory segment to return a Java object
     */
    @FunctionalInterface
    interface MemoryParser {
        Object parse(MemorySegment segment);
    }

    /**
     * Copy the native representation of a Java object into a passed memory segment
     */
    @FunctionalInterface
    interface MemorySetter {
        void store(MemorySegment segment, Object obj);
    }

    /**
     * Name of the type in BPF
     */
    String bpfName();

    MemoryLayout layout();

    MemoryParser parser();

    MemorySetter setter();

    /**
     * Size of the type in bytes
     */
    default long size() {
        return layout().byteSize();
    }

    /** Padded size of the type in bytes, use for all array index computations */
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
    default <V> V parseMemory(MemorySegment segment) {
        return (V) parser().parse(segment);
    }

    default <V> void setMemory(MemorySegment segment, V obj) {
        setter().store(segment, obj);
    }

    /**
     * Integer
     */
    record BPFIntType(String bpfName, MemoryLayout layout, MemoryParser parser, MemorySetter setter,
                      AnnotatedClass javaClass, int encoding) implements BPFType {
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
         * <code>uint64_t</code> mapped to {@code @Unsigned long}
         */
        public static BPFIntType UINT64 = new BPFIntType("u64", ValueLayout.JAVA_LONG, segment -> {
            return segment.get(ValueLayout.JAVA_LONG, 0);
        }, (segment, obj) -> {
            segment.set(ValueLayout.JAVA_LONG, 0, (long) obj);
        }, new AnnotatedClass(long.class, List.of(AnnotationInstances.UNSIGNED)), 0);

        /**
         * <code>uint32_t</code> mapped to {@code @Unsigned int}
         */
        public static BPFIntType UINT32 = new BPFIntType("u32", ValueLayout.JAVA_INT, segment -> {
            return segment.get(ValueLayout.JAVA_INT, 0);
        }, (segment, obj) -> {
            segment.set(ValueLayout.JAVA_INT, 0, (int) obj);
        }, new AnnotatedClass(int.class, List.of(AnnotationInstances.UNSIGNED)), 0);

        /**
         * <code>int32_t</code> mapped to {@code int}
         */
        public static BPFIntType INT32 = new BPFIntType("s32", ValueLayout.JAVA_INT, segment -> {
            return segment.get(ValueLayout.JAVA_INT, 0);
        }, (segment, obj) -> {
            segment.set(ValueLayout.JAVA_INT, 0, (int) obj);
        }, new AnnotatedClass(int.class, List.of()), ENCODING_SIGNED);

        /**
         * <code>char</code> mapped to {@code char}
         */
        public static BPFIntType CHAR = new BPFIntType("char", ValueLayout.JAVA_BYTE, segment -> {
            return segment.get(ValueLayout.JAVA_BYTE, 0);
        }, (segment, obj) -> {
            if ((char) obj > 255) {
                throw new IllegalArgumentException("char must be in range 0-255");
            }
            segment.set(ValueLayout.JAVA_BYTE, 0, (byte) obj);
        }, new AnnotatedClass(byte.class, List.of()), ENCODING_CHAR);
    }

    /**
     * Struct member
     *
     * @param name   name of the member
     * @param type   type of the member
     * @param offset offset from the start of the struct in bytes
     * @param getter function that takes the struct and returns the member
     */
    record BPFStructMember(String name, BPFType type, int offset, Function<?, Object> getter) {
    }

    /**
     * Struct
     *
     * @param bpfName     name of the struct in BPF
     * @param members     members of the struct, order should be the same as in the constructor
     * @param javaClass   class that represents the struct
     * @param constructor constructor that takes the members in the same order as in the constructor
     */
    record BPFStructType(String bpfName, List<BPFStructMember> members, AnnotatedClass javaClass,
                         Function<List<Object>, ?> constructor) implements BPFType {

        @Override
        public MemoryLayout layout() {
            return MemoryLayout.sequenceLayout(size(), ValueLayout.JAVA_BYTE);
        }

        @Override
        public long size() {
            return members.stream().mapToLong(member -> member.type.size() + member.offset).max().orElseThrow();
        }

        @Override
        public MemoryParser parser() {
            return segment -> {
                List<Object> args = members.stream().map(member -> member.type.parseMemory(segment.asSlice(member.offset))).toList();
                return constructor.apply(args);
            };
        }

        @SuppressWarnings("unchecked")
        @Override
        public MemorySetter setter() {
            return (segment, obj) -> {
                for (BPFStructMember member : members) {
                    member.type.setMemory(segment.asSlice(member.offset), ((Function<Object, Object>) member.getter).apply(obj));
                }
            };
        }
    }

    /**
     * Array mapped to {@code List}
     */
    record BPFArrayType(String bpfName, BPFType memberType, int length) implements BPFType {

        @Override
        public MemoryLayout layout() {
            return MemoryLayout.sequenceLayout(length, memberType.layout());
        }

        @Override
        public MemoryParser parser() {
            return segment -> IntStream.range(0, length).mapToObj(i -> memberType.parseMemory(segment.asSlice(i * memberType.size()))).toList();
        }

        @Override
        public MemorySetter setter() {
            return (segment, obj) -> {
                List<?> list = (List<?>) obj;
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
    }

    /**
     * Type alias
     */
    record BPFTypedef(String bpfName, BPFType wrapped) implements BPFType {

        @Override
        public MemoryLayout layout() {
            return wrapped.layout();
        }

        @Override
        public MemoryParser parser() {
            return wrapped.parser();
        }

        @Override
        public MemorySetter setter() {
            return wrapped.setter();
        }

        @Override
        public AnnotatedClass javaClass() {
            return wrapped.javaClass();
        }
    }


    record BPFUnionTypeMember(String name, BPFType type) {}

    /**
     * Union
     * @param bpfName
     * @param shared type that is shared between all members
     * @param members members of the union, including the shared type members
     */
    record BPFUnionType(String bpfName, BPFType shared, List<BPFUnionTypeMember> members) implements BPFType {

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
        public MemoryParser parser() {
            return segment -> {
                Map<String, Object> possibleMembers = new HashMap<>();
                for (var member : members) {
                    // try to parse all members, but only keep the ones that work
                    try {
                        possibleMembers.put(member.name(), member.type.parseMemory(segment));
                    } catch (IllegalArgumentException e) {
                    }
                }
                return new BPFUnionFromMemory<>(shared.parseMemory(segment), possibleMembers);
            };
        }

        /** Return the memory setter, only works if the passed union has a set current member */
        @Override
        public MemorySetter setter() {
            return (segment, obj) -> {
                BPFUnionFromMemory<?> union = (BPFUnionFromMemory<?>) obj;
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
        <S> S shared();
        <T> T get(String name);

        <T> void set(String name, T value);

        @Nullable String current();

        void setCurrent(String name);
    }

    static final class BPFUnionFromMemory<S> implements BPFUnion<S> {
        private final S shared;
        private final Map<String, Object> possibleMembers;

        @Nullable String current = null;

        public BPFUnionFromMemory(S shared, Map<String, Object> possibleMembers) {
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
        public S shared() {
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
