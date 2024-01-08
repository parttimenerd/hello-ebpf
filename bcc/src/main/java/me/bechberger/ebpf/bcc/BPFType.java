package me.bechberger.ebpf.bcc;

import me.bechberger.ebpf.annotations.AnnotationInstances;

import java.lang.annotation.Annotation;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.List;


/**
 * A BPF type, see <a href="https://www.kernel.org/doc/html/latest/bpf/btf.html">Linux BTF documentation</a> for
 * more information
 */
public sealed interface BPFType {

    /** Java class with annotations */
    record AnnotatedClass(Class<?> klass, List<Annotation> annotations) {
    }

    /** Parse a memory segment to return a Java object */
    @FunctionalInterface interface MemoryParser {
        Object parse(MemorySegment segment);
    }

    /** Copy the native representation of a Java object into a passed memory segment */
    @FunctionalInterface interface MemorySetter {
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

    /**
     * Class that represents the type
     */
    AnnotatedClass javaClass();

    /** Make sure to guarantee type-safety */
    @SuppressWarnings("unchecked")
    default <V> V parseMemory(MemorySegment segment) {
        return (V)parser().parse(segment);
    }

    default <V> void setMemory(MemorySegment segment, V obj) {
        setter().store(segment, obj);
    }

    /**
     * Integer
     */
    record BPFIntType(String bpfName, MemoryLayout layout, MemoryParser parser, MemorySetter setter, AnnotatedClass javaClass, int encoding) implements BPFType {
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

        /** <code>uint64_t</code> mapped to {@code @Unsigned long} */
        public static BPFIntType UINT64 = new BPFIntType("u64", ValueLayout.JAVA_LONG, segment -> {
           return segment.get(ValueLayout.JAVA_LONG, 0);
        }, (segment, obj) -> {
            segment.set(ValueLayout.JAVA_LONG, 0, (long)obj);
        }, new AnnotatedClass(long.class, List.of(AnnotationInstances.UNSIGNED)), ENCODING_SIGNED);

    }
}
