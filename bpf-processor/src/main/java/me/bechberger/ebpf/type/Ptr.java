package me.bechberger.ebpf.type;

/**
 * Represents a pointer to a value in Java code that is translated to a pointer in C code.
 * <p>
 * Example: {
 *     Ref<Integer> ref;
 *     // is translated to
 *     int *ref;
 * }
 * <b>None of the methods work in Java</b>
 * @param <T> Type of the value
 */
public class Ptr<T> {
    /** Dereference this pointer */
    public T deref() {
        throw new UnsupportedOperationException("Not implemented");
    }

    public static <T> Ptr<T> of(T value) {
        throw new UnsupportedOperationException("Not implemented");
    }

    public static <T> Ptr<T> ofNull() {
        throw new UnsupportedOperationException("Not implemented");
    }
}
