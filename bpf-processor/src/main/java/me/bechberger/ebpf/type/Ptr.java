package me.bechberger.ebpf.type;

import me.bechberger.ebpf.annotations.MethodIsBPFRelatedFunction;

/**
 * Represents a pointer to a value in Java code that is translated to a pointer in C code.
 * <p>
 * Example: {@snippet :
 *     Ptr<Integer> ptr;
 *     // is translated to
 *     int *ptr;
 * }
 * <b>None of the methods work in Java</b>
 * @param <T> Type of the value
 */
public class Ptr<T> {
    /** Dereference this pointer */
    public T val() {
        throw new MethodIsBPFRelatedFunction();
    }

    public static <T> Ptr<T> of(T value) {
        throw new MethodIsBPFRelatedFunction();
    }

    public static <T> Ptr<T> ofNull() {
        throw new MethodIsBPFRelatedFunction();
    }
}
