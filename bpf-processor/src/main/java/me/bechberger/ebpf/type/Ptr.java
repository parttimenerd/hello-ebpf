package me.bechberger.ebpf.type;

import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import org.jetbrains.annotations.Nullable;

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
    @BuiltinBPFFunction("(*($this))")
    @NotUsableInJava
    public T val() {
        throw new MethodIsBPFRelatedFunction();
    }

    /** Create a pointer of the passed value,
     * <p>
     *  Has to be a proper l-value (?) that has a place in memory,
     *  e.g. {@code Ptr.of(3)} is not allowed.
     */
    @BuiltinBPFFunction("&($arg1)")
    @NotUsableInJava
    public static <T> Ptr<T> of(@Nullable T value) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Short-cut for {@code Ptr.of(null)}
     */
    @BuiltinBPFFunction("((void*)0)")
    @NotUsableInJava
    public static Ptr<?> ofNull() {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Cast this Ptr to {@code Ptr<S>}
     */
    @BuiltinBPFFunction("(($T1*)$this)")
    @NotUsableInJava
    public <S> Ptr<S> cast() {
        throw new MethodIsBPFRelatedFunction();
    }

    /** Assumes that this pointer points to a pointer */
    @BuiltinBPFFunction("(($T1*)*$this)")
    @NotUsableInJava
    public <S> Ptr<S> castValPtr() {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Increment this pointer
     */
    @BuiltinBPFFunction("($this + $arg1)")
    @NotUsableInJava
    public Ptr<T> add(long increment) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Access the value at the index of this pointer
     */
    @BuiltinBPFFunction("($this[$arg1])")
    @NotUsableInJava
    public T get(int index) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Set the value at the index of this pointer
     */
    @BuiltinBPFFunction("($this)[$arg1] = $arg2")
    @NotUsableInJava
    public void set(int index, T value) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Set the value of this pointer
     * @param value value to set
     */
    @BuiltinBPFFunction("*($this) = $arg1")
    @NotUsableInJava
    public void set(T value) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Create a pointer that points to the first array element
     */
    @BuiltinBPFFunction("($arg1)")
    @NotUsableInJava
    public static <T> Ptr<T> of(T[] value) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Create a pointer that points to the first array element
     */
    @BuiltinBPFFunction("($arg1)")
    @NotUsableInJava
    public static Ptr<Integer> of(int[] value) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Create a pointer that points to the first array element
     */
    @BuiltinBPFFunction("($arg1)")
    @NotUsableInJava
    public static Ptr<Long> of(long[] value) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Create a pointer that points to the first array element
     */
    @BuiltinBPFFunction("($arg1)")
    @NotUsableInJava
    public static Ptr<Short> of(short[] value) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Create a pointer that points to the first array element
     */
    @BuiltinBPFFunction("($arg1)")
    @NotUsableInJava
    public static Ptr<Byte> of(byte[] value) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Create a pointer that points to the character of the string
     */
    @BuiltinBPFFunction("$arg1")
    @NotUsableInJava
    public static Ptr<Character> of(String value) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Create a pointer that points to the first array element
     */
    @BuiltinBPFFunction("($arg1)")
    @NotUsableInJava
    public static Ptr<Character> of(char[] value) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Create a pointer that points to the first array element
     */
    @BuiltinBPFFunction("($arg1)")
    @NotUsableInJava
    public static Ptr<Float> of(float[] value) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Create a pointer that points to the first array element
     */
    @BuiltinBPFFunction("($arg1)")
    @NotUsableInJava
    public static Ptr<Double> of(double[] value) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Create a pointer that points to the first array element
     */
    @BuiltinBPFFunction("($arg1)")
    @NotUsableInJava
    public static Ptr<Boolean> of(boolean[] value) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Convert an integer to a pointer
     */
    @BuiltinBPFFunction("((void*)(u64)$arg1)")
    @NotUsableInJava
    public static Ptr<?> voidPointer(long value) {
        throw new MethodIsBPFRelatedFunction();
    }

    @BuiltinBPFFunction("((void*)$this)")
    @NotUsableInJava
    public Ptr<?> asVoidPointer() {
        throw new MethodIsBPFRelatedFunction();
    }

    /** Interpret as long value */
    @BuiltinBPFFunction("(long)($this)")
    @NotUsableInJava
    public long asLong() {
        throw new MethodIsBPFRelatedFunction();
    }

    /** Is this pointer's address smaller than the other pointer's address? */
    @BuiltinBPFFunction("$this < $arg1")
    @NotUsableInJava
    public boolean lessThan(Ptr<?> other) {
        throw new MethodIsBPFRelatedFunction();
    }

    /** Is this pointer's address smaller or equal to the other pointer's address? */
    @BuiltinBPFFunction("$this <= $arg1")
    @NotUsableInJava
    public boolean lessOrEqual(Ptr<?> other) {
        throw new MethodIsBPFRelatedFunction();
    }

    /** Is this pointer's address greater than the other pointer's address? */
    @BuiltinBPFFunction("((void*)$this) > ((void*)$arg1)")
    @NotUsableInJava
    public boolean greaterThan(Ptr<?> other) {
        throw new MethodIsBPFRelatedFunction();
    }

    /** Is this pointer's address greater or equal to the other pointer's address? */
    @BuiltinBPFFunction("$this >= $arg1")
    @NotUsableInJava
    public boolean greaterOrEqual(Ptr<?> other) {
        throw new MethodIsBPFRelatedFunction();
    }

    @BuiltinBPFFunction("((void*)$arg1)")
    @NotUsableInJava
    public static Ptr<?> asVoidPointer(Object value) {
        throw new MethodIsBPFRelatedFunction();
    }

    @BuiltinBPFFunction("($T1*)($arg1)")
    @NotUsableInJava
    public static <T> Ptr<T> asPtr(long value) {
        throw new MethodIsBPFRelatedFunction();
    }

    /** Interpret as string */
    @BuiltinBPFFunction("(u8*)($this)")
    @NotUsableInJava
    public String asString() {
        throw new MethodIsBPFRelatedFunction();
    }
}
