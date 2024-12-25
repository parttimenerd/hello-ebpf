package me.bechberger.ebpf.type;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;

/**
 * Wrapper around a value that is transparent in C code
 * <p>
 * Examples:
 * <pre>{@code
 * Box<Integer> box = Box.of(42);
 * int value = box.val();
 * box.set(43);
 * }</pre>
 * is translated to the following C code:
 * <pre>{@code
 * s32 box = 42;
 * s32 value = box;
 * box = 43;
 * }</pre>
 * @param <T> The type of the value
 */
@Type
public class Box<T> {

    private T value;

    @BuiltinBPFFunction("$arg1")
    public Box(T value) {
        this.value = value;
    }

    @BuiltinBPFFunction("$arg1")
    public static <T> Box<T> of(T value) {
        return new Box<>(value);
    }

    @BuiltinBPFFunction("$this")
    public T val() {
        return this.value;
    }

    @BuiltinBPFFunction("$this = $arg1")
    public void set(T value) {
        this.value = value;
    }
}
