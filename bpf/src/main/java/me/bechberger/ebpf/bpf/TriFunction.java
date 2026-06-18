package me.bechberger.ebpf.bpf;

/**
 * 3-argument equivalent of {@link java.util.function.BiFunction}. Used for
 * lambda callbacks that need a typed {@code ctx} parameter alongside two
 * other inputs — most prominently {@link me.bechberger.ebpf.bpf.map.BPFHashMap#forEach}
 * where the kernel ABI passes {@code (key, value, ctx)}.
 */
@FunctionalInterface
public interface TriFunction<A, B, C, R> {
    R apply(A a, B b, C c);
}
