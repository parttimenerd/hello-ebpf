package me.bechberger.ebpf.bpf.compiler;

import org.jetbrains.annotations.Nullable;

import java.util.function.BiFunction;
import java.util.function.Function;

public class NullHelpers {

    static <T, R> R callIfNonNull(@Nullable T t, Function<T, R> function) {
        return t == null ? null : function.apply(t);
    }

    static <T, S, R> R callIfNonNull(@Nullable T t, @Nullable S s, BiFunction<T, S, R> function) {
        return t == null ? null : s == null ? null : function.apply(t, s);
    }
}
