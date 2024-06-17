package me.bechberger.ebpf.type;

import me.bechberger.ebpf.type.BPFType.InlineUnion;

import java.lang.reflect.Field;
import java.util.*;
import java.util.stream.Collectors;

import static me.bechberger.ebpf.type.BoxHelper.unbox;

/**
 * Adds {@link #toString()}, {@link #equals(Object)} and {@link #hashCode()} to a class.
 */
public class Struct {

    private List<InlineUnion> inlineUnions = new ArrayList<>();

    /**
     * Type {field1 = x, field2 = y, ...}
     */
    @Override
    public String toString() {
        return getClass().getName() + "{" + Arrays.stream(getClass().getDeclaredFields()).map(f -> {
            try {
                f.setAccessible(true);
                return f.getName() + " = " + f.get(this);
            } catch (IllegalAccessException e) {
                throw new RuntimeException(e);
            }
        }).collect(Collectors.joining(", ")) + "}";
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        var that = (Struct) obj;
        // check all declared fields
        return Arrays.stream(obj.getClass().getDeclaredFields()).allMatch(f -> {
            try {
                f.setAccessible(true);
                return Objects.equals(f.get(this), f.get(that));
            } catch (IllegalAccessException e) {
                throw new RuntimeException(e);
            }
        });
    }

    @Override
    public int hashCode() {
        return Arrays.stream(getClass().getDeclaredFields()).map(f -> {
            try {
                return Objects.hashCode(f.get(this));
            } catch (IllegalAccessException e) {
                throw new RuntimeException(e);
            }
        }).reduce(1, (a, b) -> 31 * a + b);
    }
}
