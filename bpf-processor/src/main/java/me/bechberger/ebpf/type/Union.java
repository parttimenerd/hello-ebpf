package me.bechberger.ebpf.type;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import static me.bechberger.ebpf.type.BoxHelper.unbox;

public class Union {
    /**
     * boxed original values
     */
    Map<String, Object> originalValues;

    public Union() {
        originalValues = null;
    }

    @SuppressWarnings("unchecked")
    public <U extends Union> U init(Map<String, Object> originalValues) {
        this.originalValues = originalValues;
        // use reflection to set the fields
        for (var entry : originalValues.entrySet()) {
            Field field;
            try {
                field = getClass().getDeclaredField(entry.getKey());
            } catch (NoSuchFieldException e) {
                throw new RuntimeException("Field " + entry.getKey() + " does not exist", e);
            }
            Object unboxed = unbox(entry.getValue(), field.getType());
            try {
                field.setAccessible(true);
                field.set(this, unboxed);
            } catch (IllegalAccessException | IllegalArgumentException e) {
                throw new IllegalArgumentException("Could not set field " + entry.getKey(), e);
            }
        }
        return (U) this;
    }

    /**
     * Union {field1 = x, field2 = y, ...}
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
        var that = (Union) obj;
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
