package me.bechberger.ebpf.type;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import static me.bechberger.ebpf.type.BoxHelper.unbox;

/**
 * Class that all unions have to extend.
 * <p>
 * Adds {@link #toString()}, {@link #equals(Object)} and {@link #hashCode()} to a class.
 */
public class Union extends Struct {
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
}
