package me.bechberger.ebpf.type;

import java.lang.reflect.Array;
import java.util.Arrays;

/**
 * Helps with boxing and unboxing of primitive types and their arrays
 */
public class BoxHelper {

    public static <T> T[] box(T[] array) {
        return array;
    }

    public static <T> T[] unbox(T[] array) {
        return array;
    }

    @SuppressWarnings("unchecked")
    public static <T> T box(T value) {
        if (value == null) {
            return null;
        }
        if (!value.getClass().isArray()) {
            return value;
        }
        return switch (value) {
            case int[] ints -> (T) box(ints);
            case long[] longs -> (T) box(longs);
            case double[] doubles -> (T) box(doubles);
            case float[] floats -> (T) box(floats);
            case short[] shorts -> (T) box(shorts);
            case byte[] bytes -> (T) box(bytes);
            case char[] chars -> (T) box(chars);
            case boolean[] booleans -> (T) box(booleans);
            default -> {
                var array = new Object[Array.getLength(value)];
                for (int i = 0; i < Array.getLength(value); i++) {
                    array[i] = box(Array.get(value, i));
                }
                yield (T) array;
            }
        };
    }

    @SuppressWarnings("unchecked")
    public static <T, S> T unbox(S value, Class<?> clazz) {
        if (!value.getClass().isArray()) {
            return (T) value;
        }
        if (!clazz.isArray()) {
            return (T) value;
        }
        var subComp = value.getClass().getComponentType();
        while (subComp.isArray()) {
            subComp = subComp.getComponentType();
        }
        if (subComp.isPrimitive()) {
            return (T) value;
        }
        if (clazz == int[].class) {
            return (T) unboxIntArray((Object[]) value);
        }
        if (clazz == long[].class) {
            return (T) unboxLongArray((Object[]) value);
        }
        if (clazz == double[].class) {
            return (T) unboxDoubleArray((Object[]) value);
        }
        if (clazz == float[].class) {
            return (T) unboxFloatArray((Object[]) value);
        }
        if (clazz == short[].class) {
            return (T) unboxShortArray((Object[]) value);
        }
        if (clazz == byte[].class) {
            return (T) unboxByteArray((Object[]) value);
        }
        if (clazz == char[].class) {
            return (T) unboxCharArray((Object[]) value);
        }
        if (clazz == boolean[].class) {
            return (T) unboxBooleanArray((Object[]) value);
        }
        var array = Array.newInstance(clazz.getComponentType(), Array.getLength(value));
        for (int i = 0; i < Array.getLength(value); i++) {
            Array.set(array, i, unbox(Array.get(value, i), clazz.getComponentType()));
        }
        return (T) array;
    }

    public static Integer[] box(int[] array) {
        return Arrays.stream(array).boxed().toArray(Integer[]::new);
    }

    public static int[] unbox(Integer[] array) {
        return Arrays.stream(array).mapToInt(Integer::intValue).toArray();
    }

    public static int[] unboxIntArray(Object[] array) {
        return Arrays.stream(array).mapToInt(o -> (Integer) o).toArray();
    }

    // same for all primitive types
    public static Long[] box(long[] array) {
        return Arrays.stream(array).boxed().toArray(Long[]::new);
    }

    public static long[] unbox(Long[] array) {
        return Arrays.stream(array).mapToLong(Long::longValue).toArray();
    }

    public static long[] unboxLongArray(Object[] array) {
        return Arrays.stream(array).mapToLong(o -> (Long) o).toArray();
    }

    public static Double[] box(double[] array) {
        return Arrays.stream(array).boxed().toArray(Double[]::new);
    }

    public static double[] unbox(Double[] array) {
        return Arrays.stream(array).mapToDouble(Double::doubleValue).toArray();
    }

    public static double[] unboxDoubleArray(Object[] array) {
        return Arrays.stream(array).mapToDouble(o -> (Double) o).toArray();
    }

    public static Float[] box(float[] array) {
        Float[] boxed = new Float[array.length];
        for (int i = 0; i < array.length; i++) {
            boxed[i] = array[i];
        }
        return boxed;
    }

    public static float[] unbox(Float[] array) {
        float[] unboxed = new float[array.length];
        for (int i = 0; i < array.length; i++) {
            unboxed[i] = array[i];
        }
        return unboxed;
    }

    public static float[] unboxFloatArray(Object[] array) {
        float[] unboxed = new float[array.length];
        for (int i = 0; i < array.length; i++) {
            unboxed[i] = (Float) array[i];
        }
        return unboxed;
    }

    public static Short[] box(short[] array) {
        Short[] boxed = new Short[array.length];
        for (int i = 0; i < array.length; i++) {
            boxed[i] = array[i];
        }
        return boxed;
    }

    public static short[] unbox(Short[] array) {
        short[] unboxed = new short[array.length];
        for (int i = 0; i < array.length; i++) {
            unboxed[i] = array[i];
        }
        return unboxed;
    }

    public static short[] unboxShortArray(Object[] array) {
        short[] unboxed = new short[array.length];
        for (int i = 0; i < array.length; i++) {
            unboxed[i] = (Short) array[i];
        }
        return unboxed;
    }

    public static Byte[] box(byte[] array) {
        Byte[] boxed = new Byte[array.length];
        for (int i = 0; i < array.length; i++) {
            boxed[i] = array[i];
        }
        return boxed;
    }

    public static byte[] unbox(Byte[] array) {
        byte[] unboxed = new byte[array.length];
        for (int i = 0; i < array.length; i++) {
            unboxed[i] = array[i];
        }
        return unboxed;
    }

    public static byte[] unboxByteArray(Object[] array) {
        byte[] unboxed = new byte[array.length];
        for (int i = 0; i < array.length; i++) {
            unboxed[i] = (Byte) array[i];
        }
        return unboxed;
    }

    public static Character[] box(char[] array) {
        Character[] boxed = new Character[array.length];
        for (int i = 0; i < array.length; i++) {
            boxed[i] = array[i];
        }
        return boxed;
    }

    public static char[] unbox(Character[] array) {
        char[] unboxed = new char[array.length];
        for (int i = 0; i < array.length; i++) {
            unboxed[i] = array[i];
        }
        return unboxed;
    }

    public static char[] unboxCharArray(Object[] array) {
        char[] unboxed = new char[array.length];
        for (int i = 0; i < array.length; i++) {
            unboxed[i] = (Character) array[i];
        }
        return unboxed;
    }

    public static Boolean[] box(boolean[] array) {
        Boolean[] boxed = new Boolean[array.length];
        for (int i = 0; i < array.length; i++) {
            boxed[i] = array[i];
        }
        return boxed;
    }

    public static boolean[] unbox(Boolean[] array) {
        boolean[] unboxed = new boolean[array.length];
        for (int i = 0; i < array.length; i++) {
            unboxed[i] = array[i];
        }
        return unboxed;
    }

    public static boolean[] unboxBooleanArray(Object[] array) {
        boolean[] unboxed = new boolean[array.length];
        for (int i = 0; i < array.length; i++) {
            unboxed[i] = (Boolean) array[i];
        }
        return unboxed;
    }
}
