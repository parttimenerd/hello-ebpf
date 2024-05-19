package me.bechberger.ebpf.type;

/**
 * Class that makes all extending structs typedefs/aliases to other types and adds
 * equals, hashCode and toString methods based on the value.
 * <p>
 * Example: {@snippet :
 *    static class IntArray extends TypedefBase<int[]> {
 *       public IntArray(int[] val) {
 *         super(val);
 *       }
 *    }
 * }
 */
public abstract class TypedefBase<T> implements Typedef<T> {

    private final T val;

    public TypedefBase(T val) {
        this.val = val;
    }

    public T val() {
        return val;
    }

    @Override
    public boolean equals(Object obj) {
        return obj instanceof TypedefBase<?> ? val.equals(((TypedefBase<?>) obj).val) : val.equals(obj);
    }

    @Override
    public int hashCode() {
        return val.hashCode();
    }

    @Override
    public String toString() {
        return val.toString();
    }
}
