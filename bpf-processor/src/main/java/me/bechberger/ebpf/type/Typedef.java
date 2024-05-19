package me.bechberger.ebpf.type;

import java.lang.reflect.Field;
import java.util.Map;

import static me.bechberger.ebpf.type.BoxHelper.box;
import static me.bechberger.ebpf.type.BoxHelper.unbox;

/**
 * Interface that makes all implementing structs typedefs/aliases to other types.
 * <p>
 * Example: {@snippet :
 *     record IntArray(int[] val) implements Typedef<int[]> {}
 * }
 * @see TypedefBase
 */
public interface Typedef<T> {

    T val();
}
