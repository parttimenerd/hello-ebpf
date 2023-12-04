package me.bechberger.ebpf.bcc;

import me.bechberger.ebpf.raw.Lib;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

public class PanamaUtil {

    public static String toString(MemorySegment segment) {
        return segment.getUtf8String(0);
    }

    /**
     * Uses my_errno function to get the errno value
     * @return errno value
     */
    public static int errno() {
        MemorySegment errno = Lib.my_errno();
        return errno.get(ValueLayout.JAVA_INT, 0);
    }

    public static String errnoString() {
        return Lib.strerror(errno()).getUtf8String(0);
    }
}
