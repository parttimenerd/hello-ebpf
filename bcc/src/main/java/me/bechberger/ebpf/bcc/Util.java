package me.bechberger.ebpf.bcc;

import me.bechberger.ebpf.bcc.raw.Lib;

public class Util {

    /**
     * Format errno to string using {@link Lib#strerror}
     */
    public static String errnoString(int error) {
        return Lib.strerror(error).getUtf8String(0);
    }
}
