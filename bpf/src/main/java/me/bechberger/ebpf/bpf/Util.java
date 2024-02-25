package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.bpf.raw.Lib;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.zip.GZIPInputStream;

public class Util {

    /**
     * Format errno to string using {@link Lib#strerror}
     */
    public static String errnoString(int error) {
        return Lib.strerror(error).getUtf8String(0);
    }

    /**
     * Decode a base64 encoded string and unzip it
     */
    public static byte[] decodeGzippedBase64(String base64) {
        byte[] decodedBytes = Base64.getDecoder().decode(base64);
        try {
            GZIPInputStream gzipInputStream = new GZIPInputStream(new ByteArrayInputStream(decodedBytes));
            return gzipInputStream.readAllBytes();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
