package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.bpf.raw.Lib;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.zip.GZIPInputStream;

public class Util {

    /**
     * Format errno to string using {@link Lib#strerror}
     */
    public static String errnoString(int error) {
        return Lib.strerror(error).getString(0);
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

    /**
     * Read the byte code from a resource file, used internally
     */
    public static byte[] readByteCodeFromResource(String resourceName) {
        try {
            var resource = BPFProgram.class.getResource(resourceName);
            if (resource == null) {
                throw new BPFProgram.BPFLoadError("Resource not found: " + resourceName);
            }
            return Files.readAllBytes(Path.of(resource.toURI()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
