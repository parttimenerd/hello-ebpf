package me.bechberger.ebpf.bpf;

import java.nio.file.Files;
import java.nio.file.Path;

public class TestUtil {
    /**
     * Triggers a openat syscall and returns the path of the file that was opened
     */
    public static Path triggerOpenAt() {
        try {
            var path = Files.createTempFile("test", "txt");
            Files.write(path, "Hello, World!".getBytes());
            Files.delete(path);
            return path;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
