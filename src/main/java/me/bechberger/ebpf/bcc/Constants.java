package me.bechberger.ebpf.bcc;

import java.nio.file.Path;

/**
 * Constants used by the library
 */
public final class Constants {
    private Constants() {}

    public static final Path DEBUGFS = Path.of("/sys/kernel/debug");
    public static final Path TRACEFS;
    static {
        if (DEBUGFS.resolve("tracing").toFile().exists()) {
            TRACEFS = DEBUGFS.resolve("tracing");
        } else {
            TRACEFS = Path.of("/sys/kernel/tracing");
        }
    }

}
