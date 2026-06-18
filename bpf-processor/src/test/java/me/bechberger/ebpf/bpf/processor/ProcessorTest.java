package me.bechberger.ebpf.bpf.processor;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

public class ProcessorTest {

    @Test
    public void multiarchName_amd64_mapsToX8664() {
        assertEquals("x86_64", Processor.multiarchName("amd64"));
    }

    @Test
    public void multiarchName_x8664_isIdempotent() {
        assertEquals("x86_64", Processor.multiarchName("x86_64"));
    }

    @Test
    public void multiarchName_aarch64_unchanged() {
        assertEquals("aarch64", Processor.multiarchName("aarch64"));
    }

    @Test
    public void multiarchName_arm64_normalizesToAarch64() {
        assertEquals("aarch64", Processor.multiarchName("arm64"));
    }

    @Test
    public void multiarchName_unknownArch_passesThrough() {
        assertEquals("loongarch64", Processor.multiarchName("loongarch64"));
    }

    /**
     * Smoke test: on a Linux build host, findIncludePath() must return an
     * existing directory. Skipped on macOS because the editor host has no
     * /usr/include/<arch>-linux-gnu (the test runs on thinkstation via
     * scripts/ts.sh).
     */
    @Test
    @EnabledOnOs(OS.LINUX)
    public void findIncludePath_returnsExistingDirectoryOnLinux() {
        Path p = Processor.findIncludePath();
        assertTrue(Files.exists(p), "findIncludePath() returned non-existent path: " + p);
        assertTrue(Files.isDirectory(p), "findIncludePath() returned non-directory: " + p);
    }

    /**
     * Specifically the multiarch dir, not the fallback /usr/include/linux.
     * On x86_64 Linux this should be /usr/include/x86_64-linux-gnu, which
     * is the dir containing asm/unistd.h. If we land on the fallback, the
     * arch normalization is broken.
     */
    @Test
    @EnabledOnOs(OS.LINUX)
    public void findIncludePath_resolvesToMultiarchDirOnLinux() {
        Path p = Processor.findIncludePath();
        String expected = Processor.multiarchName(System.getProperty("os.arch")) + "-linux-gnu";
        assertTrue(p.toString().contains(expected) || p.equals(Path.of("/usr/include/linux")),
                "findIncludePath() should resolve to either multiarch dir (" + expected + ") or fallback /usr/include/linux, got: " + p);
        // Stronger check: asm/unistd.h must be reachable from the chosen dir.
        // Multiarch dir contains it directly; /usr/include/linux does not.
        Path unistd = p.resolve("asm/unistd.h");
        assertTrue(Files.exists(unistd),
                "asm/unistd.h not found under " + p + " — clang will fail to compile any program with #include <unistd.h>");
    }
}
