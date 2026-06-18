package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.AlwaysInline;
import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.LSM;
import me.bechberger.ebpf.bpf.BPFJ;
import me.bechberger.ebpf.runtime.runtime;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.Path;

import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.bpf_probe_read_str;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Integration test for the LSM {@code file_open} denial path.
 *
 * <p>Loads an LSM program that blocks access to {@code /tmp/forbidden_test_file},
 * creates the file, then verifies that opening it fails with a permission error.
 */
public class ForbiddenFileTest {

    static final String FORBIDDEN = "/tmp/forbidden_test_file";
    // d_name.name contains only the last path component (no directory prefix)
    static final String FORBIDDEN_FILENAME = "forbidden_test_file";

    @BPF(license = "GPL")
    public static abstract class BlockForbiddenProgram extends BPFProgram {

        final GlobalVariable<Integer> denyCount = new GlobalVariable<>(0);

        @BPFFunction
        @AlwaysInline
        boolean isForbidden(@Size(256) String name) {
            String target = FORBIDDEN_FILENAME;
            for (int i = 0; i < 20; i++) {
                if (name.charAt(i) != target.charAt(i)) return false;
                if (name.charAt(i) == '\0') break;
            }
            return true;
        }

        @LSM("file_open")
        int onFileOpen(Ptr<runtime.file> file) {
            Ptr<runtime.dentry> dentry = file.val().f_path.dentry;
            runtime.qstr dName = dentry.val().d_name;
            @Size(256) String name = "";
            bpf_probe_read_str(Ptr.asVoidPointer(name), 256, Ptr.asVoidPointer(dName.name));
            if (isForbidden(name)) {
                denyCount.set(denyCount.get() + 1);
                return -13; // EACCES
            }
            return 0;
        }
    }

    @Test
    @Timeout(15)
    public void testForbiddenFileIsDenied() throws IOException {
        assumeTrue(BPFProgram.isLSMEnabled(), "BPF LSM not enabled on this kernel");
        // Create the forbidden file before loading the LSM program
        Path path = Path.of(FORBIDDEN);
        Files.writeString(path, "secret");

        try (var program = BPFProgram.load(BlockForbiddenProgram.class)) {
            program.autoAttachPrograms();

            // Opening the forbidden file should be denied
            boolean denied = false;
            try {
                Files.readString(path);
            } catch (AccessDeniedException e) {
                denied = true;
            } catch (IOException e) {
                denied = e.getMessage() != null && e.getMessage().contains("ermission");
            }

            int denies = program.denyCount.get();
            assertTrue(denies > 0, "deny counter should be > 0 (was " + denies + "), hook did not fire for the forbidden filename");
            assertTrue(denied, "Opening /tmp/forbidden_test_file should be denied by LSM (denyCount=" + denies + ")");
        } finally {
            // Unlink after the program is closed (LSM hook no longer active)
            try { Files.deleteIfExists(path); } catch (IOException ignored) {}
        }
    }

    @Test
    @Timeout(15)
    public void testNormalFileIsAllowed() throws IOException {
        assumeTrue(BPFProgram.isLSMEnabled(), "BPF LSM not enabled on this kernel");
        Path path = Files.createTempFile("lsm_allowed_", ".txt");
        Files.writeString(path, "allowed content");

        try (var program = BPFProgram.load(BlockForbiddenProgram.class)) {
            program.autoAttachPrograms();

            // A different file should be accessible
            var content = Files.readString(path);
            assertEquals("allowed content", content, "Non-forbidden file should be readable");
        } finally {
            Files.deleteIfExists(path);
        }
    }
}
