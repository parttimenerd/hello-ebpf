package me.bechberger.ebpf.bpf.compiler;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.LSM;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.runtime.runtime;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Compiler-plugin tests for the {@code @LSM} shorthand annotation.
 *
 * <p>Verifies that the plugin generates the correct section name and
 * {@code BPF_PROG()} header template for LSM hook methods.
 */
public class LSMCompilerTest {

    @BPF(license = "GPL")
    public static abstract class FileOpenHook extends BPFProgram {
        @LSM("file_open")
        int onFileOpen(Ptr<runtime.file> file) {
            return 0;
        }
    }

    @BPF(license = "GPL")
    public static abstract class MultiHookProgram extends BPFProgram {
        @LSM("file_open")
        int onFileOpen(Ptr<runtime.file> file) {
            return 0;
        }

        @LSM("bpf")
        int onBpf(int cmd, Ptr<?> attr, int size) {
            return 0;
        }

        @LSM("socket_create")
        int onSocketCreate(int family, int type, int protocol, int kern) {
            return 0;
        }
    }

    @BPF(license = "GPL")
    public static abstract class InodeHookProgram extends BPFProgram {
        @LSM("inode_unlink")
        int onInodeUnlink(Ptr<runtime.inode> dir, Ptr<runtime.dentry> dentry) {
            return 0;
        }

        @LSM("inode_rename")
        int onInodeRename(Ptr<runtime.inode> oldDir, Ptr<runtime.dentry> oldDentry,
                          Ptr<runtime.inode> newDir, Ptr<runtime.dentry> newDentry) {
            return 0;
        }
    }

    @Test
    public void testLsmSectionGenerated() {
        var code = BPFProgram.getCode(FileOpenHook.class);
        assertTrue(code.contains("SEC(\"lsm/file_open\")"),
                "expected SEC(\"lsm/file_open\") in:\n" + code);
    }

    @Test
    public void testBpfProgHeaderGenerated() {
        var code = BPFProgram.getCode(FileOpenHook.class);
        assertTrue(code.contains("BPF_PROG("),
                "expected BPF_PROG( header in:\n" + code);
    }

    @Test
    public void testMultipleHooksGenerated() {
        var code = BPFProgram.getCode(MultiHookProgram.class);
        assertTrue(code.contains("SEC(\"lsm/file_open\")"),
                "expected lsm/file_open section in:\n" + code);
        assertTrue(code.contains("SEC(\"lsm/bpf\")"),
                "expected lsm/bpf section in:\n" + code);
        assertTrue(code.contains("SEC(\"lsm/socket_create\")"),
                "expected lsm/socket_create section in:\n" + code);
    }

    @Test
    public void testInodeHooksGenerated() {
        var code = BPFProgram.getCode(InodeHookProgram.class);
        assertTrue(code.contains("SEC(\"lsm/inode_unlink\")"),
                "expected lsm/inode_unlink section in:\n" + code);
        assertTrue(code.contains("SEC(\"lsm/inode_rename\")"),
                "expected lsm/inode_rename section in:\n" + code);
    }
}
