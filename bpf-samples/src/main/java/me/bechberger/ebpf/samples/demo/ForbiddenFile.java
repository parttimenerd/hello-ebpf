package me.bechberger.ebpf.samples.demo;

import me.bechberger.ebpf.annotations.AlwaysInline;
import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.bpf.BPFJ;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.runtime.OpenDefinitions.open_how;
import me.bechberger.ebpf.runtime.interfaces.SystemCallHooks;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.bpf_probe_write_user;

/**
 * Prohibits access to a file named "/tmp/forbidden"
 * <p>
 * Inspiration: <a href="https://blog.tofile.dev/2021/08/01/bad-bpf.html">blog.tofile.dev</a>
 * <p>
 * It's unfinished, it should probably also check that
 * the file descriptor returned by openat2 doesn't point
 * to the forbidden file (symlinks), and should also handle
 * openat.
 */
@BPF(license = "GPL")
public abstract class ForbiddenFile extends BPFProgram implements SystemCallHooks {

    @BPFFunction
    @AlwaysInline
    boolean isFileForbidden(String filename) {
        String forbidden = "/tmp/forbidden";
        for (int i = 0; i < "/tmp/forbidden".length(); i++) {
            if (filename.charAt(i) != forbidden.charAt(i)) {
                return false;
            }
            if (filename.charAt(i) == '\0') {
                break;
            }
        }
        return true;
    }

    @Override
    public void enterOpenat2(int dfd, String filename, Ptr<open_how> how) {
        @Size(100) String filenameCopy = "";
        BPFJ.bpf_probe_read_user_str(filenameCopy, filename);
        if (isFileForbidden(filenameCopy)) {
            BPFJ.bpf_trace_printk("Access to file %s prohibited", filename);
            bpf_probe_write_user(Ptr.asVoidPointer(filename), Ptr.asVoidPointer(""), 1);
        }
    }

    public static void main(String[] args) throws InterruptedException {
        try (ForbiddenFile program = BPFProgram.load(ForbiddenFile.class)) {
            program.autoAttachPrograms();
            program.tracePrintLoop();
        }
    }
}