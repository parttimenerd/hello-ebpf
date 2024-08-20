package me.bechberger.ebpf.samples.demo;

import me.bechberger.ebpf.annotations.AlwaysInline;
import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.bpf.BPFJ;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.LSMHook;
import me.bechberger.ebpf.runtime.runtime;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.bpf.BPFJ.sizeof;
import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.*;

/**
 * Prohibits access to a file named "/tmp/forbidden" using LSM hooks, currently doesn't work
 */
@BPF(license = "GPL")
public abstract class ForbiddenFile2 extends BPFProgram implements LSMHook {

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
    public int restrictFileOpen(Ptr<runtime.file> file) {
        Ptr<runtime.dentry> dentry = file.val().f_path.dentry;
        runtime.qstr d_name = dentry.val().d_name;
        @Size(100) String name = "";
        bpf_probe_read_str(Ptr.asVoidPointer(name), 100, d_name.name);
        BPFJ.bpf_trace_printk("Accessing file: %s\n", name);
        if (isFileForbidden(name)) {
            BPFJ.bpf_trace_printk("Blocked access to forbidden file: %s\n", name);
            return -EACCES;  // Deny access to the file
        }
        return 0;  // Allow access
    }

    public static void main(String[] args) throws InterruptedException {
        try (ForbiddenFile2 program = BPFProgram.load(ForbiddenFile2.class)) {
            program.attachLSMHooks();
            program.tracePrintLoop();
        }
    }
}