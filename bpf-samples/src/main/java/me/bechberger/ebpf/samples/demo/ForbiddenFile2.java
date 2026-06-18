package me.bechberger.ebpf.samples.demo;

import me.bechberger.ebpf.annotations.AlwaysInline;
import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.LSM;
import me.bechberger.ebpf.bpf.BPFJ;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.runtime.runtime;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.bpf_probe_read_str;

/**
 * Prohibits access to a file named "/tmp/forbidden" using an LSM {@code file_open} hook.
 *
 * <p>Run as root with {@code CONFIG_BPF_LSM=y} and {@code lsm=...,bpf} in the kernel
 * command line. Verify LSM is active: {@code cat /sys/kernel/security/lsm | grep bpf}.
 *
 * <p>Once loaded, any attempt to open {@code /tmp/forbidden} will be denied with EACCES:
 * <pre>
 *   $ touch /tmp/forbidden
 *   $ cat /tmp/forbidden
 *   cat: /tmp/forbidden: Permission denied
 * </pre>
 */
@BPF(license = "GPL")
public abstract class ForbiddenFile2 extends BPFProgram {

    private static final int EACCES = 13;
    private static final String FORBIDDEN_PATH = "/tmp/forbidden";

    @BPFFunction
    @AlwaysInline
    boolean isFileForbidden(String filename) {
        String forbidden = FORBIDDEN_PATH;
        for (int i = 0; i < 15; i++) {
            if (filename.charAt(i) != forbidden.charAt(i)) {
                return false;
            }
            if (filename.charAt(i) == '\0') {
                break;
            }
        }
        return true;
    }

    @LSM("file_open")
    int onFileOpen(Ptr<runtime.file> file) {
        Ptr<runtime.dentry> dentry = file.val().f_path.dentry;
        runtime.qstr d_name = dentry.val().d_name;
        @Size(256) String name = "";
        bpf_probe_read_str(Ptr.asVoidPointer(name), 256, Ptr.asVoidPointer(d_name.name));
        BPFJ.bpf_trace_printk("Accessing file: %s", name);
        if (isFileForbidden(name)) {
            BPFJ.bpf_trace_printk("Blocked access to forbidden file: %s", name);
            return -EACCES;
        }
        return 0;
    }

    public static void main(String[] args) throws InterruptedException {
        if (!BPFProgram.isLSMEnabled()) {
            System.err.println("WARNING: BPF LSM is not enabled on this kernel.");
            System.err.println("  Verify: cat /sys/kernel/security/lsm | grep bpf");
        }
        try (ForbiddenFile2 program = BPFProgram.load(ForbiddenFile2.class)) {
            program.autoAttachPrograms();
            System.out.println("LSM hook active — opens of /tmp/forbidden will be denied.");
            System.out.println("Press Ctrl-C to stop.");
            program.tracePrintLoop();
        }
    }
}
