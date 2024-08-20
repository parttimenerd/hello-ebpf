package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Includes;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.runtime.runtime;
import me.bechberger.ebpf.type.Ptr;

/**
 * Linux Security Module (LSM) hooks (see <a href="https://docs.kernel.org/bpf/prog_lsm.html">docs.kernel.org</a>)
 * <p>
 * TODO: auto generate, might not work correctly, depending on the actual kernelli
 */
@Includes(
        {"linux/lsm_hook_defs.h",
                "linux/lsm_hooks.h",
                "linux/security.h"}
)
public interface LSMHooks {

    int EACCES = -13;

    /**
     * Intercept file open operations and
     * return an error if the file is forbidden
     * @param file the file to open,
     *             access pointery contents via {@link me.bechberger.ebpf.runtime.helpers.BPFHelpers#bpf_probe_read} and similar methods
     * @return 0 if the file can be opened, error code else
     */
    @BPFFunction(
            headerTemplate = "int BPF_PROG($name, struct file *file)",
            section = "lsm/u"
    )
    int restrictFileOpen(Ptr<runtime.file> file);

    default void attachLSMHooks() {
        if (this instanceof BPFProgram program) {
            program.attachLSMHooks();
        } else {
            throw new IllegalStateException("Cannot attach LSM hooks to non-BPFProgram");
        }
    }
}
