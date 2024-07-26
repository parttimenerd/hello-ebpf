package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.BPFJ;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.map.BPFRingBuffer;
import me.bechberger.ebpf.runtime.OpenDefinitions.open_how;
import me.bechberger.ebpf.runtime.interfaces.SystemCallHooks;
import me.bechberger.ebpf.type.BPFType;
import me.bechberger.ebpf.type.Ptr;

import java.util.List;

import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.*;

/**
 * Ring buffer sample that traces the openat2 syscall and prints the filename, process name, and PID
 */
@BPF(license = "GPL")
public abstract class RingSample extends BPFProgram implements SystemCallHooks {

    static final int FILE_NAME_LEN = 256;
    static final int TASK_COMM_LEN = 16;

    @Type
    static class Event {
        @Unsigned int pid;
        @Size(FILE_NAME_LEN) String filename;
        @Size(TASK_COMM_LEN) String comm;
    }

    @BPFMapDefinition(maxEntries = FILE_NAME_LEN * 4096)
    BPFRingBuffer<Event> rb;

    @Override
    @SuppressWarnings("unchecked")
    public void enterOpenat2(int dfd, String filename, Ptr<open_how> how) {
        @Size(TASK_COMM_LEN) String comm = "";
        @Size(FILE_NAME_LEN) String filenameCopy = "";

        Ptr<Event> evt;

        // Reserve the ring-buffer

        evt = rb.reserve();
        if (evt == null) {
            return;
        }

        // Get the PID of the process.
        evt.val().pid = (int)bpf_get_current_pid_tgid();

        // Read the filename from the second argument
        // The x86 arch/ABI have first argument in di and second in si registers (man syscall)
        BPFJ.bpf_probe_read_kernel_str(evt.val().filename, filenameCopy);

        bpf_get_current_comm(Ptr.of(comm), TASK_COMM_LEN);

        BPFJ.bpf_trace_printk("do_sys_openat2 called by:%s file:%s pid:%d", comm, filenameCopy, evt.val().pid);
        rb.submit(evt);
    }

    public static void main(String[] args) {
        try (RingSample program = BPFProgram.load(RingSample.class)) {
            program.rb.setCallback((buffer, event) -> {
                System.out.printf("do_sys_openat2 called by:%s file:%s pid:%d\n", event.comm, event.filename, event.pid);
            });
            program.autoAttachPrograms();
            while (true) {
                program.consumeAndThrow();
            }
        }
    }
}