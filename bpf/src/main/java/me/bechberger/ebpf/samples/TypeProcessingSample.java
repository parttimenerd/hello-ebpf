package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.Type;
import me.bechberger.ebpf.bpf.BPFProgram;

/**
 * Adaption of {@link RingSample} that shows how to use the {@link Type} annotation and related annotation processing
 */
@BPF
public abstract class TypeProcessingSample extends BPFProgram {

    static final String EBPF_PROGRAM = """
            #include "vmlinux.h"
            #include <bpf/bpf_helpers.h>
            #include <bpf/bpf_tracing.h>
            #include <string.h>
            
            #define FILE_NAME_LEN 256
            #define TASK_COMM_LEN 16
                            
            // Structure to store the data that we want to pass to user
            struct event
            {
              u32 e_pid;
              char e_filename[FILE_NAME_LEN];
              char e_comm[TASK_COMM_LEN];
            };
                            
            // eBPF map reference
            struct
            {
              __uint (type, BPF_MAP_TYPE_RINGBUF);
              __uint (max_entries, 256 * 4096);
            } rb SEC (".maps");
                            
            // The ebpf auto-attach logic needs the SEC
            SEC ("kprobe/do_sys_openat2")
                 int kprobe__do_sys_openat2 (struct pt_regs *ctx)
            {
              char filename[256];
              char comm[TASK_COMM_LEN] = { };
              struct event *evt;
              const char fmt_str[] = "do_sys_openat2 called by:%s file:%s pid:%d";
                            
              // Reserve the ring-buffer
              evt = bpf_ringbuf_reserve (&rb, sizeof (struct event), 0);
              if (!evt)
                {
                  return 0;
                }
              // Get the PID of the process.
              evt->e_pid = bpf_get_current_pid_tgid ();	// Get current process PID
                            
              // Read the filename from the second argument
              // The x86 arch/ABI have first argument in di and second in si registers (man syscall)
              bpf_probe_read (evt->e_filename, sizeof (filename), (char *) ctx->si);
                            
              // Read the current process name
              bpf_get_current_comm (evt->e_comm, sizeof (comm));
                            
              // Compare process name with our "sample_write" name
              //     -- parttimenerd: we don't need this in our example
              //if (memcmp (evt->e_comm, TARGET_NAME, 12) == 0)
              //  {
                  // Print a message with filename, process name, and PID
                  bpf_trace_printk (fmt_str, sizeof (fmt_str), evt->e_comm,
            			evt->e_filename, evt->e_pid);
                  // Also send the same message to the ring-buffer
                  bpf_ringbuf_submit (evt, 0);
              //     return 0;
              //  }
              // If the program name is not matching with TARGET_NAME, then discard the data
              //bpf_ringbuf_discard (evt, 0);
              return 0;
            }
                            
            char _license[] SEC ("license") = "GPL";
            """;

    private static final int FILE_NAME_LEN = 256;
    private static final int TASK_COMM_LEN = 16;

    @Type
    record Event(@Unsigned int pid, @Size(FILE_NAME_LEN) String filename, @Size(TASK_COMM_LEN) String comm) {}


    public static void main(String[] args) {
        try (TypeProcessingSample program = BPFProgram.load(TypeProcessingSample.class)) {
            program.autoAttachProgram(program.getProgramByName("kprobe__do_sys_openat2"));
            var eventType = program.getTypeForClass(Event.class);
            var ringBuffer = program.getRingBufferByName("rb", eventType, (buffer, event) -> {
                System.out.printf("do_sys_openat2 called by:%s file:%s pid:%d\n", event.comm(), event.filename(), event.pid());
            });
            while (true) {
                ringBuffer.consumeAndThrow();
            }
        }
    }
}