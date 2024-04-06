package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Type;
import me.bechberger.ebpf.bpf.map.BPFRingBuffer;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static me.bechberger.ebpf.bpf.TestUtil.triggerOpenAt;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Based on {@link me.bechberger.ebpf.samples.TypeProcessingSample2} and {@link me.bechberger.ebpf.bpf.RingBufferTest}
 */
public class MapGenerationTest {

    @BPF
    public static abstract class Prog extends BPFProgram {

        private static final int FILE_NAME_LEN = 256;
        private static final int TASK_COMM_LEN = 16;

        @Type(name = "event")
        record Event(@Unsigned int pid, @Size(FILE_NAME_LEN) String filename, @Size(TASK_COMM_LEN) String comm) {}

        @BPFMapDefinition(maxEntries = 256 * 4096)
        BPFRingBuffer<Event> rb;

        static final String EBPF_PROGRAM = """
            #include "vmlinux.h"
            #include <bpf/bpf_helpers.h>
            #include <bpf/bpf_tracing.h>
            #include <string.h>
            
            // non ring buffer map, used for the testWrongMapType test
            struct {
                __uint(type, BPF_MAP_TYPE_ARRAY);
                __type(key, u32);
                __type(value, long);
                __uint(max_entries, 256);
            } non_ring_buffer SEC(".maps");

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
              evt->pid = bpf_get_current_pid_tgid ();	// Get current process PID
                            
              // Read the filename from the second argument
              // The x86 arch/ABI have first argument in di and second in si registers (man syscall)
              bpf_probe_read (evt->filename, sizeof (filename), (char *) ctx->regs[1]);
                            
              // Read the current process name
              bpf_get_current_comm (evt->comm, sizeof (comm));
                            
              // Also send the same message to the ring-buffer
              bpf_ringbuf_submit (evt, 0);
              return 0;
            }
                            
            char _license[] SEC ("license") = "GPL";
            """;
    }

    @Test
    public void testSuccessfulCase() throws Exception {
        try (Prog program = BPFProgram.load(Prog.class)) {
            program.autoAttachProgram(program.getProgramByName("kprobe__do_sys_openat2"));
            AtomicReference<RingBufferTest.Event> eventRef = new AtomicReference<>();
            List<Path> paths = new ArrayList<>();
            program.rb.setCallback((buffer, event) -> {
                paths.add(Path.of(event.filename));
            });
            Path openendPath = triggerOpenAt();
            long start = System.currentTimeMillis();
            while (System.currentTimeMillis() - start < 1000) {
                Thread.sleep(10);
                program.consumeAndThrow();
                if (paths.contains(openendPath)) {
                    return;
                }
            }
            fail("No " + openendPath + " received, just " + paths);
        }
    }

}
