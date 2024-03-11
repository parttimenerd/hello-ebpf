package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.bpf.map.BPFMap;
import me.bechberger.ebpf.bpf.map.BPFRingBuffer;
import me.bechberger.ebpf.samples.RingSample;
import me.bechberger.ebpf.shared.BPFType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests the ring buffer
 * <p>
 * Based on {@link me.bechberger.ebpf.samples.RingSample} which
 * is based on <a href="https://ansilh.com/posts/09-ebpf-for-linux-admins-part9/">ebpf for linux admins part 9</a>
 */
public class RingBufferTest {

    @BPF
    public static abstract class Prog extends BPFProgram {
        static final String EBPF_PROGRAM = """
            #include "vmlinux.h"
            #include <bpf/bpf_helpers.h>
            #include <bpf/bpf_tracing.h>
            #include <string.h>
                            
            #define MAX_ENTRIES 10
            #define FILE_NAME_LEN 256
                            
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
              evt->e_pid = bpf_get_current_pid_tgid ();	// Get current process PID
                            
              // Read the filename from the second argument
              // The x86 arch/ABI have first argument in di and second in si registers (man syscall)\s
              bpf_probe_read (evt->e_filename, sizeof (filename), (char *) ctx->si);
                            
              // Read the current process name
              bpf_get_current_comm (evt->e_comm, sizeof (comm));
                            
              // Also send the same message to the ring-buffer
              bpf_ringbuf_submit (evt, 0);
              return 0;
            }
                            
            char _license[] SEC ("license") = "GPL";
            """;
    }

    /**
     * Triggers a openat syscall and returns the path of the file that was opened
     */
    private static Path triggerOpenAt() {
        try {
            var path = Files.createTempFile("test", "txt");
            Files.write(path, "Hello, World!".getBytes());
            Files.delete(path);
            return path;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static final int FILE_NAME_LEN = 256;
    private static final int TASK_COMM_LEN = 16;

    record Event(@Unsigned int pid, String filename, @Size(TASK_COMM_LEN) String comm) {}

    private static final BPFType.BPFStructType<Event> eventType = new BPFType.BPFStructType<>("rb", List.of(
            new BPFType.BPFStructMember<>("e_pid", BPFType.BPFIntType.UINT32, 0, Event::pid),
            new BPFType.BPFStructMember<>("e_filename", new BPFType.StringType(FILE_NAME_LEN), 4, Event::filename),
            new BPFType.BPFStructMember<>("e_comm", new BPFType.StringType(TASK_COMM_LEN), 4 + FILE_NAME_LEN, Event::comm)
    ), new BPFType.AnnotatedClass(Event.class, List.of()), fields -> new Event((int)fields.get(0),
            (String)fields.get(1), (String)fields.get(2)));

    @Test
    public void testWrongMapName() {
        try (Prog program = BPFProgram.load(Prog.class)) {
            program.autoAttachProgram(program.getProgramByName("kprobe__do_sys_openat2"));
            assertThrows(BPFProgram.BPFMapNotFoundError.class,
                    () -> program.getRingBufferByName("wrong-name",
                    eventType,
                    (buffer, event) -> {}));
        }
    }

    @Test
    public void testWrongMapType() {
        try (Prog program = BPFProgram.load(Prog.class)) {
            program.autoAttachProgram(program.getProgramByName("kprobe__do_sys_openat2"));
            assertThrows(BPFMap.BPFMapTypeMismatch.class,
                    () -> program.getRingBufferByName("non_ring_buffer",
                            eventType,
                            (buffer, event) -> {}));
        }
    }

    @Test
    @Timeout(5)
    public void testSuccessfulCase() throws InterruptedException {
        try (RingSample program = BPFProgram.load(RingSample.class)) {
            program.autoAttachProgram(program.getProgramByName("kprobe__do_sys_openat2"));
            AtomicReference<Event> eventRef = new AtomicReference<>();
            var ringBuffer = program.getRingBufferByName("rb", eventType, (buffer, event) -> {
                eventRef.set(event);
            });
            Path openendPath = triggerOpenAt();
            long start = System.currentTimeMillis();
            while (System.currentTimeMillis() - start < 1000) {
                Thread.sleep(10);
                int ret = ringBuffer.consumeAndThrow();
                if (ret != 0) {
                    assertNotNull(eventRef.get());
                    assertEquals(openendPath.toString(), eventRef.get().filename);
                    break;
                }
            }
            assertTrue(System.currentTimeMillis() - start < 1000);
        }
    }

    @Test
    @Timeout(5)
    public void testFailingCallback() throws InterruptedException {
        try (RingSample program = BPFProgram.load(RingSample.class)) {
            program.autoAttachProgram(program.getProgramByName("kprobe__do_sys_openat2"));
            AtomicReference<Throwable> throwableRef = new AtomicReference<>();
            var ringBuffer = program.getRingBufferByName("rb", eventType, (buffer, event) -> {
                var throwable = new RuntimeException("Test");
                throwableRef.set(throwable);
                throw throwable;
            });
            triggerOpenAt();
            long start = System.currentTimeMillis();
            while (System.currentTimeMillis() - start < 1000) {
                Thread.sleep(10);
                var ret = ringBuffer.consume();
                if (throwableRef.get() != null) {
                    assertEquals(throwableRef.get(), ret.caughtErrorsInCallBack().getLast().exception());
                    assertInstanceOf(BPFRingBuffer.CaughtBPFRingBufferError.CaughtBPFRingBufferCallbackError.class,
                            ret.caughtErrorsInCallBack().getLast());
                    break;
                }
            }
            assertTrue(System.currentTimeMillis() - start < 1000);
        }
    }

    private static final BPFType.BPFStructType<Event> brokenEventType = new BPFType.BPFStructType<>("rb", eventType.members(),
            new BPFType.AnnotatedClass(Event.class, List.of()), fields -> {
        throw new RuntimeException("Test");
    });

    @Test
    @Timeout(5)
    public void testFailingParse() throws InterruptedException {
        try (RingSample program = BPFProgram.load(RingSample.class)) {
            program.autoAttachProgram(program.getProgramByName("kprobe__do_sys_openat2"));
            var ringBuffer = program.getRingBufferByName("rb", brokenEventType, (buffer, event) -> {});
            long start = System.currentTimeMillis();
            triggerOpenAt();
            while (System.currentTimeMillis() - start < 1000) {
                Thread.sleep(10);
                var ret = ringBuffer.consume();
                if (ret.hasCaughtErrors()) {
                    var last = ret.caughtErrorsInCallBack().getLast();
                    assertInstanceOf(BPFRingBuffer.CaughtBPFRingBufferError.CaughtBPFRingBufferParseError.class, last);
                    assertEquals("Test", last.exception().getMessage());
                    break;
                }
            }
            assertTrue(System.currentTimeMillis() - start < 1000);
        }
    }
}
