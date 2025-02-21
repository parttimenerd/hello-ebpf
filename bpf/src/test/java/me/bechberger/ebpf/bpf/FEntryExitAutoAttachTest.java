package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.map.BPFRingBuffer;
import me.bechberger.ebpf.runtime.OpenDefinitions;
import me.bechberger.ebpf.runtime.interfaces.SystemCallHooks;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static me.bechberger.ebpf.bpf.BPFJ.bpf_probe_read_user_str;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test for fentry and fexit
 * <p>
 * Based on <a href="https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/fentry.bpf.c">libbpf-bootstrap</a>
 */
public class FEntryExitAutoAttachTest {

    @BPF(license = "GPL")
    public static abstract class OpenAt extends BPFProgram implements SystemCallHooks {

        final GlobalVariable<Integer> targetPid = new GlobalVariable<>(0);

        @BPFMapDefinition(maxEntries = 1024)
        BPFRingBuffer<@Size(64) String> pathBuffer;

        @Override
        public void enterOpenat2(int dfd, String filename, Ptr<OpenDefinitions.open_how> how) {
            String path = pathBuffer.reserve().asString();
            if (path != null) {
                bpf_probe_read_user_str(path, 64, filename);
                pathBuffer.submit(Ptr.of(path).<String>cast());
            }
        }

        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                #include <bpf/bpf_tracing.h>
                
                SEC("fexit/do_sys_openat2")
                int BPF_PROG(do_openat2_exit, long dfd, const char *name, struct open_how *how, long ret)
                {
                	return 0;
                }
                
                SEC ("kprobe/do_sys_openat2")
                int kprobe__do_sys_openat2 (struct pt_regs *ctx)
                {
                  return 0;
                }
                """;
    }

    @Test
    public void testOpenAt() throws IOException {
        Path testFile = Path.of("");
        List<String> files = new ArrayList<>();
        try (var program = BPFProgram.load(OpenAt.class)) {
            program.autoAttachPrograms();
            program.targetPid.set((int) ProcessHandle.current().pid());
            program.pathBuffer.setCallback(path -> {
                files.add(path);
            });
            testFile = TestUtil.triggerOpenAt();
            try {
                program.pathBuffer.consume();
            } catch (Exception e) {
                // Ignore
            }
            assertTrue(files.contains(testFile.toString()));
        }
    }

    @Test
    public void testAutoAttachAll() {
        try (var program = BPFProgram.load(OpenAt.class)) {
            assertEquals(Stream.of("do_openat2_exit", "kprobe__do_sys_openat2").sorted().toList(), program.getAutoAttachablePrograms().stream().sorted().toList());
        }
    }
}
