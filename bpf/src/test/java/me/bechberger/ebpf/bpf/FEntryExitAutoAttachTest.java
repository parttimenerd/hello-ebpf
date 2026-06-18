package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.bpf.map.BPFRingBuffer;
import me.bechberger.ebpf.runtime.OpenDefinitions;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.runtime.interfaces.SystemCallHooks;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

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

        @BPFFunction(section = "fexit/do_sys_openat2", autoAttach = true, name = "do_openat2_exit")
        int doOpenat2Exit(Ptr<PtDefinitions.pt_regs> ctx) {
            return 0;
        }

        @Kprobe("do_sys_openat2")
        int kprobe__do_sys_openat2(Ptr<PtDefinitions.pt_regs> ctx) {
            return 0;
        }
    }

    @Test
    @Timeout(15)
    public void testOpenAt() throws Exception {
        Path testFile = Path.of("");
        List<String> files = new ArrayList<>();
        try (var program = BPFProgram.load(OpenAt.class)) {
            program.autoAttachPrograms();
            program.targetPid.set((int) ProcessHandle.current().pid());
            program.pathBuffer.setCallback(path -> files.add(path));
            testFile = TestUtil.triggerOpenAt();
            final Path expected = testFile;
            long deadline = System.currentTimeMillis() + 5000;
            while (!files.contains(expected.toString()) && System.currentTimeMillis() < deadline) {
                try {
                    program.pathBuffer.consume();
                } catch (Exception e) {
                    // ring buffer consume may throw if no events — ignore
                }
                if (!files.contains(expected.toString())) {
                    Thread.sleep(50);
                }
            }
            assertTrue(files.contains(testFile.toString()),
                    "Expected '" + testFile + "' in captured paths; got: " + files);
        }
    }

    @Test
    public void testAutoAttachAll() {
        try (var program = BPFProgram.load(OpenAt.class)) {
            assertEquals(Stream.of("do_openat2_exit", "enterOpenat2", "kprobe__do_sys_openat2").sorted().toList(), program.getAllAutoAttachablePrograms().stream().sorted().toList());
        }
    }
}
