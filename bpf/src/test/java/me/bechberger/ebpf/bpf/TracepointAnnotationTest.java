package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.Tracepoint;
import me.bechberger.ebpf.runtime.OpenDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies that the {@code @Tracepoint} shorthand annotation generates the correct
 * {@code tp/<category>/<name>} section and auto-attaches successfully.
 *
 * <p>The existing {@link TracepointAttachTest} uses a raw {@code @BPFFunction} with an
 * explicit section string. This test uses the dedicated {@code @Tracepoint} annotation
 * shorthand, confirming end-to-end section derivation and auto-attach.
 */
public class TracepointAnnotationTest {

    /** Minimal tracepoint context for {@code sys_enter_openat}. */
    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {
        @Type
        record SyscallCtx(
                @Unsigned short common_type,
                byte common_flags,
                byte common_preempt_count,
                int common_pid,
                int __syscall_nr
        ) {}

        @Type
        record OpenAt2Args(@Unsigned int dfd, Ptr<Byte> filename,
                           Ptr<OpenDefinitions.open_how> how, @Unsigned long usize) {}

        @Type
        record OpenAtCtx(SyscallCtx syscall, OpenAt2Args args) {}

        final GlobalVariable<Boolean> triggered = new GlobalVariable<>(false);

        @Tracepoint(category = "syscalls", name = "sys_enter_openat")
        int onSysEnterOpenAt(Ptr<OpenAtCtx> ctx) {
            triggered.set(true);
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testTracepointAnnotationFires() {
        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();
            long deadline = System.currentTimeMillis() + 5000;
            while (!program.triggered.get() && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) {}
            }
            assertTrue(program.triggered.get(),
                    "@Tracepoint(syscalls/sys_enter_openat) should have fired");
        }
    }
}
