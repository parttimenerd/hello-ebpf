package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.shared.TraceLog;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test for fentry and fexit
 * <p>
 * Based on <a href="https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/fentry.bpf.c">libbpf-bootstrap</a>
 */
public class FEntryExitAutoAttachTest {

    @BPF(license = "GPL")
    public static abstract class UnlinkAt extends BPFProgram {

        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                #include <bpf/bpf_tracing.h>
                
                SEC("fentry/do_unlinkat")
                int BPF_PROG(do_unlinkat, int dfd, struct filename *name)
                {
                	pid_t pid;
                	pid = bpf_get_current_pid_tgid() >> 32;
                	bpf_printk("fentry: pid = %d, filename = %s\\n", pid, name->name);
                	return 0;
                }
                
                SEC("fexit/do_unlinkat")
                int BPF_PROG(do_unlinkat_exit, int dfd, struct filename *name, long ret)
                {
                	pid_t pid;
                	pid = bpf_get_current_pid_tgid() >> 32;
                	bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\\n", pid, name->name, ret);
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
    public void testUnlinkAt() {
        try (var program = BPFProgram.load(UnlinkAt.class).autoAttachPrograms()) {
            var testFile = TestUtil.triggerOpenAt();
            var line = program.readTraceFields();
            assertTrue(line.msg().contains(testFile.toString()));
            TraceLog.getInstance().readAllAvailableLines();
        }
    }

    @Test
    public void testAutoAttachAll() {
        try (var program = BPFProgram.load(UnlinkAt.class)) {
            assertEquals(List.of("do_unlinkat", "do_unlinkat_exit", "kprobe__do_sys_openat2"), program.getAutoAttachablePrograms());
        }
    }
}
