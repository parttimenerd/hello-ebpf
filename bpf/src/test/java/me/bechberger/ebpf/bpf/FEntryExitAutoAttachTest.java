package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.shared.TraceLog;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Path;
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
    public static abstract class OpenAt extends BPFProgram {

        final GlobalVariable<Integer> targetPid = new GlobalVariable<>(0);
        private static final String SYS_PREFIX = "/sys/";

        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                #include <bpf/bpf_tracing.h>
                
                SEC("fentry/do_sys_openat2")
                int BPF_PROG(do_openat2, long dfd, const u8* name, struct open_how *how)
                {
                	char name_copy[sizeof(SYS_PREFIX)];
                	BPF_SNPRINTF(name_copy, sizeof(name_copy), "%s", name);
                	bool is_sys = bpf_strncmp(name_copy, sizeof(SYS_PREFIX), (const u8*) SYS_PREFIX) == 0;
                	pid_t pid;
                	pid = bpf_get_current_pid_tgid() >> 32;
                	if (pid == targetPid && !is_sys) {
                	    bpf_printk("fentry: pid = %d, filename = %s", pid, name);
                	}
                	return 0;
                }
                
                SEC("fexit/do_sys_openat2")
                int BPF_PROG(do_openat2_exit, long dfd, const char *name, struct open_how *how, long ret)
                {
                	char name_copy[sizeof(SYS_PREFIX)];
                	BPF_SNPRINTF(name_copy, sizeof(name_copy), "%s", name);
                	bool is_sys = bpf_strncmp(name_copy, sizeof(SYS_PREFIX), (const u8*) SYS_PREFIX) == 0;
                	pid_t pid;
                	pid = bpf_get_current_pid_tgid() >> 32;
                	if (pid == targetPid && !is_sys) {
                	    bpf_printk("fexit: pid = %d, filename = %s", pid, name);
                	}
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
        Path testFile;
        try (var program = BPFProgram.load(OpenAt.class)) {
            program.autoAttachPrograms();
            program.targetPid.set((int) ProcessHandle.current().pid());
            testFile = TestUtil.triggerOpenAt();
        }
        var entryLine = TraceLog.getInstance().readLine();
        assertTrue(entryLine.contains("fentry"), entryLine);
        assertTrue(entryLine.contains(testFile.toString()), entryLine);
        var exitLine = TraceLog.getInstance().readLine();
        assertTrue(exitLine.contains("fexit"), exitLine);
        assertTrue(exitLine.contains(testFile.toString()), exitLine);

        var line = TraceLog.getInstance().readAllAvailableLines();
    }

    @Test
    public void testAutoAttachAll() {
        try (var program = BPFProgram.load(OpenAt.class)) {
            assertEquals(List.of("do_openat2", "do_openat2_exit", "kprobe__do_sys_openat2"), program.getAutoAttachablePrograms());
        }
    }
}
