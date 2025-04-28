package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.runtime.OpenDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test for ksyscall attachment
 */
public class TracepointAttachTest {

    @BPF(license = "GPL")
    public static abstract class OpenAt extends BPFProgram {

        final GlobalVariable<Boolean> ksyscallTriggered = new GlobalVariable<>(false);
        @Type
        record OpenAt2Ctx(
                SyscallCtx syscall,
                OpenAt2Args openAt
        ) {
        }

        @Type
        record SyscallCtx(
                @Unsigned short common_type,
                byte common_flags,
                byte common_preempt_count,
                int common_pid,
                int __syscall_nr
        ) {
        }

        @Type
        record OpenAt2Args(@Unsigned int dfd, Ptr<Byte> filename, Ptr<OpenDefinitions.open_how> how, @Unsigned long usize) {
        }

        @BPFFunction(
                headerTemplate = "int $name($params)",
                section = "tp/syscalls/sys_enter_openat",
                autoAttach = true
        )
        int syscall_openat2(Ptr<OpenAt2Ctx> ctx) {
            ksyscallTriggered.set(true);
            return 0;
        }
    }


    @Test
    public void testOpenAt() {
        List<String> files = new ArrayList<>();
        try (var program = BPFProgram.load(OpenAt.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();
            assertTrue(program.ksyscallTriggered.get());
        }
    }
}
