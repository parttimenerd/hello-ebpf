package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.KProbeMulti;
import me.bechberger.ebpf.bpf.BPFJ;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.type.Ptr;

import java.util.ArrayList;
import java.util.Comparator;

/**
 * Attaches one BPF program to 20 x86_64 syscall entries via
 * {@link BPFProgram#attachKProbeMulti} and prints the top-10 by call count.
 */
@BPF(license = "GPL")
public abstract class KProbeMultiCounter extends BPFProgram {
    static final String EBPF_PROGRAM = """
            #include <vmlinux.h>
            #include <bpf/bpf_helpers.h>
            """;

    @BPFMapDefinition(maxEntries = 64)
    BPFHashMap<Long, Long> counts;

    @BPFFunction(section = "kprobe.multi/all", autoAttach = false)
    @KProbeMulti("*")
    int onSyscall(Ptr<?> ctx) {
        long cookie = BPFJ.bpf_get_attach_cookie(ctx);
        Ptr<Long> cur = counts.bpf_get(cookie);
        long next;
        if (cur == null) {
            next = 1;
        } else {
            next = cur.val() + 1;
        }
        counts.put(cookie, next);
        return 0;
    }

    public static void main(String[] args) throws Exception {
        String[] syms = {
                "__x64_sys_read",  "__x64_sys_write",  "__x64_sys_open",
                "__x64_sys_close", "__x64_sys_stat",   "__x64_sys_fstat",
                "__x64_sys_lstat", "__x64_sys_poll",   "__x64_sys_lseek",
                "__x64_sys_mmap",  "__x64_sys_mprotect", "__x64_sys_munmap",
                "__x64_sys_brk",   "__x64_sys_rt_sigaction",
                "__x64_sys_rt_sigprocmask", "__x64_sys_ioctl",
                "__x64_sys_pread64", "__x64_sys_pwrite64", "__x64_sys_readv",
                "__x64_sys_writev"
        };
        long[] cookies = new long[syms.length];
        for (int i = 0; i < syms.length; i++) cookies[i] = i;

        try (var prog = BPFProgram.load(KProbeMultiCounter.class)) {
            prog.attachKProbeMulti(prog.getProgramByName("onSyscall"),
                    syms, cookies, false);
            System.out.println("Sampling for 5s...");
            Thread.sleep(5000);

            record Row(String sym, long count) {}
            var rows = new ArrayList<Row>();
            for (int i = 0; i < syms.length; i++) {
                Long v = prog.counts.get((long) i);
                rows.add(new Row(syms[i], v == null ? 0 : v));
            }
            rows.sort(Comparator.comparingLong(Row::count).reversed());
            System.out.println("Top 10:");
            rows.stream().limit(10).forEach(r ->
                    System.out.printf("  %-32s %d%n", r.sym(), r.count()));
        }
    }
}
