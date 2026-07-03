package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.KProbeMulti;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class KProbeMultiSmokeTest {

    @BPF(license = "GPL")
    public static abstract class MultiProg extends BPFProgram {
        static final String EBPF_PROGRAM = """
                #include <vmlinux.h>
                #include <bpf/bpf_helpers.h>
                """;

        @BPFMapDefinition(maxEntries = 64)
        BPFHashMap<Long, Long> hits;

        @BPFFunction(section = "kprobe.multi/dummy", autoAttach = false)
        @KProbeMulti("*")
        int onMany(Ptr<?> ctx) {
            long cookie = BPFJ.bpf_get_attach_cookie(ctx);
            Ptr<Long> cur = hits.bpf_get(cookie);
            long next;
            if (cur == null) {
                next = 1;
            } else {
                next = cur.val() + 1;
            }
            hits.put(cookie, next);
            return 0;
        }
    }

    @Test
    void multiAttachTenSymbolsAndReadPerCookieCounters() throws Exception {
        String[] syms = {
                "__x64_sys_getuid", "__x64_sys_geteuid", "__x64_sys_getgid",
                "__x64_sys_getegid", "__x64_sys_getpid", "__x64_sys_gettid",
                "__x64_sys_getppid", "__x64_sys_umask", "__x64_sys_setsid",
                "__x64_sys_setuid"
        };
        long[] cookies = new long[syms.length];
        for (int i = 0; i < syms.length; i++) cookies[i] = 0x1000L + i;

        try (var prog = BPFProgram.load(MultiProg.class)) {
            prog.attachKProbeMulti(prog.getProgramByName("onMany"), syms, cookies, false);
            for (int i = 0; i < 5; i++) {
                Runtime.getRuntime().exec(new String[]{"/bin/id"}).waitFor();
            }
            int matched = 0;
            for (long c : cookies) {
                Long v = prog.hits.get(c);
                if (v != null && v > 0) matched++;
            }
            assertTrue(matched >= 5,
                    "expected >=5 of 10 symbol cookies to fire, got " + matched);
        }
    }
}
