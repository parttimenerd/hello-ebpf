package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CookieAttachTest {

    @BPF(license = "GPL")
    public static abstract class CookieProg extends BPFProgram {
        static final String EBPF_PROGRAM = """
                #include <vmlinux.h>
                #include <bpf/bpf_helpers.h>
                #include <bpf/bpf_tracing.h>
                """;

        @BPFMapDefinition(maxEntries = 16)
        BPFHashMap<Long, Long> perCookieCount;

        @BPFFunction(section = "kprobe/__x64_sys_getuid", autoAttach = false)
        int onGetuid(Ptr<?> ctx) {
            long cookie = BPFJ.bpf_get_attach_cookie(ctx);
            Ptr<Long> cur = perCookieCount.bpf_get(cookie);
            long next;
            if (cur == null) {
                next = 1;
            } else {
                next = cur.val() + 1;
            }
            perCookieCount.put(cookie, next);
            return 0;
        }
    }

    @Test
    void twoAttachmentsWithDistinctCookiesAreDisambiguated() throws Exception {
        try (var prog = BPFProgram.load(CookieProg.class)) {
            var handle = prog.getProgramByName("onGetuid");
            // Attach the SAME program twice: once on __x64_sys_getuid, once on
            // __x64_sys_geteuid, with different cookies.
            prog.attachKProbe(handle, "__x64_sys_getuid",  false, 0xAAAAL);
            prog.attachKProbe(handle, "__x64_sys_geteuid", false, 0xBBBBL);

            // Trigger both syscalls a handful of times via /bin/id (invokes
            // getuid/geteuid).
            for (int i = 0; i < 5; i++) {
                Runtime.getRuntime().exec(new String[]{"/bin/id"}).waitFor();
            }

            Long a = prog.perCookieCount.get(0xAAAAL);
            Long b = prog.perCookieCount.get(0xBBBBL);
            assertNotNull(a, "cookie 0xAAAA should have counted at least one call");
            assertNotNull(b, "cookie 0xBBBB should have counted at least one call");
            assertTrue(a > 0);
            assertTrue(b > 0);
        }
    }
}
