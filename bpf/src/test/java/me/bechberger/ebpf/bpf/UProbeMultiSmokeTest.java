package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.UProbeMulti;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class UProbeMultiSmokeTest {

    @BPF(license = "GPL")
    public static abstract class UProg extends BPFProgram {
        static final String EBPF_PROGRAM = """
                #include <vmlinux.h>
                #include <bpf/bpf_helpers.h>
                """;

        @BPFMapDefinition(maxEntries = 32)
        BPFHashMap<Long, Long> hits;

        @BPFFunction(section = "uprobe.multi/dummy", autoAttach = false)
        @UProbeMulti("*")
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
    void multiAttachThreeLibcFuncsAndTriggerFromChild() throws Exception {
        String binaryPath = "/usr/lib/x86_64-linux-gnu/libc.so.6";
        String[] funcs   = { "malloc", "free", "getenv" };
        long[]   cookies = { 0x11L, 0x22L, 0x33L };

        try (var prog = BPFProgram.load(UProg.class)) {
            try {
                prog.attachUprobeMulti(prog.getProgramByName("onMany"),
                        binaryPath, funcs, cookies, false);
            } catch (BPFProgram.BPFAttachError e) {
                // EINVAL (22) means uprobe multi-attach is not supported on this kernel
                assumeTrue(e.getErrorCode() != 22,
                        "uprobe multi-attach not available on this kernel (EINVAL): " + e.getMessage());
                throw e;
            }
            // /bin/ls hits all three of malloc/free/getenv.
            Runtime.getRuntime().exec(new String[]{"/bin/ls", "/"}).waitFor();

            int matched = 0;
            for (long c : cookies) {
                Long v = prog.hits.get(c);
                if (v != null && v > 0) matched++;
            }
            assertEquals(3, matched,
                    "all three libc functions should have fired at least once");
        }
    }
}
