package me.bechberger.ebpf.bpf.structops;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.runtime.BpfDefinitions;
import me.bechberger.ebpf.runtime.NetlinkDefinitions;
import me.bechberger.ebpf.runtime.SkDefinitions;
import me.bechberger.ebpf.runtime.runtime;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Smoke test for {@link QdiscOps}: loads a minimal BPF-driven qdisc,
 * confirms attach registers a struct_ops of kind {@code Qdisc_ops},
 * and that close cleans up without error.
 *
 * <p>Requires {@code CONFIG_NET_SCH_BPF=y} and a kernel ≥ 6.10 —
 * both satisfied by the thinkstation vng test kernel (6.17+).
 */
class QdiscOpsSmokeTest {

    /**
     * Minimum viable {@code Qdisc_ops} — the kernel's {@code bpf_qdisc_reg}
     * requires enqueue, dequeue, reset, destroy, and init to all be present.
     * enqueue drops every skb via {@code bpf_kfree_skb} and returns
     * {@code NET_XMIT_DROP} (= 1); dequeue returns NULL; reset/destroy are
     * no-ops; init returns 0.
     */
    @BPF(license = "GPL")
    abstract static class MinimalQdisc extends BPFProgram implements QdiscOps {

        @Override
        public int enqueue(Ptr<SkDefinitions.sk_buff> skb, Ptr<runtime.Qdisc> sch,
                           Ptr<Ptr<SkDefinitions.sk_buff>> toFree) {
            BpfDefinitions.bpf_kfree_skb(skb);
            return 1;
        }

        @Override
        public Ptr<SkDefinitions.sk_buff> dequeue(Ptr<runtime.Qdisc> sch) {
            return null;
        }

        @Override
        public int init(Ptr<runtime.Qdisc> sch, Ptr<runtime.nlattr> opt,
                        Ptr<NetlinkDefinitions.netlink_ext_ack> extack) {
            return 0;
        }

        @Override
        public void reset(Ptr<runtime.Qdisc> sch) { }

        @Override
        public void destroy(Ptr<runtime.Qdisc> sch) { }

        @Override
        public String id() { return "bpftest_qdisc"; }
    }

    @Test
    void attachSucceedsAndDetachesCleanly() throws Exception {
        try (var prog = BPFProgram.load(MinimalQdisc.class)) {
            var infos = prog.structOpsInfo();
            assertEquals(1, infos.size(),
                    "expected exactly one @StructOps attach for MinimalQdisc; got " + infos);
            var only = infos.get(0);
            assertEquals("Qdisc_ops", only.kernelName(),
                    "kernelName should match the BTF struct type");
            assertEquals("MinimalQdisc", only.mapName(),
                    "mapName should match the C-side struct variable name");
            assertTrue(only.mapFd() > 0,
                    "mapFd should be a valid file descriptor; got " + only.mapFd());
            assertNotEquals(0L, only.bpfLinkId(),
                    "bpfLinkId should be non-zero after attach; got " + only.bpfLinkId());
        }
    }
}
