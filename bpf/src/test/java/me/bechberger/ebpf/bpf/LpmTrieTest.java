package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.bpf.map.BPFLpmTrie;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import me.bechberger.ebpf.type.Struct;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test for {@link BPFLpmTrie}.
 *
 * <p>Populates a /24 CIDR entry from the Java side, then a kprobe fires on each
 * {@code do_sys_openat2} call and looks up the current PID against the trie.
 * A match increments a counter.  We pre-populate the trie with a "match all" /0
 * entry so every lookup hits, verify the counter grows, then delete the entry
 * and verify lookups miss.
 */
public class LpmTrieTest {

    @Type
    public static class IPv4Key extends Struct {
        public @Unsigned int prefixlen;
        public @Unsigned int addr;
    }

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        @BPFMapDefinition(maxEntries = 64)
        BPFLpmTrie<IPv4Key, Long> aclMap;

        @BPFMapDefinition(maxEntries = 16)
        BPFHashMap<Integer, Long> hitCounter;

        @BPFFunction(section = "kprobe/do_sys_openat2", autoAttach = true)
        int probe(Ptr<PtDefinitions.pt_regs> ctx) {
            IPv4Key key = new IPv4Key();
            key.prefixlen = 32;
            key.addr = 0xC0A80101; // 192.168.1.1 — matches the /0 default route
            Ptr<Long> action = aclMap.bpf_get(key);
            if (action != null) {
                int cpu = BPFJ.currentCpuId();
                Ptr<Long> cnt = hitCounter.bpf_get(cpu);
                if (cnt != null) {
                    cnt.set(cnt.val() + 1);
                } else {
                    hitCounter.bpf_put(cpu, 1L);
                }
            }
            return 0;
        }
    }

    @Test
    @Timeout(15)
    public void testLpmTrieLookup() throws Exception {
        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();

            // Insert a /0 default-route entry — matches any address
            var key = new IPv4Key();
            key.prefixlen = 0;
            key.addr = 0;
            program.aclMap.put(key, 1L);

            // Trigger several openat syscalls
            for (int i = 0; i < 5; i++) {
                TestUtil.triggerOpenAt();
            }
            Thread.sleep(200);

            // Sum hits across all CPUs
            long totalHits = 0;
            var it = program.hitCounter.keyIterator();
            while (it.hasNext()) {
                Integer k = it.next();
                Long v = program.hitCounter.get(k);
                if (v != null) totalHits += v;
            }
            assertTrue(totalHits >= 5,
                    "Expected at least 5 hits from /0 entry, got " + totalHits);

            // Remove the /0 entry — subsequent lookups must miss
            program.aclMap.delete(key);

            // Drain the counter
            it = program.hitCounter.keyIterator();
            while (it.hasNext()) {
                program.hitCounter.delete(it.next());
            }

            for (int i = 0; i < 3; i++) {
                TestUtil.triggerOpenAt();
            }
            Thread.sleep(200);

            long hitsAfterDelete = 0;
            it = program.hitCounter.keyIterator();
            while (it.hasNext()) {
                Integer k = it.next();
                Long v = program.hitCounter.get(k);
                if (v != null) hitsAfterDelete += v;
            }
            assertEquals(0, hitsAfterDelete,
                    "After deleting the /0 entry, no lookups should match");
        }
    }
}
