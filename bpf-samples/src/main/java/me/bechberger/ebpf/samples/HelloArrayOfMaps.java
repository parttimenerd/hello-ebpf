package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.InnerMap;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.map.BPFArrayOfMaps;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;

/**
 * ARRAY_OF_MAPS sample: a fixed outer array of NUM_SLOTS inner hash maps where
 * each slot represents a "priority bucket" — syscall_nr % NUM_SLOTS determines
 * the bucket, and the inner map tracks per-syscall invocation counts within
 * that bucket.
 */
@BPF(license = "GPL")
public abstract class HelloArrayOfMaps extends BPFProgram {

    static final int NUM_SLOTS = 4;

    /** Template inner map — teaches libbpf the inner layout. */
    @BPFMapDefinition(maxEntries = 512)
    BPFHashMap<@Unsigned Long, @Unsigned Long> innerTemplate;

    /** Outer array: slot index -> inner hash map of (syscall_nr -> count). */
    @InnerMap("innerTemplate")
    @BPFMapDefinition(maxEntries = NUM_SLOTS)
    BPFArrayOfMaps<BPFHashMap<@Unsigned Long, @Unsigned Long>> outerMap;

    @BPFFunction(
            headerTemplate = "int BPF_PROG($name, $params)",
            lastStatement = "return 0;",
            section = "raw_tracepoint/sys_enter",
            autoAttach = false
    )
    public void countSyscall(Ptr<PtDefinitions.pt_regs> regs, @Unsigned long nr) {
        int slot = (int) (nr % NUM_SLOTS);
        Ptr<BPFHashMap<Long, Long>> inner = outerMap.lookup(slot);
        if (inner == null) return;
        Ptr<Long> counter = inner.val().bpf_get(nr);
        if (counter != null) {
            counter.set(counter.val() + 1);
        } else {
            long one = 1L;
            inner.val().bpf_put(nr, one);
        }
    }

    /**
     * Registers NUM_SLOTS inner maps (reusing innerTemplate), attaches the
     * tracepoint, sleeps for {@code seconds}, then reads and prints per-slot
     * totals.
     */
    public long[] run(int seconds) throws InterruptedException {
        for (int slot = 0; slot < NUM_SLOTS; slot++) {
            outerMap.register(slot, innerTemplate);
        }
        rawTracepointAttach("countSyscall", "sys_enter");
        Thread.sleep(seconds * 1000L);

        long[] slotTotals = new long[NUM_SLOTS];
        for (var entry : innerTemplate) {
            int slot = (int) (entry.getKey() % NUM_SLOTS);
            slotTotals[slot] += entry.getValue();
        }
        return slotTotals;
    }

    public static void main(String[] args) throws InterruptedException {
        try (HelloArrayOfMaps program = BPFProgram.load(HelloArrayOfMaps.class)) {
            long[] totals = program.run(3);
            System.out.println("Syscall counts by priority slot (slot = syscall_nr % " + NUM_SLOTS + "):");
            for (int i = 0; i < NUM_SLOTS; i++) {
                System.out.printf("  slot %d: %d syscalls%n", i, totals[i]);
            }
        }
    }
}
