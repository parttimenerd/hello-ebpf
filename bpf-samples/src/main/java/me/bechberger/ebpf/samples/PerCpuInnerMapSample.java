package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.InnerMap;
import me.bechberger.ebpf.bpf.BPFJ;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.bpf.map.BPFHashOfMaps;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;

import java.util.HashMap;
import java.util.Map;

/**
 * HASH_OF_MAPS sample: outer keyed by CPU id, inner is a HashMap of per-syscall
 * call counts. Each CPU gets its own inner so writes are contention-free on the
 * hot path. Userspace aggregates the per-CPU inners at read time.
 */
@BPF(license = "GPL")
public abstract class PerCpuInnerMapSample extends BPFProgram {

    /** Template inner map - the processor uses this to teach libbpf the inner layout. */
    @BPFMapDefinition(maxEntries = 512)
    BPFHashMap<@Unsigned Long, @Unsigned Long> innerTemplate;

    /** Outer map: cpu_id -&gt; per-cpu inner hash map of syscall counts. */
    @InnerMap("innerTemplate")
    @BPFMapDefinition(maxEntries = 256)
    BPFHashOfMaps<@Unsigned Integer, BPFHashMap<@Unsigned Long, @Unsigned Long>> perCpu;

    @BPFFunction(
            headerTemplate = "int BPF_PROG($name, $params)",
            lastStatement = "return 0;",
            section = "raw_tracepoint/sys_enter",
            autoAttach = false
    )
    public void countSyscall(Ptr<PtDefinitions.pt_regs> regs, @Unsigned long nr) {
        int cpu = BPFJ.currentCpuId();
        Ptr<BPFHashMap<Long, Long>> inner = perCpu.lookup(cpu);
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
     * Registers the template inner map at slots {@code [0, numCpus)}, runs for
     * {@code seconds}, and returns the aggregated syscall counts.
     *
     * <p>For the sample we register the same physical inner map at multiple
     * outer keys - kernel accepts this as long as the template matches. Real
     * apps that want per-CPU isolation should allocate distinct inner maps via
     * {@code bpf_map_create}.
     */
    public Map<Long, Long> run(int seconds, int numCpus) throws InterruptedException {
        for (int cpu = 0; cpu < numCpus; cpu++) {
            perCpu.register(cpu, innerTemplate);
        }
        rawTracepointAttach("countSyscall", "sys_enter");
        Thread.sleep(seconds * 1000L);

        HashMap<Long, Long> total = new HashMap<>();
        for (var entry : innerTemplate) {
            total.merge(entry.getKey(), entry.getValue(), Long::sum);
        }
        return total;
    }

    public static void main(String[] args) throws InterruptedException {
        int numCpus = Runtime.getRuntime().availableProcessors();
        try (PerCpuInnerMapSample program = BPFProgram.load(PerCpuInnerMapSample.class)) {
            Map<Long, Long> counts = program.run(3, numCpus);
            System.out.println("Total syscalls by nr (top 10):");
            counts.entrySet().stream()
                    .sorted(Map.Entry.<Long, Long>comparingByValue().reversed())
                    .limit(10)
                    .forEach(e -> System.out.printf("  nr=%3d  count=%d%n",
                            e.getKey(), e.getValue()));
        }
    }
}
