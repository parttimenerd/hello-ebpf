package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.bpf.map.BPFArray;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests {@link BPFJ} context helpers:
 * <ul>
 *   <li>{@link BPFJ#currentPid()} — lower 32 bits of bpf_get_current_pid_tgid()</li>
 *   <li>{@link BPFJ#currentTgid()} — upper 32 bits of bpf_get_current_pid_tgid()</li>
 *   <li>{@link BPFJ#currentCpuId()} — bpf_get_smp_processor_id()</li>
 *   <li>{@link BPFJ#currentNs()} — bpf_ktime_get_ns()</li>
 * </ul>
 *
 * <p>The kprobe stores each value into a BPFArray or GlobalVariable.
 * User-space then checks that the values are in the expected range.
 *
 * <p>Index layout of the {@code results} array:
 * <pre>
 *   0 — pid
 *   1 — tgid
 *   2 — cpuId
 * </pre>
 * Nanosecond timestamp is stored in a {@code GlobalVariable<Long>}.
 */
public class BpfContextHelpersTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        @BPFMapDefinition(maxEntries = 3)
        BPFArray<Integer> results;

        final GlobalVariable<Long> ns = new GlobalVariable<>(0L);
        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) return 0;
            done.set(true);

            int pid    = BPFJ.currentPid();
            int tgid   = BPFJ.currentTgid();
            int cpuId  = BPFJ.currentCpuId();
            long kns   = BPFJ.currentNs();

            results.put(0, pid);
            results.put(1, tgid);
            results.put(2, cpuId);
            ns.set(kns);
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testContextHelpersReturnSensibleValues() throws InterruptedException {
        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();

            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }
            assertTrue(program.done.get(), "kprobe should have fired");

            int pid   = program.results.get(0);
            int tgid  = program.results.get(1);
            int cpuId = program.results.get(2);
            long kns  = program.ns.get();

            // pid and tgid should be positive
            assertTrue(pid > 0, "pid should be positive, got " + pid);
            assertTrue(tgid > 0, "tgid should be positive, got " + tgid);

            // CPU id should be in range [0, 4096)
            assertTrue(cpuId >= 0 && cpuId < 4096,
                    "cpuId should be in [0, 4096), got " + cpuId);

            // ktime ns should be positive (system has been running > 0 ns)
            assertTrue(kns > 0, "ktime_get_ns() should return a positive value, got " + kns);
        }
    }

    /**
     * Verifies that pid and tgid are both positive (sensible values).
     */
    @Test
    @Timeout(10)
    public void testPidAndTgidBothPositive() throws InterruptedException {
        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();
            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }
            assertTrue(program.done.get(), "kprobe should have fired");
            int pid  = program.results.get(0);
            int tgid = program.results.get(1);
            assertTrue(pid > 0,  "pid must be positive");
            assertTrue(tgid > 0, "tgid must be positive");
        }
    }
}
