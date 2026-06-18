package me.bechberger.ebpf.bpf.compiler;

import me.bechberger.ebpf.annotations.Kptr;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.*;
import me.bechberger.ebpf.bpf.BPFJ;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.Scheduler;
import me.bechberger.ebpf.bpf.SchedulerBase;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.bpf.map.BPFTaskStorage;
import me.bechberger.ebpf.bpf.map.BPFTimerMap;
import me.bechberger.ebpf.runtime.BpfDefinitions.bpf_cpumask;
import me.bechberger.ebpf.runtime.BpfDefinitions.bpf_timer;
import me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;
import me.bechberger.ebpf.runtime.XdpDefinitions.xdp_action;
import me.bechberger.ebpf.runtime.XdpDefinitions.xdp_md;
import me.bechberger.ebpf.bpf.XDPHook;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;

import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.bpf_timer_init;
import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.bpf_timer_start;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_bpf_create_dsq;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_bpf_dsq_move_to_local;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_public_consts.SCX_SLICE_DFL;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Compiler-plugin unit tests for framework features added in Items 1–2, 4–7.
 *
 * <p>Each test calls {@link BPFProgram#getCode} to trigger the full
 * annotation-processing + compiler-plugin pipeline and checks specific tokens
 * in the generated C without running a kernel.
 */
public class SchedulerFeatureTest {

    // -------------------------------------------------------------------------
    // Minimal Scheduler stub — used by tests that only need the after= block
    // -------------------------------------------------------------------------

    @BPF(license = "GPL")
    @Property(name = "sched_name", value = "test_sched")
    public static abstract class MinimalScheduler extends SchedulerBase implements Scheduler {

        @Override
        public int init() {
            return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
        }

        @Override
        public void enqueue(Ptr<task_struct> p, long enq_flags) {
            dsqInsert(p, enq_flags);
        }

        @Override
        public void dispatch(int cpu, Ptr<task_struct> prev) {
            scx_bpf_dsq_move_to_local(SHARED_DSQ_ID);
        }
    }

    // -------------------------------------------------------------------------
    // Item 1: extra_flags @Property substitution
    // -------------------------------------------------------------------------

    @BPF(license = "GPL")
    @Property(name = "sched_name", value = "extra_flags_sched")
    @Property(name = "extra_flags", value = "42")
    public static abstract class ExtraFlagsScheduler extends SchedulerBase implements Scheduler {

        @Override
        public int init() {
            return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
        }

        @Override
        public void enqueue(Ptr<task_struct> p, long enq_flags) {
            dsqInsert(p, enq_flags);
        }

        @Override
        public void dispatch(int cpu, Ptr<task_struct> prev) {
            scx_bpf_dsq_move_to_local(SHARED_DSQ_ID);
        }
    }

    @Test
    public void testExtraFlagsPropertySubstituted() {
        var code = BPFProgram.getCode(ExtraFlagsScheduler.class);
        // __property_extra_flags token must be gone — replaced by the value
        assertFalse(code.contains("__property_extra_flags"),
                "extra_flags placeholder was not substituted in:\n" + code);
        // The value 42 must appear in the flags field
        assertTrue(code.contains("(42)"),
                "expected (42) in the flags expression:\n" + code);
    }

    // -------------------------------------------------------------------------
    // Item 2: runnable() ops slot appears in SCX_OPS_DEFINE
    // -------------------------------------------------------------------------

    @Test
    public void testRunnableOpsSlotEmitted() {
        var code = BPFProgram.getCode(MinimalScheduler.class);
        assertTrue(code.contains(".runnable"),
                "expected .runnable in SCX_OPS_DEFINE:\n" + code);
        assertTrue(code.contains("sched_runnable"),
                "expected sched_runnable function in generated C:\n" + code);
    }

    // -------------------------------------------------------------------------
    // Item 4: BPFTaskStorage map emits BPF_MAP_TYPE_TASK_STORAGE
    // -------------------------------------------------------------------------

    @BPF(license = "GPL")
    public static abstract class TaskStorageProgram extends BPFProgram {

        @Type
        public static class TaskCtx {
            public long counter;
        }

        @BPFMapDefinition(maxEntries = 1)
        BPFTaskStorage<TaskCtx> storage;
    }

    @Test
    public void testTaskStorageMapTypeEmitted() {
        var code = BPFProgram.getCode(TaskStorageProgram.class);
        assertTrue(code.contains("BPF_MAP_TYPE_TASK_STORAGE"),
                "expected BPF_MAP_TYPE_TASK_STORAGE in:\n" + code);
        assertTrue(code.contains("BPF_F_NO_PREALLOC"),
                "expected BPF_F_NO_PREALLOC flag for task storage in:\n" + code);
    }

    // -------------------------------------------------------------------------
    // Item 5: @Kptr field emits __kptr qualifier
    // -------------------------------------------------------------------------

    @BPF(license = "GPL")
    public static abstract class KptrProgram extends BPFProgram {

        @Type
        public static class WithKptr {
            @Kptr public Ptr<bpf_cpumask> mask;
        }
    }

    @Test
    public void testKptrFieldEmitsKptrQualifier() {
        var code = BPFProgram.getCode(KptrProgram.class);
        assertTrue(code.contains("__kptr"),
                "expected __kptr qualifier for @Kptr-annotated field in:\n" + code);
    }

    // -------------------------------------------------------------------------
    // Item 6: bpf_timer_set_callback with method reference lowers to C name
    // -------------------------------------------------------------------------

    @BPF(license = "GPL")
    public static abstract class TimerMethodRefProgram extends BPFProgram implements XDPHook {

        @Type
        public static class TimerVal {
            public bpf_timer timer;
            public @Unsigned int initialized;
        }

        @BPFMapDefinition(maxEntries = 1)
        BPFHashMap<@Unsigned Integer, TimerVal> timerMap;

        @BPFFunction
        public int onTick(Ptr<?> map, Ptr<Integer> key, Ptr<TimerVal> val) {
            bpf_timer_start(Ptr.of(val.val().timer), 1_000_000_000L, 0);
            return 0;
        }

        @Override
        public xdp_action xdpHandlePacket(Ptr<xdp_md> ctx) {
            int key = 0;
            Ptr<TimerVal> val = timerMap.bpf_get(key);
            if (val == null) {
                return xdp_action.XDP_PASS;
            }
            if (val.val().initialized == 0) {
                val.val().initialized = 1;
                bpf_timer_init(Ptr.of(val.val().timer), Ptr.of(timerMap), 1);
                BPFJ.bpf_timer_set_callback(Ptr.of(val.val().timer), this::onTick);
                bpf_timer_start(Ptr.of(val.val().timer), 1_000_000_000L, 0);
            }
            return xdp_action.XDP_PASS;
        }
    }

    @Test
    public void testTimerMethodRefLoweredToCName() {
        var code = BPFProgram.getCode(TimerMethodRefProgram.class);
        // Method reference this::onTick must be lowered to bare C identifier "onTick"
        assertTrue(code.contains("onTick"),
                "expected onTick as C callback identifier in:\n" + code);
        // The call site must not contain a Java method-reference literal
        assertFalse(code.contains("this::"),
                "Java method-reference syntax must not appear in generated C:\n" + code);
        assertTrue(code.contains("bpf_timer_set_callback"),
                "expected bpf_timer_set_callback call in:\n" + code);
    }

    // -------------------------------------------------------------------------
    // Item 7: SEC("syscall") produces correct function header
    // -------------------------------------------------------------------------

    @BPF(license = "GPL")
    public static abstract class SyscallProgram extends BPFProgram {

        @Type
        public static class Ctx {
            public int a;
            public int b;
            public int result;
        }

        @BPFFunction(
                headerTemplate = "int $name($params)",
                section = "syscall",
                autoAttach = false
        )
        public int compute(Ptr<Ctx> input) {
            input.val().result = input.val().a + input.val().b;
            return input.val().result;
        }
    }

    @Test
    public void testSyscallSectionHeaderEmitted() {
        var code = BPFProgram.getCode(SyscallProgram.class);
        assertTrue(code.contains("SEC(\"syscall\")"),
                "expected SEC(\"syscall\") in generated C:\n" + code);
        assertTrue(code.contains("int compute("),
                "expected compute function definition in:\n" + code);
    }

    // -------------------------------------------------------------------------
    // Feature A: BPFTimerMap — value type is timer_val with bpf_timer field
    // -------------------------------------------------------------------------

    @BPF(license = "GPL")
    public static abstract class TimerMapProgram extends BPFProgram implements XDPHook {

        @BPFMapDefinition(maxEntries = 1)
        BPFTimerMap<BPFTimerMap.TimerVal> timerMap;

        @BPFTimer
        @BPFFunction
        public int onTick(Ptr<?> map, Ptr<Integer> key, Ptr<BPFTimerMap.TimerVal> val) {
            bpf_timer_start(Ptr.of(val.val().timer), 500_000_000L, 0);
            return 0;
        }

        @Override
        public xdp_action xdpHandlePacket(Ptr<xdp_md> ctx) {
            Ptr<BPFTimerMap.TimerVal> slot = timerMap.bpf_get(0);
            if (slot != null && slot.val().initialized == 0) {
                slot.val().initialized = 1;
                bpf_timer_init(Ptr.of(slot.val().timer), Ptr.of(timerMap), 1);
                BPFJ.bpf_timer_set_callback(Ptr.of(slot.val().timer), this::onTick);
                bpf_timer_start(Ptr.of(slot.val().timer), 500_000_000L, 0);
            }
            return xdp_action.XDP_PASS;
        }
    }

    @Test
    public void testBPFTimerMapEmitsHashMapWithTimerVal() {
        var code = BPFProgram.getCode(TimerMapProgram.class);
        assertTrue(code.contains("BPF_MAP_TYPE_HASH"),
                "expected BPF_MAP_TYPE_HASH in:\n" + code);
        assertTrue(code.contains("bpf_timer"),
                "expected bpf_timer field in value type in:\n" + code);
        assertTrue(code.contains("initialized"),
                "expected initialized field in value type in:\n" + code);
    }

    // -------------------------------------------------------------------------
    // Feature C: BPFJ.bpfRand / bpfRandBounded emit correct C expressions
    // -------------------------------------------------------------------------

    @BPF(license = "GPL")
    public static abstract class RandProgram extends BPFProgram implements XDPHook {

        @BPFFunction
        @Override
        public xdp_action xdpHandlePacket(Ptr<xdp_md> ctx) {
            @Unsigned int r = BPFJ.bpfRand();
            @Unsigned int b = BPFJ.bpfRandBounded(100L);
            return xdp_action.XDP_PASS;
        }
    }

    @Test
    public void testBpfRandEmitsPrandom() {
        var code = BPFProgram.getCode(RandProgram.class);
        assertTrue(code.contains("bpf_get_prandom_u32()"),
                "expected bpf_get_prandom_u32() in:\n" + code);
    }

    @Test
    public void testBpfRandBoundedEmitsLemireExpression() {
        var code = BPFProgram.getCode(RandProgram.class);
        assertTrue(code.contains("bpf_get_prandom_u32()"),
                "expected bpf_get_prandom_u32() in bounded rand expression in:\n" + code);
        assertTrue(code.contains(">> 32"),
                "expected >> 32 (Lemire shift) in bounded rand expression in:\n" + code);
    }

    // -------------------------------------------------------------------------
    // Feature D: Scheduler.isDescendantOf emits bounded loop over real_parent
    // -------------------------------------------------------------------------

    @BPF(license = "GPL")
    @Property(name = "sched_name", value = "descendant_sched")
    public static abstract class DescendantScheduler extends SchedulerBase implements Scheduler {

        @Override
        public int init() {
            return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
        }

        @Override
        public void enqueue(Ptr<task_struct> p, long enq_flags) {
            if (isDescendantOf(p, 12345)) {
                dsqInsert(p, enq_flags);
            } else {
                dsqInsert(p, enq_flags);
            }
        }

        @Override
        public void dispatch(int cpu, Ptr<task_struct> prev) {
            scx_bpf_dsq_move_to_local(SHARED_DSQ_ID);
        }
    }

    @Test
    public void testIsDescendantOfEmitsBoundedLoop() {
        var code = BPFProgram.getCode(DescendantScheduler.class);
        assertTrue(code.contains("real_parent"),
                "expected real_parent traversal in isDescendantOf:\n" + code);
        assertTrue(code.contains("tgid"),
                "expected tgid comparison in isDescendantOf:\n" + code);
        assertTrue(code.contains("isDescendantOf"),
                "expected isDescendantOf function in generated C:\n" + code);
    }
}
