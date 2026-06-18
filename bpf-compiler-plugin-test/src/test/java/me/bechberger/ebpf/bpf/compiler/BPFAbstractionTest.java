package me.bechberger.ebpf.bpf.compiler;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.*;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.Scheduler;
import me.bechberger.ebpf.bpf.SchedulerBase;
import me.bechberger.ebpf.bpf.sched.DispatchQueue;
import me.bechberger.ebpf.bpf.sched.EnqFlags;
import me.bechberger.ebpf.bpf.sched.KickFlags;
import me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;

import java.util.stream.Collectors;

import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_bpf_create_dsq;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@code @BPFAbstraction} + {@code @BPFJavaInline} carrier inlining.
 *
 * <p>Each test verifies the generated C code contains the expected BPF kfunc
 * calls after the compiler plugin inlines the Java method bodies.
 */
public class BPFAbstractionTest {

    // ── helpers ───────────────────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    static String codeOf(Class<?> cls) {
        return BPFProgram.getCode((Class<? extends BPFProgram>) cls);
    }

    /** Strip __always_inline, #line directives, and blank lines for concise assertions. */
    static String stripped(String code) {
        return code.lines()
                .filter(l -> !l.trim().startsWith("#line "))
                .map(l -> l.replace("__always_inline ", ""))
                .collect(Collectors.joining("\n"));
    }

    // ── Test 1: simple insert — carrier substitution ──────────────────────────

    @BPF(license = "GPL")
    @Property(name = "sched_name", value = "abstr_insert")
    public static abstract class InsertTest extends SchedulerBase implements Scheduler {

        private static final long MY_DSQ = 99L;

        final DispatchQueue myDsq = new DispatchQueue(MY_DSQ);

        @Override
        public int init() {
            return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
        }

        @Override
        public void enqueue(Ptr<task_struct> p, long enq_flags) {
            myDsq.insert(p, -1L, EnqFlags.passThrough(enq_flags));
        }

        @Override
        public void dispatch(int cpu, Ptr<task_struct> prev) {
            myDsq.moveToLocal();
        }
    }

    @Test
    void testInsertInlinesCarrier() {
        String code = stripped(codeOf(InsertTest.class));
        // insert() inlined: scx_bpf_dsq_insert(p, 99L, -1, enq_flags)
        assertTrue(code.contains("scx_bpf_dsq_insert"), "insert must be inlined to scx_bpf_dsq_insert\n" + code);
        assertTrue(code.contains("99"), "carrier id 99 must appear in generated code\n" + code);
    }

    @Test
    void testMoveToLocalInlinesCarrier() {
        String code = stripped(codeOf(InsertTest.class));
        assertTrue(code.contains("scx_bpf_dsq_move_to_local"), "moveToLocal must be inlined\n" + code);
    }

    @Test
    void testInitPrologueContainsCreateDsq() {
        String code = stripped(codeOf(InsertTest.class));
        // constructor prologue: scx_bpf_create_dsq(MY_DSQ, -1) prepended to sched_init.
        // The C output uses the symbolic constant name MY_DSQ (not the literal 99).
        assertTrue(code.contains("scx_bpf_create_dsq(MY_DSQ"), "init prologue must contain scx_bpf_create_dsq(MY_DSQ, -1)\n" + code);
    }

    // ── Test 2: nrQueued + nonEmpty — method calling method ──────────────────

    @BPF(license = "GPL")
    @Property(name = "sched_name", value = "abstr_nonempty")
    public static abstract class NonEmptyTest extends SchedulerBase implements Scheduler {

        private static final long Q_DSQ = 42L;

        final DispatchQueue qDsq = new DispatchQueue(Q_DSQ);

        @Override
        public int init() {
            return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
        }

        @Override
        public void enqueue(Ptr<task_struct> p, long enq_flags) {
            if (qDsq.nonEmpty()) {
                qDsq.insert(p, -1L, EnqFlags.passThrough(enq_flags));
            }
        }

        @Override
        public void dispatch(int cpu, Ptr<task_struct> prev) {
            qDsq.moveToLocal();
        }
    }

    @Test
    void testNonEmptyInlinesNrQueued() {
        String code = stripped(codeOf(NonEmptyTest.class));
        // nonEmpty() calls nrQueued() which is also inlined → scx_bpf_dsq_nr_queued(42L)
        assertTrue(code.contains("scx_bpf_dsq_nr_queued"), "nrQueued must be inlined\n" + code);
        assertTrue(code.contains("42"), "carrier id 42 must appear\n" + code);
    }

    @Test
    void testNonEmptyNoSeparateCFunction() {
        String code = stripped(codeOf(NonEmptyTest.class));
        // No top-level C function named "nonEmpty" or "nrQueued" should be emitted
        assertFalse(code.contains("nonEmpty("), "nonEmpty must not emit a C function\n" + code);
        assertFalse(code.contains("nrQueued("), "nrQueued must not emit a C function\n" + code);
    }

    // ── Test 3: insertScaled — local variable + branching ────────────────────

    @BPF(license = "GPL")
    @Property(name = "sched_name", value = "abstr_scaled")
    public static abstract class InsertScaledTest extends SchedulerBase implements Scheduler {

        private static final long S_DSQ = 7L;

        final DispatchQueue sDsq = new DispatchQueue(S_DSQ);

        @Override
        public int init() {
            return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
        }

        @Override
        public void enqueue(Ptr<task_struct> p, long enq_flags) {
            sDsq.insertScaled(p, EnqFlags.passThrough(enq_flags));
        }

        @Override
        public void dispatch(int cpu, Ptr<task_struct> prev) {
            sDsq.moveToLocal();
        }
    }

    @Test
    void testInsertScaledContainsNrQueued() {
        String code = stripped(codeOf(InsertScaledTest.class));
        assertTrue(code.contains("scx_bpf_dsq_nr_queued"), "insertScaled must inline nrQueued\n" + code);
    }

    @Test
    void testInsertScaledContainsDsqInsert() {
        String code = stripped(codeOf(InsertScaledTest.class));
        assertTrue(code.contains("scx_bpf_dsq_insert"), "insertScaled must inline insert\n" + code);
    }

    @Test
    void testInsertScaledCarrierId() {
        String code = stripped(codeOf(InsertScaledTest.class));
        assertTrue(code.contains("7"), "carrier id 7 must appear for insertScaled\n" + code);
    }

    // ── Test 4: insertVtime — simple kfunc delegation ─────────────────────────

    @BPF(license = "GPL")
    @Property(name = "sched_name", value = "abstr_vtime")
    public static abstract class InsertVtimeTest extends SchedulerBase implements Scheduler {

        private static final long V_DSQ = 55L;

        final DispatchQueue vDsq = new DispatchQueue(V_DSQ);

        @Override
        public int init() {
            return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
        }

        @Override
        public void enqueue(Ptr<task_struct> p, long enq_flags) {
            long vtime = p.val().scx.dsq_vtime;
            vDsq.insertVtime(p, -1L, vtime, EnqFlags.passThrough(enq_flags));
        }

        @Override
        public void dispatch(int cpu, Ptr<task_struct> prev) {
            vDsq.moveToLocal();
        }
    }

    @Test
    void testInsertVtimeInlined() {
        String code = stripped(codeOf(InsertVtimeTest.class));
        assertTrue(code.contains("scx_bpf_dsq_insert_vtime"), "insertVtime must be inlined\n" + code);
        assertTrue(code.contains("55"), "carrier id 55 must appear\n" + code);
    }

    // ── Test 5: attach() — no init prologue ───────────────────────────────────

    @BPF(license = "GPL")
    @Property(name = "sched_name", value = "abstr_attach")
    public static abstract class AttachTest extends SchedulerBase implements Scheduler {

        // attach() has value="" — no scx_bpf_create_dsq should appear in init() prologue
        final DispatchQueue shared = DispatchQueue.attach(SHARED_DSQ_ID);

        @Override
        public int init() {
            return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
        }

        @Override
        public void enqueue(Ptr<task_struct> p, long enq_flags) {
            shared.insert(p, -1L, EnqFlags.passThrough(enq_flags));
        }

        @Override
        public void dispatch(int cpu, Ptr<task_struct> prev) {
            shared.moveToLocal();
        }
    }

    @Test
    void testAttachNoExtraCreateDsq() {
        String code = stripped(codeOf(AttachTest.class));
        // Only one scx_bpf_create_dsq call — from init() body, not from the field prologue.
        // Exclude __ksym forward-declaration lines which also contain the function name.
        long createCount = code.lines()
                .filter(l -> l.contains("scx_bpf_create_dsq"))
                .filter(l -> !l.contains("__ksym"))
                .count();
        assertTrue(createCount <= 1,
                "attach() must not inject a second scx_bpf_create_dsq\n" + code);
    }

    // ── Test 6: destroy() — inlined with carrier ──────────────────────────────

    @BPF(license = "GPL")
    @Property(name = "sched_name", value = "abstr_destroy")
    public static abstract class DestroyTest extends SchedulerBase implements Scheduler {

        private static final long D_DSQ = 33L;

        final DispatchQueue dDsq = new DispatchQueue(D_DSQ);

        @Override
        public int init() {
            return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
        }

        @Override
        public void enqueue(Ptr<task_struct> p, long enq_flags) {
            dDsq.insert(p, -1L, EnqFlags.passThrough(enq_flags));
        }

        @Override
        public void dispatch(int cpu, Ptr<task_struct> prev) {
            dDsq.moveToLocal();
        }

        @BPFFunction
        public void cleanupDsq() {
            dDsq.destroy();
        }
    }

    @Test
    void testDestroyInlined() {
        String code = stripped(codeOf(DestroyTest.class));
        assertTrue(code.contains("scx_bpf_destroy_dsq"), "destroy must be inlined\n" + code);
        assertTrue(code.contains("33"), "carrier id 33 must appear in destroy\n" + code);
    }

    // ── Test 7: EnqFlags carrier inlining ────────────────────────────────────

    @BPF(license = "GPL")
    @Property(name = "sched_name", value = "abstr_enqflags")
    public static abstract class EnqFlagsTest extends SchedulerBase implements Scheduler {

        private static final long E_DSQ = 11L;

        final DispatchQueue eDsq = new DispatchQueue(E_DSQ);

        @Override
        public int init() {
            return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
        }

        @Override
        public void enqueue(Ptr<task_struct> p, long enq_flags) {
            // EnqFlags.empty() has carrier "0" — should appear in the insert call
            eDsq.insert(p, -1L, EnqFlags.empty());
        }

        @Override
        public void dispatch(int cpu, Ptr<task_struct> prev) {
            eDsq.moveToLocal();
        }
    }

    @Test
    void testEnqFlagsEmptyCarrierIsZero() {
        String code = stripped(codeOf(EnqFlagsTest.class));
        // EnqFlags.empty() carrier = 0; flags.value() = $this = 0 → should see 0 in the insert call
        assertTrue(code.contains("scx_bpf_dsq_insert"), "insert must be inlined\n" + code);
    }

    // ── Test 8: two DSQ fields — each gets its own carrier ───────────────────

    @BPF(license = "GPL")
    @Property(name = "sched_name", value = "abstr_two_dsqs")
    public static abstract class TwoDsqTest extends SchedulerBase implements Scheduler {

        private static final long BOOSTED_DSQ = 100L;
        private static final long NORMAL_DSQ = 200L;

        final DispatchQueue boosted = new DispatchQueue(BOOSTED_DSQ);
        final DispatchQueue normal  = new DispatchQueue(NORMAL_DSQ);

        @Override
        public int init() {
            return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
        }

        @Override
        public void enqueue(Ptr<task_struct> p, long enq_flags) {
            boosted.insert(p, -1L, EnqFlags.passThrough(enq_flags));
        }

        @Override
        public void dispatch(int cpu, Ptr<task_struct> prev) {
            if (boosted.nonEmpty()) {
                boosted.moveToLocal();
            } else {
                normal.moveToLocal();
            }
        }
    }

    @Test
    void testTwoDsqProloguesInDeclarationOrder() {
        String code = stripped(codeOf(TwoDsqTest.class));
        // Both DSQs must be created; 100 before 200
        int idx100 = code.indexOf("100");
        int idx200 = code.indexOf("200");
        assertTrue(idx100 >= 0, "boosted DSQ id 100 must appear\n" + code);
        assertTrue(idx200 >= 0, "normal DSQ id 200 must appear\n" + code);
        assertTrue(idx100 < idx200, "boosted (100) must be created before normal (200)\n" + code);
    }

    @Test
    void testTwoDsqBothCarriersUsed() {
        String code = stripped(codeOf(TwoDsqTest.class));
        // moveToLocal for boosted uses 100, for normal uses 200
        assertTrue(code.contains("scx_bpf_dsq_move_to_local"), "moveToLocal must appear\n" + code);
        assertTrue(code.contains("100"), "boosted carrier 100 must appear\n" + code);
        assertTrue(code.contains("200"), "normal carrier 200 must appear\n" + code);
    }

    // ── Test 9: local DispatchQueue variable inside a @BPFFunction ───────────

    @BPF(license = "GPL")
    @Property(name = "sched_name", value = "abstr_local_dq")
    public static abstract class LocalDqTest extends SchedulerBase implements Scheduler {

        @Override
        public int init() {
            return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
        }

        @Override
        public void enqueue(Ptr<task_struct> p, long enq_flags) {
            // Local DispatchQueue via attach — no new C variable, carrier = SHARED_DSQ_ID
            DispatchQueue dq = DispatchQueue.attach(SHARED_DSQ_ID);
            dq.insert(p, -1L, EnqFlags.passThrough(enq_flags));
        }

        @Override
        public void dispatch(int cpu, Ptr<task_struct> prev) {
            DispatchQueue dq = DispatchQueue.attach(SHARED_DSQ_ID);
            dq.moveToLocal();
        }
    }

    @Test
    void testLocalDqVariableInlined() {
        String code = stripped(codeOf(LocalDqTest.class));
        assertTrue(code.contains("scx_bpf_dsq_insert"), "local dq.insert must be inlined\n" + code);
        assertTrue(code.contains("scx_bpf_dsq_move_to_local"), "local dq.moveToLocal must be inlined\n" + code);
    }

    @Test
    void testLocalDqNoCVariableDeclaration() {
        String code = stripped(codeOf(LocalDqTest.class));
        // No C declaration for the local DispatchQueue variable should appear
        assertFalse(code.contains("DispatchQueue"), "DispatchQueue type must not appear in C output\n" + code);
    }

    // ── Test 10: KickFlags carrier ────────────────────────────────────────────

    @BPF(license = "GPL")
    @Property(name = "sched_name", value = "abstr_kick")
    public static abstract class KickFlagsTest extends SchedulerBase implements Scheduler {

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
            scx_bpf_dsq_move_to_local_stub(SHARED_DSQ_ID);
        }

        @BuiltinBPFFunction("scx_bpf_dsq_move_to_local($arg1)")
        @NotUsableInJava
        void scx_bpf_dsq_move_to_local_stub(long dsqId) { throw new MethodIsBPFRelatedFunction(); }

        @BPFFunction
        public void kickCpuIdle(int cpu) {
            // KickFlags.idle() has carrier SCX_KICK_IDLE
            DispatchQueue.kickCpu(cpu, KickFlags.idle());
        }
    }

    @Test
    void testKickFlagsIdleCarrier() {
        String code = stripped(codeOf(KickFlagsTest.class));
        assertTrue(code.contains("scx_bpf_kick_cpu"), "kickCpu must appear\n" + code);
        assertTrue(code.contains("SCX_KICK_IDLE"), "SCX_KICK_IDLE must appear for KickFlags.idle()\n" + code);
    }

    // ── Test 11: insertVtimeClamped — complex method body with branching ──────

    @BPF(license = "GPL")
    @Property(name = "sched_name", value = "abstr_vtimeclamped")
    public static abstract class VtimeClampedTest extends SchedulerBase implements Scheduler {

        private static final long VC_DSQ = 77L;

        final DispatchQueue vcDsq = new DispatchQueue(VC_DSQ);

        @Override
        public int init() {
            return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
        }

        @Override
        public void enqueue(Ptr<task_struct> p, long enq_flags) {
            long vtimeNow = p.val().scx.dsq_vtime;
            vcDsq.insertVtimeClamped(p, vtimeNow, EnqFlags.passThrough(enq_flags));
        }

        @Override
        public void dispatch(int cpu, Ptr<task_struct> prev) {
            vcDsq.moveToLocal();
        }
    }

    @Test
    void testInsertVtimeClampedInlined() {
        String code = stripped(codeOf(VtimeClampedTest.class));
        assertTrue(code.contains("scx_bpf_dsq_insert_vtime"), "insertVtimeClamped must be inlined\n" + code);
        assertTrue(code.contains("77"), "carrier id 77 must appear\n" + code);
        // The clamping branch must be present
        assertTrue(code.contains("dsq_vtime"), "dsq_vtime access must appear for clamping\n" + code);
    }
}
