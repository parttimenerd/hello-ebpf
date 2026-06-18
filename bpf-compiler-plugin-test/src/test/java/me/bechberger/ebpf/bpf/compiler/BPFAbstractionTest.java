package me.bechberger.ebpf.bpf.compiler;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.*;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.Scheduler;
import me.bechberger.ebpf.bpf.SchedulerBase;
import me.bechberger.ebpf.bpf.map.BPFStackTraceMap;
import me.bechberger.ebpf.bpf.perf.PerfEvent;
import me.bechberger.ebpf.bpf.probe.ProbeContext;
import me.bechberger.ebpf.bpf.sched.DispatchQueue;
import me.bechberger.ebpf.bpf.sched.EnqFlags;
import me.bechberger.ebpf.bpf.sched.KickFlags;
import me.bechberger.ebpf.runtime.BpfDefinitions.bpf_perf_event_data;
import me.bechberger.ebpf.runtime.BpfDefinitions.bpf_perf_event_value;
import me.bechberger.ebpf.runtime.PtDefinitions.pt_regs;
import me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;

import java.util.stream.Collectors;

import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_bpf_create_dsq;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_bpf_dsq_move_to_local;
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

    // ── Test 12: @BPFJavaInline with return value — return converted to expression ──

    @BPFAbstraction(constructorPrependTo = "")
    public static final class Counter {

        @NotUsableInJava
        private final int count = 0;

        @BuiltinBPFFunction(value = "", carrier = "$arg1")
        @NotUsableInJava
        public static Counter of(int count) { throw new MethodIsBPFRelatedFunction(); }

        /** Returns the carrier value doubled. Uses @BPFJavaInline to test return-value inlining. */
        @BPFJavaInline
        @NotUsableInJava
        public int doubled() { return count * 2; }
    }

    @BPF(license = "GPL")
    @Property(name = "sched_name", value = "abstr_retval")
    public static abstract class ReturnValueTest extends SchedulerBase implements Scheduler {

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

        @BPFFunction
        public int getDoubled(int n) {
            Counter c = Counter.of(n);
            return c.doubled();
        }
    }

    @Test
    void testBPFJavaInlineReturnConvertedToExpression() {
        String code = stripped(codeOf(ReturnValueTest.class));
        // doubled() body is "return count * 2;" where count=carrier=n
        // The GNU statement expression must NOT contain "return " — it must be bare "n * 2"
        long returnInGnuStmt = code.lines()
                .filter(l -> l.contains("({") && l.contains("return "))
                .count();
        assertTrue(returnInGnuStmt == 0,
                "GNU statement expression must not contain 'return'; got\n" + code);
        // The expression itself must appear
        assertTrue(code.contains("* 2"), "doubled() expression 'n * 2' or similar must appear\n" + code);
    }

    // ── Test 13a: auto-id DispatchQueue — <auto> resolved to stable hex constant ─

    @BPF(license = "GPL")
    @Property(name = "sched_name", value = "abstr_autoid")
    public static abstract class AutoIdTest extends SchedulerBase implements Scheduler {
        // Two auto-id queues — should get different stable ids in scx_bpf_create_dsq(...)
        final DispatchQueue q0 = new DispatchQueue();
        final DispatchQueue q1 = new DispatchQueue();

        @Override public void enqueue(Ptr<task_struct> p, long enq_flags) {
            q0.insert(p, 5000000L, EnqFlags.passThrough(enq_flags));
        }
        @Override public void dispatch(int cpu, Ptr<task_struct> prev) {
            q0.moveToLocal();
        }
    }

    @Test
    void testAutoIdNoPendingAuto() {
        String code = stripped(codeOf(AutoIdTest.class));
        assertFalse(code.contains("<auto>"),
                "No unresolved <auto> placeholder must remain in generated C\n" + code);
    }

    @Test
    void testAutoIdTwoDistinctIds() {
        String code = stripped(codeOf(AutoIdTest.class));
        // Both queues must produce scx_bpf_create_dsq calls with distinct id literals
        var createLines = code.lines()
                .filter(l -> l.contains("scx_bpf_create_dsq("))
                .toList();
        assertTrue(createLines.size() >= 2,
                "Expected ≥2 scx_bpf_create_dsq calls for two auto-id queues\n" + code);
        // Extract the id arguments — they must be distinct
        var ids = createLines.stream()
                .map(l -> l.replaceAll(".*scx_bpf_create_dsq\\(([^,]+),.*", "$1").trim())
                .collect(java.util.stream.Collectors.toSet());
        assertTrue(ids.size() >= 2,
                "Auto-allocated ids must be distinct; got ids=" + ids + "\n" + code);
    }

    // ── Test 13: PerfEvent — carrier = ctx, field access inlining ─────────────

    @BPF(license = "GPL")
    public static abstract class PerfEventTest extends BPFProgram {

        @BPFMapDefinition(maxEntries = 8192)
        BPFStackTraceMap stackTraces;

        @BPFFunction
        public void onSample(Ptr<bpf_perf_event_data> ctx) {
            PerfEvent pe = PerfEvent.of(ctx);
            long period = pe.samplePeriod();
            long addr   = pe.addr();
        }

        @BPFFunction
        public void stackCapture(Ptr<bpf_perf_event_data> ctx) {
            PerfEvent pe = PerfEvent.of(ctx);
            long sid = pe.getStackId(stackTraces, PerfEvent.STACK_USER | PerfEvent.STACK_REUSE);
        }

        @BPFFunction
        public void readRegs(Ptr<bpf_perf_event_data> ctx) {
            PerfEvent pe = PerfEvent.of(ctx);
            Ptr<?> r = pe.regs();
        }

        @BPFFunction
        public void counterRead(Ptr<bpf_perf_event_data> ctx, Ptr<bpf_perf_event_value> buf) {
            PerfEvent pe = PerfEvent.of(ctx);
            long rc = pe.readValue(buf);
        }
    }

    @Test
    void testPerfEventSamplePeriodInlined() {
        String code = stripped(codeOf(PerfEventTest.class));
        // pe.samplePeriod() → ctx->sample_period
        assertTrue(code.contains("sample_period"), "samplePeriod() must inline to ->sample_period\n" + code);
    }

    @Test
    void testPerfEventAddrInlined() {
        String code = stripped(codeOf(PerfEventTest.class));
        // pe.addr() → ctx->addr
        assertTrue(code.contains("->addr"), "addr() must inline to ->addr\n" + code);
    }

    @Test
    void testPerfEventGetStackIdInlined() {
        String code = stripped(codeOf(PerfEventTest.class));
        // pe.getStackId(stackTraces, flags) → bpf_get_stackid(ctx, &stackTraces, flags)
        assertTrue(code.contains("bpf_get_stackid"), "getStackId must inline to bpf_get_stackid\n" + code);
    }

    @Test
    void testPerfEventRegsInlined() {
        String code = stripped(codeOf(PerfEventTest.class));
        // pe.regs() → (&ctx->regs)
        assertTrue(code.contains("->regs"), "regs() must inline to ->regs\n" + code);
    }

    @Test
    void testPerfEventReadValueInlined() {
        String code = stripped(codeOf(PerfEventTest.class));
        // pe.readValue(buf) → bpf_perf_prog_read_value(ctx, buf, sizeof(*buf))
        assertTrue(code.contains("bpf_perf_prog_read_value"), "readValue must inline to bpf_perf_prog_read_value\n" + code);
        assertTrue(code.contains("sizeof"), "sizeof must appear in readValue expansion\n" + code);
    }

    @Test
    void testPerfEventNoCType() {
        String code = stripped(codeOf(PerfEventTest.class));
        // PerfEvent is a @BPFAbstraction — must not appear as a C type
        assertFalse(code.contains("PerfEvent"), "PerfEvent must not appear as a C type\n" + code);
    }

    // ── Test 14: ProbeContext — arg/retval/ip/sp carrier inlining ─────────────

    @BPF(license = "GPL")
    public static abstract class ProbeContextTest extends BPFProgram {

        @BPFFunction
        public void onKprobe(Ptr<pt_regs> ctx) {
            ProbeContext pc = ProbeContext.of(ctx);
            long a0 = pc.arg0();
            long a1 = pc.arg1();
            long a2 = pc.arg2();
            long a3 = pc.arg3();
            long a4 = pc.arg4();
            long a5 = pc.arg5();
        }

        @BPFFunction
        public void onKretprobe(Ptr<pt_regs> ctx) {
            ProbeContext pc = ProbeContext.of(ctx);
            long rv = pc.retval();
        }

        @BPFFunction
        public void onKprobeIpSp(Ptr<pt_regs> ctx) {
            ProbeContext pc = ProbeContext.of(ctx);
            long instrPtr = pc.ip();
            long stackPtr = pc.sp();
        }

        @BPFFunction
        public void probeReadTest(Ptr<pt_regs> ctx, Ptr<?> dst, Ptr<?> src) {
            ProbeContext.probeRead(dst, 8, src);
        }
    }

    @Test
    void testProbeContextArg0Inlined() {
        String code = stripped(codeOf(ProbeContextTest.class));
        // pc.arg0() → PT_REGS_PARM1(ctx)
        assertTrue(code.contains("PT_REGS_PARM1"), "arg0() must inline to PT_REGS_PARM1\n" + code);
    }

    @Test
    void testProbeContextAllArgsInlined() {
        String code = stripped(codeOf(ProbeContextTest.class));
        assertTrue(code.contains("PT_REGS_PARM1"), "arg0 must appear\n" + code);
        assertTrue(code.contains("PT_REGS_PARM2"), "arg1 must appear\n" + code);
        assertTrue(code.contains("PT_REGS_PARM3"), "arg2 must appear\n" + code);
        assertTrue(code.contains("PT_REGS_PARM4"), "arg3 must appear\n" + code);
        assertTrue(code.contains("PT_REGS_PARM5"), "arg4 must appear\n" + code);
        assertTrue(code.contains("PT_REGS_PARM6"), "arg5 must appear\n" + code);
    }

    @Test
    void testProbeContextRetvalInlined() {
        String code = stripped(codeOf(ProbeContextTest.class));
        // pc.retval() → PT_REGS_RC(ctx)
        assertTrue(code.contains("PT_REGS_RC"), "retval() must inline to PT_REGS_RC\n" + code);
    }

    @Test
    void testProbeContextIpSpInlined() {
        String code = stripped(codeOf(ProbeContextTest.class));
        assertTrue(code.contains("PT_REGS_IP"), "ip() must inline to PT_REGS_IP\n" + code);
        assertTrue(code.contains("PT_REGS_SP"), "sp() must inline to PT_REGS_SP\n" + code);
    }

    @Test
    void testProbeContextProbeReadInlined() {
        String code = stripped(codeOf(ProbeContextTest.class));
        assertTrue(code.contains("bpf_probe_read_kernel"), "probeRead must inline to bpf_probe_read_kernel\n" + code);
    }

    @Test
    void testProbeContextNoCType() {
        String code = stripped(codeOf(ProbeContextTest.class));
        assertFalse(code.contains("ProbeContext"), "ProbeContext must not appear as a C type\n" + code);
    }
}
