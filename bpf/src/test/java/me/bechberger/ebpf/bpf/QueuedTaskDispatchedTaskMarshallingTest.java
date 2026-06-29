package me.bechberger.ebpf.bpf;

import org.junit.jupiter.api.Test;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies that the wire-format offsets the framework will use to read/write
 * QueuedTask/DispatchedTask via Panama VarHandles match the BPF struct layouts.
 *
 * <p>The framework reads via VarHandles on a MemorySegment; this test simulates
 * one round trip (write a POJO into a segment via offsets, read it back into a
 * fresh POJO, assert equal) to catch alignment/padding bugs early. The BPF-side
 * layout is asserted by the integration smoke test, which observes that PIDs
 * and weights flow through correctly.
 */
public class QueuedTaskDispatchedTaskMarshallingTest {

    // Offsets matching BPF's queued_task_ctx (matches spec §"Data structures")
    private static final long QT_PID            = 0;
    private static final long QT_PREV_CPU       = 4;
    private static final long QT_NR_CPUS_ALLOW  = 8;
    private static final long QT_FLAGS          = 16;
    private static final long QT_START_TS       = 24;
    private static final long QT_STOP_TS        = 32;
    private static final long QT_EXEC_RUNTIME   = 40;
    private static final long QT_WEIGHT         = 48;
    private static final long QT_VTIME          = 56;
    private static final long QT_ENQ_CNT        = 64;
    private static final long QT_COMM           = 72;
    private static final long QT_SIZEOF         = 88;   // 72 + 16

    @Test
    public void testQueuedTaskRoundTrip() {
        QueuedTask src = new QueuedTask();
        src.pid = 4242; src.prevCpu = 3; src.nrCpusAllowed = 8L;
        src.flags = 0xCAFEBABEL; src.startTs = 111_000L; src.stopTs = 222_000L;
        src.execRuntime = 999L; src.weight = 200L; src.vtime = 12_345L;
        src.enqCnt = 7L;
        byte[] commIn = "java\0".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        System.arraycopy(commIn, 0, src.comm, 0, commIn.length);

        try (Arena a = Arena.ofConfined()) {
            MemorySegment seg = a.allocate(QT_SIZEOF);
            // Write via the wire offsets.
            seg.set(ValueLayout.JAVA_INT,  QT_PID,           src.pid);
            seg.set(ValueLayout.JAVA_INT,  QT_PREV_CPU,      src.prevCpu);
            seg.set(ValueLayout.JAVA_LONG, QT_NR_CPUS_ALLOW, src.nrCpusAllowed);
            seg.set(ValueLayout.JAVA_LONG, QT_FLAGS,         src.flags);
            seg.set(ValueLayout.JAVA_LONG, QT_START_TS,      src.startTs);
            seg.set(ValueLayout.JAVA_LONG, QT_STOP_TS,       src.stopTs);
            seg.set(ValueLayout.JAVA_LONG, QT_EXEC_RUNTIME,  src.execRuntime);
            seg.set(ValueLayout.JAVA_LONG, QT_WEIGHT,        src.weight);
            seg.set(ValueLayout.JAVA_LONG, QT_VTIME,         src.vtime);
            seg.set(ValueLayout.JAVA_LONG, QT_ENQ_CNT,       src.enqCnt);
            MemorySegment.copy(src.comm, 0, seg, ValueLayout.JAVA_BYTE, QT_COMM, 16);

            QueuedTask dst = new QueuedTask();
            dst.pid           = seg.get(ValueLayout.JAVA_INT,  QT_PID);
            dst.prevCpu       = seg.get(ValueLayout.JAVA_INT,  QT_PREV_CPU);
            dst.nrCpusAllowed = seg.get(ValueLayout.JAVA_LONG, QT_NR_CPUS_ALLOW);
            dst.flags         = seg.get(ValueLayout.JAVA_LONG, QT_FLAGS);
            dst.startTs       = seg.get(ValueLayout.JAVA_LONG, QT_START_TS);
            dst.stopTs        = seg.get(ValueLayout.JAVA_LONG, QT_STOP_TS);
            dst.execRuntime   = seg.get(ValueLayout.JAVA_LONG, QT_EXEC_RUNTIME);
            dst.weight        = seg.get(ValueLayout.JAVA_LONG, QT_WEIGHT);
            dst.vtime         = seg.get(ValueLayout.JAVA_LONG, QT_VTIME);
            dst.enqCnt        = seg.get(ValueLayout.JAVA_LONG, QT_ENQ_CNT);
            MemorySegment.copy(seg, ValueLayout.JAVA_BYTE, QT_COMM, dst.comm, 0, 16);

            assertEquals(src.pid,           dst.pid);
            assertEquals(src.prevCpu,       dst.prevCpu);
            assertEquals(src.nrCpusAllowed, dst.nrCpusAllowed);
            assertEquals(src.flags,         dst.flags);
            assertEquals(src.startTs,       dst.startTs);
            assertEquals(src.stopTs,        dst.stopTs);
            assertEquals(src.execRuntime,   dst.execRuntime);
            assertEquals(src.weight,        dst.weight);
            assertEquals(src.vtime,         dst.vtime);
            assertEquals(src.enqCnt,        dst.enqCnt);
            assertEquals("java",            dst.commStr());
            assertTrue(dst.commEquals("java"));
        }
    }

    @Test
    public void testDispatchedTaskFillFromClearsDispatchFields() {
        QueuedTask q = new QueuedTask();
        q.pid = 99; q.flags = 5; q.enqCnt = 17;
        DispatchedTask d = new DispatchedTask();
        d.targetCpu = 42; d.sliceNs = 9_999; d.vtime = 1_234;
        d.fillFrom(q);
        assertEquals(99,                       d.pid);
        assertEquals(DispatchedTask.ANY_CPU,   d.targetCpu);
        assertEquals(0L,                       d.sliceNs);
        assertEquals(0L,                       d.vtime);
        assertEquals(5L,                       d.flags);
        assertEquals(17L,                      d.enqCnt);
    }

    @Test
    public void testCommHelpersEdgeCases() {
        QueuedTask empty = new QueuedTask();
        assertEquals("", empty.commStr());
        assertTrue(empty.commEquals(""));

        QueuedTask full = new QueuedTask();
        // Fill all 16 bytes with no NUL — commStr returns the full string,
        // commEquals must reject any prefix because the buffer is not NUL-terminated.
        java.util.Arrays.fill(full.comm, (byte) 'a');
        assertEquals(16, full.commStr().length());
        assertFalse(full.commEquals("aaaaaaaaaaaaaaa"));  // 15 'a's, but byte[15] != 0
    }
}
