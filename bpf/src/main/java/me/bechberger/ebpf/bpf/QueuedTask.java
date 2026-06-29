package me.bechberger.ebpf.bpf;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * Kernel→user record. Mutable public fields, rustland-style. The framework
 * holds a pooled instance and refills it from the ringbuf {@link
 * java.lang.foreign.MemorySegment} via {@code fillFromSegment} on each drain
 * callback.
 *
 * <p>Wire-layout-equivalent to BPF's {@code queued_task_ctx} struct.
 * See {@link UserspaceScheduler} for the lifecycle contract — the flyweight
 * is invalidated on the next {@code dequeueTask()} or {@code batch.next()}.
 */
public final class QueuedTask {
    public int  pid;
    public int  prevCpu;        // -1 if never run
    public long nrCpusAllowed;
    public long flags;
    public long startTs;
    public long stopTs;
    public long execRuntime;
    public long weight;         // [1..10000], default 100
    public long vtime;
    public long enqCnt;
    public final byte[] comm = new byte[16];

    // Wire offsets — match BPF's queued_task_ctx and QueuedTaskDispatchedTaskMarshallingTest.
    private static final long QT_PID           =  0;
    private static final long QT_PREV_CPU      =  4;
    private static final long QT_NR_CPUS_ALLOW =  8;
    private static final long QT_FLAGS         = 16;
    private static final long QT_START_TS      = 24;
    private static final long QT_STOP_TS       = 32;
    private static final long QT_EXEC_RUNTIME  = 40;
    private static final long QT_WEIGHT        = 48;
    private static final long QT_VTIME         = 56;
    private static final long QT_ENQ_CNT       = 64;
    private static final long QT_COMM          = 72;

    public QueuedTask() {}

    public QueuedTask(QueuedTask src) {
        // KEEP IN SYNC: every field above must be copied here.
        this.pid = src.pid; this.prevCpu = src.prevCpu;
        this.nrCpusAllowed = src.nrCpusAllowed; this.flags = src.flags;
        this.startTs = src.startTs; this.stopTs = src.stopTs;
        this.execRuntime = src.execRuntime; this.weight = src.weight;
        this.vtime = src.vtime; this.enqCnt = src.enqCnt;
        System.arraycopy(src.comm, 0, this.comm, 0, 16);
    }

    /**
     * Fill {@code out} from the raw {@link MemorySegment} delivered by
     * {@link me.bechberger.ebpf.bpf.map.BPFRingBuffer#consumeRaw consumeRaw}.
     * Offsets match the BPF struct {@code queued_task_ctx} layout verified
     * by {@code QueuedTaskDispatchedTaskMarshallingTest}.
     *
     * @param seg ring-buffer record segment; must be at least 88 bytes
     * @param out mutable target to fill; existing contents are overwritten
     */
    public static void fillFromSegment(MemorySegment seg, QueuedTask out) {
        out.pid           = seg.get(ValueLayout.JAVA_INT,  QT_PID);
        out.prevCpu       = seg.get(ValueLayout.JAVA_INT,  QT_PREV_CPU);
        out.nrCpusAllowed = seg.get(ValueLayout.JAVA_LONG, QT_NR_CPUS_ALLOW);
        out.flags         = seg.get(ValueLayout.JAVA_LONG, QT_FLAGS);
        out.startTs       = seg.get(ValueLayout.JAVA_LONG, QT_START_TS);
        out.stopTs        = seg.get(ValueLayout.JAVA_LONG, QT_STOP_TS);
        out.execRuntime   = seg.get(ValueLayout.JAVA_LONG, QT_EXEC_RUNTIME);
        out.weight        = seg.get(ValueLayout.JAVA_LONG, QT_WEIGHT);
        out.vtime         = seg.get(ValueLayout.JAVA_LONG, QT_VTIME);
        out.enqCnt        = seg.get(ValueLayout.JAVA_LONG, QT_ENQ_CNT);
        MemorySegment.copy(seg, ValueLayout.JAVA_BYTE, QT_COMM, out.comm, 0, 16);
    }

    public String commStr() {
        int n = 0; while (n < 16 && comm[n] != 0) n++;
        return new String(comm, 0, n, java.nio.charset.StandardCharsets.UTF_8);
    }

    public boolean commEquals(String other) {
        int len = other.length();
        if (len > 15) return false;            // 16th byte must be NUL
        for (int i = 0; i < len; i++) {
            if ((comm[i] & 0xFF) != (other.charAt(i) & 0xFF)) return false;
        }
        return comm[len] == 0;
    }
}
