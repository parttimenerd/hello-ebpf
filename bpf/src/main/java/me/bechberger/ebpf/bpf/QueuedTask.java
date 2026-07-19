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
 * See {@code UserspaceScheduler} for the lifecycle contract — the flyweight
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

    /** Size of the stable rustland-compatible prefix. Never changes. */
    public static final long QT_SIZEOF = 88;

    /**
     * Fixed size of the per-task extension tail appended after the 88-byte prefix.
     * MUST equal {@code UserspaceSchedulerBase.QueuedTaskCtx.EXT_CAP}. Asserted by
     * {@code QueuedTaskDispatchedTaskMarshallingTest} and {@code TaskExtensionTest}.
     */
    public static final int EXT_CAP = 64;

    /** Zero-copy view over the EXT_CAP tail of the current record; never null after fill. */
    private final byte[] extBytes = new byte[EXT_CAP];

    private Object cachedExt;
    private Class<?> cachedExtType;

    public QueuedTask() {}

    public QueuedTask(QueuedTask src) {
        // KEEP IN SYNC: every field above must be copied here.
        this.pid = src.pid; this.prevCpu = src.prevCpu;
        this.nrCpusAllowed = src.nrCpusAllowed; this.flags = src.flags;
        this.startTs = src.startTs; this.stopTs = src.stopTs;
        this.execRuntime = src.execRuntime; this.weight = src.weight;
        this.vtime = src.vtime; this.enqCnt = src.enqCnt;
        System.arraycopy(src.comm, 0, this.comm, 0, 16);
        System.arraycopy(src.extBytes, 0, this.extBytes, 0, EXT_CAP);
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
        out.cachedExt     = null;
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
        if (seg.byteSize() >= QT_SIZEOF + EXT_CAP) {
            MemorySegment.copy(seg, ValueLayout.JAVA_BYTE, QT_SIZEOF, out.extBytes, 0, EXT_CAP);
        } else {
            java.util.Arrays.fill(out.extBytes, (byte) 0);
        }
    }

    /**
     * Returns a deep copy of this task that is safe to retain across batch boundaries.
     *
     * <p>The framework reuses flyweight instances in {@code taskPool} on every drain;
     * call {@code copy()} if you need to store a task in a queue or data structure
     * that outlives the current {@link UserspaceScheduler#schedule} call.
     * The copy is fully dispatchable via
     * {@link UserspaceScheduler#dispatchTask(QueuedTask, int)}.
     */
    public QueuedTask copy() {
        return new QueuedTask(this);
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

    /** Read a signed 64-bit value from the extension tail at {@code offset} (0-based within the tail). */
    public long extLong(int offset) {
        return (extBytes[offset] & 0xFFL)
             | (extBytes[offset + 1] & 0xFFL) << 8
             | (extBytes[offset + 2] & 0xFFL) << 16
             | (extBytes[offset + 3] & 0xFFL) << 24
             | (extBytes[offset + 4] & 0xFFL) << 32
             | (extBytes[offset + 5] & 0xFFL) << 40
             | (extBytes[offset + 6] & 0xFFL) << 48
             | (extBytes[offset + 7] & 0xFFL) << 56;
    }

    /** Read a signed 32-bit value from the extension tail at {@code offset}. */
    public int extInt(int offset) {
        return (extBytes[offset] & 0xFF)
             | (extBytes[offset + 1] & 0xFF) << 8
             | (extBytes[offset + 2] & 0xFF) << 16
             | (extBytes[offset + 3] & 0xFF) << 24;
    }

    /** Read a single byte from the extension tail at {@code offset}. */
    public byte extByte(int offset) {
        return extBytes[offset];
    }

    /**
     * Build a typed view of the extension tail as a record instance. The record's
     * components must be {@code long}/{@code int} in declaration order; they are read
     * from the tail with natural alignment (long on 8-byte boundaries, int on 4-byte).
     *
     * <p>Cached per flyweight until the next {@code fillFromSegment} refill.
     */
    @SuppressWarnings("unchecked")
    public <E extends Record> E ext(Class<E> type) {
        if (cachedExtType == type && cachedExt != null) {
            return (E) cachedExt;
        }
        E view = buildExtView(type);
        cachedExt = view;
        cachedExtType = type;
        return view;
    }

    private <E extends Record> E buildExtView(Class<E> type) {
        var comps = type.getRecordComponents();
        Object[] args = new Object[comps.length];
        Class<?>[] paramTypes = new Class<?>[comps.length];
        int off = 0;
        for (int i = 0; i < comps.length; i++) {
            Class<?> ct = comps[i].getType();
            paramTypes[i] = ct;
            if (ct == long.class) {
                off = align(off, 8);
                args[i] = extLong(off);
                off += 8;
            } else if (ct == int.class) {
                off = align(off, 4);
                args[i] = extInt(off);
                off += 4;
            } else {
                throw new IllegalArgumentException(
                    "@TaskExtension record components must be long or int, got " + ct + " in " + type);
            }
        }
        try {
            return type.getDeclaredConstructor(paramTypes).newInstance(args);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("cannot build extension view for " + type, e);
        }
    }

    private static int align(int off, int to) {
        int rem = off % to;
        return rem == 0 ? off : off + (to - rem);
    }
}
