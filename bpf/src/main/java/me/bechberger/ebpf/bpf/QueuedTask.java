package me.bechberger.ebpf.bpf;

/**
 * Kernel→user record. Mutable public fields, rustland-style. The framework
 * holds a pooled instance and refills it from the ringbuf {@link
 * java.lang.foreign.MemorySegment} via {@link #fillFromSegment} on each drain
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
    final byte[] comm = new byte[16];

    public QueuedTask() {}

    public QueuedTask(QueuedTask src) {
        this.pid = src.pid; this.prevCpu = src.prevCpu;
        this.nrCpusAllowed = src.nrCpusAllowed; this.flags = src.flags;
        this.startTs = src.startTs; this.stopTs = src.stopTs;
        this.execRuntime = src.execRuntime; this.weight = src.weight;
        this.vtime = src.vtime; this.enqCnt = src.enqCnt;
        System.arraycopy(src.comm, 0, this.comm, 0, 16);
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
        return len == 16 || comm[len] == 0;
    }
}
