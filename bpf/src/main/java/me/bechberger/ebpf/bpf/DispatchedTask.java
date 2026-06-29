package me.bechberger.ebpf.bpf;

/**
 * User→kernel record. Mutable public fields. Fill via {@link #fillFrom} from a
 * {@link QueuedTask}; never {@code new} on the hot path — the framework keeps
 * a pooled instance accessible as {@code scratch}.
 */
public final class DispatchedTask {
    /** "Use SHARED_DSQ, kernel picks the CPU". Wire-compatible with rustland's RL_CPU_ANY. */
    public static final int ANY_CPU = -1;

    public int  pid;
    public int  targetCpu;      // ANY_CPU = SHARED_DSQ
    public long flags;
    public long sliceNs;        // 0 ⇒ framework default
    public long vtime;          // 0 ⇒ monotonic
    public long enqCnt;

    public DispatchedTask() {}

    public DispatchedTask fillFrom(QueuedTask q) {
        this.pid    = q.pid;
        this.flags  = q.flags;
        this.enqCnt = q.enqCnt;
        this.targetCpu = ANY_CPU;
        this.sliceNs   = 0;
        this.vtime     = 0;
        return this;
    }

    public static DispatchedTask from(QueuedTask q, DispatchedTask into) {
        return into.fillFrom(q);
    }
}
