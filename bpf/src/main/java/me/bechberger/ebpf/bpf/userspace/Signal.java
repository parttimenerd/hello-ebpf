// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

/**
 * A typed event pushed from BPF to the Java scheduler over the signals ring.
 * Delivered to {@link UserspaceScheduler#onSignal(Signal)} in arrival order.
 *
 * @param kind    author-defined int; framework-reserved values in {@link SignalKind}
 * @param pid     subject task pid (or -1 if not task-scoped)
 * @param payload author-defined 64-bit payload
 * @param tsNs    BPF-side timestamp (bpf_ktime_get_ns) at emit time
 */
public record Signal(int kind, int pid, long payload, long tsNs) {

    /** Framework-reserved signal kinds. Author kinds should start well above these. */
    public static final class SignalKind {
        private SignalKind() {}
        public static final int CPU_RELEASED = 1;
        public static final int CPU_IDLE     = 2;
        public static final int TASK_EXIT    = 3;
        /** Authors define domain kinds at or above this value. */
        public static final int FIRST_USER_KIND = 1000;
    }
}
