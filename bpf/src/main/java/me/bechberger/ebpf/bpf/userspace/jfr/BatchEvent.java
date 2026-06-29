// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace.jfr;

import jdk.jfr.*;

/**
 * JFR event emitted once per batch drain in {@code UserspaceScheduler.drainBatchOnce}.
 *
 * <p>Only emitted when at least one task was drained. Threshold-filtered at 200 us
 * so only slow batches appear in recordings by default.
 */
@Name("hellobpf.userspace.Batch")
@Label("Userspace Scheduler Batch")
@Category({"hello-ebpf", "userspace-scheduler"})
@StackTrace(false)
@Threshold("200 us")
public class BatchEvent extends jdk.jfr.Event {
    @Label("Batch Size") public int size;
    @Label("Dispatched") public int dispatched;
}
