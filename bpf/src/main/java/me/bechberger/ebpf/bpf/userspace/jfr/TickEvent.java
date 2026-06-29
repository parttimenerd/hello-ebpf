// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace.jfr;

import jdk.jfr.*;

/**
 * JFR event emitted once per heartbeat tick in {@code UserspaceScheduler.emitTickEvent}.
 *
 * <p>Threshold-filtered at 500 us so only slow tick invocations appear in
 * recordings by default.
 */
@Name("hellobpf.userspace.Tick")
@Label("Userspace Scheduler Tick")
@Category({"hello-ebpf", "userspace-scheduler"})
@StackTrace(false)
@Threshold("500 us")
public class TickEvent extends jdk.jfr.Event {
    @Label("Heap Used (MiB)") public long heapUsedMb;
    @Label("Framework PIDs") public int frameworkPids;
}
