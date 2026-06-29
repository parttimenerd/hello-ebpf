// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace.jfr;

import jdk.jfr.*;

/**
 * JFR event emitted once per dispatch in {@code UserspaceScheduler.dispatchInternal}.
 *
 * <p>Threshold-filtered at 100 us so only slow individual dispatches appear in
 * recordings by default.
 */
@Name("hellobpf.userspace.Dispatch")
@Label("Userspace Scheduler Dispatch")
@Category({"hello-ebpf", "userspace-scheduler"})
@StackTrace(false)
@Threshold("100 us")
public class DispatchEvent extends jdk.jfr.Event {
    @Label("PID") public int pid;
    @Label("CPU") public int cpu;
    @Label("Return Code") public int rc;
}
