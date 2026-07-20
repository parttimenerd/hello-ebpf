// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

import java.util.List;

/** Pure push/pull load-balancing engine ported from scx_rusty. No BPF, no I/O. */
public final class DomainLoadBalancer {

    /**
     * One task's contribution to domain load.
     * @param pid the task pid
     * @param load decayed duty-cycle * weight (see RustyScheduler load metric)
     * @param domMask bitmask of domains this task is allowed to run in (cpu affinity)
     * @param preferredDomMask domains the task has cache affinity with (its prevCpu's domain)
     * @param isKworker true for kernel worker threads (may be skipped by the balancer)
     */
    public record TaskLoad(int pid, double load, long domMask, long preferredDomMask,
                           boolean isKworker) {}

    /** A decision to move a task from one domain to another. */
    public record Migration(int pid, int fromDom, int toDom) {}

    private DomainLoadBalancer() {}
}
