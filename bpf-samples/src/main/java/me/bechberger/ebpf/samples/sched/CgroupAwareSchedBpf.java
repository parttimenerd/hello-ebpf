// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.Property;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.bpf.UserspaceSchedulerBase;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

/**
 * BPF-transport subclass demonstrating the {@code @TaskExtension} end-to-end path.
 *
 * <p>Overrides {@link UserspaceSchedulerBase#fillExtension} to stamp two
 * BPF-computed longs into the per-task extension tail of every queued task:
 * <ol>
 *   <li>the task's cgroup id (from {@code p->cgroups->dfl_cgrp->kn->id}),</li>
 *   <li>the parent tgid (from {@code p->real_parent->tgid}).</li>
 * </ol>
 *
 * <p>The tail is a fixed {@link UserspaceSchedulerBase#EXT_CAP}-byte byte array.
 * We view it as a small {@link CgroupExtCtx} struct by decaying the byte array to
 * a {@code Ptr<Byte>} ({@link Ptr#of(byte[])}) and reinterpreting it via
 * {@link Ptr#cast()}. Writing the two struct fields lays down two native
 * little-endian 8-byte values at tail offsets 0 and 8 — exactly what the Java
 * read-side ({@code QueuedTask.ext(CgroupExt.class)}) expects.
 *
 * <p>Loaded from the policy side via
 * {@code CgroupAwareSample.bpfProgramClass()}.
 */
@BPF(license = "GPL")
@Property(name = "sched_name", value = "cgroup_aware")
public abstract class CgroupAwareSchedBpf extends UserspaceSchedulerBase {

    /**
     * Parallel struct laid over the first 16 bytes of the extension tail.
     * Two {@code @Unsigned long} fields → native 8-byte writes at offsets 0 and 8,
     * matching {@code CgroupAwareSample.CgroupExt(long cgroupId, long ppid)} on the
     * Java read-side (both little-endian on x86-64/aarch64).
     */
    @Type
    static class CgroupExtCtx {
        @Unsigned long cgroupId;
        @Unsigned long ppid;
    }

    @Override
    @BPFFunction
    public void fillExtension(Ptr<QueuedTaskCtx> evt, Ptr<task_struct> p) {
        // Reinterpret the byte-array tail as our typed struct.
        Ptr<CgroupExtCtx> e = Ptr.of(evt.val().ext).<CgroupExtCtx>cast();

        // cgroup id: p->cgroups->dfl_cgrp->kn->id
        e.val().cgroupId = p.val().cgroups.val().dfl_cgrp.val().kn.val().id;

        // parent tgid: p->real_parent->tgid
        e.val().ppid = p.val().real_parent.val().tgid;
    }
}
