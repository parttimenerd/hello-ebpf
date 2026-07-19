// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

/** Discriminator for a control-ring record. Matches ControlCtx.kind on the BPF side. */
public final class ControlKind {
    private ControlKind() {}
    /** Preempt whatever runs on the target's CPU so {@code pid} can run ASAP. */
    public static final int PREEMPT = 1;
    /** Kick a specific CPU with {@code flags} (SCX_KICK_*). */
    public static final int KICK    = 2;
}
