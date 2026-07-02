package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a {@code @StructOps} method whose BPF section should be emitted
 * as {@code struct_ops.s/<name>} (a sleepable variant) rather than the
 * default {@code struct_ops/<name>}.
 *
 * <p>The kernel accepts both prefixes for methods declared sleepable in
 * their BTF metadata (see {@code libbpf} {@code find_struct_ops_map}
 * lookup logic). Only sched-ext's {@code init} needs this today,
 * but the marker is written generically so any future struct_ops kind
 * can opt in.
 *
 * <h2>Example</h2>
 * <pre>{@code
 * @BPF(license = "GPL")
 * public abstract class MyScheduler extends BPFProgram implements Scheduler {
 *     @Override
 *     @Sleepable
 *     public int init() {
 *         // Sleepable context — may call helpers that would block.
 *         return scx_bpf_create_dsq(0L, -1);
 *     }
 * }
 * }</pre>
 *
 * <p>Only kernel struct_ops slots that carry the sleepable BTF flag accept a
 * sleepable program. As of kernel 6.14, sched-ext's {@code init} is the
 * canonical sleepable slot.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.CLASS)
public @interface Sleepable {}
