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
 * lookup logic). Only sched-ext's {@code sched_init} needs this today,
 * but the marker is written generically so any future struct_ops kind
 * can opt in.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.CLASS)
public @interface Sleepable {}
