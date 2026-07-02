package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks an interface as the Java mirror of a kernel {@code bpf_struct_ops}
 * table. The interface's methods are the struct_ops callback slots; their
 * names lower to kernel field names via camelCase → snake_case.
 *
 * <p>When a {@code @BPF} class implements a {@code @StructOps}-annotated
 * interface, the hello-ebpf compiler plugin:
 * <ol>
 *   <li>Loads the BTF-derived layout for {@link #value()} from
 *       {@code bpf-compiler-plugin/src/main/resources/struct-ops-layouts/}.</li>
 *   <li>Validates each overridden method's return/arg types against the
 *       kernel field prototype.</li>
 *   <li>Emits one BPF program per overridden method plus a
 *       {@code SEC(".struct_ops.link")} struct instance for attach.</li>
 * </ol>
 *
 * <p>Un-overridden interface methods (defaults) emit nothing; the kernel
 * accepts NULL for optional callbacks. The interface itself must be
 * annotated directly — the plugin does not follow chains of extending
 * interfaces.
 */
@Retention(RetentionPolicy.CLASS)
@Target(ElementType.TYPE)
@Documented
public @interface StructOps {

    /** Kernel BTF type name of the struct_ops kind, e.g.
     *  {@code "sched_ext_ops"}, {@code "tcp_congestion_ops"},
     *  {@code "Qdisc_ops"}, {@code "hid_bpf_ops"}. Must match a
     *  bundled layout file. */
    String value();

    /** BPF section prefix used for each callback's {@code SEC(...)}.
     *  Default {@code "struct_ops/"}. Set to {@code "struct_ops.s/"} for
     *  sleepable kinds. Rarely overridden per-interface; users typically
     *  don't touch it. */
    String sectionPrefix() default "struct_ops/";

    /** Optional override for the C-side struct instance variable name.
     *  Defaults to the implementing {@code @BPF} class's simple name.
     *  Used for the {@code SEC(".struct_ops.link") struct <kind> <name>}
     *  declaration and matches libbpf's map-name lookup. */
    String instanceName() default "";
}
