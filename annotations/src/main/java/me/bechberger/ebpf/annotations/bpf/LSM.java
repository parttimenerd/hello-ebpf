package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

/**
 * Shorthand for an LSM (Linux Security Module) BPF program that is automatically attached.
 *
 * <p>Equivalent to:
 * <pre>{@code
 * @BPFFunction(
 *     section = "lsm/<hook>",
 *     headerTemplate = "int BPF_PROG($name, $params)",
 *     lastStatement = "return 0;",
 *     autoAttach = true
 * )
 * }</pre>
 *
 * <p>The method return type must be {@code int}. Return {@code 0} to allow the operation
 * or a negative errno (e.g. {@code -EACCES}) to deny it.
 *
 * <p>Requires {@code CONFIG_BPF_LSM=y} and {@code lsm=...,bpf} in the kernel command line
 * (or set via {@code /sys/kernel/security/lsm}).
 *
 * <p>Example — deny opens of a specific file:
 * <pre>{@code
 * @LSM("file_open")
 * int onFileOpen(Ptr<runtime.file> file, int mask) {
 *     // inspect file and return -EACCES to deny
 *     return 0;
 * }
 * }</pre>
 *
 * <p>Common hooks: {@code file_open}, {@code bpf}, {@code socket_create},
 * {@code task_fix_setuid}, {@code inode_rename}, {@code inode_unlink}.
 * See {@code include/linux/lsm_hook_defs.h} for the full list.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface LSM {
    /** LSM hook name, e.g. {@code "file_open"}, {@code "bpf"}, {@code "socket_create"}. */
    String value();
}
