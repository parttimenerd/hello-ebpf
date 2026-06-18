package me.bechberger.ebpf.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a BPF-context pointer parameter as originating from user space.
 *
 * <p>When the compiler plugin sees a dereference ({@code ptr.val()}) on a {@code @BPFUserMemory}
 * parameter, it will (in a future pass) automatically emit
 * {@code bpf_probe_read_user(&dst, sizeof(dst), ptr)} instead of a direct load.
 *
 * <p>Syscall hook arguments of type {@code String} (user-space addresses) should be marked
 * with this annotation in the generated {@code SystemCallHooks} interface.
 *
 * @see BPFKernelMemory
 */
@Target({ElementType.PARAMETER, ElementType.LOCAL_VARIABLE})
@Retention(RetentionPolicy.RUNTIME)
public @interface BPFUserMemory {
}
