package me.bechberger.ebpf.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a generated Java class as mirroring a kernel BTF type
 * (struct/union/typedef) emitted by {@code bpf-gen}. The compiler plugin
 * uses this to switch field access from plain {@code receiver->field} to
 * {@code BPF_CORE_READ(receiver, field)} so libbpf can relocate the access
 * against the target kernel's BTF at load time (CO-RE).
 * <p>
 * Only attached by {@code bpf-gen}'s {@code Generator}. User-written
 * {@code @Type} records and classes must NOT carry it — their layout is
 * fixed at compile time and CO-RE relocation does not apply.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface KernelBTF {
}
