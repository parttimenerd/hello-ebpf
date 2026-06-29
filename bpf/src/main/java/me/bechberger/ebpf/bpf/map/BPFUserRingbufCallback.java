package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.type.Ptr;

/**
 * Typed drain callback for {@link BPFUserRingBuffer#drain}. The compiler plugin
 * lowers the lambda body into a C thunk that reads {@code sizeof(E)} bytes from
 * the kernel-provided {@code bpf_dynptr*} via {@code bpf_dynptr_read} into a
 * stack-allocated {@code E}, then invokes the user body with a pointer to it.
 *
 * <p>Return 0 to continue draining, 1 to stop (matches libbpf's
 * {@code bpf_user_ringbuf_callback_fn} contract).
 *
 * @param <E>   type of the record written by user space
 * @param <Ctx> type of the opaque context passed through from the caller
 */
@FunctionalInterface
public interface BPFUserRingbufCallback<E, Ctx> {
    int apply(Ptr<E> record, Ptr<Ctx> ctx);
}
