package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a BPF method as a timer callback.
 *
 * <p>A method annotated with {@code @BPFTimer} is called periodically by the kernel
 * via {@code bpf_timer_set_callback} / {@code bpf_timer_start}. The signature must be
 * compatible with the BPF timer callback convention:
 *
 * <pre>
 *     &#64;BPFTimer
 *     &#64;BPFFunction
 *     static int onTimer(Ptr&lt;?&gt; map, Ptr&lt;Integer&gt; key, Ptr&lt;TimerEntry&gt; value) { ... }
 * </pre>
 *
 * <p>The callback is registered by calling
 * {@link me.bechberger.ebpf.runtime.helpers.BPFHelpers#bpf_timer_set_callback} with a
 * reference to this method, and started with
 * {@link me.bechberger.ebpf.runtime.helpers.BPFHelpers#bpf_timer_start}.
 *
 * @see me.bechberger.ebpf.runtime.helpers.BPFHelpers#bpf_timer_init
 * @see me.bechberger.ebpf.runtime.helpers.BPFHelpers#bpf_timer_set_callback
 * @see me.bechberger.ebpf.runtime.helpers.BPFHelpers#bpf_timer_start
 * @see me.bechberger.ebpf.runtime.helpers.BPFHelpers#bpf_timer_cancel
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface BPFTimer {
}
