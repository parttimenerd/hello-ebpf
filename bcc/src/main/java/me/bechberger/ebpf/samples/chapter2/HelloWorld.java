/**
 * Simple hello world example from chapter 2
 */
package me.bechberger.ebpf.samples.chapter2;

import me.bechberger.ebpf.bcc.BPF;

/**
 * Basic hello world example from chapter2/hello_world.py
 * <p>
 * {@snippet :
    from bcc import BPF

    program = r"""
    int hello(void *ctx) {
        bpf_trace_printk("Hello World!");
        return 0;
    }
    """

    b = BPF(text=program)
    syscall = b.get_syscall_fnname("execve")
    b.attach_kprobe(event=syscall, fn_name="hello")

    b.trace_print()
 *}
 */
public class HelloWorld {
    public static void main(String[] args) {
        try (BPF b = BPF.builder("""
                int hello(void *ctx) {
                   bpf_trace_printk("Hello, World!");
                   return 0;
                }
                """).build()) {
            var syscall = b.get_syscall_fnname("execve");
            b.attach_kprobe(syscall, "hello");
            b.trace_print();
        }
    }
}