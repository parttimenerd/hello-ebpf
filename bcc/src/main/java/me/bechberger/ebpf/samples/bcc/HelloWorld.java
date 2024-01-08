/**
 * Most basic example from the bcc repository
 */
package me.bechberger.ebpf.samples.bcc;

import me.bechberger.ebpf.bcc.BPF;

/**
 * Basic hello world example from hello_world.py
 * <p>
 * {@snippet :
    from bcc import BPF

    BPF(text = r"""
    int kprobe__sys_clone(void *ctx) {
       bpf_trace_printk("Hello, World!");
       return 0;
    }
    """).trace_print()
 }
 */
public class HelloWorld {
    public static void main(String[] args) {
        try (BPF b = BPF.builder("""
                int kprobe__sys_clone(void *ctx) {
                   bpf_trace_printk("Hello, World!");
                   return 0;
                }
                """).build()) {
            b.trace_print();
        }
    }
}