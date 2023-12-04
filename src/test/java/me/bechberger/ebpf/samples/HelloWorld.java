package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.bcc.BCC;

/**
 * Basic hello world example from hello_world.py
 * <p>
 * {@snippet :
 * from bcc import BPF
 *
 * BPF(text = r"""
 * int kprobe__sys_clone(void *ctx) {
 *     bpf_trace_printk("Hello, World!\\n");
 *     return0;
 * }
 * """).trace_print()
 *}
 */
public class HelloWorld {
    public static void main(String[] args) {
        try (BCC bcc = BCC.builder("""
                int kprobe__sys_clone(void *ctx) {
                   bpf_trace_printk("Hello, World!\\\\n");
                   return0;
                }
                """).build()) {
            bcc.trace_print();
        }
    }
}