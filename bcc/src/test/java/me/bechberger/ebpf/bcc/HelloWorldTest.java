package me.bechberger.ebpf.bcc;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test version of {@link me.bechberger.ebpf.samples.chapter2.HelloWorld}
 */
public class HelloWorldTest {
    @Test
    @Disabled
    public void testHelloWorld() throws Exception {
        try (BPF b = BPF.builder("""
                int hello(void *ctx) {
                   bpf_trace_printk("Hello, World!");
                   return 0;
                }
                """).build()) {
            var syscall = b.get_syscall_fnname("execve");
            b.attach_kprobe(syscall, "hello");
            Utils.runCommand("uname", "-r");
            var line = b.trace_readline();
            int tries = 0;
            while (!line.contains("Hello, World!") && tries < 10) {
                System.out.println(line);
                line = b.trace_readline();
                tries++;
            }
            assertTrue(line.contains("Hello, World!"));
        }
    }
}
