/**
 * HelloBuffer that outputs different trace messages for even and odd process ids
 */
package me.bechberger.ebpf.samples.chapter2.ex;

import me.bechberger.ebpf.bcc.BPF;
import me.bechberger.ebpf.bcc.BPFTable;
import me.bechberger.ebpf.samples.chapter2.HelloBuffer;

import static me.bechberger.ebpf.samples.chapter2.HelloBuffer.DATA_TYPE;

/**
 * Also shows how to reuse data types from {@link HelloBuffer}
 */
public class HelloBufferEvenOdd {
    public static void main(String[] args) throws InterruptedException {
        try (var b = BPF.builder("""
                BPF_PERF_OUTPUT(output);
                                
                struct data_t {
                    int pid;
                    int uid;
                    char command[16];
                    char message[12];
                };
                                
                int hello(void *ctx) {
                    struct data_t data = {};
                    
                    char even_message[12] = "Even pid";
                    char odd_message[12] = "Odd pid";
                   
                    data.pid = bpf_get_current_pid_tgid() >> 32;
                    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
                                
                    bpf_get_current_comm(&data.command, sizeof(data.command));
                    if (data.pid % 2 == 0) {
                        bpf_probe_read_kernel(&data.message, sizeof(data.message), even_message);
                    } else {
                        bpf_probe_read_kernel(&data.message, sizeof(data.message), odd_message);
                    }
                                
                    output.perf_submit(ctx, &data, sizeof(data));
                                
                    return 0;
                }
                """).build()) {
            var syscall = b.get_syscall_fnname("execve");
            b.attach_kprobe(syscall, "hello");

            BPFTable.PerfEventArray.EventCallback<HelloBuffer.Data> print_event = (array, cpu, data, size) -> {
                var d = array.event(data);
                System.out.printf("%d %d %s %s%n", d.pid(), d.uid(), d.command(), d.message());
            };

            try (var output = b.get("output", BPFTable.PerfEventArray.<HelloBuffer.Data>createProvider(DATA_TYPE)).open_perf_buffer(print_event)) {
                while (true) {
                    b.perf_buffer_poll();
                }
            }
        }
    }
}
