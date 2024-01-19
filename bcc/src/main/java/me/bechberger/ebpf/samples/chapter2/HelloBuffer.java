/**
 * Record data in perf buffer
 */
package me.bechberger.ebpf.samples.chapter2;

import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.bcc.BPF;
import me.bechberger.ebpf.bcc.BPFTable;
import me.bechberger.ebpf.bcc.BPFType;

import java.util.List;

/**
 * {@snippet :
 * #!/usr/bin/python3
 * from bcc import BPF
 *
 * program = r"""
 * BPF_PERF_OUTPUT(output);
 *
 * struct data_t {
 * int pid;
 * int uid;
 * char command[16];
 * char message[12];
 * };
 *
 * int hello(void *ctx) {
 * struct data_t data = {};
 * char message[12] = "Hello World";
 *
 * data.pid = bpf_get_current_pid_tgid() >> 32;
 * data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
 *
 * bpf_get_current_comm(&data.command, sizeof(data.command));
 * bpf_probe_read_kernel(&data.message, sizeof(data.message), message);
 *
 * output.perf_submit(ctx, &data, sizeof(data));
 *
 * return 0;
 * }
 * """
 *
 * b = BPF(text=program)
 * syscall = b.get_syscall_fnname("execve")
 * b.attach_kprobe(event=syscall, fn_name="hello")
 *
 * def print_event(cpu, data, size):
 * data = b["output"].event(data)
 * print(f"{data.pid}{data.uid}{data.command.decode()}{data.message.decode()}")
 *
 * b["output"].open_perf_buffer(print_event)
 * while True:
 * b.perf_buffer_poll()
 *}
 */
public class HelloBuffer {
    public record Data(int pid, int uid, @Size(16) String command, @Size(12) String message) {
    }

    public static final BPFType.BPFStructType<Data> DATA_TYPE = new BPFType.BPFStructType<>("data_t",
            List.of(
                    new BPFType.BPFStructMember<>("pid", BPFType.BPFIntType.INT32, 0, Data::pid),
                    new BPFType.BPFStructMember<>("uid", BPFType.BPFIntType.INT32, 4, Data::uid),
                    new BPFType.BPFStructMember<>("command", new BPFType.StringType(16), 8, Data::command),
                    new BPFType.BPFStructMember<>("message", new BPFType.StringType(12), 24, Data::message)),
            new BPFType.AnnotatedClass(Data.class, List.of()),
                objects -> new Data((int) objects.get(0), (int) objects.get(1), (String) objects.get(2), (String) objects.get(3)));

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
                    char message[12] = "Hello World";
                                
                    data.pid = bpf_get_current_pid_tgid() >> 32;
                    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
                                
                    bpf_get_current_comm(&data.command, sizeof(data.command));
                    bpf_probe_read_kernel(&data.message, sizeof(data.message), message);
                                
                    output.perf_submit(ctx, &data, sizeof(data));
                                
                    return 0;
                }
                """).build()) {
            var syscall = b.get_syscall_fnname("execve");
            b.attach_kprobe(syscall, "hello");

            BPFTable.PerfEventArray.EventCallback<Data> print_event = (array, cpu, data, size) -> {
                var d = array.event(data);
                System.out.printf("%d %d %s %s%n", d.pid(), d.uid(), d.command(), d.message());
            };

            try (var output = b.get("output", BPFTable.PerfEventArray.<Data>createProvider(DATA_TYPE)).open_perf_buffer(print_event)) {
                while (true) {
                    b.perf_buffer_poll();
                }
            }
        }
    }
}
