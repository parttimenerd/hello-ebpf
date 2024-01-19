/**
 * HelloTail that counts the syscalls per user and prints them out every 2 seconds
 */
package me.bechberger.ebpf.samples.chapter2.ex;

import me.bechberger.ebpf.bcc.BPF;
import me.bechberger.ebpf.bcc.BPFTable;

import java.util.Comparator;
import java.util.Map;
import java.util.stream.Collectors;

public class HelloTailCountSyscalls {
    public static void main(String[] args) throws InterruptedException {
        try (var b = BPF.builder("""
                BPF_HASH(counter_table);
                
                int hello(struct bpf_raw_tracepoint_args *ctx) {
                    u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
                    u64 *p = counter_table.lookup(&uid);
                    u64 counter = 0;
                    if (p != 0) {
                        counter = *p;
                    }
                    counter++;
                    counter_table.update(&uid, &counter);
                    return 0;
                }
                """).build()) {
            b.attach_raw_tracepoint("sys_enter", "hello");
            var counterTable = b.get_table("counter_table", BPFTable.HashTable.UINT64T_MAP_PROVIDER);
            while (true) {
                Thread.sleep(2000);
                counterTable.entrySet().stream().sorted(Comparator.comparing(Map.Entry::getKey)).forEach(entry -> {
                    System.out.printf("ID %d: %d\t", entry.getKey(), entry.getValue());
                });
                System.out.println();
            }
        }
    }
}
