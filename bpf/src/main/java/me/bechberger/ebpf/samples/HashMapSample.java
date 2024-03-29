package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.Type;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.shared.BPFType;

import java.util.Map;

/**
 * Print the number of openat syscalls per process, using a hash map to count them
 */
@BPF
public abstract class HashMapSample extends BPFProgram {

    static final String EBPF_PROGRAM = """
                       #include "vmlinux.h"
            #include <bpf/bpf_helpers.h>
            #include <bpf/bpf_tracing.h>
            #include <string.h>
                            
            #define TASK_COMM_LEN 16
                            
                            
            // eBPF map reference
            struct
            {
              __uint (type, BPF_MAP_TYPE_HASH);
              __uint (max_entries, 256);
              __type (key, char[TASK_COMM_LEN]);
              __type (value, u32);
            } map SEC (".maps");
                            
            // The ebpf auto-attach logic needs the SEC
            SEC ("kprobe/do_sys_openat2")
                 int kprobe__do_sys_openat2 (struct pt_regs *ctx)
            {
              char comm[TASK_COMM_LEN] = { 42, 0 };
                          
              // Read the current process name
              bpf_get_current_comm (comm, sizeof (comm));
                            
              // increment the counter at map[comm]
              u32 *counter = bpf_map_lookup_elem (&map, comm);
              if (counter == NULL)
                {
                  u32 one = 1;
                  bpf_map_update_elem (&map, comm, &one, BPF_ANY);
                }
              else
                {
                  (*counter)++;
                }
              return 0;
            }
                            
            char _license[] SEC ("license") = "GPL";
            """;
    private static final int TASK_COMM_LEN = 16;

    public static void main(String[] args) throws InterruptedException {
        try (HashMapSample program = BPFProgram.load(HashMapSample.class)) {
            program.autoAttachProgram(program.getProgramByName("kprobe__do_sys_openat2"));
            var map = program.getHashMapByName("map", new BPFType.StringType(TASK_COMM_LEN), BPFType.BPFIntType.UINT32);
            while (true) {
                System.out.println("OpenAt's per process:");
                for (var entry : map) {
                    System.out.printf("%16s: %4d\n", entry.getKey(), entry.getValue());
                }
                Thread.sleep(1000);
            }
        }
    }
}