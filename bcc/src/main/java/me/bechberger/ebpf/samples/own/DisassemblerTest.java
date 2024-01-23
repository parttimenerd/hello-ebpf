/**
 * Use disassembler to disassemble eBPF bytecode of HelloMap
 */
package me.bechberger.ebpf.samples.own;

import me.bechberger.ebpf.bcc.BPF;

public class DisassemblerTest {
    public static void main(String[] args) {
        try (var b = BPF.builder("""
                BPF_HASH(counter_table);
                
                int hello(void *ctx) {
                   u64 uid;
                   u64 counter = 0;
                   u64 *p;
                
                   uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
                   p = counter_table.lookup(&uid);
                   if (p != 0) {
                      counter = *p;
                   }
                   counter++;
                   counter_table.update(&uid, &counter);
                   return 0;
                }
                """).build()) {
            var expected = """
                    Disassemble of BPF program hello:
                       0: (85) call bpf_get_current_uid_gid#15
                       1: (67) r0 <<= 32
                       2: (77) r0 >>= 32
                       3: (7b) *(u64*)(r10 -8) = r0
                       4: (18) r1 = <map at fd #4>
                       6:      (64-bit upper word)
                       6: (bf) r2 = r10
                       7: (07) r2 += -8
                       8: (85) call bpf_map_lookup_elem#1
                       9: (b7) r1 = 1
                      10: (15) if r0 == 0 goto pc+2 <13>
                      11: (79) r1 = *(u64*)(r0 +0)
                      12: (07) r1 += 1
                      13: (7b) *(u64*)(r10 -16) = r1
                      14: (18) r1 = <map at fd #4>
                      16:      (64-bit upper word)
                      16: (bf) r2 = r10
                      17: (07) r2 += -8
                      18: (bf) r3 = r10
                      19: (07) r3 += -16
                      20: (b7) r4 = 0
                      21: (85) call bpf_map_update_elem#2
                      22: (b7) r0 = 0
                      23: (95) exit
                    """;
            var actual = b.disassemble_func("hello");
            System.out.println(actual);
            if (!actual.equals(expected)) {
                System.out.println("Differs from the output of the similar Python program");
            }
        }
    }
}
