from bcc import BPF

b = BPF(text="""
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
                """)
print(b.disassemble_func("hello"))