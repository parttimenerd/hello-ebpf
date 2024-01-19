/**
 * Count and print `execve` calls per user and store the result as a struct in a map
 */
package me.bechberger.ebpf.samples.own;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.bcc.BPF;
import me.bechberger.ebpf.bcc.BPFTable;
import me.bechberger.ebpf.bcc.BPFType;

import java.util.List;

/**
 * Based on {@link me.bechberger.ebpf.samples.chapter2.HelloMap}, but with a struct in the map
 */
public class HelloStructMap {

    /** Data stored in the map, with user id, group id and counter */
    record Data(@Unsigned long uid, @Unsigned long gid, @Unsigned int counter) {
    }

    static final BPFType.BPFStructType<Data> DATA_TYPE = new BPFType.BPFStructType<>("data_t",
            List.of(
                    new BPFType.BPFStructMember<>("uid", BPFType.BPFIntType.UINT64, 0, Data::uid),
                    new BPFType.BPFStructMember<>("gid", BPFType.BPFIntType.UINT64, 8, Data::gid),
                    new BPFType.BPFStructMember<>("counter", BPFType.BPFIntType.UINT32, 16, Data::counter)),
            new BPFType.AnnotatedClass(Data.class, List.of()),
            objects -> new Data((long) objects.get(0), (long) objects.get(1), (int) objects.get(2)));
    static final BPFTable.TableProvider<BPFTable.HashTable<@Unsigned Long, Data>> UINT64T_DATA_MAP_PROVIDER =
            (bpf, mapId, mapFd, name) ->
                    new BPFTable.HashTable<>(bpf, mapId, mapFd, BPFType.BPFIntType.UINT64, DATA_TYPE, name);

    public static void main(String[] args) throws InterruptedException {
        try (var b = BPF.builder("""
                struct data_t {
                   u64 uid;
                   u64 gid;
                   u32 counter;
                };
                                
                BPF_HASH(counter_table, u64, struct data_t);
                                
                int hello(void *ctx) {
                   u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
                   u64 gid = bpf_get_current_uid_gid() >> 32;
                   struct data_t info = {uid, gid, 0};
                   struct data_t *p = counter_table.lookup(&uid);
                   if (p != 0) {
                      info = *p;
                   }
                   info.counter++;
                   counter_table.update(&uid, &info);
                   return 0;
                }
                """).build()) {
            var syscall = b.get_syscall_fnname("execve");
            b.attach_kprobe(syscall, "hello");

            var counterTable = b.get_table("counter_table", UINT64T_DATA_MAP_PROVIDER);
            while (true) {
                Thread.sleep(2000);
                for (var value : counterTable.values()) {
                    System.out.printf("ID %d (GID %d): %d\t", value.uid(), value.gid(), value.counter());
                }
                System.out.println();
            }
        }
    }
}
