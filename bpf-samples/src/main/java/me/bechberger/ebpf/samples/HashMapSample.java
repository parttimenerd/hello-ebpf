package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.map.BPFBaseMap.PutMode;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.runtime.AnonDefinitions.__sifields;
import me.bechberger.ebpf.runtime.OpenDefinitions.open_how;
import me.bechberger.ebpf.runtime.interfaces.SystemCallHooks;
import me.bechberger.ebpf.runtime.runtime;
import me.bechberger.ebpf.runtime.runtime.TASK_COMM_LEN;
import me.bechberger.ebpf.type.BPFType;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.bpf_get_current_comm;

/**
 * Print the number of openat syscalls per process, using a hash map to count them
 */
@BPF
public abstract class HashMapSample extends BPFProgram implements SystemCallHooks {

    private static final int TASK_COMM_LEN = 16;

    @BPFMapDefinition(maxEntries = 256)
    BPFHashMap<@Size(TASK_COMM_LEN) String, @Unsigned Integer> map;

    @Override
    public void enterOpenat2(int dfd, String filename, Ptr<open_how> how) {
        @Size(TASK_COMM_LEN) String comm = "";

        // Read the current process name
        bpf_get_current_comm(Ptr.of(comm), TASK_COMM_LEN);

        // increment the counter at map[comm]
        Ptr<@Unsigned Integer> counter = map.bpf_get(comm);
        if (counter == null) {
            @Unsigned int one = 1;
            map.put(comm, one, PutMode.BPF_EXIST);
        } else {
            counter.set(counter.val() + 1);
        }
    }

    public static void main(String[] args) throws InterruptedException {
        try (HashMapSample program = BPFProgram.load(HashMapSample.class)) {
            program.autoAttachPrograms();
            while (true) {
                System.out.println("OpenAt's per process:");
                for (var entry : program.map) {
                    System.out.printf("%16s: %4d\n", entry.getKey(), entry.getValue());
                }
                Thread.sleep(1000);
            }
        }
    }
}