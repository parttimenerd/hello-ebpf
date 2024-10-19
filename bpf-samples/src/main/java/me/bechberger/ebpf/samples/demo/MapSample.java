package me.bechberger.ebpf.samples.demo;

import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.BPFJ;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.runtime.OpenDefinitions.open_how;
import me.bechberger.ebpf.runtime.interfaces.SystemCallHooks;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.bpf_get_current_comm;

/**
 * Count the number of files opened per process
 */
@BPF(license = "GPL")
public abstract class MapSample extends BPFProgram implements SystemCallHooks {

    static final int STRING_SIZE = 100;

    @Type
    static class Entry {
        @Size(STRING_SIZE)
        String comm;
        int count;
    }

    @BPFMapDefinition(maxEntries = 100 * 1024)
    BPFHashMap<@Size(STRING_SIZE) String, Entry> readFilePerProcess;

    @Override
    public void enterOpenat2(int dfd, String filename, Ptr<open_how> how) {
        @Size(STRING_SIZE) String key = "";
        bpf_get_current_comm(Ptr.asVoidPointer(key), 100);
        var result = readFilePerProcess.bpf_get(key);
        if (result == null) {
            Entry entry = new Entry();
            entry.count = 1;
            BPFJ.bpf_probe_read_user_str(entry.comm, filename);
            readFilePerProcess.put(key, entry);
        } else {
           result.val().count++;
           BPFJ.bpf_probe_read_user_str(result.val().comm, filename);
        }
    }

    public static void main(String[] args) throws InterruptedException {
        try (MapSample program = BPFProgram.load(MapSample.class)) {
            program.autoAttachPrograms();
            while (true) {
                program.readFilePerProcess.forEach((key, value) -> {
                    System.out.println("Process: " + key + " opened " + value.count + " files, e.g. " + value.comm);
                    // program.readFilePerProcess.delete(key);
                });
                Thread.sleep(1000);
            }
        }
    }
}