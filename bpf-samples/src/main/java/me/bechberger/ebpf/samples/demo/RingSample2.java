package me.bechberger.ebpf.samples.presentation;

import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.BPFJ;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.map.BPFRingBuffer;
import me.bechberger.ebpf.runtime.OpenDefinitions.open_how;
import me.bechberger.ebpf.runtime.interfaces.SystemCallHooks;
import me.bechberger.ebpf.type.Ptr;

/**
 * Log the filenames of openat2 calls in a ring buffer
 */
@BPF(license = "GPL")
public abstract class RingSample2 extends BPFProgram implements SystemCallHooks {

    @BPFMapDefinition(maxEntries = 100 * 1024)
    BPFRingBuffer<@Size(100) String> readFiles;

    @Override
    public void enterOpenat2(int dfd, String filename, Ptr<open_how> how) {
        var elem = readFiles.reserve();
        if (elem == null) {
            return;
        }
        BPFJ.bpf_probe_read_user_str(elem.val(), filename);
        readFiles.submit(elem);
    }

    public static void main(String[] args) throws InterruptedException {
        try (RingSample2 program = BPFProgram.load(RingSample2.class)) {
            program.readFiles.setCallback(System.out::println);
            program.autoAttachPrograms();
            while (true) {
                program.consumeAndThrow();
                Thread.sleep(1000);
            }
        }
    }
}