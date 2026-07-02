package me.bechberger.ebpf.bpf.structops;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.runtime.runtime;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class StructOpsAttachTest {

    @BPF(license = "GPL")
    abstract static class HelloCcSample extends BPFProgram implements TcpCongestionControl {
        @Override public @Unsigned int ssthresh(Ptr<runtime.sock> sk)              { return 42; }
        @Override public void congAvoid(Ptr<runtime.sock> sk, @Unsigned int ack, @Unsigned int acked) { }
        @Override public @Unsigned int undoCwnd(Ptr<runtime.sock> sk)              { return 0; }
        @Override public String name() { return "hellocc"; }
    }

    @Test
    void tcpCongregistrsAndUnregisters() throws Exception {
        String proc = "/proc/sys/net/ipv4/tcp_available_congestion_control";
        try (var prog = BPFProgram.load(HelloCcSample.class)) {
            var infos = prog.structOpsInfo();
            assertEquals(1, infos.size(), "expected exactly one @StructOps entry");
            assertEquals("tcp_congestion_ops", infos.get(0).kernelName());
            assertEquals("HelloCcSample", infos.get(0).mapName());
            String available = Files.readString(Path.of(proc));
            assertTrue(available.contains("hellocc"),
                    "expected 'hellocc' in " + proc + " but got: " + available);
        }
        String after = Files.readString(Path.of(proc));
        assertFalse(after.contains("hellocc"),
                "expected 'hellocc' removed from " + proc + " after close but got: " + after);
    }
}
