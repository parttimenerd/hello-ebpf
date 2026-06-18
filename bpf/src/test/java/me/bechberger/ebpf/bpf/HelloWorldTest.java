package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.bpf.BPFProgram.BPFProgramNotFound;
import me.bechberger.ebpf.bpf.BPFProgram.LoadedProgramInfo;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.shared.TraceLog;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests a simple compile, load and attach
 */
public class HelloWorldTest {

    @BPF(license = "GPL")
    public static abstract class Prog extends BPFProgram {
        final GlobalVariable<Boolean> hello = new GlobalVariable<>(false);

        @BPFFunction(
                section = "fentry/do_sys_openat2",
                autoAttach = true
        )
        int helloWorld(Ptr<PtDefinitions.pt_regs> ctx) {
            hello.set(true);
            return 0;
        }
    }

    @Test
    @Timeout(5)
    public void testProgramLoad() {
        try (var program = BPFProgram.load(Prog.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();
            assertTrue(program.hello.get());
        }
    }

    @Test
    public void testFailingProgramByName() {
        try (var program = BPFProgram.load(Prog.class)) {
            assertThrows(BPFProgramNotFound.class, () -> program.getProgramByName("invalid-name"));
        }
    }

    /**
     * Test the program is properly closed after
     */
    @Test
    public void testProgramClose() {
        try (var program = BPFProgram.load(Prog.class)) {
            var attached = program.autoAttachProgram(program.getProgramByName("helloWorld"));
            program.detachProgram(attached);
            program.hello.set(false);
            TestUtil.triggerOpenAt();

            long start = System.currentTimeMillis();
            // run for 20ms
            while (System.currentTimeMillis() - start < 20) {
                assertFalse(program.hello.get());
            }
        }
    }

    @Test
    @Timeout(5)
    public void testLoaded() {
        try (var program = BPFProgram.load(Prog.class)) {
            List<LoadedProgramInfo> infos = program.loaded();
            assertEquals(1, infos.size(), "Expected one program entry point");
            LoadedProgramInfo info = infos.get(0);
            assertEquals("helloWorld", info.name());
            assertTrue(info.fd() >= 0, "fd must be non-negative");
            assertTrue(info.id() > 0, "kernel program id must be positive");
        }
    }

    @Test
    @Timeout(5)
    public void testStatusServer() throws Exception {
        try (var program = BPFProgram.load(Prog.class)) {
            program.startStatusServer(19875);
            var client = HttpClient.newHttpClient();
            var response = client.send(
                    HttpRequest.newBuilder(URI.create("http://localhost:19875/status")).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, response.statusCode());
            var body = response.body();
            assertTrue(body.contains("\"programs\""), "response must contain programs key");
            assertTrue(body.contains("helloWorld"), "response must list the helloWorld program");
            assertTrue(body.contains("\"byteCodeHash\""), "response must contain byteCodeHash");
            program.stopStatusServer();
        }
    }

    @Test
    @Timeout(5)
    public void testByteCodeHash() {
        try (var program = BPFProgram.load(Prog.class)) {
            var hash = program.byteCodeHash();
            assertNotNull(hash);
            assertEquals(64, hash.length(), "SHA-256 hex digest must be 64 chars");
            assertTrue(hash.matches("[0-9a-f]+"), "hash must be lowercase hex");
            // Same program loaded twice should have same hash (deterministic compiler)
        }
    }
}
