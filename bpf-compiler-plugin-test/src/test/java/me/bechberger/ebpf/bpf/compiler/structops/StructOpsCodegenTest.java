package me.bechberger.ebpf.bpf.compiler.structops;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.structops.TcpCongestionControl;
import me.bechberger.ebpf.type.Ptr;
import me.bechberger.ebpf.runtime.runtime.sock;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * End-to-end integration for {@code @StructOps}: verifies that a {@code @BPF}
 * class implementing a {@code @StructOps}-annotated interface produces
 *   (a) the SEC-tagged BPF_PROG stubs for each overridden virtual field,
 *   (b) the {@code SEC(".struct_ops.link") struct tcp_congestion_ops ...} instance,
 *   (c) a companion {@link me.bechberger.ebpf.bpf.structops.StructOpsManifest}
 *       source file emitted via the annotation processor's {@code Filer}.
 */
class StructOpsCodegenTest {

    @BPF
    public static abstract class HelloCc extends BPFProgram implements TcpCongestionControl {
        @Override public int ssthresh(Ptr<sock> sk) { return 42; }
        @Override public String name() { return "hellocc"; }
    }

    @Test
    void tcpCongMinimalEmits() {
        String c = BPFProgram.getCode(HelloCc.class);
        assertTrue(c.contains("SEC(\"struct_ops/ssthresh\")"),
                "expected SEC struct_ops/ssthresh in:\n" + c);
        assertTrue(c.contains("BPF_PROG(ssthresh"),
                "expected BPF_PROG(ssthresh...) header in:\n" + c);
        assertTrue(c.contains("SEC(\".struct_ops.link\")"),
                "expected SEC .struct_ops.link in:\n" + c);
        assertTrue(c.contains("struct tcp_congestion_ops HelloCc = {"),
                "expected struct instance in:\n" + c);
        assertTrue(c.contains(".ssthresh = (void *)ssthresh"),
                "expected ssthresh field wire-up in:\n" + c);
        assertTrue(c.contains(".name = \"hellocc\""),
                "expected .name literal init in:\n" + c);
    }

    /**
     * The CompilerPlugin hooks into javac at {@code TaskEvent.Kind.ANALYZE},
     * i.e. after annotation-processing rounds have closed. Filer-emitted
     * source files therefore land on disk but javac no longer compiles them,
     * so we cannot resolve the manifest class at test-runtime via
     * {@code Class.forName}. Instead, verify the manifest source was written
     * and contains the expected entry — the runtime {@code ServiceLoader}
     * consumers of {@link StructOpsManifest} pick it up on the next compile
     * cycle when the file is part of the initial input set.
     */
    @Test
    void manifestSourceGenerated() throws Exception {
        // Manifest .java file is written under generated-test-sources.
        Path root = Path.of(System.getProperty("user.dir"));
        Path manifest = root.resolve(
                "target/generated-test-sources/test-annotations/"
                        + "me/bechberger/ebpf/bpf/compiler/structops/"
                        + "HelloCcStructOpsManifest.java");
        if (!Files.exists(manifest)) {
            // Fallback: locate it anywhere under target/ (Surefire may cwd differently).
            try (var stream = Files.walk(Path.of("target"))) {
                manifest = stream
                        .filter(p -> p.getFileName().toString().equals("HelloCcStructOpsManifest.java"))
                        .findFirst()
                        .orElseThrow(() -> new AssertionError(
                                "HelloCcStructOpsManifest.java not found under target/"));
            }
        }
        List<String> lines = Files.readAllLines(manifest);
        String src = String.join("\n", lines);
        assertTrue(src.contains("package me.bechberger.ebpf.bpf.compiler.structops;"),
                "manifest must declare correct package:\n" + src);
        assertTrue(src.contains("implements me.bechberger.ebpf.bpf.structops.StructOpsManifest"),
                "manifest must implement SPI:\n" + src);
        assertTrue(src.contains("\"tcp_congestion_ops\""),
                "manifest must list tcp_congestion_ops kernel name:\n" + src);
        assertTrue(src.contains("\"HelloCc\""),
                "manifest must list HelloCc map name:\n" + src);
        assertTrue(src.contains("\"5.6\""),
                "manifest must list 5.6 since-version:\n" + src);
    }
}

