package me.bechberger.ebpf.bpf.compiler.structops;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.structops.TcpCongestionControl;
import me.bechberger.ebpf.type.Ptr;
import me.bechberger.ebpf.runtime.runtime.sock;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end integration for {@code @StructOps}: verifies that a {@code @BPF}
 * class implementing a {@code @StructOps}-annotated interface produces
 *   (a) the SEC-tagged BPF_PROG stubs for each overridden virtual field,
 *   (b) the {@code SEC(".struct_ops.link") struct tcp_congestion_ops ...} instance,
 *   (c) a {@code META-INF/ebpf-struct-ops/<userClass>.json} manifest resource
 *       emitted via the annotation processor's {@code Filer}.
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
     * source files therefore land on disk but javac no longer compiles them.
     * We therefore emit the manifest as a JSON classpath resource
     * ({@code META-INF/ebpf-struct-ops/<userClass>.json}) via
     * {@code Filer.createResource(CLASS_OUTPUT, ...)}, which packages regardless
     * of processing phase. The runtime loads it via {@code getResourceAsStream}.
     * The resource path uses {@code Class.getName()} form so nested-class binary
     * names (e.g. {@code Outer$Inner}) round-trip correctly.
     */
    @Test
    void manifestResourceGenerated() throws Exception {
        // Resource is written to target/test-classes/META-INF/ebpf-struct-ops/...
        // Prefer the classloader lookup so the test does not depend on Surefire cwd.
        String resourceName = "META-INF/ebpf-struct-ops/"
                + HelloCc.class.getName() + ".json";
        var url = HelloCc.class.getClassLoader().getResource(resourceName);
        String src;
        if (url != null) {
            src = Files.readString(Path.of(url.toURI()));
        } else {
            // Fallback: scan target/ for the JSON file (older builds, quirky cwds).
            Path root = Path.of(System.getProperty("user.dir"));
            try (var stream = Files.walk(root.resolve("target"))) {
                Path found = stream
                        .filter(p -> p.toString().replace('\\', '/').endsWith(
                                "META-INF/ebpf-struct-ops/" + HelloCc.class.getName() + ".json"))
                        .findFirst()
                        .orElseThrow(() -> new AssertionError(
                                resourceName + " not found on classpath or under target/"));
                src = Files.readString(found);
            }
        }
        // String-contains checks match the existing test style and avoid
        // adding a femtojson dep to this module just for a shape check.
        assertTrue(src.contains("\"userClass\""),
                "manifest must declare a userClass field:\n" + src);
        assertTrue(src.contains(HelloCc.class.getName()),
                "manifest userClass must match the runtime binary name:\n" + src);
        assertTrue(src.contains("\"kernelName\""),
                "manifest must declare a kernelName field:\n" + src);
        assertTrue(src.contains("\"tcp_congestion_ops\""),
                "manifest must list tcp_congestion_ops kernel name:\n" + src);
        assertTrue(src.contains("\"mapName\""),
                "manifest must declare a mapName field:\n" + src);
        assertTrue(src.contains("\"HelloCc\""),
                "manifest must list HelloCc map name:\n" + src);
        assertTrue(src.contains("\"5.6\""),
                "manifest must list 5.6 since-version:\n" + src);
    }
}
