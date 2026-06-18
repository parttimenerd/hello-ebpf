package me.bechberger.ebpf.bpf.compiler;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Convention test: every static-detection pass that emits messages must follow the 4-part
 * format ("what / Why: / Fix: / See:"). This locks in the format so a future contributor
 * doesn't accidentally regress to one-liners.
 *
 * <p>The check is intentionally light: it samples each pass with a representative trigger and
 * asserts the produced message contains "Why:" and "Fix:" (the See: line is optional for
 * categories without a cookbook section).
 */
class DiagnosticFormatTest {

    /** Each entry samples a single pass with a fixture that should produce one detection. */
    private record PassFixture(String name, List<String> messages) {}

    private static List<PassFixture> sampleEachPass() {
        return List.of(
                new PassFixture("JavaIsmsRejectPass.throw",
                        toMessages(JavaIsmsRejectPass.detect(parse("""
                                class T { void f() { throw new RuntimeException(); } }
                                """, "f")))),
                new PassFixture("JavaIsmsRejectPass.system-out",
                        toMessages(JavaIsmsRejectPass.detect(parse("""
                                class T { void f() { System.out.println("x"); } }
                                """, "f")))),
                new PassFixture("MapIdiomLintPass.unchecked-lookup",
                        toMessages2(MapIdiomLintPass.detect(parse("""
                                class T { void f(M m, int k) { m.bpf_get(k).val(); } }
                                """, "f")))),
                new PassFixture("MapIdiomLintPass.no-submit",
                        toMessages2(MapIdiomLintPass.detect(parse("""
                                class T { void f(B rb) { var ev = rb.reserve(); } }
                                """, "f")))),
                new PassFixture("UnboundedLoopPass",
                        toMessages4(UnboundedLoopPass.detect(parse("""
                                class T { void f() { while (true) { } } }
                                """, "f")))),
                new PassFixture("ProbeReadSizeZeroPass",
                        toMessages5(ProbeReadSizeZeroPass.detect(parse("""
                                class T { void f(Object dst, Object src) { bpf_probe_read_kernel(dst, 0, src); } }
                                """, "f")))),
                new PassFixture("MissingCoreReadPass",
                        toMessages6(MissingCoreReadPass.detect(parse("""
                                class T { int f(Object p) { return p.<Object>cast().field; } }
                                """, "f"))))
        );
    }

    private static List<String> toMessages(List<JavaIsmsRejectPass.Detection> ds) {
        return ds.stream().map(JavaIsmsRejectPass.Detection::message).toList();
    }

    private static List<String> toMessages2(List<MapIdiomLintPass.Detection> ds) {
        return ds.stream().map(MapIdiomLintPass.Detection::message).toList();
    }

    private static List<String> toMessages4(List<UnboundedLoopPass.Detection> ds) {
        return ds.stream().map(UnboundedLoopPass.Detection::message).toList();
    }

    private static List<String> toMessages5(List<ProbeReadSizeZeroPass.Detection> ds) {
        return ds.stream().map(ProbeReadSizeZeroPass.Detection::message).toList();
    }

    private static List<String> toMessages6(List<MissingCoreReadPass.Detection> ds) {
        return ds.stream().map(MissingCoreReadPass.Detection::message).toList();
    }

    private static com.sun.source.tree.Tree parse(String src, String methodName) {
        return me.bechberger.ebpf.bpf.compiler.flow.JavacTestSupport.parseMethod(src, methodName).getBody();
    }

    @Test
    void everyPassEmitsAtLeastOneMessage() {
        for (var fixture : sampleEachPass()) {
            assertFalse(fixture.messages.isEmpty(),
                    fixture.name + " produced no messages — fixture may be wrong");
        }
    }

    @Test
    void allMessagesContainWhyAndFix() {
        for (var fixture : sampleEachPass()) {
            for (var msg : fixture.messages) {
                assertTrue(msg.contains("Why:"),
                        fixture.name + " missing 'Why:' line:\n" + msg);
                assertTrue(msg.contains("Fix:"),
                        fixture.name + " missing 'Fix:' line:\n" + msg);
            }
        }
    }

    @Test
    void allMessagesAreMultiLine() {
        // 4-part messages span at least 3 lines (lead + Why + Fix).
        for (var fixture : sampleEachPass()) {
            for (var msg : fixture.messages) {
                long lines = Stream.of(msg.split("\n")).filter(s -> !s.isBlank()).count();
                assertTrue(lines >= 3, fixture.name + " message is not multi-line:\n" + msg);
            }
        }
    }

    @Test
    void allMessagesHaveLeadingWhatLine() {
        // The first non-empty line should not start with "Why:" or "Fix:" — it's the "what".
        for (var fixture : sampleEachPass()) {
            for (var msg : fixture.messages) {
                String first = Stream.of(msg.split("\n")).filter(s -> !s.isBlank()).findFirst().orElse("");
                assertFalse(first.startsWith("Why:"),
                        fixture.name + " starts with 'Why:' instead of a 'what' line:\n" + msg);
                assertFalse(first.startsWith("Fix:"),
                        fixture.name + " starts with 'Fix:' instead of a 'what' line:\n" + msg);
            }
        }
    }
}
