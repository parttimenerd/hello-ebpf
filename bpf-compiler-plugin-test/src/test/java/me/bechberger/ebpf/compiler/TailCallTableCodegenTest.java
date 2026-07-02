package me.bechberger.ebpf.compiler;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verify the annotation processor emits the expected register(...) calls
 * into the generated Impl.java. We inspect the emitted source text (not
 * bytecode) because it is stable and easy to read.
 */
public class TailCallTableCodegenTest {

    @Test
    public void generatedImplContainsRegisterCallsForEachSlot() {
        var src = new InMemoryJavaCompiler.Source("tct.Prog",
                "package tct;\n"
                        + "import me.bechberger.ebpf.annotations.bpf.*;\n"
                        + "import me.bechberger.ebpf.bpf.BPFProgram;\n"
                        + "import me.bechberger.ebpf.bpf.map.*;\n"
                        + "@BPF(license = \"GPL\")\n"
                        + "public abstract class Prog extends BPFProgram {\n"
                        + "  public enum Slot { PARSE_ETH, PARSE_IP, COUNT }\n"
                        + "  @BPFTailCallTable(slots = Slot.class)\n"
                        + "  @BPFMapDefinition(maxEntries = 3)\n"
                        + "  BPFProgArray dispatch;\n"
                        + "  @BPFFunction(section = \"xdp\") @TailCallSlot(\"PARSE_ETH\")\n"
                        + "  public int parseEthImpl() { return 0; }\n"
                        + "  @BPFFunction(section = \"xdp\") @TailCallSlot(\"PARSE_IP\")\n"
                        + "  public int parseIpImpl() { return 0; }\n"
                        + "  @BPFFunction(section = \"xdp\") @TailCallSlot(\"COUNT\")\n"
                        + "  public int countImpl() { return 0; }\n"
                        + "}\n");
        var res = InMemoryJavaCompiler.compile(List.of(src),
                new me.bechberger.ebpf.bpf.processor.Processor())
                .requireSuccess("processor should accept a valid @BPFTailCallTable");

        String generated = res.generatedSource("tct.ProgImpl")
                .orElseThrow(() -> new AssertionError("no ProgImpl emitted; generated="
                        + res.generatedSources().keySet()));
        // register calls should appear in the constructor.
        assertTrue(generated.contains("dispatch.register(0, getProgramByName(\"parseEthImpl\"))"),
                "missing register(0, parseEthImpl) in:\n" + generated);
        assertTrue(generated.contains("dispatch.register(1, getProgramByName(\"parseIpImpl\"))"),
                "missing register(1, parseIpImpl) in:\n" + generated);
        assertTrue(generated.contains("dispatch.register(2, getProgramByName(\"countImpl\"))"),
                "missing register(2, parseIpImpl) in:\n" + generated);
    }
}
