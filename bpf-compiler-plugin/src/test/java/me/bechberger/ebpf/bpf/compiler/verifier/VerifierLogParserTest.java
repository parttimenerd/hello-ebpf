package me.bechberger.ebpf.bpf.compiler.verifier;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class VerifierLogParserTest {

    @Test
    void emptyLogReturnsEmptyResult() {
        var r = VerifierLogParser.parse("");
        assertTrue(r.instructions().isEmpty());
        assertTrue(r.error().isEmpty());
        assertTrue(r.processedInsnCount().isEmpty());
    }

    @Test
    void nullLogIsHandledGracefully() {
        var r = VerifierLogParser.parse(null);
        assertTrue(r.instructions().isEmpty());
        assertTrue(r.error().isEmpty());
    }

    @Test
    void simpleInsnTraceParses() {
        var log = """
                0: (b7) r1 = 0
                1: (61) r0 = *(u32 *)(r1 +0)
                R1 invalid mem access 'inv'
                processed 2 insns (limit 1000000) max_states_per_insn 0
                """;
        var r = VerifierLogParser.parse(log);
        assertEquals(2, r.instructions().size());
        assertEquals(0, r.instructions().get(0).offset());
        assertEquals("b7", r.instructions().get(0).rawHex());
        assertEquals("r1 = 0", r.instructions().get(0).body());
        assertEquals(1, r.instructions().get(1).offset());
        assertEquals(2, r.processedInsnCount().orElseThrow());
    }

    @Test
    void invalidMemAccessIsClassified() {
        var log = """
                0: (61) r0 = *(u32 *)(r1 +0)
                R1 invalid mem access 'inv'
                """;
        var err = VerifierLogParser.parse(log).error().orElseThrow();
        assertEquals(VerifierLogParser.ErrorClass.INVALID_MEM_ACCESS, err.errorClass());
        assertTrue(err.message().contains("invalid mem access"));
        assertEquals(0, err.instructionOffset().orElseThrow(),
                "the error attaches to the most recent traced insn");
    }

    @Test
    void uncheckedNullDerefIsClassified() {
        var log = """
                42: (15) if r0 == 0x0 goto pc+5
                R0 pointer comparison prohibited
                """;
        var err = VerifierLogParser.parse(log).error().orElseThrow();
        assertEquals(VerifierLogParser.ErrorClass.UNCHECKED_NULL_DEREF, err.errorClass());
    }

    @Test
    void outOfBoundsIsClassified() {
        var log = """
                10: (07) r1 += 8
                R1 max value is outside of the allowed memory range
                """;
        var err = VerifierLogParser.parse(log).error().orElseThrow();
        assertEquals(VerifierLogParser.ErrorClass.OUT_OF_BOUNDS, err.errorClass());
    }

    @Test
    void infiniteLoopIsClassified() {
        var log = """
                0: (b7) r1 = 0
                back-edge from insn 5 to 0
                """;
        var err = VerifierLogParser.parse(log).error().orElseThrow();
        assertEquals(VerifierLogParser.ErrorClass.INFINITE_LOOP, err.errorClass());
    }

    @Test
    void helperNotAllowedIsClassified() {
        var log = """
                3: (85) call bpf_get_current_task#143
                unknown func bpf_get_current_task#143
                """;
        var err = VerifierLogParser.parse(log).error().orElseThrow();
        assertEquals(VerifierLogParser.ErrorClass.HELPER_NOT_ALLOWED, err.errorClass());
    }

    @Test
    void registerStateDumpIsTreatedAsBookkeeping() {
        var log = """
                0: (b7) r1 = 0
                R0=inv R1=ctx(off=0,imm=0) R10=fp0
                R1 invalid mem access 'inv'
                """;
        var err = VerifierLogParser.parse(log).error().orElseThrow();
        // The register-state dump should NOT be picked up as the error line.
        assertTrue(err.message().contains("invalid mem access"),
                "register-state line must not displace the real error: " + err.message());
    }

    @Test
    void processedInsnsLineIsNotTreatedAsError() {
        var log = """
                0: (b7) r1 = 0
                R1 invalid mem access 'inv'
                processed 2 insns (limit 1000000)
                """;
        var err = VerifierLogParser.parse(log).error().orElseThrow();
        assertFalse(err.message().startsWith("processed "),
                "processed-N-insns line must be filtered out: " + err.message());
    }

    @Test
    void unrecognizedErrorFallsBackToOther() {
        var log = """
                0: (b7) r1 = 0
                some completely new verifier message
                """;
        var err = VerifierLogParser.parse(log).error().orElseThrow();
        assertEquals(VerifierLogParser.ErrorClass.OTHER, err.errorClass());
    }

    @Test
    void instructionOffsetEmptyWhenNoTrace() {
        var log = "no trace, just an error\n";
        var err = VerifierLogParser.parse(log).error().orElseThrow();
        assertTrue(err.instructionOffset().isEmpty());
    }

    @Test
    void classifyExposesClassificationDirectly() {
        assertEquals(VerifierLogParser.ErrorClass.INVALID_MEM_ACCESS,
                VerifierLogParser.classify("R1 invalid mem access 'inv'"));
        assertEquals(VerifierLogParser.ErrorClass.HELPER_NOT_ALLOWED,
                VerifierLogParser.classify("unknown func bpf_get_current_task#143"));
        assertEquals(VerifierLogParser.ErrorClass.OTHER,
                VerifierLogParser.classify("brand new error string"));
    }

    @Test
    void multilineTraceWithEdgeAnnotationsParses() {
        // Real verifier logs interleave from/to edge annotations between insns.
        var log = """
                0: (b7) r1 = 0
                1: (15) if r1 == 0x0 goto pc+2
                from 1 to 4: R0_w=inv R1_w=inv0
                4: (61) r0 = *(u32 *)(r1 +0)
                R1 invalid mem access 'inv'
                """;
        var r = VerifierLogParser.parse(log);
        assertEquals(3, r.instructions().size(), "should pick up insns at 0, 1, 4: " + r.instructions());
        assertEquals(VerifierLogParser.ErrorClass.INVALID_MEM_ACCESS, r.error().orElseThrow().errorClass());
        assertEquals(4, r.error().orElseThrow().instructionOffset().orElseThrow());
    }

    // --- Improved error parsing (real-world shapes) ---

    @Test
    void mapValueOrNullClassifiesAsUncheckedNullDeref() {
        // Canonical "forgot to null-check the map lookup" shape.
        var err = VerifierLogParser.classify("R0 invalid mem access 'map_value_or_null'");
        assertEquals(VerifierLogParser.ErrorClass.UNCHECKED_NULL_DEREF, err,
                "map_value_or_null is the missing-null-check signal, not a generic mem-access");
    }

    @Test
    void ptrOrNullClassifiesAsUncheckedNullDeref() {
        var err = VerifierLogParser.classify("R2 invalid mem access 'sock_or_null'");
        assertEquals(VerifierLogParser.ErrorClass.UNCHECKED_NULL_DEREF, err);
    }

    @Test
    void misalignedStackAccessClassifiesAsStackOob() {
        assertEquals(VerifierLogParser.ErrorClass.STACK_OOB,
                VerifierLogParser.classify("misaligned stack access off=-7 size=4"));
    }

    @Test
    void invalidWriteToStackClassifiesAsStackOob() {
        assertEquals(VerifierLogParser.ErrorClass.STACK_OOB,
                VerifierLogParser.classify("invalid write to stack R10 off=-520 size=8"));
    }

    @Test
    void unboundedMemoryAccessClassifiesAsOutOfBounds() {
        assertEquals(VerifierLogParser.ErrorClass.OUT_OF_BOUNDS,
                VerifierLogParser.classify("R3 unbounded memory access, use 'var &= const' or 'if (var < const)'"));
    }

    @Test
    void mapValueOutOfBoundsClassifiesAsOutOfBounds() {
        assertEquals(VerifierLogParser.ErrorClass.OUT_OF_BOUNDS,
                VerifierLogParser.classify("R0 map_value access out of bounds: off=200 size=4 value_size=128"));
    }

    @Test
    void programTooLargeIsItsOwnClass() {
        assertEquals(VerifierLogParser.ErrorClass.PROGRAM_TOO_LARGE,
                VerifierLogParser.classify("BPF program is too large. Processed 1000001 insn"));
    }

    @Test
    void tooManyInstructionsClassifiesAsProgramTooLarge() {
        assertEquals(VerifierLogParser.ErrorClass.PROGRAM_TOO_LARGE,
                VerifierLogParser.classify("too many instructions"));
    }

    @Test
    void infiniteLoopDetectedClassifies() {
        assertEquals(VerifierLogParser.ErrorClass.INFINITE_LOOP,
                VerifierLogParser.classify("infinite loop detected at insn 42"));
    }

    @Test
    void argTypeMismatchClassifies() {
        assertEquals(VerifierLogParser.ErrorClass.TYPE_MISMATCH,
                VerifierLogParser.classify("arg #1 type SCALAR_VALUE expected ptr_to_map_value"));
    }

    @Test
    void programOfThisTypeCannotUseHelperClassifies() {
        assertEquals(VerifierLogParser.ErrorClass.HELPER_NOT_ALLOWED,
                VerifierLogParser.classify("program of this type cannot use helper bpf_get_current_task"));
    }

    @Test
    void registerIsExtractedFromErrorLine() {
        var log = """
                0: (61) r0 = *(u32 *)(r1 +0)
                R0 invalid mem access 'inv'
                """;
        var err = VerifierLogParser.parse(log).error().orElseThrow();
        assertEquals("R0", err.register().orElseThrow());
    }

    @Test
    void registerIsEmptyWhenLineDoesNotStartWithR() {
        var log = """
                0: (b7) r1 = 0
                back-edge from insn 5 to 0
                """;
        var err = VerifierLogParser.parse(log).error().orElseThrow();
        assertTrue(err.register().isEmpty(), "back-edge has no register prefix");
    }

    @Test
    void firstClassifiableLineWinsOverTrailingRegisterDump() {
        // Real verifier output: register dump after the actionable error line.
        var log = """
                0: (61) r0 = *(u32 *)(r1 +0)
                R0 invalid mem access 'map_value_or_null'
                R0=map_value_or_null R1=ctx
                somenoise that does not classify
                """;
        var err = VerifierLogParser.parse(log).error().orElseThrow();
        assertEquals(VerifierLogParser.ErrorClass.UNCHECKED_NULL_DEREF, err.errorClass(),
                "should pick the classifiable line, not the trailing noise");
        assertTrue(err.message().contains("map_value_or_null"));
    }

    @Test
    void unclassifiedLogStillReturnsLastNonBookkeepingLine() {
        // No line classifies, but there's still an error to surface.
        var log = """
                0: (b7) r1 = 0
                some completely new verifier message
                another completely new verifier message
                """;
        var err = VerifierLogParser.parse(log).error().orElseThrow();
        assertEquals(VerifierLogParser.ErrorClass.OTHER, err.errorClass());
        assertEquals("another completely new verifier message", err.message(),
                "fallback to last candidate when nothing classifies");
    }

    @Test
    void sourceCommentLinesAreNotTreatedAsErrors() {
        // bpftool-style ; <java statement> // path:line comments must not be picked up as errors.
        var log = """
                ; int x = ptr->field;     // Foo.java:42
                0: (61) r0 = *(u32 *)(r1 +0)
                R0 invalid mem access 'inv'
                """;
        var err = VerifierLogParser.parse(log).error().orElseThrow();
        assertEquals(VerifierLogParser.ErrorClass.INVALID_MEM_ACCESS, err.errorClass());
        assertFalse(err.message().startsWith(";"),
                "source-comment line must not become the error message: " + err.message());
    }

    @Test
    void callerCalleeFrameLinesAreFiltered() {
        // Multi-program logs include caller/callee/frame markers.
        var log = """
                caller:
                 0: (b7) r1 = 0
                callee:
                frame1: R6=inv
                3: (61) r0 = *(u32 *)(r1 +0)
                R0 invalid mem access 'inv'
                """;
        var err = VerifierLogParser.parse(log).error().orElseThrow();
        assertEquals(VerifierLogParser.ErrorClass.INVALID_MEM_ACCESS, err.errorClass());
    }

    @Test
    void hexOpcodePrefixToleratedOnInsn() {
        // Some verifier dumps include the 0x prefix on the opcode.
        var log = """
                7: (0x07) r1 += 8
                R1 invalid mem access 'inv'
                """;
        var r = VerifierLogParser.parse(log);
        assertEquals(1, r.instructions().size(), "should still parse insn with 0x prefix");
        assertEquals(7, r.instructions().get(0).offset());
    }

    @Test
    void backwardsCompatibleErrorConstructorFillsEmptyRegister() {
        // Older callers used the 3-arg form. The compat ctor must still work.
        var err = new VerifierLogParser.VerifierError(
                "synthetic", VerifierLogParser.ErrorClass.OTHER, java.util.Optional.of(1));
        assertTrue(err.register().isEmpty(), "register should default to empty");
    }

    // --- Real-kernel shapes captured from thinkstation (kernel 6.17, 2026-06) ---

    @Test
    void modernKernelReadOkClassifiesAsStackOob() {
        // Kernel 6.17+ phrases uninitialised reads as "R0 !read_ok" rather than the older
        // "invalid read from stack" form. Captured live during RealVerifierClassificationTest.
        var log = """
                libbpf: prog 'kprobe__bad': BPF program load failed: -EACCES
                libbpf: prog 'kprobe__bad': -- BEGIN PROG LOAD LOG --
                0: R1=ctx() R10=fp0
                ;  @ <stdin>:10
                0: (95) exit
                R0 !read_ok
                processed 1 insns (limit 1000000)
                -- END PROG LOAD LOG --
                """;
        var err = VerifierLogParser.parse(log).error().orElseThrow();
        assertEquals(VerifierLogParser.ErrorClass.STACK_OOB, err.errorClass(),
                "modern kernel '!read_ok' must classify as STACK_OOB: " + err.message());
    }

    @Test
    void invalidFuncClassifiesAsHelperNotAllowed() {
        // Kernel says "invalid func unknown#999999" — earlier kernels said "unknown func".
        var log = """
                0: R1=ctx() R10=fp0
                0: (85) call unknown#999999
                invalid func unknown#999999
                """;
        var err = VerifierLogParser.parse(log).error().orElseThrow();
        assertEquals(VerifierLogParser.ErrorClass.HELPER_NOT_ALLOWED, err.errorClass());
    }

    @Test
    void libbpfPreambleLinesAreNotPickedUpAsErrors() {
        // The libbpf-emitted preamble ("libbpf: prog ...: BPF program load failed: -EACCES")
        // must not displace the real error line.
        var log = """
                libbpf: object 'bpfXXX': failed (-95) to create BPF token from '/sys/fs/bpf', skipping optional step...
                libbpf: prog 'kprobe__bad': BPF program load failed: -EACCES
                libbpf: prog 'kprobe__bad': -- BEGIN PROG LOAD LOG --
                0: R1=ctx() R10=fp0
                0: (95) exit
                R0 !read_ok
                -- END PROG LOAD LOG --
                libbpf: prog 'kprobe__bad': failed to load: -EACCES
                """;
        var err = VerifierLogParser.parse(log).error().orElseThrow();
        assertEquals(VerifierLogParser.ErrorClass.STACK_OOB, err.errorClass(),
                "should pick the !read_ok line, not a 'libbpf:' preamble: " + err.message());
    }

    @Test
    void prologLogMarkerLinesAreNotErrors() {
        // The "-- BEGIN/END PROG LOAD LOG --" markers must not be classified as errors.
        var log = """
                libbpf: prog 'p': -- BEGIN PROG LOAD LOG --
                0: (95) exit
                R0 !read_ok
                -- END PROG LOAD LOG --
                """;
        var err = VerifierLogParser.parse(log).error().orElseThrow();
        assertFalse(err.message().contains("PROG LOAD LOG"),
                "log marker must not become the error message: " + err.message());
    }

    @Test
    void typeEqualsExpectedEqualsClassifiesAsTypeMismatch() {
        // Real shape captured from kernel 6.17: "R1 type=scalar expected=map_ptr"
        assertEquals(VerifierLogParser.ErrorClass.TYPE_MISMATCH,
                VerifierLogParser.classify("R1 type=scalar expected=map_ptr"));
    }

    @Test
    void invalidAccessToMapValueClassifiesAsOutOfBounds() {
        // Real shape: "invalid access to map value, value_size=4 off=0 size=8"
        assertEquals(VerifierLogParser.ErrorClass.OUT_OF_BOUNDS,
                VerifierLogParser.classify("invalid access to map value, value_size=4 off=0 size=8"));
    }

    @Test
    void invalidAccessToPacketClassifiesAsOutOfBounds() {
        assertEquals(VerifierLogParser.ErrorClass.OUT_OF_BOUNDS,
                VerifierLogParser.classify("invalid access to packet, off=200 size=4 R3(id=0,off=200,r=128)"));
    }

    @Test
    void scalarMemAccessClassifiesAsInvalidMemAccess() {
        // Real shape: "R1 invalid mem access 'scalar'" (treating an int as a pointer)
        assertEquals(VerifierLogParser.ErrorClass.INVALID_MEM_ACCESS,
                VerifierLogParser.classify("R1 invalid mem access 'scalar'"));
    }

    @Test
    void realCaptureOomMapValueLog() {
        // Full real log from kernel 6.17 OutOfBoundsProg run, with multiple candidate lines.
        var log = """
                libbpf: prog 'kprobe__bad': BPF program load failed: -EACCES
                libbpf: prog 'kprobe__bad': -- BEGIN PROG LOAD LOG --
                0: R1=ctx() R10=fp0
                ;  @ <stdin>:15
                0: (b4) w6 = 0                        ; R6_w=0
                ;  @ <stdin>:18
                7: (15) if r0 == 0x0 goto pc+1        ; R0_w=map_value(map=m,ks=4,vs=4)
                ;  @ <stdin>:20
                8: (79) r6 = *(u64 *)(r0 +0)
                invalid access to map value, value_size=4 off=0 size=8
                R0 min value is outside of the allowed memory range
                processed 8 insns (limit 1000000)
                -- END PROG LOAD LOG --
                """;
        var err = VerifierLogParser.parse(log).error().orElseThrow();
        assertEquals(VerifierLogParser.ErrorClass.OUT_OF_BOUNDS, err.errorClass(),
                "real OOB log should classify as OUT_OF_BOUNDS");
    }

    @Test
    void realCaptureInfiniteLoopLog() {
        // Trimmed real log from kernel 6.17 InfiniteLoopProg run.
        var log = """
                libbpf: prog 'kprobe__bad': BPF program load failed: -EINVAL
                libbpf: prog 'kprobe__bad': -- BEGIN PROG LOAD LOG --
                0: R1=ctx() R10=fp0
                8: (c6) if w1 s< 0x3b9aca00 goto pc-5 ;  @ <stdin>:12
                infinite loop detected at insn 4
                cur state: R1_w=scalar(...)
                old state: R1_w=scalar(...)
                processed 24 insns (limit 1000000)
                -- END PROG LOAD LOG --
                """;
        var err = VerifierLogParser.parse(log).error().orElseThrow();
        assertEquals(VerifierLogParser.ErrorClass.INFINITE_LOOP, err.errorClass());
    }

    @Test
    void realCaptureTypeMismatchLog() {
        var log = """
                libbpf: prog 'kprobe__bad': BPF program load failed: -EACCES
                libbpf: prog 'kprobe__bad': -- BEGIN PROG LOAD LOG --
                0: R1=ctx() R10=fp0
                5: (85) call bpf_map_lookup_elem#1
                R1 type=scalar expected=map_ptr
                processed 6 insns (limit 1000000)
                -- END PROG LOAD LOG --
                """;
        var err = VerifierLogParser.parse(log).error().orElseThrow();
        assertEquals(VerifierLogParser.ErrorClass.TYPE_MISMATCH, err.errorClass());
        assertEquals("R1", err.register().orElseThrow());
    }

    @Test
    void instructionOffsetReflectsChosenLineNotFirstCandidate() {
        // When the first non-bookkeeping line is unclassified noise and the *real* error sits
        // later (after another insn), the reported instructionOffset must match the chosen
        // line's preceding insn — not the first candidate's. This was a real bug pre-fix:
        // the pointer would land on the wrong instruction in the trace.
        var log = """
                0: (61) r0 = *(u32 *)(r1 +0)
                some completely new verifier message
                4: (61) r0 = *(u32 *)(r1 +0)
                R0 invalid mem access 'inv'
                """;
        var err = VerifierLogParser.parse(log).error().orElseThrow();
        assertEquals(VerifierLogParser.ErrorClass.INVALID_MEM_ACCESS, err.errorClass());
        assertEquals(4, err.instructionOffset().orElseThrow(),
                "offset must attach to the chosen error line's preceding insn, not the first candidate");
    }
}
