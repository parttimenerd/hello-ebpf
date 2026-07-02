package me.bechberger.ebpf.bpf.compiler.structops;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pure-function tests for {@link StructOpsValidator}. The validator is a
 * data-only wrapper around {@link StructOpsLayout} — end-to-end wiring
 * through javac happens in a later plugin-integration task, so this test
 * exclusively drives the public static API with hand-built layouts.
 */
class StructOpsValidatorTest {

    private static void assertMessageContains(String msg, String needle) {
        assertTrue(msg.contains(needle),
                "expected message to contain '" + needle + "', but was: " + msg);
    }

    @Test
    void camelToSnake() {
        assertEquals("cong_avoid", StructOpsValidator.camelToSnake("congAvoid"));
        assertEquals("select_cpu", StructOpsValidator.camelToSnake("selectCpu"));
        assertEquals("hid_raw_event", StructOpsValidator.camelToSnake("hidRawEvent"));
        assertEquals("undo_cwnd", StructOpsValidator.camelToSnake("undoCwnd"));
        assertEquals("name", StructOpsValidator.camelToSnake("name"));
        assertEquals("send2", StructOpsValidator.camelToSnake("send2"));
        // Consecutive-capital case per spec §6.1 point 2 (simple pass).
        assertEquals("acpi_init", StructOpsValidator.camelToSnake("acpiInit"));
    }

    @Test
    void validateHappyPathTcpCong() {
        // Hand-build a layout mirroring TcpCongestionControl's ssthresh + name
        // fields and assert the pure validator API accepts a matching Java rendering.
        // End-to-end plugin wiring is exercised in a later task.
        var layout = new StructOpsLayout("tcp_congestion_ops", "5.6", List.of(
                new StructOpsLayout.Field("ssthresh", "function", "__u32", List.of(
                        new StructOpsLayout.Field.Arg("sk", "struct sock *"))),
                new StructOpsLayout.Field("name", "char[16]", "char[16]", List.of())));

        assertDoesNotThrow(() -> {
            StructOpsValidator.validateFieldExists(layout, "ssthresh");
            var ssthresh = layout.field("ssthresh");
            StructOpsValidator.validateArgCount(ssthresh, 1, "ssthresh");
            StructOpsValidator.validateReturnType(ssthresh, "__u32", "ssthresh");
            StructOpsValidator.validateArgType(
                    ssthresh.args().get(0), "struct sock *", 0, "ssthresh");

            StructOpsValidator.validateFieldExists(layout, "name");
            var name = layout.field("name");
            StructOpsValidator.validateArgCount(name, 0, "name");
            StructOpsValidator.validateReturnType(name, "char[16]", "name");
        });
    }

    @Test
    void wrongReturnTypeDiagnosed() {
        var stubLayout = new StructOpsLayout("test_ops", "6.14", List.of(
                new StructOpsLayout.Field("do_thing", "function", "int",
                        List.of(new StructOpsLayout.Field.Arg("x", "int")))));
        var ex = assertThrows(StructOpsValidator.ValidationException.class,
                () -> StructOpsValidator.validateReturnType(
                        stubLayout.field("do_thing"), "void", "do_thing"));
        String msg = ex.getMessage();
        assertMessageContains(msg, "do_thing");
        assertMessageContains(msg, "return type");
        assertMessageContains(msg, "void");
        assertMessageContains(msg, "int");
    }

    @Test
    void argCountMismatchDiagnosed() {
        var layoutField = new StructOpsLayout.Field("f", "function", "void",
                List.of(
                        new StructOpsLayout.Field.Arg("a", "int"),
                        new StructOpsLayout.Field.Arg("b", "int")));
        var ex = assertThrows(StructOpsValidator.ValidationException.class,
                () -> StructOpsValidator.validateArgCount(layoutField, 1, "f"));
        String msg = ex.getMessage();
        assertMessageContains(msg, "expected 2 args, method has 1");
        assertMessageContains(msg, "'f'");
    }

    @Test
    void unknownMethodDiagnosed() {
        var layout = new StructOpsLayout("tcp_congestion_ops", "5.6", List.of(
                new StructOpsLayout.Field("ssthresh", "function", "int", List.of())));
        var ex = assertThrows(StructOpsValidator.ValidationException.class,
                () -> StructOpsValidator.validateFieldExists(layout, "fooBar"));
        String msg = ex.getMessage();
        assertMessageContains(msg, "fooBar");
        assertMessageContains(msg, "no matching field");
        assertMessageContains(msg, "tcp_congestion_ops");
    }
}
