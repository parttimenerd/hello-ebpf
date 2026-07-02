package me.bechberger.ebpf.bpf.compiler.structops;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class StructOpsLayoutTest {

    @Test
    void loadsBundledSchedExtOps() {
        StructOpsLayout layout = StructOpsLayout.load("sched_ext_ops");
        assertEquals("sched_ext_ops", layout.kernelName());
        assertEquals("6.12", layout.since());
        assertTrue(layout.hasField("enqueue"));
        assertTrue(layout.hasField("select_cpu"));
        assertTrue(layout.hasField("name"));
        StructOpsLayout.Field enq = layout.field("enqueue");
        assertEquals("function", enq.kind());
        assertEquals("void", enq.returnType());
        assertEquals(2, enq.args().size());
        assertEquals("struct task_struct *", enq.args().get(0).type());
    }

    @Test
    void unknownKindThrows() {
        var ex = assertThrows(IllegalArgumentException.class,
                () -> StructOpsLayout.load("no_such_ops"));
        assertTrue(ex.getMessage().contains("no_such_ops"));
        assertTrue(ex.getMessage().contains("supported"));
    }

    @Test
    void nameFieldIsDataKind() {
        StructOpsLayout layout = StructOpsLayout.load("tcp_congestion_ops");
        StructOpsLayout.Field name = layout.field("name");
        assertEquals("data", name.kind());
        assertEquals("char[16]", name.returnType());
    }

    @Test
    void allFourLayoutsLoadClean() {
        for (String k : java.util.List.of("sched_ext_ops",
                                         "tcp_congestion_ops",
                                         "bpf_qdisc_ops",
                                         "hid_bpf_ops")) {
            StructOpsLayout l = StructOpsLayout.load(k);
            assertEquals(k, l.kernelName());
            assertFalse(l.fields().isEmpty(), k + " has no fields");
            assertNotNull(l.since(), k + " missing since");
        }
    }
}
