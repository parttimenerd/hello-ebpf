package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.TaskExtension;
import org.junit.jupiter.api.Test;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import static org.junit.jupiter.api.Assertions.*;

class TaskExtensionTest {

    @TaskExtension
    record CgroupExt(long cgroupId, long ppid) {}

    /** Build a full 88 + EXT_CAP record segment with a known prefix pid and a known tail. */
    private MemorySegment recordWithTail(Arena arena, int pid, long cgroupId, long ppid) {
        MemorySegment seg = arena.allocate(QueuedTask.QT_SIZEOF + QueuedTask.EXT_CAP);
        seg.set(ValueLayout.JAVA_INT, 0, pid);                 // prefix pid at offset 0
        long tail = QueuedTask.QT_SIZEOF;                       // tail starts at 88
        seg.set(ValueLayout.JAVA_LONG, tail + 0, cgroupId);
        seg.set(ValueLayout.JAVA_LONG, tail + 8, ppid);
        return seg;
    }

    @Test
    void tailPrimitiveAccessorsRoundTrip() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment seg = recordWithTail(arena, 4242, 0xABCDL, 7L);
            QueuedTask t = new QueuedTask();
            QueuedTask.fillFromSegment(seg, t);

            assertEquals(4242, t.pid);
            assertEquals(0xABCDL, t.extLong(0));
            assertEquals(7L, t.extLong(8));
        }
    }

    @Test
    void extRecordViewRoundTrips() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment seg = recordWithTail(arena, 1, 999L, 123L);
            QueuedTask t = new QueuedTask();
            QueuedTask.fillFromSegment(seg, t);

            CgroupExt ext = t.ext(CgroupExt.class);
            assertEquals(999L, ext.cgroupId());
            assertEquals(123L, ext.ppid());
        }
    }

    @Test
    void copyPreservesTail() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment seg = recordWithTail(arena, 5, 55L, 66L);
            QueuedTask t = new QueuedTask();
            QueuedTask.fillFromSegment(seg, t);

            QueuedTask c = t.copy();
            assertEquals(55L, c.extLong(0));
            assertEquals(66L, c.extLong(8));
        }
    }

    @Test
    void extCapConstantsAgree() {
        assertEquals(64, QueuedTask.EXT_CAP);
    }
}
