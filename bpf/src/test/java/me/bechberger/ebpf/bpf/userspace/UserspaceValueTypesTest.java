// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the pure-Java value types in the userspace scheduler package.
 */
public class UserspaceValueTypesTest {

    @Test
    void testSchedStatsSnapshotZero() {
        SchedStatsSnapshot z = SchedStatsSnapshot.ZERO;
        assertEquals(0L, z.ringEnqueued());
        assertEquals(0L, z.ringDropped());
        assertEquals(0L, z.ringDrained());
        assertEquals(0L, z.ringCanceled());
        assertEquals(0L, z.dispatched());
        assertEquals(0L, z.dispatchFailed());
        assertEquals(0L, z.stallFallbacks());
        assertEquals(0L, z.heartbeatKicks());
    }

    @Test
    void testJvmHealthSnapshotZero() {
        JvmHealthSnapshot z = JvmHealthSnapshot.ZERO;
        assertEquals(0L, z.totalGcCountDelta());
        assertEquals(0L, z.totalGcTimeMsDelta());
        assertEquals(0L, z.heapUsedBytes());
        assertEquals(0L, z.heapMaxBytes());
    }

    @Test
    void testStartupExceptionWrapsCause() {
        Throwable cause = new IllegalStateException("kernel too old");
        UserspaceSchedulerStartupException ex =
                new UserspaceSchedulerStartupException("attach failed", cause);
        assertEquals("attach failed", ex.getMessage());
        assertSame(cause, ex.getCause());
    }
}
