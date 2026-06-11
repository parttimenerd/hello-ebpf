package me.bechberger.ebpf.bpf;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Phase A.3 — unit tests for {@link VerifierLogCapture}'s public surface that
 * don't depend on actually triggering a libbpf print callback. The capture
 * path through libbpf is exercised by {@link VerifierLogCaptureTest}.
 */
public class VerifierLogCaptureUnitTest {

    /** With no capture activity, drainAndReset returns the empty string,
     *  not null. */
    @Test
    public void testDrainEmptyWhenNothingCaptured() {
        // Drain any leftover from earlier tests on this thread, then drain again
        // to guarantee a clean state for the assertion below.
        VerifierLogCapture.drainAndReset();
        String s = VerifierLogCapture.drainAndReset();
        assertNotNull(s, "drainAndReset must never return null");
        assertEquals("", s, "drainAndReset on a clean buffer must return empty");
    }

    /** install() is idempotent — calling it many times must not throw or
     *  crash. (Re-installing the libbpf print callback would corrupt the
     *  global registration; the implementation guards on a static flag.) */
    @Test
    public void testInstallIsIdempotent() {
        VerifierLogCapture.install();
        VerifierLogCapture.install();
        VerifierLogCapture.install();
        // Implicit assertion: no throw, no crash.
    }
}
