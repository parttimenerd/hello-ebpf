// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

class OptsTest {

    @Test
    void testDefaultsAreSafe() {
        Opts opts = Opts.defaults();
        assertEquals(256, opts.batchSize, "batchSize default");
        assertEquals(1024, opts.ringPollBudget, "ringPollBudget default");
        assertTrue(opts.verifyZgcOnStart, "verifyZgcOnStart default");
        assertEquals(Duration.ofSeconds(5), opts.frameworkPidRescan, "frameworkPidRescan default");
        assertEquals(100, opts.policyExceptionBudgetPerSec, "policyExceptionBudgetPerSec default");
    }

    @Test
    void testDefaultsFactoryReturnsFreshInstance() {
        Opts a = Opts.defaults();
        Opts b = Opts.defaults();
        assertNotSame(a, b, "defaults() must return distinct instances (fields are mutable)");
    }

    @Test
    void testFieldsAreMutable() {
        Opts opts = new Opts();
        opts.batchSize = 512;
        opts.ringPollBudget = 2048;
        opts.verifyZgcOnStart = false;
        opts.frameworkPidRescan = Duration.ofSeconds(10);
        opts.policyExceptionBudgetPerSec = 50;

        assertEquals(512, opts.batchSize);
        assertEquals(2048, opts.ringPollBudget);
        assertFalse(opts.verifyZgcOnStart);
        assertEquals(Duration.ofSeconds(10), opts.frameworkPidRescan);
        assertEquals(50, opts.policyExceptionBudgetPerSec);
    }
}
