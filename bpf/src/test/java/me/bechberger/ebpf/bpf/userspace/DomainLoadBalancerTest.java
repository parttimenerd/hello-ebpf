package me.bechberger.ebpf.bpf.userspace;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class DomainLoadBalancerTest {

    // ── LoadEntity state machine (rusty's cost_ratio guard) ──

    @Test
    void balancedWhenImbalanceWithinCostRatioBand() {
        // load_avg = 100, cost_ratio = 0.05 -> band is +/- 5.0
        var d = new Domain(0, 0b1L);
        d.setLoadSum(103.0);
        assertEquals(Domain.BalanceState.BALANCED, d.state(100.0));
        assertEquals(3.0, d.imbal(100.0), 1e-9);
    }

    @Test
    void needsPushWhenOverloadedBeyondBand() {
        var d = new Domain(0, 0b1L);
        d.setLoadSum(120.0);
        assertEquals(Domain.BalanceState.NEEDS_PUSH, d.state(100.0));
        assertEquals(20.0, d.imbal(100.0), 1e-9);
    }

    @Test
    void needsPullWhenUnderloadedBeyondBand() {
        var d = new Domain(0, 0b1L);
        d.setLoadSum(80.0);
        assertEquals(Domain.BalanceState.NEEDS_PULL, d.state(100.0));
        assertEquals(-20.0, d.imbal(100.0), 1e-9);
    }
}
