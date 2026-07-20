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

    // ── balancer engine ──

    private static DomainLoadBalancer.TaskLoad task(int pid, double load, long domMask) {
        return new DomainLoadBalancer.TaskLoad(pid, load, domMask, domMask, false);
    }

    /** Build a 2-domain layout: dom0 (mask 0b01) hot, dom1 (mask 0b10) cold. */
    private static java.util.List<Domain> twoDomains(
            java.util.List<DomainLoadBalancer.TaskLoad> hot,
            java.util.List<DomainLoadBalancer.TaskLoad> cold) {
        var d0 = new Domain(0, 0b01L);
        var d1 = new Domain(1, 0b10L);
        hot.forEach(d0::addTask);
        cold.forEach(d1::addTask);
        return java.util.List.of(d0, d1);
    }

    @Test
    void migratesTaskClosestToXferTarget() {
        // dom0 load = 200 (tasks 40,60,100), dom1 load = 0. avg = 100.
        // pushImbal=100, pullImbal=100 -> xfer = min(100,100)*0.5 = 50.
        // Task closest to 50 among {40,60,100} that can run in dom1 is pid 2 (load 60).
        var doms = twoDomains(
                java.util.List.of(task(1, 40, 0b11), task(2, 60, 0b11), task(3, 100, 0b11)),
                java.util.List.of());
        var migs = DomainLoadBalancer.balance(doms, 100.0, new DomainLoadBalancer.Options(false));
        assertEquals(1, migs.size());
        assertEquals(2, migs.get(0).pid());
        assertEquals(0, migs.get(0).fromDom());
        assertEquals(1, migs.get(0).toDom());
    }

    @Test
    void noMigrationWhenBalanced() {
        var doms = twoDomains(
                java.util.List.of(task(1, 100, 0b11)),
                java.util.List.of(task(2, 100, 0b11)));
        var migs = DomainLoadBalancer.balance(doms, 100.0, new DomainLoadBalancer.Options(false));
        assertTrue(migs.isEmpty(), "balanced domains must not migrate");
    }

    @Test
    void skipsTaskInfeasibleForPullDomain() {
        // dom0 hot with one task pinned to dom0 only (domMask 0b01) -> cannot move to dom1.
        var doms = twoDomains(
                java.util.List.of(task(1, 200, 0b01)),
                java.util.List.of());
        var migs = DomainLoadBalancer.balance(doms, 100.0, new DomainLoadBalancer.Options(false));
        assertTrue(migs.isEmpty(), "task not allowed in pull domain must be skipped");
    }

    @Test
    void prefersCacheAffineTaskOverEqualLoadNonPreferred() {
        // Two equal-load (50) candidates; pid 2 is cache-affine to dom1, pid 1 is not.
        var d0 = new Domain(0, 0b01L);
        var d1 = new Domain(1, 0b10L);
        d0.addTask(new DomainLoadBalancer.TaskLoad(1, 50, 0b11, 0b01, false)); // prefers dom0
        d0.addTask(new DomainLoadBalancer.TaskLoad(2, 50, 0b11, 0b10, false)); // prefers dom1
        d0.addTask(new DomainLoadBalancer.TaskLoad(3, 100, 0b11, 0b01, false));
        var migs = DomainLoadBalancer.balance(java.util.List.of(d0, d1), 100.0,
                new DomainLoadBalancer.Options(false));
        assertEquals(1, migs.size());
        assertEquals(2, migs.get(0).pid(), "cache-affine task preferred over equal-load non-preferred");
    }

    @Test
    void skipsKworkersWhenRequested() {
        var d0 = new Domain(0, 0b01L);
        var d1 = new Domain(1, 0b10L);
        d0.addTask(new DomainLoadBalancer.TaskLoad(1, 60, 0b11, 0b11, true)); // kworker
        d0.addTask(new DomainLoadBalancer.TaskLoad(2, 140, 0b11, 0b11, false));
        var migsSkip = DomainLoadBalancer.balance(java.util.List.of(d0, d1), 100.0,
                new DomainLoadBalancer.Options(true));
        // With kworkers skipped, only pid 2 is feasible; xfer target = 50, only candidate is 140-load pid2.
        assertTrue(migsSkip.stream().noneMatch(m -> m.pid() == 1),
                "kworker must never be migrated when skipKworkers=true");
    }
}
