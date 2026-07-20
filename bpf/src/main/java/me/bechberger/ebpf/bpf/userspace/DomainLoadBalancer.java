// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

import java.util.ArrayList;
import java.util.List;

/**
 * Pure push/pull load-balancing engine ported from scx_rusty's {@code balance_within_node}
 * ({@code /tmp/rusty_lb.rs}). No BPF, no I/O — fully unit-testable.
 *
 * <p>The outer loop processes each overloaded (push) domain once, popping it from the
 * most-overloaded end. For each push domain it pulls into underloaded (pull) domains, ordered
 * least-loaded first, transferring at most {@code push_cutoff = pushImbal * PUSH_MAX_RATIO} total
 * load out of that domain. For each (push, pull) pair the transfer target is
 * {@code xfer = min(pushImbal, pullImbal) * XFER_RATIO}; among the push domain's tasks that
 * (a) are allowed in the pull domain ({@code domMask} bit set), (b) are not a skipped kworker,
 * and (c) have not already been migrated, it picks the task whose load is closest to {@code xfer}
 * — preferring tasks cache-affine to the pull domain ({@code preferredDomMask} bit set) — but only
 * if the move reduces the pair's total imbalance. Migrations are recorded (no I/O).
 */
public final class DomainLoadBalancer {

    public record TaskLoad(int pid, double load, long domMask, long preferredDomMask,
                           boolean isKworker) {}

    public record Migration(int pid, int fromDom, int toDom) {}

    /** @param skipKworkers when true, kernel worker threads are never migrated. */
    public record Options(boolean skipKworkers) {}

    private DomainLoadBalancer() {}

    public static List<Migration> balance(List<Domain> domains, double loadAvg, Options opts) {
        List<Migration> migrations = new ArrayList<>();
        // Mutable working copy so the caller's Domains aren't mutated.
        List<MutableDom> doms = new ArrayList<>(domains.size());
        for (Domain d : domains) {
            doms.add(new MutableDom(d.id(), d.loadSum(), new ArrayList<>(d.tasks())));
        }

        double band = loadAvg * Domain.COST_RATIO;

        // Outer loop: each push domain is processed once (rusty pops from the most-overloaded end).
        // We iterate over a snapshot of domains sorted most-overloaded-first.
        List<MutableDom> pushOrder = new ArrayList<>(doms);
        pushOrder.sort((a, b) -> Double.compare(b.load, a.load));

        for (MutableDom push : pushOrder) {
            double pushImbal = push.load - loadAvg;
            if (pushImbal <= band) continue; // not overloaded beyond the tolerance band

            double pushCutoff = pushImbal * Domain.PUSH_MAX_RATIO;
            double pushed = 0.0;

            // Pull domains ordered least-loaded first.
            List<MutableDom> pullOrder = new ArrayList<>();
            for (MutableDom d : doms) {
                if (d != push) pullOrder.add(d);
            }
            pullOrder.sort((a, b) -> Double.compare(a.load, b.load));

            for (MutableDom pull : pullOrder) {
                if (pushed >= pushCutoff) break;
                double pullImbal = loadAvg - pull.load;
                if (pullImbal <= band) continue; // not underloaded beyond the band

                // to_push / to_pull are the pair's imbalances at the start of this transfer.
                double toPush = push.load - loadAvg;
                double toPull = Math.abs(loadAvg - pull.load);
                double xfer = Math.min(Math.abs(toPush), Math.abs(toPull)) * Domain.XFER_RATIO;

                TaskLoad chosen = pickTask(push, pull, xfer, toPush, toPull, opts);
                if (chosen == null) continue;

                push.tasks.remove(chosen);
                push.load -= chosen.load();
                pull.load += chosen.load();
                pushed += chosen.load();
                migrations.add(new Migration(chosen.pid(), push.id, pull.id));
            }
        }
        return migrations;
    }

    /**
     * Pick the task from {@code push} whose load is closest to {@code xfer} and reduces the pair's
     * imbalance, preferring cache-affine tasks (two-pass: preferred filter first, then any task).
     * Mirrors rusty's {@code try_find_move_task}. Returns null if no beneficial move exists.
     */
    private static TaskLoad pickTask(MutableDom push, MutableDom pull, double xfer,
                                     double toPush, double toPull, Options opts) {
        long pullBit = 1L << pull.id;
        double oldImbal = Math.abs(toPush) + Math.abs(toPull);

        // First pass: only cache-affine (preferred) tasks. Second pass: any feasible task.
        TaskLoad pref = pickClosest(push, pullBit, xfer, toPush, toPull, oldImbal, opts, true);
        if (pref != null) return pref;
        return pickClosest(push, pullBit, xfer, toPush, toPull, oldImbal, opts, false);
    }

    private static TaskLoad pickClosest(MutableDom push, long pullBit, double xfer,
                                        double toPush, double toPull, double oldImbal,
                                        Options opts, boolean preferredOnly) {
        // Mirror rusty's try_find_move_task: among feasible tasks, consider only the two that
        // bracket the transfer target — the largest task with load <= xfer and the smallest with
        // load >= xfer — then pick whichever yields the lower resulting pair imbalance.
        TaskLoad left = null;  // largest load <= xfer
        TaskLoad right = null; // smallest load >= xfer
        for (TaskLoad t : push.tasks) {
            if (opts.skipKworkers() && t.isKworker()) continue;
            if ((t.domMask() & pullBit) == 0) continue; // not allowed in pull domain
            if (preferredOnly && (t.preferredDomMask() & pullBit) == 0) continue;
            if (t.load() <= xfer) {
                if (left == null || t.load() > left.load()) left = t;
            }
            if (t.load() >= xfer) {
                if (right == null || t.load() < right.load()) right = t;
            }
        }

        TaskLoad chosen;
        if (left == null && right == null) {
            return null;
        } else if (left == null) {
            chosen = right;
        } else if (right == null) {
            chosen = left;
        } else {
            double imbalLeft = newImbal(toPush, toPull, left.load());
            double imbalRight = newImbal(toPush, toPull, right.load());
            chosen = imbalLeft <= imbalRight ? left : right;
        }

        // Only migrate if the best candidate reduces the pair's total imbalance.
        if (newImbal(toPush, toPull, chosen.load()) > oldImbal) return null;
        return chosen;
    }

    private static double newImbal(double toPush, double toPull, double load) {
        return Math.abs(toPush - load) + Math.abs(Math.abs(toPull) - load);
    }

    private static final class MutableDom {
        final int id;
        double load;
        final List<TaskLoad> tasks;
        MutableDom(int id, double load, List<TaskLoad> tasks) {
            this.id = id; this.load = load; this.tasks = tasks;
        }
    }
}
