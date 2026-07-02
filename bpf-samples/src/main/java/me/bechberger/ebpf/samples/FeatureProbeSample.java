package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.bpf.features.BPFProgramType;
import me.bechberger.ebpf.bpf.features.Features;
import me.bechberger.ebpf.bpf.features.ProbeResult;

import java.util.Map;

/**
 * Print the running kernel version and a table of feature-probe results.
 *
 * <p>If {@code STRUCT_OPS} and {@code sched_ext_ops} are supported, print
 * a note; the actual struct_ops load path lands in a later plan.
 */
public final class FeatureProbeSample {

    private FeatureProbeSample() {}

    public static void main(String[] args) {
        System.out.println("Kernel: " + Features.kernelVersion().raw());
        System.out.println();

        long t0 = System.currentTimeMillis();
        Map<String, ProbeResult> snap = Features.snapshot();
        long dt = System.currentTimeMillis() - t0;

        int maxKey = 0;
        for (String k : snap.keySet()) maxKey = Math.max(maxKey, k.length());
        String fmt = "%-" + (maxKey + 2) + "s%s%n";

        for (var e : snap.entrySet()) {
            System.out.printf(fmt, e.getKey(), render(e.getValue()));
        }
        System.out.println();
        System.out.printf("Probed %d features in %d ms%n", snap.size(), dt);

        boolean canSchedExt = Features.hasProgramType(BPFProgramType.STRUCT_OPS)
                && Features.hasStructOps("sched_ext_ops");
        if (canSchedExt) {
            System.out.println("sched_ext_ops available; struct_ops load path is a follow-up plan.");
        } else {
            System.out.println("sched_ext_ops NOT available on this kernel; skipping load.");
        }
    }

    private static String render(ProbeResult r) {
        return switch (r) {
            case ProbeResult.Supported s          -> "yes";
            case ProbeResult.Unsupported u        -> "no (" + u.reason() + ")";
            case ProbeResult.ProbeUnavailable u   -> "unknown (" + u.reason() + ")";
        };
    }
}
