package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.type.Ptr;

import java.util.List;

import static me.bechberger.ebpf.runtime.SkDefinitions.*;

/**
 * Implement a Traffic Control (TC) classifier.
 * <p>
 * More information at
 * <a href="https://ebpf-docs.dylanreimerink.nl/linux/program-type/BPF_PROG_TYPE_SCHED_CLS/">ebpf-docs.dylanreimerink.nl</a>
 */
public interface TCHook {

    /**
     * Handle incoming packets.
     * <p>
     * Important: Not all fields of the sk_buff are available in the TC hook, see
     * <a href="https://ebpf-docs.dylanreimerink.nl/linux/program-type/BPF_PROG_TYPE_SCHED_CLS/">ebpf-docs.dylanreimerink.nl</a>
     */
    @BPFFunction(section = "tc")
    @NotUsableInJava
    default sk_action tcHandleIngress(Ptr<__sk_buff> packet) {
        return sk_action.SK_PASS;
    }

    /**
     * Handle outgoing packets.
     * <p>
     * Important: Not all fields of the sk_buff are available in the TC hook, see
     * <a href="https://ebpf-docs.dylanreimerink.nl/linux/program-type/BPF_PROG_TYPE_SCHED_CLS/">ebpf-docs.dylanreimerink.nl</a>
     */
    @BPFFunction(section = "tc")
    @NotUsableInJava
    default sk_action tcHandleEgress(Ptr<__sk_buff> packet) {
        return sk_action.SK_PASS;
    }

    default void tcAttachIngress(int ifindex) {
        tcAttachIngress(List.of(ifindex));
    }

    default void tcAttachIngress(List<Integer> ifindexes) {
        if (this instanceof BPFProgram program) {
            program.tcAttach(program.getProgramByName("tcHandleIngress"), ifindexes, true);
        } else {
            throw new IllegalStateException("This is not a BPF program");
        }
    }

    /** Attach the ingress handler to all network interfaces that are up and not loop back */
    default void tcAttachIngress() {
        tcAttachIngress(NetworkUtil.getNetworkInterfaceIndexes());
    }

    default void tcAttachEgress(int ifindex) {
        tcAttachEgress(List.of(ifindex));
    }

    default void tcAttachEgress(List<Integer> ifindexes) {
        if (this instanceof BPFProgram program) {
            program.tcAttach(program.getProgramByName("tcHandleEgress"), ifindexes, false);
        } else {
            throw new IllegalStateException("This is not a BPF program");
        }
    }

    /** Attach the egress handler to all network interfaces that are up and not loopback */
    default void tcAttachEgress() {
        tcAttachEgress(NetworkUtil.getNetworkInterfaceIndexes());
    }
}
