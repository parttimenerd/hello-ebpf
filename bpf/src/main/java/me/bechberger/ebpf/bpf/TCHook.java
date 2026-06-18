package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.type.Ptr;

import java.util.List;

import static me.bechberger.ebpf.runtime.SkDefinitions.*;

/**
 * Implement a Traffic Control (TC) classifier.
 * <p>
 * More information at
 * <a href="https://ebpf-docs.dylanreimerink.nl/linux/program-type/BPF_PROG_TYPE_SCHED_CLS/">ebpf-docs.dylanreimerink.nl</a>
 * <p>
 * Override {@link #tcHandleIngress(TCContext)} / {@link #tcHandleEgress(TCContext)} for
 * ergonomic packet access, or the legacy {@code Ptr<__sk_buff>} overloads if needed.
 */
public interface TCHook {

    /**
     * Handle incoming packets.
     *
     * <p>The {@link TCContext} parameter provides ergonomic packet access:
     * {@link TCContext#length()}, {@link TCContext#boundsOk(int, int)}, {@link TCContext#byteAt(int)}, etc.
     */
    @BPFFunction(section = "tc")
    @NotUsableInJava
    default __sk_action tcHandleIngress(TCContext skb) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Handle outgoing packets.
     *
     * <p>The {@link TCContext} parameter provides ergonomic packet access:
     * {@link TCContext#length()}, {@link TCContext#boundsOk(int, int)}, {@link TCContext#byteAt(int)}, etc.
     */
    @BPFFunction(section = "tc")
    @NotUsableInJava
    default __sk_action tcHandleEgress(TCContext skb) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Handle incoming packets using a raw {@code Ptr<__sk_buff>}.
     *
     * @deprecated Override {@link #tcHandleIngress(TCContext)} instead.
     */
    @Deprecated
    @BPFFunction(section = "tc")
    @NotUsableInJava
    default __sk_action tcHandleIngress(Ptr<__sk_buff> packet) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Handle outgoing packets using a raw {@code Ptr<__sk_buff>}.
     *
     * @deprecated Override {@link #tcHandleEgress(TCContext)} instead.
     */
    @Deprecated
    @BPFFunction(section = "tc")
    @NotUsableInJava
    default __sk_action tcHandleEgress(Ptr<__sk_buff> packet) {
        throw new MethodIsBPFRelatedFunction();
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

