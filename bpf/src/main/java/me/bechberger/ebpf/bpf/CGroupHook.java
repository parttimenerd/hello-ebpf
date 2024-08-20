package me.bechberger.ebpf.bpf;

import jdk.jfr.Label;
import me.bechberger.ebpf.annotations.EnumMember;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFInterface;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import static me.bechberger.ebpf.runtime.SkDefinitions.*;

import me.bechberger.ebpf.type.Enum;
import me.bechberger.ebpf.type.Ptr;

/**
 * Use cgroups for package filtering
 * <p>
 * See <a href="https://ebpf-docs.dylanreimerink.nl/linux/program-type/BPF_PROG_TYPE_CGROUP_SKB/">ebpf-docs.dylanreimerink.nl</a>
 * <p>
 * Be aware that network fields might have a different byte order than
 * your host machine, so use {@link XDPHook#bpf_ntohl(int)} (long)}} to convert from network
 * to host byte order and {@link XDPHook#bpf_htonl(int)} to convert from host to network byte order
 * in the eBPF program (other methods for other integer data types are available).
 */
@BPFInterface
public interface CGroupHook {

    @Type
    enum CGroupAction implements Enum<CGroupAction> {
        @EnumMember(name = "CGROUP_PASS")
        DROP,
        @EnumMember(name = "CGROUP_DROP")
        PASS
    }

    /**
     * Handle incoming packets via cgroups
     * <p>
     * See <a href="https://ebpf-docs.dylanreimerink.nl/linux/program-context/__sk_buff/">ebpf-docs.dylanreimerink.nl</a>
     * for more info on the passed parameter
     */
    @BPFFunction(section = "cgroup_skb/ingress")
    @NotUsableInJava
    default CGroupAction cgroupHandleIngress(Ptr<__sk_buff> skb) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Handle outgoing packets via cgroups
     * <p>
     * See <a href="https://ebpf-docs.dylanreimerink.nl/linux/program-context/__sk_buff/">ebpf-docs.dylanreimerink.nl</a>
     * for more info on the passed parameter
     */
    @BPFFunction(section = "cgroup_skb/egress")
    @NotUsableInJava
    default CGroupAction cgroupHandleEgress(Ptr<__sk_buff> skb) {
        throw  new MethodIsBPFRelatedFunction();
    }

    /**
     * Attach the ingress cgroup hook to the specified cgroup
     * <p>
     * Use {@code systemctl status} to find the available cgroups,
     * see <a href="https://wiki.archlinux.org/title/Cgroups">wiki.archlinux.org</a>
     *
     * @param cgroupName name of the cgroup
     */
    default void cgroupAttachIngress(String cgroupName) {
        if (this instanceof BPFProgram program) {
            program.cgroupAttach(program.getProgramByName("cgroupHandleIngress"), cgroupName);
        } else {
            throw new IllegalStateException("Cannot attach cgroup hooks to non-BPFProgram");
        }
    }

    /**
     * Attach the ingress cgroup hook to the {@code user.slice} cgroup
     */
    default void cgroupAttachIngress() {
        cgroupAttachIngress("user.slice");
    }

    /**
     * Attach the egress cgroup hook to the specified cgroup
     * <p>
     * Use {@code systemctl status} to find the available cgroups,
     * see <a href="https://wiki.archlinux.org/title/Cgroups">wiki.archlinux.org</a>
     *
     * @param cgroupName name of the cgroup
     */
    default void cgroupAttachEgress(String cgroupName) {
        if (this instanceof BPFProgram program) {
            program.cgroupAttach(program.getProgramByName("cgroupHandleEgress"), cgroupName);
        } else {
            throw new IllegalStateException("Cannot attach cgroup hooks to non-BPFProgram");
        }
    }

    /**
     * Attach the egress cgroup hook to the {@code user.slice} cgroup
     */
    default void cgroupAttachEgress() {
        cgroupAttachEgress("user.slice");
    }
}
