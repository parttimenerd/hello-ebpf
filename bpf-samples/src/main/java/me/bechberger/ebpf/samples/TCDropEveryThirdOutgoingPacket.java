package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.bpf.*;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.SkDefinitions.*;

/**
 * Implement a Traffic Control to block every third outgoing packet at random
 * <p>
 * This uses a Park-Miller pseudo-random number generator to decide whether to drop a packet
 * (<a href="https://en.wikipedia.org/wiki/Lehmer_random_number_generator">wikipedia</a>).
 */
@BPF(license = "GPL")
public abstract class TCDropEveryThirdOutgoingPacket extends BPFProgram implements TCHook {

    final GlobalVariable<@Unsigned Integer> passCount =
            new GlobalVariable<>(0);
    final GlobalVariable<@Unsigned Integer> dropCount =
            new GlobalVariable<>(0);
    final GlobalVariable<@Unsigned Integer> parkMillerState =
            new GlobalVariable<>(31);

    @BPFFunction
    public int nextPseudoRandomNumber() {
        parkMillerState.set((parkMillerState.get() * 48271) % 0x7fffffff);
        return parkMillerState.get();
    }

    @BPFFunction
    public boolean shouldDrop() {
        return nextPseudoRandomNumber() % 3 == 0;
    }

    @Override
    public __sk_action tcHandleEgress(Ptr<__sk_buff> packet) {
        if (shouldDrop()) {
            dropCount.set(dropCount.get() + 1);
            return __sk_action.__SK_DROP;
        } else {
            passCount.set(passCount.get() + 1);
            return __sk_action.__SK_PASS;
        }
    }

    public static void main(String[] args) throws InterruptedException {
        try (TCDropEveryThirdOutgoingPacket program =
                     BPFProgram.load(TCDropEveryThirdOutgoingPacket.class)) {
            program.tcAttachEgress();
            while (true) {
                System.out.println("Packet count: passed " + program.passCount.get() +
                        ", dropped: " + program.dropCount.get());
                Thread.sleep(1000);
            }
        }
    }
}
