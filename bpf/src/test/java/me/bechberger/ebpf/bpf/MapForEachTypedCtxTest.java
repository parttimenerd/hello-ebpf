package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Typed-ctx variant of {@link MapForEachTest}: lambda has 3 parameters
 * (key, value, ctx) and the explicit {@code <Ptr<State>>} type witness on
 * the call site flows through to the lifted C function so the body sees a
 * typed {@code st}, not a {@code void *}.
 */
public class MapForEachTypedCtxTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        @Type
        static class State {
            int count;
            int sum;
        }

        @BPFMapDefinition(maxEntries = 16)
        BPFHashMap<Integer, Integer> map;

        // Results live in globals so user-space can read them. The intermediate
        // `State` that flows through bpf_for_each_map_elem's ctx must be a *stack*
        // pointer (the kernel's verifier rejects map_value pointers as ctx), so
        // we allocate it locally inside the kprobe and copy results back into
        // globals at the end.
        final GlobalVariable<Integer> count = new GlobalVariable<>(0);
        final GlobalVariable<Integer> sum = new GlobalVariable<>(0);
        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) {
                return 0;
            }
            done.set(true);
            map.put(1, 10);
            map.put(2, 20);
            map.put(3, 30);
            State st = new State();
            st.count = 0;
            st.sum = 0;
            // Typed-ctx: lambda body receives `s` already cast to Ptr<State>,
            // so we can write to fields without extra casts.
            map.<Ptr<State>>forEach((k, v, s) -> {
                s.val().count = s.val().count + 1;
                s.val().sum = s.val().sum + v;
                return 0;
            }, Ptr.of(st));
            count.set(st.count);
            sum.set(st.sum);
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testTypedCtxForEach() {
        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();
            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) {}
            }
            assertTrue(program.done.get(), "kprobe never fired");
            assertEquals(3, program.count.get().intValue(), "forEach should visit all 3 entries");
            assertEquals(60, program.sum.get().intValue(), "forEach should sum 10+20+30=60");
        }
    }
}
