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

        final GlobalVariable<State> state = new GlobalVariable<>(new State());
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
            Ptr<State> stPtr = Ptr.of(state.get());
            // Typed-ctx: lambda body receives `st` already cast to Ptr<State>,
            // so we can write to fields without extra casts.
            map.<Ptr<State>>forEach((k, v, st) -> {
                st.val().count = st.val().count + 1;
                st.val().sum = st.val().sum + v;
                return 0;
            }, stPtr);
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
            assertEquals(3, program.state.get().count, "forEach should visit all 3 entries");
            assertEquals(60, program.state.get().sum, "forEach should sum 10+20+30=60");
        }
    }
}
