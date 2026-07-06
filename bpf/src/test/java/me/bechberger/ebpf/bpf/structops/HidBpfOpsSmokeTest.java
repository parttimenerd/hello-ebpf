package me.bechberger.ebpf.bpf.structops;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.runtime.HidDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Smoke test for {@link HidBpfOps}: loads a minimal BPF-driven hid_bpf_ops
 * table, confirms attach registers a struct_ops of kind {@code hid_bpf_ops},
 * and that close cleans up without error.
 *
 * <p>Requires {@code CONFIG_HID_BPF=y} and a kernel >= 6.11 (the version the
 * {@code hid_bpf_ops} layout is tagged with). Gated on the presence of
 * {@code /sys/class/hidraw/} — a proxy for HID subsystem availability in the
 * test kernel — since bpf_struct_ops for hid can't register without it.
 */
class HidBpfOpsSmokeTest {

    /**
     * Minimum viable {@code hid_bpf_ops} — wildcards on all HID devices and
     * returns 0 (unmodified) from every callback. The kernel accepts this as
     * a valid registration; no device event needs to fire for attach to
     * succeed.
     */
    @BPF(license = "GPL")
    abstract static class MinimalHidOps extends BPFProgram implements HidBpfOps {

        @Override
        public int hidDeviceEvent(Ptr<HidDefinitions.hid_bpf_ctx> hctx,
                                  int type, long source) {
            return 0;
        }

        @Override
        public int hidRdescFixup(Ptr<HidDefinitions.hid_bpf_ctx> hctx) {
            return 0;
        }

        @Override
        public int hidHwRequest(Ptr<HidDefinitions.hid_bpf_ctx> hctx,
                                int reportnum, int rtype, int reqtype,
                                long source) {
            return 0;
        }

        @Override
        public int hidId() { return 0; }
    }

    @Test
    void attachSucceedsAndDetachesCleanly() throws Exception {
        assumeTrue(Files.exists(Path.of("/sys/class/hidraw")),
                "no /sys/class/hidraw — HID subsystem unavailable in this kernel");
        try (var prog = BPFProgram.load(MinimalHidOps.class)) {
            var infos = prog.structOpsInfo();
            assertEquals(1, infos.size(),
                    "expected exactly one @StructOps attach for MinimalHidOps; got " + infos);
            var only = infos.get(0);
            assertEquals("hid_bpf_ops", only.kernelName(),
                    "kernelName should match the BTF struct type");
            assertEquals("MinimalHidOps", only.mapName(),
                    "mapName should match the C-side struct variable name");
            assertTrue(only.mapFd() > 0,
                    "mapFd should be a valid file descriptor; got " + only.mapFd());
            assertNotEquals(0L, only.bpfLinkId(),
                    "bpfLinkId should be non-zero after attach; got " + only.bpfLinkId());
        } catch (BPFProgram.BPFLoadError.StructOpsAttachFailed e) {
            // errno=22 (EINVAL) means the kernel doesn't have CONFIG_HID_BPF=y or the
            // hid_bpf_ops struct_ops type is not registered — treat as a skip.
            assumeTrue(!e.getMessage().contains("errno=22"),
                    "hid_bpf_ops struct_ops not available on this kernel (errno=22): " + e.getMessage());
            throw e;
        }
    }
}
