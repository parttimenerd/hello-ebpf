package me.bechberger.ebpf.bpf.features;

import me.bechberger.ebpf.bpf.features.probes.BtfLoader;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import static org.junit.jupiter.api.Assertions.*;

@EnabledOnOs(OS.LINUX)
class BtfLoaderTest {

    @Test
    void loadsVmlinuxBtf() {
        assertTrue(BtfLoader.isAvailable(), "vmlinux BTF must load on thinkstation");
    }

    @Test
    void findsWellKnownFunc() {
        assertTrue(BtfLoader.hasFuncByName("vfs_read"));
    }

    @Test
    void findsWellKnownStruct() {
        assertTrue(BtfLoader.hasStructByName("task_struct"));
    }

    @Test
    void missingFuncIsNegative() {
        assertFalse(BtfLoader.hasFuncByName("definitely_not_a_kfunc_zzz"));
    }
}
