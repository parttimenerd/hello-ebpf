package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.bpf.map.BPFBaseMap;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.shared.BPFType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests the {@link BPFHashMap} class
 */
public class HashMapTest {

    @BPF
    public static abstract class Program extends BPFProgram {
        static final String EBPF_PROGRAM = """
            #include "vmlinux.h"
            #include <bpf/bpf_helpers.h>
            #include <bpf/bpf_tracing.h>
            #include <string.h>
                            
            // eBPF map reference
            struct
            {
              __uint (type, BPF_MAP_TYPE_HASH);
              __uint (max_entries, 256);
              __type (key, char[2]);
              __type (value, u32);
            } map SEC (".maps");
                            
            // The ebpf auto-attach logic needs the SEC
            SEC ("kprobe/do_sys_openat2")
                 int kprobe__do_sys_openat2 (struct pt_regs *ctx)
            {
              char comm[2] = { 'a', 0 };
                            
              // {'a': 0}: no entry in map before
              // {'a': 2, 'b': 3}: after user land sets value of a to 1
              u32 *counter = bpf_map_lookup_elem (&map, comm);
              if (counter == NULL)
                {
                  u32 start = 0;
                  bpf_map_update_elem (&map, comm, &start, BPF_ANY);
                }
              else
                {
                  if (*counter == 1) {
                    *counter = 2;
                    u32 value = 3;
                    comm[0] = 'b';
                    bpf_map_update_elem (&map, comm, &value, BPF_ANY);
                  }
                }
              return 0;
            }
                            
            char _license[] SEC ("license") = "GPL";
            """;
    }

    private static BPFHashMap<String, Integer> getHashMap(BPFProgram program) {
        return program.getHashMapByName("map", new BPFType.StringType(3), BPFType.BPFIntType.UINT32);
    }

    /** Check that the program can be loaded and the map can be accessed */
    @Test
    public void testInitialInit() {
        try (Program program = BPFProgram.load(Program.class)) {
            program.autoAttachProgram(program.getProgramByName("kprobe__do_sys_openat2"));
            assertNotNull(getHashMap(program));
            assertFalse(getHashMap(program).usesLRU());
        }
    }

    @Test
    public void testInitialValue() {
        try (Program program = BPFProgram.load(Program.class)) {
            program.autoAttachProgram(program.getProgramByName("kprobe__do_sys_openat2"));
            var map = getHashMap(program);
            TestUtil.triggerOpenAt();
            Assertions.assertAll(
                    () -> assertFalse(map.isEmpty(), "Map should not be empty"),
                    () -> assertTrue(map.containsKey("a"), "Map should contain a"),
                    () -> assertFalse(map.containsKey("b"), "Map should not contain b"),
                    () -> assertEquals(0, map.get("a"), "Value for key 'a' should be 0"),
                    () -> assertEquals(Set.of("a"), map.keySet(), "Key set should be {'a'}"),
                    () -> assertEquals(Set.of(0), map.values(), "Value set should be {0}"),
                    () -> assertNull(map.get("b")),
                    () -> assertEquals(1, map.slowSize(), "Size should be 1")
            );
        }
    }

    @Test
    public void testPuttingValueIntoMap() {
        try (Program program = BPFProgram.load(Program.class)) {
            program.autoAttachProgram(program.getProgramByName("kprobe__do_sys_openat2"));
            var map = getHashMap(program);
            TestUtil.triggerOpenAt();
            assertEquals(0, map.get("a"));
            assertTrue(map.put("a", 1));
            assertTrue(map.put("a", 1, BPFBaseMap.PutMode.BPF_ANY));
            assertTrue(map.put("a", 1, BPFBaseMap.PutMode.BPF_EXIST));
            assertFalse(map.put("a", 2, BPFHashMap.PutMode.BPF_NOEXIST));
            // the ebpf program then sets it to 2 and adds a new entry for 'b'
            TestUtil.triggerOpenAt();
            Assertions.assertAll(
                    () -> assertEquals(2, map.get("a"), "Value for key 'a' should be 2"),
                    () -> assertEquals(3, map.get("b"), "Value for key 'b' should be 3"),
                    () -> assertEquals(Set.of("a", "b"), map.keySet(), "Key set should be {'a', 'b'}"),
                    () -> assertEquals(Set.of(2, 3), map.values(), "Value set should be {2, 3}"),
                    () -> assertEquals(2, map.slowSize(), "Size should be 2"));
            TestUtil.triggerOpenAt();
            // values should not change
            assertEquals(2, map.get("a"));
            assertEquals(3, map.get("b"));
            // now we remove the entry for 'a', this should not remove the entry for 'b' but should set 'a' to 0
            // at the next run of the ebpf program
            assertTrue(map.delete("a"));
            TestUtil.triggerOpenAt();
            Assertions.assertAll(
                    () -> assertEquals(0, map.get("a"), "Value for key 'a' should be 1"),
                    () -> assertEquals(3, map.get("b"), "Value for key 'b' should be 3"),
                    () -> assertEquals(Set.of("a", "b"), map.keySet(), "Key set should be {'a', 'b'}"),
                    () -> assertEquals(Set.of(0, 3), map.values(), "Value set should be {0, 3}"),
                    () -> assertEquals(2, map.slowSize(), "Size should be 2"));
        }
    }

    @Test
    public void testAddAndRemoveAdditionalEntry() throws InterruptedException {
        try (Program program = BPFProgram.load(Program.class)) {
            program.autoAttachProgram(program.getProgramByName("kprobe__do_sys_openat2"));
            var map = getHashMap(program);
            map.put("c", 1);
            assertTrue(map.containsKey("c"));
            map.delete("c");
            assertFalse(map.containsKey("c"));
        }
    }

    @BPF
    public static abstract class LRUProgram extends BPFProgram {
        static final String EBPF_PROGRAM = """
            #include "vmlinux.h"
            #include <bpf/bpf_helpers.h>
            #include <bpf/bpf_tracing.h>
            #include <string.h>
                            
            // eBPF map reference
            struct
            {
              __uint (type, BPF_MAP_TYPE_LRU_HASH);
              __uint (max_entries, 2); // just two entries to test LRU
              __type (key, char[2]);
              __type (value, u32);
            } map SEC (".maps");
                            
            // The ebpf auto-attach logic needs the SEC
            SEC ("kprobe/do_sys_openat2")
                 int kprobe__do_sys_openat2 (struct pt_regs *ctx)
            {
              return 0;
            }

            char _license[] SEC ("license") = "GPL";
            """;
    }

    @Test
    public void testLRUHashMap() {
        try (LRUProgram program = BPFProgram.load(LRUProgram.class)) {
            program.autoAttachProgram(program.getProgramByName("kprobe__do_sys_openat2"));
            var map = getHashMap(program);
            assertTrue(map.usesLRU());
            map.put("b", 1);
            map.put("c", 2);
            map.put("d", 3);
            map.put("e", 4);
            Assertions.assertAll(
                    () -> assertFalse(map.containsKey("b"), "Map should not contain b"),
                    () -> assertFalse(map.containsKey("c"), "Map should contain c"),
                    () -> assertTrue(map.containsKey("d"), "Map should contain d"),
                    () -> assertTrue(map.containsKey("e"), "Map should contain e"),
                    () -> assertEquals(2, map.slowSize(), "Size should be 2"),
                    () -> assertEquals(Set.of(Map.entry("d", 3), Map.entry("e", 4)), map.entrySet())
            );
        }
    }

}