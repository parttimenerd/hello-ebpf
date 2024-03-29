package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.bpf.BPFError;
import me.bechberger.ebpf.bpf.raw.Lib;
import me.bechberger.ebpf.bpf.raw.bpf_map_info;
import me.bechberger.ebpf.shared.PanamaUtil;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

/**
 * A map in the eBPF program, will be automatically closed when the process exits
 */
public class BPFMap {

    /**
     * Error thrown when the type of the map does not match the expected type
     */
    public static class BPFMapTypeMismatch extends BPFError {
        public BPFMapTypeMismatch(MapTypeId expected, MapTypeId actual) {
            super("Map type mismatch, expected " + expected + " but got " + actual);
        }
    }

    protected final MapTypeId typeId;
    protected final FileDescriptor fd;

    protected final MapInfo info;

    /**
     * Create a new map
     *
     * @param typeId type of the map
     * @param fd     file descriptor of the map
     * @throws BPFMapTypeMismatch if the type of the map does not match the expected type
     */
    BPFMap(MapTypeId typeId, FileDescriptor fd) {
        this.typeId = typeId;
        this.fd = fd;
        this.info = getInfo(fd);
        if (info.type != typeId) {
            throw new BPFMapTypeMismatch(typeId, info.type);
        }
    }

    /**
     * Information on a specific map
     */
    public record MapInfo(FileDescriptor fd, MapTypeId type, int keySize, int valueSize, int maxEntries, int mapFlags) {
    }

    private static MemorySegment obtainRawInfo(Arena arena, FileDescriptor fd) {
        var info = bpf_map_info.allocate(arena);
        var infoSizeRef = PanamaUtil.allocateIntRef(arena, (int) info.byteSize());
        var ret = Lib.bpf_obj_get_info_by_fd(fd.fd(), info, infoSizeRef);
        if (ret < 0) {
            throw new BPFError("Failed to get map info", ret);
        }
        return info;
    }

    /**
     * Get the info of the map
     *
     * @param fd file descriptor of the map
     * @return map info
     * @throws BPFError if the info could not be obtained
     */
    public static MapInfo getInfo(FileDescriptor fd) {
        try (var arena = Arena.ofConfined()) {
            var info = obtainRawInfo(arena, fd);
            return new MapInfo(fd, MapTypeId.fromId(bpf_map_info.type$get(info)), bpf_map_info.key_size$get(info),
                    bpf_map_info.value_size$get(info), bpf_map_info.max_entries$get(info),
                    bpf_map_info.map_flags$get(info));
        }
    }

    /**
     * Close this map
     */
    public void close() {
        Lib.close(fd.fd());
    }

    public MapInfo getInfo() {
        return info;
    }

    public int getMaxEntries() {
        return info.maxEntries;
    }
}
