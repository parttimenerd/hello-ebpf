package me.bechberger.ebpf.bpf.features;

/**
 * Commonly-probed BPF helpers. Ids match kernel {@code BPF_FUNC_*} numbering.
 * The {@code carrierProgramType} names a program type known to allow the helper
 * so the probe can build a synthetic loader.
 */
public enum BPFHelper {
    MAP_LOOKUP_ELEM(1,   BPFProgramType.SOCKET_FILTER),
    MAP_UPDATE_ELEM(2,   BPFProgramType.SOCKET_FILTER),
    MAP_DELETE_ELEM(3,   BPFProgramType.SOCKET_FILTER),
    PROBE_READ(4,        BPFProgramType.KPROBE),
    KTIME_GET_NS(5,      BPFProgramType.SOCKET_FILTER),
    TRACE_PRINTK(6,      BPFProgramType.KPROBE),
    GET_PRANDOM_U32(7,   BPFProgramType.SOCKET_FILTER),
    GET_SMP_PROCESSOR_ID(8, BPFProgramType.SOCKET_FILTER),
    TAIL_CALL(12,        BPFProgramType.SOCKET_FILTER),
    GET_CURRENT_PID_TGID(14, BPFProgramType.KPROBE),
    GET_CURRENT_UID_GID(15,  BPFProgramType.KPROBE),
    GET_CURRENT_COMM(16, BPFProgramType.KPROBE),
    PERF_EVENT_OUTPUT(25, BPFProgramType.KPROBE),
    GET_STACK(27,        BPFProgramType.KPROBE),
    PERF_EVENT_READ_VALUE(29, BPFProgramType.KPROBE),
    PROBE_READ_STR(45,   BPFProgramType.KPROBE),
    RINGBUF_OUTPUT(130,  BPFProgramType.SOCKET_FILTER),
    RINGBUF_RESERVE(131, BPFProgramType.SOCKET_FILTER),
    RINGBUF_SUBMIT(132,  BPFProgramType.SOCKET_FILTER),
    RINGBUF_DISCARD(133, BPFProgramType.SOCKET_FILTER),
    RINGBUF_QUERY(134,   BPFProgramType.SOCKET_FILTER),
    LOOP(181,            BPFProgramType.KPROBE),
    STRNCMP(182,         BPFProgramType.SOCKET_FILTER),
    KPTR_XCHG(194,       BPFProgramType.KPROBE),
    DYNPTR_FROM_MEM(197, BPFProgramType.SOCKET_FILTER),
    RINGBUF_RESERVE_DYNPTR(198, BPFProgramType.SOCKET_FILTER),
    RINGBUF_SUBMIT_DYNPTR(199,  BPFProgramType.SOCKET_FILTER),
    RINGBUF_DISCARD_DYNPTR(200, BPFProgramType.SOCKET_FILTER);

    private final int id;
    private final BPFProgramType carrier;

    BPFHelper(int id, BPFProgramType carrier) {
        this.id = id;
        this.carrier = carrier;
    }

    public int id() { return id; }
    public BPFProgramType carrierProgramType() { return carrier; }
}
