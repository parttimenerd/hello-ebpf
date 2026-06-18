package me.bechberger.ebpf.samples;

/**
 * @deprecated Use {@link me.bechberger.ebpf.bpf.BasePacketParser} instead.
 */
@Deprecated
public interface BasePacketParser extends me.bechberger.ebpf.bpf.BasePacketParser {

    /** @deprecated Use {@link me.bechberger.ebpf.bpf.BasePacketParser#HTTP_PORT} */
    @Deprecated
    int HTTP_PORT = me.bechberger.ebpf.bpf.BasePacketParser.HTTP_PORT;

    /** @deprecated Use {@link me.bechberger.ebpf.bpf.BasePacketParser#HTTPS_PORT} */
    @Deprecated
    int HTTPS_PORT = me.bechberger.ebpf.bpf.BasePacketParser.HTTPS_PORT;
}
