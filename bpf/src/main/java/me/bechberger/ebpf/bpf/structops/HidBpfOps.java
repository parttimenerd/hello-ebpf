package me.bechberger.ebpf.bpf.structops;

import me.bechberger.ebpf.annotations.bpf.StructOps;
import me.bechberger.ebpf.runtime.HidDefinitions;
import me.bechberger.ebpf.type.Ptr;

/**
 * Marker interface for {@code hid_bpf_ops}. Implement to intercept and
 * modify HID (Human Interface Device) reports before they reach userspace.
 *
 * <p>{@link #hidDeviceEvent(Ptr, int)} returns bytes of report modified,
 * or a negative errno on failure.
 */
@StructOps("hid_bpf_ops")
public interface HidBpfOps {

    default int hidDeviceEvent(Ptr<HidDefinitions.hid_bpf_ctx> ctx, int type)          { return 0; }
    default int hidRdescFixup(Ptr<HidDefinitions.hid_bpf_ctx> ctx)                     { return 0; }
    default int hidHwRequest(Ptr<HidDefinitions.hid_bpf_ctx> ctx, int reportnum,
                             int rtype, int reqtype)                                   { return 0; }

    /** Program name (registered with the HID subsystem). */
    default String name()   { return "hello_hid"; }
    /** HID device identifier (0 = any). */
    default int   hidId()   { return 0; }
}
