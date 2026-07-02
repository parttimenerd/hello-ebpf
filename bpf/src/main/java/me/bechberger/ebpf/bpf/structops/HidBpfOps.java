package me.bechberger.ebpf.bpf.structops;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.StructOps;
import me.bechberger.ebpf.runtime.HidDefinitions;
import me.bechberger.ebpf.type.Ptr;

/**
 * Marker interface for {@code hid_bpf_ops}. Implement to intercept and
 * modify HID (Human Interface Device) reports before they reach userspace.
 *
 * <p>{@link #hidDeviceEvent} returns bytes of report modified, or a negative
 * errno on failure.
 *
 * <p>{@link #hidId()} is the HID device identifier the ops match on
 * (0 = wildcard, or a specific product/vendor id). Data field in the kernel
 * struct.
 */
@StructOps("hid_bpf_ops")
public interface HidBpfOps {

    default int hidDeviceEvent(Ptr<HidDefinitions.hid_bpf_ctx> ctx,
                               int type, @Unsigned long source)          { return 0; }
    default int hidRdescFixup(Ptr<HidDefinitions.hid_bpf_ctx> ctx)       { return 0; }
    default int hidHwRequest(Ptr<HidDefinitions.hid_bpf_ctx> ctx,
                             @Unsigned int reportnum,
                             int rtype, int reqtype,
                             @Unsigned long source)                       { return 0; }

    /** HID device identifier (0 = any). */
    default int hidId() { return 0; }
}
