package me.bechberger.ebpf.samples.demo;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.runtime.interfaces.SystemCallHooks;

/**
 * Empty global variable sample
 */
@BPF(license = "GPL")
public abstract class GlobalVariableSample extends BPFProgram implements SystemCallHooks {


}