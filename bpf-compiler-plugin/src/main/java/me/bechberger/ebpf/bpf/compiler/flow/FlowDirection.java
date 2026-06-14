package me.bechberger.ebpf.bpf.compiler.flow;

/**
 * Direction of a dataflow analysis.
 *
 * <p>{@link #FORWARD} analyses (e.g. constant propagation, region inference) propagate
 * information from predecessors to successors. {@link #BACKWARD} analyses (e.g. liveness,
 * stack-budget) propagate from successors to predecessors.
 */
public enum FlowDirection { FORWARD, BACKWARD }
