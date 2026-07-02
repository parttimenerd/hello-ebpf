package me.bechberger.ebpf.bpf.features;

/**
 * Outcome of a single feature probe.
 *
 * <p>Distinguishes three cases:
 * <ul>
 *   <li>{@link Supported} — the kernel accepted the probe.</li>
 *   <li>{@link Unsupported} — the kernel rejected it with a features-related errno.</li>
 *   <li>{@link ProbeUnavailable} — the probe itself could not be performed
 *       (missing capabilities, LSM lockdown, unreadable BTF).</li>
 * </ul>
 */
public sealed interface ProbeResult {

    record Supported() implements ProbeResult {}
    record Unsupported(String reason) implements ProbeResult {}
    record ProbeUnavailable(String reason) implements ProbeResult {}

    /** {@code true} only for {@link Supported}. */
    default boolean isSupported() { return this instanceof Supported; }
}
