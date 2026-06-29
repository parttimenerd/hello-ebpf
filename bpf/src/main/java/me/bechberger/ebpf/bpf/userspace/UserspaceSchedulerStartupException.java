// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

/**
 * Thrown synchronously from {@code UserspaceScheduler#runUntilExit} setup if the
 * scheduler cannot attach (verifier failure, missing capabilities, kernel too old).
 * Wraps the underlying cause so callers can inspect.
 */
public class UserspaceSchedulerStartupException extends RuntimeException {
    public UserspaceSchedulerStartupException(String message, Throwable cause) {
        super(message, cause);
    }
}
