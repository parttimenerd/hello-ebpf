# NOTICE

hello-ebpf incorporates the following third-party sources.

## Linux kernel selftests header

`bpf-compiler-plugin/src/main/resources/bpf_experimental.h` is a trimmed
copy of `tools/testing/selftests/bpf/bpf_experimental.h` from the Linux
kernel source tree. Only the `may_goto`, `can_loop`, and `bpf_for`
definitions are retained; other macros were removed. The file preserves
its upstream `SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause`
identifier.

The trim is documented in
`docs/superpowers/specs/2026-07-02-bpf-for-design.md`.
