#!/usr/bin/python
# source: https://github.com/iovisor/bcc/blob/master/examples/hello_world.py
# formatted and modified by Johannes Bechberger
#
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# run in project examples directory with:
# sudo ./hello_world.py"

from bcc import BPF

BPF(text=r"""
int kprobe__sys_clone(void *ctx) {
    bpf_trace_printk("Hello, World!");
    return 0;
}
""").trace_print()
