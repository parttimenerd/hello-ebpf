#!/usr/bin/python3

# source https://github.com/lizrice/learning-ebpf/blob/207f0d49de783c9b849c15cd51d9d7901999e8ee/chapter2/hello.py

from pysamples.helpers import trace

trace.setup(r".*bcc.*")
from bcc import BPF

program = r"""
int hello(void *ctx) {
    bpf_trace_printk("Hello World!");
    return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

b.trace_print()