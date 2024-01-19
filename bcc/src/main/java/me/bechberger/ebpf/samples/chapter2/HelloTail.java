/**
 * Print a message when a syscall is called, and also when a timer is created or deleted.
 */
package me.bechberger.ebpf.samples.chapter2;

import me.bechberger.ebpf.bcc.BPF;
import me.bechberger.ebpf.bcc.BPFTable;
import me.bechberger.ebpf.bcc.Syscalls;

/**
 * {@snippet :
 * #!/usr/bin/python3
 * from bcc import BPF
 * import ctypes as ct
 *
 * program = r"""
 * BPF_PROG_ARRAY(syscall, 300);
 *
 * int hello(struct bpf_raw_tracepoint_args *ctx) {
 *     int opcode = ctx->args[1];
 *     syscall.call(ctx, opcode);
 *     bpf_trace_printk("Another syscall: %d", opcode);
 *     retur 0;
 * }
 *
 * int hello_exec(void *ctx) {
 *     bpf_trace_printk("Executing a program");
 *     return 0;
 * }
 *
 * int hello_timer(struct bpf_raw_tracepoint_args *ctx) {
 *     int opcode = ctx->args[1];
 *     switch (opcode) {
 *         case 222:
 *             bpf_trace_printk("Creating a timer");
 *             break;
 *         case 226:
 *             bpf_trace_printk("Deleting a timer");
 *             break;
 *         default:
 *             bpf_trace_printk("Some other timer operation");
 *             break;
 *     }
 *     return 0;
 * }
 *
 * int ignore_opcode(void *ctx) {
 *     return 0;
 * }
 * """
 *
 * b = BPF(text=program)
 * b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")
 *
 * ignore_fn = b.load_func("ignore_opcode", BPF.RAW_TRACEPOINT)
 * exec_fn = b.load_func("hello_exec", BPF.RAW_TRACEPOINT)
 * timer_fn = b.load_func("hello_timer", BPF.RAW_TRACEPOINT)
 *
 * prog_array = b.get_table("syscall")
 * prog_array[ct.c_int(59)] = ct.c_int(exec_fn.fd)
 * prog_array[ct.c_int(222)] = ct.c_int(timer_fn.fd)
 * prog_array[ct.c_int(223)] = ct.c_int(timer_fn.fd)
 * prog_array[ct.c_int(224)] = ct.c_int(timer_fn.fd)
 * prog_array[ct.c_int(225)] = ct.c_int(timer_fn.fd)
 * prog_array[ct.c_int(226)] = ct.c_int(timer_fn.fd)
 *
 * # Ignore some syscalls that come up a lot
 * prog_array[ct.c_int(21)] = ct.c_int(ignore_fn.fd)
 * prog_array[ct.c_int(22)] = ct.c_int(ignore_fn.fd)
 * prog_array[ct.c_int(25)] = ct.c_int(ignore_fn.fd)
 * prog_array[ct.c_int(29)] = ct.c_int(ignore_fn.fd)
 * prog_array[ct.c_int(56)] = ct.c_int(ignore_fn.fd)
 * prog_array[ct.c_int(57)] = ct.c_int(ignore_fn.fd)
 * prog_array[ct.c_int(63)] = ct.c_int(ignore_fn.fd)
 * prog_array[ct.c_int(64)] = ct.c_int(ignore_fn.fd)
 * prog_array[ct.c_int(66)] = ct.c_int(ignore_fn.fd)
 * prog_array[ct.c_int(72)] = ct.c_int(ignore_fn.fd)
 * prog_array[ct.c_int(73)] = ct.c_int(ignore_fn.fd)
 * prog_array[ct.c_int(79)] = ct.c_int(ignore_fn.fd)
 * prog_array[ct.c_int(98)] = ct.c_int(ignore_fn.fd)
 * prog_array[ct.c_int(101)] = ct.c_int(ignore_fn.fd)
 * prog_array[ct.c_int(115)] = ct.c_int(ignore_fn.fd)
 * prog_array[ct.c_int(131)] = ct.c_int(ignore_fn.fd)
 * prog_array[ct.c_int(134)] = ct.c_int(ignore_fn.fd)
 * prog_array[ct.c_int(135)] = ct.c_int(ignore_fn.fd)
 * prog_array[ct.c_int(139)] = ct.c_int(ignore_fn.fd)
 * prog_array[ct.c_int(172)] = ct.c_int(ignore_fn.fd)
 * prog_array[ct.c_int(233)] = ct.c_int(ignore_fn.fd)
 * prog_array[ct.c_int(280)] = ct.c_int(ignore_fn.fd)
 * prog_array[ct.c_int(291)] = ct.c_int(ignore_fn.fd)
 *
 * b.trace_print()
 *}
 */
public class HelloTail {

    public static void main(String[] args) {
        try (var b = BPF.builder("""
                BPF_PROG_ARRAY(syscall, 300);

                int hello(struct bpf_raw_tracepoint_args *ctx) {
                    int opcode = ctx->args[1];
                    syscall.call(ctx, opcode);
                    bpf_trace_printk("Another syscall: %d", opcode);
                    return 0;
                }

                int hello_exec(void *ctx) {
                    bpf_trace_printk("Executing a program");
                    return 0;
                }

                int hello_timer(struct bpf_raw_tracepoint_args *ctx) {
                    int opcode = ctx->args[1];
                    switch (opcode) {
                        case 222:
                            bpf_trace_printk("Creating a timer");
                            break;
                        case 226:
                            bpf_trace_printk("Deleting a timer");
                            break;
                        default:
                            bpf_trace_printk("Some other timer operation");
                            break;
                    }
                    return 0;
                }

                int ignore_opcode(void *ctx) {
                    return 0;
                }
                """).build()) {
            b.attach_raw_tracepoint("sys_enter", "hello");

            var ignoreFn = b.load_raw_tracepoint_func("ignore_opcode");
            var execFn = b.load_raw_tracepoint_func("hello_exec");
            var timerFn = b.load_raw_tracepoint_func("hello_timer");

            var progArray = b.get_table("syscall", BPFTable.ProgArray.createProvider());
            progArray.set(Syscalls.getSyscall("execve").number(), execFn);
            progArray.set(Syscalls.getSyscall("timer_create").number(), timerFn);
            progArray.set(Syscalls.getSyscall("timer_gettime").number(), timerFn);
            progArray.set(Syscalls.getSyscall("timer_getoverrun").number(), timerFn);
            progArray.set(Syscalls.getSyscall("timer_settime").number(), timerFn);
            progArray.set(Syscalls.getSyscall("timer_delete").number(), timerFn);
            // ignore some syscalls that come up a lot
            for (int i : new int[]{
                    21, 22, 25, 29, 56, 57, 63, 64, 66, 72,
                    73, 79, 98, 101, 115, 131,
                    134, 135, 139, 172, 233, 280, 291}) {
                progArray.set(i, ignoreFn);
            }
            b.trace_print(f -> {
                String another = "Another syscall: ";
                // replace other syscall with their names
                if (f.line().contains(another)) {
                    // skip these lines if --skip-others is passed
                    if (args.length > 0 && args[0].equals("--skip-others")) {
                        return null;
                    }
                    var syscall = Syscalls.getSyscall(
                            Integer.parseInt(f.line().substring(
                                    f.line().indexOf(another) + another.length())));
                    return f.line().replace(another + syscall.number(), another + syscall.name());
                }
                return f.line();
            });
        }
    }
}
