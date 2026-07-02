/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Trimmed subset of tools/testing/selftests/bpf/bpf_experimental.h from
 * the Linux kernel source tree. Contains only the may_goto machinery and
 * the bpf_for macro used by hello-ebpf's compiler plugin to lower
 * dynamic-bound loops. Retains the upstream SPDX identifier.
 *
 * See docs/superpowers/specs/2026-07-02-bpf-for-design.md for context.
 */

#ifndef __BPF_EXPERIMENTAL__
#define __BPF_EXPERIMENTAL__

#ifndef __arraycount
#define __arraycount(x) (sizeof(x) / sizeof((x)[0]))
#endif

/*
 * may_goto is a verifier-visible instruction that lets a loop fall
 * through to termination after a bounded (BPF_MAX_LOOPS ~ 8 million by
 * default) number of iterations, regardless of what the runtime
 * condition evaluates to.
 */
#define __may_goto_label_0 __PASTE(__may_goto_label_, __COUNTER__)

#define can_loop                                    \
	({ __label__ l_break, l_continue;           \
	   bool ret = true;                         \
	   asm volatile goto("may_goto %l[l_break]" \
	                     :::: l_break);         \
	   goto l_continue;                         \
	   l_break: ret = false;                    \
	   l_continue:;                             \
	   ret;                                     \
	})

#define may_goto                                    \
	({ __label__ l_break;                       \
	   asm volatile goto("may_goto %l[l_break]" \
	                     :::: l_break);         \
	   l_break:;                                \
	})

#define bpf_for(i, start, end) \
	for (i = (start); i < (end) && can_loop; i++)

#endif /* __BPF_EXPERIMENTAL__ */
