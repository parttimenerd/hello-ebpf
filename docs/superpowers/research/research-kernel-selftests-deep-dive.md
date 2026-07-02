# Kernel BPF selftests deep-read: features hello-ebpf lacks

Source: `/tmp/ebpf-research/linux-selftests` at commit `665159e246749578d4e4bfe106ee3b74edcdab18` ("Merge tag 'probes-fixes-v7.2-rc1'"). Path: `tools/testing/selftests/bpf/`. 1006 BPF selftest progs surveyed.

Prior deep-reads cross-referenced (nothing already in these is repeated here):
- `research-aya-deep-dive.md` — LoadOptions, aya-log, freplace, XDP modes, TCX, feature-probe
- `research-cilium-ebpf-deep-dive.md` — feature-probe, batch map ops, perf/ringbuf multiplex, LinkInfo
- `research-libbpf-rs-deep-dive.md` — skeleton three-phase, `.rodata`/`.data` typed access, BTF-to-Rust, BPF streams (`bpf_stream_open`, `bpf_prog_stream_read`), static linker
- `research-bpftrace-deep-dive.md` — aggregations, symbol resolution, printf directives, glob expansion
- `research-gap-catalog-rust-go.md` — kprobe.multi, uprobe.multi, iter/ programs, sockmap plane, sk_lookup, sk_reuseport, flow_dissector, freplace, tcx, netkit, netfilter, cgroup_sock*, tp_btf, lsm_cgroup, socket_filter, LWT, SOCKMAP/SOCKHASH, ARRAY_OF_MAPS, DEVMAP_HASH, XSKMAP, batch map ops, pinning, autoattach, attach cookies, BTF split, BPF token, program stats, USDT
- `research-gap-catalog-otel-awesome.md` — DWARF unwinder, interpreter tracers, off-CPU, `bpf_perf_event_output`

This doc catalogs only what the selftest tree adds on top of that surface. Focus is on kfunc catalogs, arena data structures, and program-body-side features that the framework's `@BuiltinBPFFunction` / `@BPFFunction` / `@BPFMapDefinition` machinery does not yet expose.

---

## 1. BPF arena native data structures — the biggest untapped area

hello-ebpf has arena support (`@InArena Ptr<T>`, `BPFArena.bpf_arena_word_at`), but ships no arena-native containers. The kernel selftest tree provides four header-only, drop-in libraries that BPF programs `#include` verbatim.

**`bpf_arena_alloc.h`** — per-CPU page-fragment allocator (`bpf_alloc(size)`, `bpf_free(addr)`) built on top of the raw `bpf_arena_alloc_pages` / `bpf_arena_free_pages` kfuncs (`bpf_arena_alloc.h:20-65`). Also `bpf_arena_reserve_pages` (selftests reference it).

**`bpf_arena_list.h`** — intrusive doubly-linked list scoped inside the arena. Types `arena_list_head_t`, `arena_list_node_t`, macros `list_for_each_entry`, `list_add_head`, `__list_del`. Uses `pprev` slot for O(1) delete. `bpf_arena_list.h:15-82`.

**`bpf_arena_htab.h`** — open-addressed hash table built on `bpf_arena_list.h`, with `htab_init`, `htab_lookup_elem`, `htab_update_elem` (`bpf_arena_htab.h:5-63`). Test driver: `progs/arena_htab.c` inserts 100 000 entries in a bounded `can_loop` loop.

**`bpf_arena_spin_lock.h`** — arena-resident spinlock: `arena_spin_lock(&lock)`, `arena_spin_lock_irqsave(&lock, flags)`, plus `_unlock*` counterparts. Program body: `progs/arena_spin_lock.c:41`. This unlocks concurrent-producer patterns that a plain arena cannot express (the kernel `bpf_spin_lock` primitive is map-value-scoped, not arena-scoped).

**`bpf_arena_strsearch.h`** — arena-string helpers `bpf_arena_strlen`, `glob_match` for device-blacklist-style workloads (`bpf_arena_strsearch.h:6-75`).

**`arena_atomics.c`** — full `__sync_fetch_and_{add,sub,and,or,xor}` and `__c11_atomic_fetch_*` on `__arena` variables of both 32 and 64 bit width. hello-ebpf's `Ptr<T>` in arena has no atomic-op wrapper today.

**Framework gap** — hello-ebpf's Java-side arena API is a bare `Ptr<T>` with byte-level access; there are no `ArenaList<T>`, `ArenaHashMap<K,V>`, `ArenaSpinLock`, or arena-scope atomic ops wrappers. All five headers could be shipped as `me.bechberger.ebpf.arena.*` and injected into the compilation unit the same way `@BuiltinBPFFunction` templates already inject snippets. `preserve_access_index`-style CO-RE relocation still applies since these are all pure C over `__arena` pointers.

---

## 2. Dynptr — the missing pointer abstraction — **New**

hello-ebpf currently references `bpf_dynptr` (opaque type) and `bpf_dynptr_read` only inside generated code but has no user-visible Java wrapper. The kernel exposes a full family:

- **Local dynptr**: `bpf_dynptr_from_mem(mem, size, flags, &dynptr)` — bind an on-stack or map-value buffer to a dynptr.
- **Ring-buffer dynptr**: `bpf_ringbuf_reserve_dynptr`, `bpf_ringbuf_submit_dynptr`, `bpf_ringbuf_discard_dynptr` (`progs/dynptr_success.c:47-65`) — reserve a variable-size ringbuf record and write via dynptr, avoiding the fixed-size limitation of the existing `@BPFRingBuffer` wrapper.
- **skb / xdp dynptr**: `bpf_dynptr_from_skb(skb, flags, &dp)`, `bpf_dynptr_from_xdp`, `bpf_dynptr_from_skb_meta` (`bpf_kfuncs.h:11-22`) — packet-plane access without manual bounds arithmetic.
- **Access**: `bpf_dynptr_read(buf, sz, dp, off, flags)`, `bpf_dynptr_write`, `bpf_dynptr_slice(dp, off, buf, sz)` (read-only), `bpf_dynptr_slice_rdwr` (`bpf_kfuncs.h:31-40`).
- **Introspection**: `bpf_dynptr_adjust`, `bpf_dynptr_is_null`, `bpf_dynptr_is_rdonly`, `bpf_dynptr_size`, `bpf_dynptr_clone` (`bpf_kfuncs.h:43-47`).

This is a natural fit for a Java-side `DynPtr` wrapper that owns lifetime like `try-with-resources` (release on drop). Every packet-processing sample in the framework (XDP, TC) still uses hand-rolled `data`/`data_end` bounds checks (`XDPContext.java:49-177`) — the dynptr surface would replace all of that.

---

## 3. BPF kptrs (referenced kernel pointers) — **New**

Kernel selftests exercise a whole subsystem where a **BPF map value can hold a refcounted kernel pointer**, with the kernel managing acquire/release:

- Declare a field `struct task_struct __kptr * task;` in a map value (`progs/task_kfunc_common.h:12-14`).
- Acquire with `bpf_task_acquire(p)`, release with `bpf_task_release(p)`.
- Swap into the map atomically with `bpf_kptr_xchg(&mapval->task, new)` — returns the previous kptr for the caller to release (`progs/refcounted_kptr.c:123`).
- Same pattern for `bpf_cgroup_acquire` / `bpf_cgroup_release` / `bpf_cgroup_from_id` / `bpf_cgroup_ancestor`, and for `bpf_get_task_exe_file` / `bpf_put_file` (`bpf_experimental.h:59-65`).

Local kptrs (not in a map): `bpf_obj_new(typeof(*n))` / `bpf_obj_drop(n)` / `bpf_refcount_acquire(n)` (`progs/refcounted_kptr.c:79-91`). Percpu variant: `bpf_percpu_obj_new(type)` / `bpf_percpu_obj_drop`.

hello-ebpf has neither `__kptr` field annotations nor `bpf_obj_new` / `bpf_kptr_xchg` wrappers. `@Type` field modifiers would be the natural place; a `@Kptr` annotation on a record field could emit the `__kptr` decoration plus generate matching acquire/release helper methods.

---

## 4. BPF kernel-side lists and rbtrees — **New**

Kernel-side intrusive data structures shipped as first-class kfuncs (as of ~6.4):

- **bpf_list_head / bpf_list_node**: `bpf_list_push_front(head, node)`, `bpf_list_push_back`, `bpf_list_pop_front`, `bpf_list_pop_back` (`progs/linked_list.c:38-63`). Declared with `struct bpf_list_head head __contains(foo, node2)` decl-tag so verifier knows the element type.
- **bpf_rb_root / bpf_rb_node**: `bpf_rbtree_add(root, node, less_fn)`, `bpf_rbtree_first(root)`, `bpf_rbtree_remove(root, node)` (`progs/rbtree_fail.c:41-92`). The `less` callback is a BPF subprog with well-known signature; kernel invokes it during insertion.
- Both must be manipulated under `bpf_spin_lock`; the entire subsystem is designed for hot-path concurrent producers.

No hello-ebpf wrapper today. A Java-side `@BPFList<T>` or `@BPFRbTree<T>` field-embed (parallel to how `@BPFMapDefinition` already generates map declarations) would close the gap. The `less` callback maps cleanly to a Java `Comparator<T>`-shaped lambda that the plugin translates into a subprog.

---

## 5. Struct_ops beyond sched_ext — **New**

hello-ebpf's `@Scheduler` / `PerCpuSchedulerBase` / `UserspaceSchedulerBase` only cover the `sched_ext` struct_ops surface. The selftest tree ships two more that use identical machinery:

- **TCP congestion control**: `progs/bpf_dctcp.c`, `progs/bpf_cubic.c`, `progs/bpf_cc_cubic.c`, `progs/bpf_dctcp_release.c`. Program body uses `SEC("struct_ops") void BPF_PROG(bpf_dctcp_init, struct sock *sk) { ... }` (`bpf_dctcp.c:61-62`). The `struct tcp_congestion_ops` slots are the plugin points.
- **Qdisc**: `progs/bpf_qdisc_fifo.c`, `progs/bpf_qdisc_fq.c`, `progs/bpf_qdisc_common.h`. `SEC("struct_ops/bpf_fifo_enqueue") int BPF_PROG(bpf_fifo_enqueue, struct sk_buff *skb, ...)` (`bpf_qdisc_fifo.c:19-21`). Uses `bpf_qdisc_skb_drop` kfunc.

The framework's scheduler machinery (attach, load, per-op callback wiring) is 90% the same. A generic `@StructOps` annotation parameterised by the struct name — with `@Scheduler` becoming a `@StructOps("sched_ext_ops")` alias — would unblock TCP CC and qdisc BPF within the existing infrastructure. Extra kernel selftest struct_ops surface worth noting: `progs/struct_ops_multi_pages.c`, `struct_ops_private_stack.c`, `struct_ops_refcounted.c`, `struct_ops_module.c` (loading struct_ops from a kernel module), `struct_ops_detach.c` (detach/reattach), `struct_ops_autocreate.c`.

Bonus: `progs/bpf_qdisc_dynptr_use_after_invalidate_clone.c` shows dynptr in struct_ops — same argument for §2.

---

## 6. Sleepable + `.s` program suffix — **New**

`@BPFFunction` (annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/BPFFunction.java:59-83) exposes `section()` but no `sleepable` attribute. Selftests use the trailing `.s` on the SEC name to opt into sleepable execution — the verifier allows a much larger helper set (kfuncs like `bpf_get_file_xattr`, `bpf_verify_pkcs7_signature`, `bpf_lookup_user_key`) that can page-fault or block.

SEC prefixes seen with `.s`: `fentry.s/`, `fexit.s/`, `lsm.s/`, `uprobe.s`, `iter.s/cgroup`, `raw_tracepoint.s/`, `struct_ops.s/`. hello-ebpf's `Scheduler.java:176-182` already special-cases `struct_ops.s/`, but the general mechanism isn't user-facing.

Framework gap: `@BPFFunction(sleepable = true)` should append `.s` to the emitted section string. Also needed: `autoAttachableSections` set (`BPFFunction.java:92`) currently lists `fentry,fexit,kprobe,kretprobe,ksyscall,tp,lsm` but doesn't include the `.s` variants or `.multi` variants (see §11).

---

## 7. Iterator kfuncs (bpf_iter_num, task, task_vma, css_task, kmem_cache, dmabuf) — **New**

`bpf_experimental.h:20-362` catalogs the current kernel iterator kfunc set:

- `bpf_iter_task_vma_new(it, task, addr)` / `_next` / `_destroy` — walk VMAs of a task
- `bpf_iter_task_new(it, task, flags)` / `_next` / `_destroy` — walk task hierarchy (threads/procs)
- `bpf_iter_css_new(it, start, flags)` / `_next` / `_destroy` — walk cgroup subsys state tree
- `bpf_iter_css_task_new(it, css, flags)` / `_next` / `_destroy` — walk tasks in a cgroup
- `bpf_iter_kmem_cache_new(it)` / `_next` / `_destroy` — slab-cache walker (`bpf_experimental.h:355-357`)
- `bpf_iter_dmabuf_new(it)` / `_next` / `_destroy` — DMA-buf walker (`bpf_experimental.h:360-362`)
- `bpf_iter_num_new(&it, i, j)` — range iterator, used as the primitive for the `bpf_for(i, 0, N)` macro. `progs/iters_num.c`.

hello-ebpf only wraps `bpf_iter_scx_dsq` (via sched_ext scaffolding). A `BPFIterators` builtin class with `@BuiltinBPFFunction`-template methods would surface all six — the templates already handle the RAII new/destroy pair pattern (see how cpumask acquire/release is done). Bonus: these unlock the corresponding SEC iter programs from §3.1.6 of the awesome-ebpf catalog with a much richer body language than `iter/task` alone.

Also unwrapped: `bpf_iter_bits`, and — pointed by `progs/kmem_cache_iter.c:95` — the `bpf_for_each(kmem_cache, s) { ... }` macro that hides the new/next/destroy dance behind a syntactic loop. A Java equivalent would be a `forEachKmemCache(kmemCache -> { ... })` lambda that the plugin lowers to the loop.

---

## 8. cpumask kfunc surface — delta — **Refines** sched_ext coverage

hello-ebpf wraps 8 cpumask kfuncs (grep of `bpf_cpumask_` in `bpf/src/main/java/`): `first`, `first_zero`, `set_cpu`, `clear_cpu`, `test_cpu`, `weight`, `intersects`, `empty`. The kernel selftest header `bpf_cpumask_common.h:31-64` lists **26 more**:

- Lifecycle: `bpf_cpumask_create`, `bpf_cpumask_release`, `bpf_cpumask_acquire`
- Bit ops: `bpf_cpumask_test_and_set_cpu`, `bpf_cpumask_test_and_clear_cpu`, `bpf_cpumask_setall`, `bpf_cpumask_clear`
- Set ops: `bpf_cpumask_and`, `bpf_cpumask_or`, `bpf_cpumask_xor`
- Predicates: `bpf_cpumask_equal`, `bpf_cpumask_subset`, `bpf_cpumask_full`
- Ranges/misc: `bpf_cpumask_first_and`, `bpf_cpumask_any_distribute`, `bpf_cpumask_any_and_distribute`, `bpf_cpumask_copy`, `bpf_cpumask_populate` (byte-source), `bpf_cpumask_weight`

The MEMORY note `feedback_cpumask_reference_leak.md` already warns about ref-leak with lifecycle factories, but that shouldn't gate wrapping the non-lifecycle ops (`_and`, `_or`, `_xor`, `_full`, `_equal`, `_subset`, `_populate`, `_setall`, `_clear`, `_test_and_set_cpu`, `_test_and_clear_cpu`) which don't take/return a `bpf_cpumask *`.

Adjacent: **`bpf_rcu_read_lock` / `bpf_rcu_read_unlock`** (`bpf_cpumask_common.h:66-67`) — needed to safely dereference rcu-protected pointers inside program bodies, unrelated to sched_ext. hello-ebpf has no wrapper.

---

## 9. Conntrack helpers — **New (Refines §3.3 of otel-awesome)**

`progs/test_bpf_nf.c` and `_fail.c:18-31` declare the conntrack kfunc surface:

- `bpf_skb_ct_alloc(skb, tup, tup_sz, opts, opts_sz)` — allocate a new nf_conn from skb-plane
- `bpf_skb_ct_lookup(skb, tup, tup_sz, opts, opts_sz)` — look up existing conntrack from skb
- `bpf_xdp_ct_alloc` / `bpf_xdp_ct_lookup` — same from XDP-plane
- `bpf_ct_insert_entry(nf_conn)` / `bpf_ct_release(nf_conn)` — commit / release
- `bpf_ct_set_timeout` / `bpf_ct_change_timeout` / `bpf_ct_set_status` / `bpf_ct_change_status` — mutation

Enables full stateful firewall in BPF. Wrap as a `Conntrack` builtin class; the `struct bpf_ct_opts` config struct is small (3 ints + 1 u32) and would map to a Java record easily.

---

## 10. may_goto / verifier features — **New**

`progs/verifier_may_goto_1.c` and `_2.c` exercise the `may_goto` primitive — a verifier-aware "if we ran out of budget, exit-the-loop" branch that lets the verifier accept much larger loops than the historical 1M-instr complexity limit. It's used via a `.byte`-encoded `BPF_RAW_INSN(BPF_JMP | BPF_JCOND, 0, 0, offset, 0)`, wrapped by the `bpf_may_goto.h` macro. Combined with the `can_loop` idiom (`progs/arena_htab.c:38`) it enables 100 000-iteration loops in BPF.

`verifier_gotol.c` exercises the plain `gotol` (long goto) instruction — needed for large program bodies where the standard `goto` offset field overflows.

hello-ebpf's `@BPFFunction` bodies are Java loops that the plugin lowers to C `for`/`while`. There's no way to emit a `may_goto`-bounded loop or the `can_loop` marker. A `Loop.canLoop()` or `@LoopBudget(1_000_000)` annotation on a Java loop that translates to `while (can_loop && cond)` would unlock large map inits and per-CPU tables. The `bpf_experimental.h:8` `#include <bpf_may_goto.h>` shows the C-side is trivially available.

Companion: `verifier_iterating_callbacks.c`, `verifier_precision.c`, `verifier_subprog_precision.c` — these exercise features the plugin already relies on indirectly, no user-facing action.

---

## 11. Newer `.multi` attach modes — **Refines** kprobe.multi/uprobe.multi bullet

Beyond the already-catalogued `kprobe.multi` / `uprobe.multi`:

- **`fentry.multi` / `fexit.multi`** (`progs/tracing_multi_intersect_attach.c:15-32`) — attach one program to a *set* of kernel functions with a single syscall. `progs/tracing_multi_intersect_attach.c` demonstrates the shape: `SEC("fentry.multi") int BPF_PROG(fentry_1)`. Uses `bpf_kprobe_multi_link_create`-style API from the loader side.
- **`fentry.multi/bpf_fentry_test*"` — glob pattern in the SEC name for wildcard attach.
- **`fentry.multi.s/`** — sleepable variant of the above.
- **`kretsyscall/`** — matches `ksyscall/` but for return-side probes (`kretsyscall/nanosleep` in the SEC scan). hello-ebpf has `ksyscall` but not `kretsyscall`.

hello-ebpf's SEC-string handling is a plain pass-through, so these can be typed on the annotation once the loader learns the `bpf_kprobe_multi_link_create`-family syscalls (mostly already covered by the rust-go catalog for `kprobe.multi`).

---

## 12. Map creation flags (BPF_F_*) — **Refines** BPFMapDefinition surface

`@BPFMapDefinition` (`annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/BPFMapDefinition.java`) exposes only `maxEntries()`. Selftests routinely set `__uint(map_flags, BPF_F_...)` — the full list from a grep over `progs/*.c`:

`BPF_F_NO_PREALLOC`, `BPF_F_INNER_MAP`, `BPF_F_RDONLY_PROG`, `BPF_F_WRONLY_PROG`, `BPF_F_MMAPABLE`, `BPF_F_PRESERVE_ELEMS`, `BPF_F_CLONE`, `BPF_F_RB_OVERWRITE`, `BPF_F_STACK_BUILD_ID`.

`BPF_F_NO_PREALLOC` alone is required for `HASH` maps that hold spin locks or kptrs (`progs/uptr_update_failure.c:11`), so it blocks §3 and §4 wrappers today. hello-ebpf hard-codes `BPF_F_MMAPABLE` internally for arenas; add `flags()` to `@BPFMapDefinition` and expose the enum.

`BPF_F_INNER_MAP` unlocks `ARRAY_OF_MAPS` / `HASH_OF_MAPS` from the rust-go catalog. `BPF_F_RDONLY_PROG` / `_WRONLY_PROG` are needed for immutable rodata and single-writer scenarios. `BPF_F_STACK_BUILD_ID` is the buildid-included form of `BPF_MAP_TYPE_STACK_TRACE` — a prerequisite for the OTel-catalog symbolization pipeline.

---

## 13. Exceptions / bpf_throw — **New**

`progs/exceptions.c:23,48,84` uses `bpf_throw(cookie)` to abort a BPF program mid-execution with a user-defined cookie return value. Combined with `__exception_cb(callback)` decl-tag (`bpf_experimental.h:95`), the caller can install a per-program exception handler with signature `int handler(u64 cookie)`. Also `bpf_assert(cond)` and `bpf_assert_range(x, lo, hi)` macros (`bpf_experimental.h:285-330`) — assertions that emit `if (!cond) bpf_throw(0)` and are visible to the verifier for bounds inference.

hello-ebpf has no equivalent. Java's `throw` semantics map naturally: a `@BPFFunction throws BPFException { ... bpf_throw(42); ... }` would emit the call. `bpf_assert_range(x, 0, N)` is particularly high-value — it teaches the verifier explicit range bounds that eliminate whole classes of "invalid access to map value with wrong offset" errors.

---

## 14. BPF workqueues (bpf_wq) — **New**

`bpf_experimental.h:351-352` declares `bpf_wq_init(wq, p_map, flags)` and `bpf_wq_start(wq, flags)`, with `bpf_wq_set_callback(wq, cb, flags)` seen in `progs/wq.c:80`. Difference vs. `bpf_timer`: workqueues execute in process (kthread) context, so they can call sleepable helpers; timers fire in softirq. `bpf_wq` structs are embedded in map values just like `bpf_timer`.

hello-ebpf has a `TIMER` embed but no `WQ` embed. Same code path in the plugin, distinct type.

---

## 15. BPF crypto kfunc surface — **New**

`progs/crypto_sanity.c` + `crypto_bench.c` + `crypto_common.h` exercise:

- `bpf_crypto_ctx_create(params, sz, err)` — allocate crypto transform
- `bpf_crypto_ctx_acquire` / `bpf_crypto_ctx_release`
- `bpf_crypto_encrypt(ctx, src_dynptr, dst_dynptr, iv_dynptr)` / `bpf_crypto_decrypt`

Requires dynptr (§2) as inputs. Unlocks BPF-side symmetric encryption for L7 proxies. No hello-ebpf wrapper.

---

## 16. Filesystem / xattr / signature kfuncs — **New**

Sleepable-only kfuncs (`bpf_kfuncs.h:71-93`):

- `bpf_get_file_xattr(file, name, value_dynptr)` / `bpf_get_dentry_xattr` / `bpf_set_dentry_xattr` / `bpf_remove_dentry_xattr`
- `bpf_get_fsverity_digest(file, digest_dynptr)`
- `bpf_lookup_user_key(serial, flags)` / `bpf_lookup_system_key(id)` / `bpf_key_put(key)`
- `bpf_verify_pkcs7_signature(data_dynptr, sig_dynptr, trusted_keyring)`

Enables signed-loader / kernel-integrity BPF (`progs/test_signed_loader.c`, `test_sig_in_xattr.c`, `test_verify_pkcs7_sig.c`). LSM+sleepable is the enabler; §6 gates this.

---

## 17. RCU read side + trusted pointer casts — **New**

`bpf_rcu_read_lock()` / `bpf_rcu_read_unlock()` (`bpf_cpumask_common.h:66-67`) delimit an RCU-read critical section — required to dereference an rcu-protected pointer stored in a kptr field. `bpf_rdonly_cast(obj, btf_id)` (`bpf_kfuncs.h:69`) converts an untyped pointer to a typed read-only kernel pointer, enabling verifier-checked field access on kfunc-returned objects.

Companion: `bpf_preempt_disable()` / `bpf_preempt_enable()` (`bpf_experimental.h:256-257`) and the `bpf_guard_preempt()` cleanup-attribute macro (`bpf_experimental.h:273-276`) — the C `__attribute__((cleanup))` idiom that gives scope-based preempt guards. A Java `try-with-resources RcuReadLock` and `try-with-resources PreemptGuard` are the obvious mappings.

---

## 18. bpf_get_kmem_cache and other utility kfuncs — **New**

Small but useful:

- `bpf_get_kmem_cache(addr)` (`progs/kmem_cache_iter.c:31`) — resolve an address to its slab cache
- `bpf_task_from_pid(pid)` / `bpf_task_from_vpid(vpid)` (`progs/task_kfunc_common.h:25`) — resolve pid/vpid to a refcounted task_struct
- `bpf_path_d_path(path, buf, sz)` (`bpf_experimental.h:75`) — resolve a `struct path *` to a textual path
- `bpf_get_task_exe_file(task)` (`bpf_experimental.h:59`) — acquire exe_file, `bpf_put_file` to release
- `bpf_cgroup_read_xattr(cgroup, name, dynptr)` (`bpf_experimental.h:364`) — cgroup xattr access

---

## 19. New iterator SEC program types — **Refines** rust-go iter/ bullet

The rust-go catalog listed `iter/{task, bpf_map, tcp, udp, sock, task_file, bpf_prog, cgroup}`. Selftests add: `iter/task_vma`, `iter/sockmap`, `iter/dmabuf`, `iter/kmem_cache`, `iter/ksym`, `iter/netlink`, `iter/unix`, `iter/bpf_link`, `iter/bpf_map_elem`, `iter/bpf_sk_storage_map`. And the sleepable variant `iter.s/cgroup`. `dmabuf_iter.c` and `kmem_cache_iter.c` are the newest (2024–2025).

---

## 20. Cross-reference & priority

| # | Section | New / Refines | Priority for a Java framework | Rationale |
|---|---|---|---|---|
| 1 | Arena native data structures | New | **P0** | Header-only kernel code, ships as-is; unlocks concurrent producers via arena_spin_lock; hello-ebpf arena is currently a byte buffer |
| 2 | Dynptr | New | **P0** | Replaces manual bounds arithmetic in every XDP/TC body; prerequisite for §9, §15, §16 |
| 3 | kptrs + bpf_obj_new | New | **P1** | Kernel-owned object lifecycle already implicit in scheduler code; a `@Kptr` annotation would formalise it |
| 4 | Lists and rbtrees | New | **P1** | Non-arena kernel-side containers; enables ordered scheduler queues, connection-tracking indexes |
| 5 | Struct_ops beyond sched_ext | New | **P0** | Generic `@StructOps` reuses 90% of the sched_ext machinery, immediately unlocks TCP CC + qdisc |
| 6 | Sleepable `.s` sections | New | **P0** | Trivial `@BPFFunction(sleepable = true)` addition; gates §15, §16 |
| 7 | Iterator kfuncs | New | **P1** | 6 new iterators, natural fit for `@BuiltinBPFFunction` templates |
| 8 | cpumask kfunc delta | Refines | **P2** | 26 more wrappers; straightforward mechanical work |
| 9 | Conntrack helpers | New | **P2** | Stateful firewall / NAT samples |
| 10 | may_goto / can_loop | New | **P2** | Unlocks large-loop map inits; requires plugin loop-lowering change |
| 11 | fentry.multi / fexit.multi / kretsyscall | Refines | **P1** | Batch tracer attach — natural extension of existing kprobe.multi gap |
| 12 | Map flags | Refines | **P1** | `@BPFMapDefinition(flags = { NO_PREALLOC, RDONLY_PROG })` — small annotation change, unblocks §3, §4 |
| 13 | Exceptions / bpf_throw | New | **P2** | `bpf_assert_range` alone justifies it (verifier-friendly bounds hints) |
| 14 | bpf_wq | New | **P2** | Sleepable siblings of `TIMER` embed |
| 15 | Crypto kfuncs | New | **P3** | L7-proxy sample enabler; depends on §2 |
| 16 | xattr / signature kfuncs | New | **P3** | Signed-loader / integrity sample enabler; depends on §6 |
| 17 | RCU / preempt guards | New | **P2** | `try-with-resources` mapping is elegant; needed for safe kptr deref |
| 18 | Utility kfuncs | New | **P2** | Small, standalone additions |
| 19 | Extra iter/ program types | Refines | **P2** | Same SEC-parsing pattern as existing iter/ bullet |

**Top-5 highest-value gaps for a Java framework audience**:

1. **§1 Arena native data structures** — Kernel ships them as portable C headers, hello-ebpf can ship them verbatim plus Java-side facade classes; instantly unlocks concurrent producer patterns (scheduler runqueues, per-CPU histograms with fan-in).
2. **§5 Struct_ops beyond sched_ext** — The `@Scheduler` machinery is already generic under the hood. Renaming to `@StructOps(name = "tcp_congestion_ops")` unlocks TCP CC and qdisc without new syscalls. This is the single-biggest ratio of "framework surface delta" to "new samples enabled".
3. **§2 Dynptr** — Every XDP/TC sample in the framework currently reimplements bounds arithmetic. A `DynPtr` Java class + kfunc-template wrappers eliminates 100+ lines of boilerplate per program and unblocks §9, §15, §16.
4. **§6 Sleepable + §12 map flags** — Two small annotation changes (`@BPFFunction(sleepable = true)`, `@BPFMapDefinition(flags = ...)`) with outsized impact — they gate ~half of the other entries and are cheap to add.
5. **§7 Iterator kfuncs + §11 fentry.multi** — The two "batch-observability" gaps that align with hello-ebpf's existing tracing story. `bpf_iter_task_vma` + `bpf_iter_css_task` in particular are what makes the OTel-catalog off-CPU/task-tree profilers implementable in the framework.

---
