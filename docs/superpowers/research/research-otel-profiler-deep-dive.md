# OTel eBPF profiler deep-read: concrete mechanics for hello-ebpf Gap 4

Source: `/tmp/ebpf-research/otel-profiler` at commit `e911babd`. Path: `support/ebpf/` + `interpreter/hotspot/`.
Refines: `research-gap-designs.md` Gap 4 (native-stack profiler).

The OTel eBPF profiler is a whole-system, always-on sampling profiler. It ships nine tracers (HotSpot, Python, Ruby, Perl, PHP, .NET, V8, BEAM, Go) plus a native DWARF unwinder, all glued together by a single per-CPU state machine and a `PROG_ARRAY` tail-call graph. Everything below is what hello-ebpf's Gap 4 (currently a README-derived 11-week sketch) needs to grow if it wants to be more than a JFR wrapper.

## 1. HotSpot Java unwinding — the crown jewel

The whole HotSpot unwinder is `hotspot_tracer.ebpf.c` (956 LOC). Its shape:

**Per-process metadata map** (`hotspot_procs`, hash, key `pid_t`, value `HotspotProcInfo`, max 256; `hotspot_tracer.ebpf.c:94-101`): populated by userspace after JVMTI/introspection of the target JVM. Contains ~15 field offsets like `codeblob_codestart`, `codeblob_framesize`, `nmethod_deopt_offset`, `method_constmethod`, `segment_shift`, `heapblock_size`, `new_bcp_slot`, `nmethod_uses_offsets` — every one of these is a byte offset inside a JDK-internal C++ struct, extracted per JVM binary.

**Unwind entry point** (`unwind_hotspot`, `hotspot_tracer.ebpf.c:917-955`): unwinds up to `HOTSPOT_FRAMES_PER_PROGRAM = 4` frames, then tail-calls the next unwinder to keep instruction count under the verifier's 1M limit. Loops back to itself if still in JVM code.

**Frame-type dispatch** (`hotspot_tracer.ebpf.c:891-905`) picks per-CodeBlob strategy from the first 4 bytes of the CodeBlob name (`"nmethod"`, `"native nmethod"`, `"Interpreter"`, `"vtable chunks"`, everything else = stub). Each has its own logic:

- `hotspot_handle_nmethod` (l.577) — JIT-compiled method. Detects prologue/epilogue by comparing PC against `code_start + frame_complete`, handles deoptimization (`deopt_handler` fixup at l.591-620), and on x86 falls back to a return-address search across up to 6 stack slots because the JVM occasionally pushes extra words (`HOTSPOT_RA_SEARCH_SLOTS`).
- `hotspot_handle_interpreter` (l.218) — reads custom frame-pointer layout with hardcoded slot indices (`BCP_SLOT_JVM8=7`, `BCP_SLOT_JVM9=8` on x86). BCP (Byte Code Pointer) → BCI (Byte Code Index) by subtracting `cmethod + cmethod_size`.
- `hotspot_handle_vtable_chunks` (l.200) — megamorphic call-site trampoline: return-address only on x86, LR-based on ARM.
- `hotspot_handle_stub` (l.701) — everything else; uses `text_section_id`-encoded stub metadata bits on ARM.

**CodeBlob lookup via segmap** (`hotspot_find_codeblob`, l.151-198): the CodeCache is chopped into fixed-size segments (`heapblock_size`). A "segmap" byte array holds tag values that walk backwards through segments to the CodeBlob header. Up to `HOTSPOT_SEGMAP_ITERATIONS = 12` steps (JDK8 needs 9). The segmap start address is packed into `PIDPage.file_id`. This is the mechanism that gives you an `nmethod*` from an arbitrary PC in JIT code — no symbol tables involved.

**Prologue/epilogue heuristics** (l.417-575): byte-pattern searches for `ret` (0xc3), `pop rbp` (0x5d), safepoint polling, `leave` on x86; encoded `ldp`/`add` search on ARM. These recover mid-instruction unwinds when the sample lands in the first few bytes of a function.

**Illustrative core** (~25 lines abridged from l.865-911):

```c
static ErrorCode hotspot_unwind_one_frame(PerCPURecord *record, HotspotProcInfo *ji, bool topmost) {
  UnwindState *state = &record->state;
  HotspotUnwindInfo ui = { .pc = state->pc, .sp = state->sp, .fp = state->fp };
  CodeBlobInfo cbi;
  ErrorCode err = hotspot_read_codeblob(state, ji, &record->hotspotUnwindScratch, &cbi);
  if (err) return err;

  HotspotUnwindAction action = UA_UNWIND_INVALID;
  switch (cbi.frame_type) {
    case FRAMETYPE_nmethod:
    case FRAMETYPE_native_nmethod:
      err = hotspot_handle_nmethod(&cbi, trace, &ui, ji, &action, topmost && !state->return_address);
      break;
    case FRAMETYPE_Interpreter:
      err = hotspot_handle_interpreter(state, &ui, ji, &action); break;
    case FRAMETYPE_vtable_chunks:
      err = hotspot_handle_vtable_chunks(&ui, &action); break;
    default:
      err = hotspot_handle_stub(state, &cbi, &ui, &action);
  }
  return hotspot_execute_unwind_action(&cbi, action, &ui, state, trace);
}
```

**Java-side sketch for hello-ebpf**:

```java
@BPF public abstract class HotSpotUnwinder extends BPFProgram {
  @Type record HotspotProcInfo(u8 codeblob_codestart, u8 codeblob_codeend,
      u8 codeblob_framesize, u8 codeblob_framecomplete, u8 codeblob_name,
      u32 segment_shift, u32 heapblock_size,
      u8 nmethod_deopt_offset, u8 nmethod_compileid, u8 nmethod_orig_pc_offset,
      u8 method_constmethod, u16 cmethod_size,
      boolean new_bcp_slot, boolean nmethod_uses_offsets) {}

  @BPFMapDefinition(maxEntries = 256)
  BPFHashMap<Integer, HotspotProcInfo> hotspotProcs;
}
```

The `HotspotProcInfo` must be populated **per JVM PID** from userspace before samples arrive. That population is Section 10 below; without it, `unwind_hotspot` returns `ERR_HOTSPOT_NO_PROC_INFO` and the sample degrades to a native-only stack.

## 2. Native DWARF unwinding — shipping .eh_frame to the kernel

The native unwinder does not read DWARF at sample time. Instead:

**Userspace pre-parses `.eh_frame`** into per-executable "stack delta" tables. A stack delta says "at PC X, SP moved by Y and FP is at [SP-Z]" — a compressed form of `.eh_frame`'s CFA instructions.

**Two-level map hierarchy** (`native_stack_trace.ebpf.c:43-83`):
- `stack_delta_page_to_info` (HASH, 40000 entries, key `StackDeltaPageKey{fileID, page}`): finds the "shard" and first delta index for a code page.
- `exe_id_to_N_stack_deltas` for N in 8..23 (`BPF_MAP_TYPE_HASH_OF_MAPS`, 4096 outer entries each): outer keyed by `u64 fileID`, inner is an `ARRAY` of `1<<N` `StackDelta` records for one executable. Sixteen size buckets = poor-man's dynamic map sizing since BPF map sizes are fixed at load. This is 16 distinct maps, one per size class — userspace picks the smallest one that fits each binary's delta count.
- `unwind_info_array` (`native_stack_trace.ebpf.c:78-83`): global ARRAY dedup table of `UnwindInfo` records — the CFA/FP/RA compute recipes. `StackDelta.unwindInfo` indexes into this.

**`StackDelta` and `UnwindInfo`** (`types.h:879-949`): each `StackDelta` is 4 bytes — `u16 addrLow` (low 16 bits of the ELF virtual address) and `u16 unwindInfo` (index into `unwind_info_array`, or a `UNWIND_COMMAND_*` sentinel if `STACK_DELTA_COMMAND_FLAG=0x8000` is set — sentinels handle PLT stubs, signal frames, stack roots). Each `UnwindInfo` is 16 bytes: `flags`, `baseReg`, `auxBaseReg`, `mergeOpcode`, `s32 param`, `s32 auxParam`. Registers referenced by index (`UNWIND_REG_CFA=1, PC=2, SP=3, FP=4, LR=5`, plus arch-specific like `UNWIND_REG_X86_RAX=6`). CFA expression is `baseReg + param`; if `UNWIND_FLAG_DEREF_CFA` is set, dereference and add the low 3 bits of param × 8. FP is computed the same way from `auxBaseReg + auxParam`.

**PC→row lookup**: binary search within a page's delta range for the largest `addrLow` ≤ `pc & 0xffff`. Bounded iteration (verifier). Errors `ERR_NATIVE_EXCEEDED_DELTA_LOOKUP_ITERATIONS = 4003`, `ERR_NATIVE_BAD_UNWIND_INFO_INDEX = 4015` (`errors.h:140,177`) surface pathological binaries.

**`native_tracer_entry`** (`native_stack_trace.ebpf.c:163-177`): the perf event hook itself is 15 lines — get pid_tgid, ktime, call `collect_trace(regs, TRACE_SAMPLING, pid, tid, ts, 0)`. Same shape for `off_cpu.ebpf.c` and `generic_probe.ebpf.c` — origin discriminator changes, everything else is shared.

**Java-side takeaway**: a full .eh_frame parser is not trivial. Options for hello-ebpf:
1. Vendor one of the Rust ports (blazesym, gimli) via JNI — pragmatic but breaks the "Java-first" story.
2. Reuse OpenJDK's own `java.lang.foreign` DWARF reader (JDK 23+ has partial support in `jdk.internal.foreign`).
3. Ship only frame-pointer unwinding for MVP; publish stack-delta support in a follow-up. This mirrors bcc's `profile.py` which was FP-only for years.

Option 3 is the honest MVP. Frame-pointer unwinding is `unwinder_unwind_frame_pointer` (`tracemgmt.h:387-395`): two memory reads (`state->fp` → `[fp]`, `[fp+8]`) and done. Modern OpenJDK builds with `-XX:+PreserveFramePointer`; that plus glibc's `-fno-omit-frame-pointer` (Fedora/Ubuntu 24.04 default) covers most real workloads.

## 3. Tracer dispatch — the PROG_ARRAY pattern

`perf_progs` (`interpreter_dispatcher.ebpf.c:30-35`) is a `BPF_MAP_TYPE_PROG_ARRAY` of size `NUM_TRACER_PROGS`. Each slot is one tail-callable eBPF program. Program IDs (from `types.h`, referenced in tracers): `PROG_UNWIND_STOP`, `PROG_UNWIND_NATIVE`, `PROG_UNWIND_HOTSPOT`, `PROG_UNWIND_PYTHON`, `PROG_UNWIND_RUBY`, `PROG_UNWIND_PERL`, `PROG_UNWIND_PHP`, `PROG_UNWIND_V8`, `PROG_UNWIND_DOTNET`, `PROG_UNWIND_BEAM`, `PROG_GO_LABELS`.

**Discriminator**: `resolve_unwind_mapping` (`tracemgmt.h:576-627`) looks up the current PC in `pid_page_to_mapping_info` (LPM_TRIE, key `PIDPage{pid, page_addr}`). The value's high 8 bits encode which unwinder to run. If the mapping falls into a range known to belong to an interpreter (`interpreter_offsets` map, `tracemgmt.h:683-701`), the interpreter unwinder is chosen instead.

**Tail-call wrapper** (`tracemgmt.h:741-764`): counts calls, aborts at 29 (kernels only guarantee 32), and stores the current program index in `record->tailCalls`. Errors bump `metricID_MaxTailCalls`.

**Frame-count budget**: each unwinder unwinds a bounded number of frames (`HOTSPOT_FRAMES_PER_PROGRAM = 4`) then tail-calls back into itself or `PROG_UNWIND_NATIVE`. Effective depth ceiling: ~120 frames (29 tail calls × 4 frames — real value is lower because natives use larger batches).

**Contrast with hello-ebpf**: `TailCallDemo` demonstrates a two-program tail call but the current framework has no equivalent of `perf_progs` — no map-type helper, no dispatcher pattern. Gap: a `@BPFTailCallTable` annotation that generates the `BPF_MAP_TYPE_PROG_ARRAY`, wires programs into slots, and gives the parent a typed `tailCall(slot)` helper. This is a prerequisite for any pluggable unwinder pipeline.

## 4. `tracemgmt.h` — the "operating system" of a profiler

978 LOC of shared infrastructure. The Java equivalent would be a `@Profiler`-annotated base class.

**Per-CPU state** (`per_cpu_records`, `interpreter_dispatcher.ebpf.c:14-19`): `BPF_MAP_TYPE_PERCPU_ARRAY` with a single entry holding a `PerCPURecord` (~4KB). Contains:
- `UnwindState state` — regs (pc/sp/fp/rax/rdi/lr/…), `error_metric`, `unwind_error`, `text_section_bias/id/offset`, `return_address`, `lr_invalid`, `fp_bound`.
- `Trace trace` — output being built: `pid`, `tid`, `comm`, `ktime`, `value`, `num_frames`, `num_kernel_frames`, `frame_data[MAX_FRAME_UNWINDS]`, `apm_trace_id`, `custom_labels`.
- Per-interpreter scratch: `hotspotUnwindScratch` (a codeblob buffer for over-reads), `perlUnwindState`, `pythonUnwindState`, `phpUnwindState`, `rubyUnwindState`, `customLabelsState`.
- `unwindersDone` bitmap — prevents re-entering an unwinder that already declared it's done.
- `tailCalls` counter, `ratelimitAction`.

**Sample entry point** (`collect_trace`, `tracemgmt.h:919-976`):

```c
PerCPURecord *record = get_pristine_per_cpu_record();  // resets state
trace->origin = origin; trace->pid = pid; trace->tid = tid;
bpf_get_current_comm(&trace->comm, sizeof(trace->comm));
push_kernel_frames(ctx, trace);       // bpf_get_stack for kernel side
if (pid == 0) tail_call(ctx, PROG_UNWIND_STOP);
get_usermode_regs(ctx, &record->state, &has_usermode_regs);
resolve_unwind_mapping(record, &unwinder);
tail_call(ctx, unwinder);
```

**Kernel-mode-to-user-mode regs bridge** (`get_usermode_regs`, l.873-902): if the sample interrupted kernel mode, walk `task_struct` via `task_stack_offset + stack_ptregs_offset` (both userspace-provided constants) to find the entry `pt_regs`. This is how the profiler survives sampling that lands in a syscall.

**Frame builder** (`push_frame`, l.416-433): allocates space in `trace->frame_data`, writes a 64-bit header packing `frame_type:4 | flags:4 | length:4 | data:52`, returns a pointer to the variable payload. `push_hotspot` writes `[file, line]` after the header (l.104-117).

**Trace sink** (`send_trace`, l.476-499): `bpf_ringbuf_output` into `trace_events` with `BPF_RB_NO_WAKEUP` (userspace polls). `Trace.frame_data` is `u64[3072]` (`types.h:658`) → ~24KB max per sample; total `Trace` size ~25KB. `PerCPURecord` is capped at 32KB (`types.h:875` `_Static_assert`). Ring buffer is preferred over perf events precisely because there's a lost-events counter; the comment at l.494 says "there's no 'lost events' counter that userspace can access" — meaning perf event arrays don't expose one; ring buffers do via `bpf_ringbuf_query`. hello-ebpf currently uses `BPFRingBuffer` but has no equivalent per-CPU scratch pattern.

**Java sketch — `@Profiler` base**:
```java
@BPF public abstract class Profiler extends BPFProgram {
  @BPFMapDefinition(maxEntries = 1)
  BPFPerCpuArray<PerCPURecord> perCpuRecord;

  @BPFMapDefinition(maxEntries = NUM_METRICS)
  BPFPerCpuArray<@Unsigned Long> metrics;

  @BPFTailCallTable(size = NUM_TRACER_PROGS) TailCallTable perfProgs;

  @BPFFunction abstract void incrementMetric(@Unsigned int id);
  @BPFFunction abstract long pushFrame(int type, int flags, long data, int varlen);
  @BPFFunction abstract void tailCall(Ptr<pt_regs> ctx, int next);
}
```
Without this scaffolding, every profiler-adjacent hello-ebpf sample re-implements per-CPU state ad hoc.

## 5. Off-CPU and sched monitor

`off_cpu.ebpf.c` (90 LOC) is **two hooks**, not one:
1. `tracepoint/sched/sched_switch` (l.25-48): applies `bpf_get_prandom_u32() > off_cpu_threshold` sampling probability, records the switch-out timestamp in `sched_times` (`BPF_MAP_TYPE_LRU_PERCPU_HASH`, key `pid_tgid`). No unwinding here — the target thread is being descheduled, so its regs aren't current.
2. `kprobe/finish_task_switch` (l.61-90): fires after the scheduler restores the incoming task's registers. Looks up the entry timestamp; if present, deletes it, computes `diff = now - start_ts`, and calls `collect_trace(ctx, TRACE_OFF_CPU, pid, tid, ts, diff)`. `diff` becomes the sample's `value` — off-CPU nanoseconds. The delete-then-call ordering prevents double-report on races.

The `off_cpu_threshold` is a `BPF_RODATA_VAR` set at load time from userspace (l.22) — the constant is compiled into the program.

`sched_monitor.ebpf.c` (54 LOC) attaches to `sched/sched_process_free`, with **two versioned handlers** (`sched_monitor.ebpf.c:44-54`): `v2` for kernel 6.16+ (skip=12 bytes) and `v1` for older kernels (skip=24 bytes), because the tracepoint's binary format changed in commit `155fd6c3e2f0` when `comm` shrunk. It only reports PIDs that are already in `reported_pids` or `pid_page_to_mapping_info` — kernel workers don't count.

**Java takeaway**: off-CPU is 90 LOC of BPF because the heavy lifting (stack building, unwinder dispatch, ringbuf) is shared with on-CPU. In hello-ebpf, adding an off-CPU mode to a hypothetical `@Profiler` should be a single annotation flag, not a separate sample. The lesson is orthogonal composition: *sample source* (`perf_event`, `sched_switch`+`finish_task_switch`, `sched_wakeup_new`, kprobe/generic) × *unwinding pipeline* (per-PID). Also, the kernel-format versioning of `sched_process_free` is a reminder that BPF programs need CO-RE or manual version dispatch — hello-ebpf's compiler-plugin approach could annotate `@SEC` targets with kernel version predicates and auto-select.

## 6. `generic_probe.ebpf.c` — the dynamic-probe pattern

Only 25 lines. One `SEC("kprobe/generic")` handler calls `collect_trace(ctx, TRACE_PROBE, pid, tid, ts, 0)`. What makes it "generic" is that userspace can attach this compiled program to **any kprobe target at runtime** without recompiling BPF. Contrast with hello-ebpf's compile-per-`@BPF`-class model: every new probe point re-runs the compiler plugin and JAR bundling.

**Design implication for Gap 4**: to run a Java profiler as an OTel-competitive service, hello-ebpf needs a "pre-compiled probe" concept — an artifact loaded once and re-attached to different targets via BPF link updates. The current `@BPFProgram` build lifecycle assumes 1:1 probe:program.

## 7. TSD/TLS reading from BPF (`tsd.h` + `go_labels.ebpf.c`)

**TSD base**: `tsd_get_base` (`tsd.h:87-108`) reads `task_struct->thread.fsbase` (x86) via the userspace-supplied `tpbase_offset`. This gives you the thread's TLS pointer without knowing which glibc/musl version is in use.

**TSD key lookup** (`tsd_read`, `tsd.h:10-33`): `tsd_base + tsi->offset [ + indirection ] + key * multiplier` — matches glibc's pthread key layout. Used to fetch the current Python `PyThreadState`, Ruby thread, Perl `PerlInterpreter`.

**DTV walking** (`dtv_read`, l.35-84): shared-library TLS. Reads the Dynamic Thread Vector at `tsd_base + dtvi->offset`, indexes by `module_id * multiplier`, then dereferences `tls_block + tls_offset`. This is how you read a `__thread` variable from a `.so` when TLSDESC isn't available.

**Go pprof labels** (`go_labels.ebpf.c`, 206 LOC): walks `runtime.g → runtime.m → m.curg.labels` — a linked chain of pointers dereferenced with per-Go-version offsets from a `GoLabelsOffsets` struct. **Two decoding paths** based on Go version (l.172-178): Go 1.24+ stores labels as a `GoSlice` of `[key, val]` pairs → `get_go_custom_labels_from_slice` reads up to 16 key/val strings inline; Go ≤1.23 stores labels as a `map[string]string` → `get_go_custom_labels_from_map` walks up to 16 hash buckets, each with 8 slots (`GO_MAP_BUCKET_SIZE=8`), reading the `tophash[]/keys[]/values[]` triple layout. The offset struct itself is populated from userspace by parsing `runtime.g`'s DWARF or reading Go binary metadata. This is the canonical "userspace-provided offsets → BPF struct walker" pattern.

**Java equivalent**: JVMTI can enumerate `jthread` handles and their associated `Thread` objects. A `thread_labels` map keyed by `(pid, native_tid)` and populated from userspace on `ThreadStart`/`ThreadEnd` JVMTI callbacks would let BPF attach a "Java thread name" (or `MDC` label) to each sample without the BPF side ever crossing the JVM's heap. This is what a Java-side `Sample.threadName()` should be built on.

## 8. Frame encoding (`frametypes.h` + `types.h`)

Every frame in `trace->frame_data` starts with a 64-bit header. Layout (`tracemgmt.h:397-407`):

```
bits    field
[63:60] frame_type    (FRAME_MARKER_*: unknown, python, php, native, kernel, hotspot, ruby, perl, v8, php_jit, dotnet, go, beam, luajit)
[59:56] flags         (ERROR=1, RETURN_ADDRESS=2, PID_SPECIFIC=4)
[55:52] varlen        (number of trailing u64s)
[51:0]  data          (type-specific 52-bit payload)
```

**HotSpot frame** (2 varlens): `data` = 0, then `[file, line]`. `line` is `subtype:4 | pc_or_bci:28 | ptr_check:32` (`hotspot_tracer.ebpf.c:120-123`).
- `file` = CodeBlob address (native/stub) or Method* (interpreter).
- Subtypes: `STUB=0, VTABLE=1, INTERPRETER=2, NATIVE=3`.
- `ptr_check` is the `compile_id` (nmethod) or `cmethod_ptr >> 3` (interpreter) — a validation cookie so the userspace symbolizer can detect stale caches when the JIT re-emits code at the same address.

**Native frame** (1 varlen): `data` = `text_section_id` (48 bits), payload = `text_section_offset` — a stable executable identity plus offset that userspace symbolizes offline.

**Java `Sample<Frame>` API sketch**:
```java
public sealed interface Frame {
  record Native(long fileId, long offset) implements Frame {}
  record HotspotJit(long codeBlob, int pcDelta, int compileId) implements Frame {}
  record HotspotInterp(long method, int bci, int cmethodCookie) implements Frame {}
  record Kernel(long addr) implements Frame {}
}
public record Sample<F extends Frame>(int pid, int tid, long ktime,
    List<F> kernelFrames, List<F> userFrames, byte[] comm) {}
```

## 9. Error taxonomy (`errors.h`)

Errors bucketed by unwinder (each block gets a 1000-range):
- `0`: OK / internal (unreachable, stack length, empty stack, max tail calls).
- `1000-1005`: HotSpot (no codeblob, interpreter FP, invalid RA, invalid codeblob, LR mid-trace, no proc info).
- `2000-2008`: Python (bad code obj, bad frame, bad cframe, bad thread state, bad autoTLSkey, bad TSD).
- `3000-3033`: Ruby (13 distinct failure modes across ISEQ/EP/CME reading).
- `4000-4020`: Native (delta lookup exceeded, invalid delta, stop record, PC read fail, kernel-mode read fail, IRQ chase fail, unexpected kernel addr, no PID mapping, zero PC, small PC, bad unwind info index, 32-bit compat mode, unsupported mapping, no VMA, non-executable VMA).
- `5000-5002`: V8. `6000-6003`: .NET. `7000-7006`: BEAM.

Every one of these maps 1:1 to a metric ID that gets incremented in a `BPF_MAP_TYPE_PERCPU_ARRAY` (`interpreter_dispatcher.ebpf.c:22-27`). Userspace exports them as OTel metrics.

**hello-ebpf gap**: current framework has one `ERR_*` per module maybe. There is no "error frame in the trace" concept, no per-CPU metrics array, no unwinder-scoped taxonomy. For a serious profiler this taxonomy IS the debugging story — without it a broken JVM upgrade is a black-box failure with no signal. Recommend `@ProfilerError` enum-per-unwinder generation.

## 10. Interpreter offset injection — the Java-side dual

`interpreter/hotspot/` (2746 LOC of Go) is what populates `hotspot_procs`. Concrete sequence from `hotspot.go:142` and `data.go:660-698`:

1. **Recognize target**: `loader()` (l.142-152) matches `.*/libjvm\.so` in the mapped file name, opens it as ELF.
2. **Resolve introspection symbols** (`data.go:660-697`): look up ELF exports `gHotSpotVMStructs`, `gHotSpotVMStructEntryArrayStride`, `gHotSpotVMStructEntryTypeNameOffset`, `gHotSpotVMStructEntryFieldNameOffset`, `gHotSpotVMStructEntryOffsetOffset`, `gHotSpotVMStructEntryAddressOffset`, plus the parallel `gHotSpotVMTypes*` set. These are documented HotSpot Serviceability Agent debug symbols — the same interface DTrace uses. On JVMs with JVMCI (Graal), an additional `jvmciVMStructs` table exists (`data.go:688-695`).
3. **Read remote tables** (`data.go:250-317` — `parseIntrospection`): walk the array at `base` with `stride` bytes per entry, reading `type_name`, `field_name`, `offset` triples from the target's memory via a `remoteMemory` reader (backed by `process_vm_readv` or `/proc/<pid>/mem`).
4. **Version-gate logic** (`hotspot.go:37-83`): a lookup table of per-JDK-major-version quirks — `newBcpSlot = 1` for JDK 9+ (frame layout change), `nmethodUsesOffsets` for JDK 7/8 and 23+ (deopt handler field became a u32 offset instead of absolute pointer), `_deopt_handler_offset` renamed to `_deopt_handler_entry_offset` in JDK 26, etc.
5. **Assemble `HotspotProcInfo`** (`instance.go:766-793`):
   ```go
   procInfo := support.HotspotProcInfo{
     Nmethod_deopt_offset:   uint16(vms.Nmethod.DeoptimizeOffset),
     Codeblob_codestart:     uint8(vms.CodeBlob.CodeBegin),
     Codeblob_framesize:     uint8(vms.CodeBlob.FrameSize),
     Cmethod_size:           uint8(vms.ConstMethod.Sizeof),
     Heapblock_size:         uint8(vms.HeapBlock.Sizeof),
     Segment_shift:          uint8(heap.segmentShift),
     Nmethod_uses_offsets:   vmd.nmethodUsesOffsets,
     New_bcp_slot:           newBcpSlot,
     Codecache_start/end:    from vms.CodeCache.{LowBound,HighBound} for JDK9+, from heap ranges for JDK8
     …
   }
   ebpf.UpdateProcData(libpf.HotSpot, pid, unsafe.Pointer(&procInfo))
   ```
6. **Register JIT mappings** (`instance.go:752` — `addJitArea`): for each CodeHeap range, insert into `pid_page_to_mapping_info` with unwinder = `PROG_UNWIND_HOTSPOT` and `text_section_id` encoding the segmap start bits (`HS_TSID_SEG_MAP_BIT`, `HS_TSID_IS_STUB_BIT`, etc.).

**JDK version coverage**: hotspot.go documents "Tested ok" for JDK 7 through 26 (JDK 25 shipped Sep 2025). The introspection-table approach is stable across two decades of JVMs.

**This is what Gap 4 hand-waves.** In hello-ebpf terms:

```java
public final class HotSpotIntrospection {
  // Resolves gHotSpotVMStructs from libjvm.so, reads the target's memory,
  // and returns a filled HotspotProcInfo ready to insert into a BPF map.
  public HotspotProcInfo scan(long pid) throws IOException { ... }
  public void writeInto(BPFHashMap<Integer, HotspotProcInfo> map, long pid) { ... }
  public List<JitArea> jitAreas(long pid) { ... }  // for pid_page_to_mapping_info
}
```

Two Java approaches:
- **In-process JVMTI agent**: use `com.sun.tools.attach.VirtualMachine` to load a small agent JAR into the target JVM that reads `gHotSpotVMStructs` from inside and writes offsets to a file/socket the profiler picks up. Only works for same-user JVMs. Simpler because reading its own memory is trivial.
- **Out-of-process ELF parsing** (what OTel does): parse `libjvm.so` with `java.lang.foreign` MemorySegment-mapped ELF, walk `gHotSpotVMStructs` in the target's memory via `/proc/<pid>/mem` (`RandomAccessFile` seek+read). Requires `CAP_SYS_PTRACE` or root. This is what enables ambient system-wide profiling — you do not need to modify the target JVM.

The second is what makes OTel-style always-on profiling work. **You do not need to modify or restart the JVM.** That is the property hello-ebpf must preserve if it wants to compete with async-profiler.

**AOT limitation** (hotspot.go:85-87): OTel does not support AOT-compiled Java (Graal Native Image, HotSpot Leyden AOT) because AOT code is mapped directly to the process address space and does not go through the CodeCache — the segmap-based `hotspot_find_codeblob` cannot locate it. hello-ebpf would inherit this limitation.

## 11. Map inventory

Complete map catalog for the OTel profiler BPF programs. This is "what shape a profiler is":

| Map | Type | Key | Value | Purpose | Referenced by |
|---|---|---|---|---|---|
| `per_cpu_records` | PERCPU_ARRAY | int | `PerCPURecord` (~4KB) | Per-CPU scratch: state, trace-being-built, per-interpreter unwinder state | all tracers |
| `metrics` | PERCPU_ARRAY | u32 | u64 | Error / event counters | all tracers |
| `perf_progs` | PROG_ARRAY | u32 | prog fd | Tail-call dispatch to unwinders | dispatcher |
| `report_events` | PERF_EVENT_ARRAY | int | u32 | Immediate PID event notifications to userspace | `event_send_trigger` |
| `reported_pids` | LRU_HASH (65536) | u32 pid | u64 rate-limit token | Suppress duplicate PID notifications | `pid_event_ratelimit` |
| `pid_events` | HASH (65536) | u64 pid_tgid | bool | PIDs awaiting userspace processing | `report_pid` |
| `pid_page_to_mapping_info` | LPM_TRIE (2^19, `NO_PREALLOC`) | `PIDPage{pid, page_addr}` | `PIDPageMappingInfo{file_id, bias\|unwind_program}` | Which unwinder to use for a given PC in a given PID | `resolve_unwind_mapping` |
| `inhibit_events` | HASH (2) | u32 event_type | bool | Latch to avoid re-notification while userspace drains events | `event_send_trigger` |
| `trace_events` | RINGBUF | — | `Trace` | Completed traces to userspace | `send_trace` |
| `hotspot_procs` | HASH (256) | pid_t | `HotspotProcInfo` | JVM struct offsets per PID | `unwind_hotspot` |
| `py_procs` | HASH | pid_t | `PyProcInfo` | Python interp offsets | python tracer |
| `ruby_procs` | HASH | pid_t | `RubyProcInfo` | Ruby VM offsets | ruby tracer |
| `perl_procs` | HASH | pid_t | `PerlProcInfo` | Perl offsets | perl tracer |
| `php_procs` | HASH | pid_t | `PhpProcInfo` | PHP offsets | php tracer |
| `v8_procs` | HASH | pid_t | `V8ProcInfo` | V8 offsets | v8 tracer |
| `dotnet_procs` | HASH | pid_t | `DotnetProcInfo` | .NET offsets | dotnet tracer |
| `beam_procs` | HASH | pid_t | `BeamProcInfo` | Erlang BEAM offsets | beam tracer |
| `apm_int_procs` | HASH (128) | pid_t | `ApmIntProcInfo` | APM correlation TLS offsets | `maybe_add_apm_info` |
| `traces_ctx_v1` | LRU_HASH (16384) | u64 pid_tgid | `SpanTraceInfo` | OTel span/trace-id correlation | `maybe_add_otel_span_trace_id` |
| `go_labels_procs` | HASH | pid_t | `GoLabelsOffsets` | Go runtime.g layout | go_labels tracer |
| `interpreter_offsets` | HASH | u64 text_section_id | `OffsetRange{lower/upper, program_index}` | "This exe range belongs to this interpreter" | `get_next_interpreter` |
| `exe_id_to_N_stack_deltas` (N=8..23) | HASH_OF_MAPS | u64 exe_id | inner HASH of `StackDelta` | Bucketed .eh_frame tables by executable | native unwinder |
| `stack_delta_page_to_info` | LPM_TRIE | `(exe_id, page)` | delta shard index | Page → first delta idx | native unwinder |
| `unwind_info_array` | ARRAY | u32 idx | `UnwindInfo` opcodes | Dedup table of "how to compute new SP/FP/RA" | native unwinder |

Twenty-plus maps. hello-ebpf currently offers `BPFHashMap`, `BPFRingBuffer`, `BPFArray`, `BPFArena`, `BPFPerCpuArray`, `BPFPerCpuHashMap`. It is **missing**: `LPM_TRIE`, `LRU_HASH`, `PROG_ARRAY`, `HASH_OF_MAPS`, `PERF_EVENT_ARRAY`, `NO_PREALLOC` flag. Any of these five gaps blocks a naive port.

## 12. Cross-reference to Gap 4 milestones

Assuming Gap 4's 6 milestones as sketched in `research-gap-designs.md`:

**M1 — Base `@Profiler` scaffolding**: Section 4 is the entire spec. Introduce `PerCPURecord`, per-CPU array, tail-call table, metrics array, error taxonomy. Everything else is layered on top. Without M1, M2-M6 are all boilerplate reinvention.

**M2 — Sample source diversity (perf_event, sched_switch, off-CPU, generic kprobe)**: Section 5 + 6. The insight is that all four sources call the same `collect_trace(ctx, origin, pid, tid, ts, value)`; the "profiler" is a shared library, not per-source. Copy that.

**M3 — Native frame-pointer unwinding (MVP)**: Section 2 option 3. `unwinder_unwind_frame_pointer` is 8 lines; ship this first, defer DWARF. Emit `Frame.Native{fileId, offset}` and require `-XX:+PreserveFramePointer` initially.

**M4 — HotSpot unwinding**: Section 1 + Section 10. Two deliverables:
- BPF-side: `HotSpotUnwinder` mirroring `hotspot_tracer.ebpf.c` structure, with `hotspotProcs` map and 4-frames-per-batch loop.
- User-side: `HotSpotIntrospection` that reads `gHotSpotVMStructs` from either an in-process JVMTI agent or out-of-process ELF+`/proc/<pid>/mem`. **This is the majority of the work.**

**M5 — DWARF unwinding**: Section 2. Non-trivial. Consider deferring past 11 weeks or vendoring `blazesym` via JNI.

**M6 — Symbolization + wire format**: Section 8 + Section 9. `Sample<Frame>` sealed hierarchy, error frames as a separate `Frame.Error` variant, per-frame validation cookies to invalidate stale caches on JIT re-emit.

**Cross-cutting: TSD reads (Section 7)**. Not on Gap 4 as a milestone but required for M4 (Interpreter frame's cmethod fetch is TSD-adjacent through `Thread::current()`), for APM/OTel correlation, and for any Java `ThreadLocal`-reading tracer. Should be its own sub-task under M4.

**Framework blockers to Gap 4 (from Section 11)**:
1. `BPF_MAP_TYPE_PROG_ARRAY` + `@BPFTailCallTable` — M1.
2. `BPF_MAP_TYPE_LPM_TRIE` — M3/M4 (PID×page mapping).
3. `BPF_MAP_TYPE_LRU_HASH` — M1 (rate limiting, span correlation).
4. `BPF_MAP_TYPE_HASH_OF_MAPS` — M5 (only DWARF needs this; skippable for MVP).
5. `BPF_MAP_TYPE_PERF_EVENT_ARRAY` — M1 (immediate userspace triggers; can be substituted with ringbuf writes short-term).

Land 1-3 before M1 ships. 4-5 can wait.

**One-line summary**: The OTel profiler is a per-CPU state machine plus a tail-call table of language-specific unwinders, each of which is a byte-offset-driven walker over the runtime's internal structs; the "magic" is entirely in the userspace-populated offset maps (`hotspot_procs`, `py_procs`, …), and porting to Java means porting *those* readers as much as the BPF code itself.
