# Step 0 Acceptance Report — userspace-scheduler

**Date:** 2026-06-29
**Branch:** `userspace-scheduler`
**HEAD:** `609429a`

Step 0 lays the BPF / compiler-plugin foundations needed by Step 1+. Three
sub-tasks (0a/0b/0c). All pass.

## 0a — `BPFRingBuffer.consumeRaw` (zero-alloc dequeue)

**Commit:** `262785c`
**Test:** `me.bechberger.ebpf.bpf.BPFRingBufferConsumeRawTest` — 4/4 passing.

Assertions covered:
- `testConsumeRawDeliversSegments` — `SegmentCallback` receives correctly-sized
  `MemorySegment`s for each producer record.
- `testConsumeRawIsZeroAlloc` — `SegmentCallback` allocates **< 256 B/record**
  on the consumer hot path (observed ≈ 100 B/rec, all from Panama upcall
  framework, no Java-heap allocations).
- `testConsumeRawAddressDeliversPayload` — `AddressCallback` payload bytes
  read directly from the address match producer-written bytes.
- `testConsumeRawAddressIsTightlyZeroAlloc` — `AddressCallback` allocates
  **< 80 B/record** (observed ≈ 67 B/rec); this is the irreducible Panama
  upcall floor — both APIs are intentionally exposed (user choice during
  brainstorming).

**Spec drift vs. spec §Infrastructure assumptions:** Spec assumed
6.4 B/record for the zero-alloc path. Actual floor is ~67 B/record due to
Panama upcall overhead. Two-tier API (SegmentCallback for ergonomics,
AddressCallback for the hot path) added per user decision; no functional
fallback triggered.

## 0b — User-ringbuf compiler-plugin emission

**Commit:** `939d57a` (refactor follow-up: `7213948`)
**Test:** `me.bechberger.ebpf.bpf.compiler.UserRingBufferCompilationTest` —
1/1 passing.

Assertions covered:
- Emitted C contains `BPF_MAP_TYPE_USER_RINGBUF`.
- Emitted C contains `__uint(max_entries, 4096)` (placeholder propagation).

`BPFUserRingBuffer<E>` skeleton + `MapTypeId.USER_RINGBUF(31)` wired through
the existing `@BPFMapClass(cTemplate=…)` dispatch — no separate emitter
class required. Follow-up commit `7213948` aligned the BPF-side stubs
(`reserve`/`submit`/`discard`) with the existing `@NotUsableInJava` +
`MethodIsBPFRelatedFunction` convention used by `BPFRingBuffer`.

**No spec drift.** No fallback triggered.

## 0c — Typed `BPFUserRingbufCallback<E, Ctx>` lowering

**Commit:** `44d6485` (docs follow-up: `609429a`)
**Test:** `me.bechberger.ebpf.bpf.compiler.BPFUserRingbufCallbackCompilationTest`
— 1/1 passing.

Assertions covered:
- Emitted C contains `bpf_user_ringbuf_drain`.
- Emitted C contains `bpf_dynptr_read` (thunk prologue).
- Emitted C contains `BPF_MAP_TYPE_USER_RINGBUF` (map declaration).

The plugin lowers `rb.drain((m, ctx) -> …, ctxPtr)` into:
1. A synthetic `static __always_inline int <name>(struct bpf_dynptr *,
   void *)` thunk.
2. A `bpf_dynptr_read(&rec, sizeof(rec), dynptr, 0, 0)` prologue.
3. The user lambda body inlined with the record-pointer in scope.

**Naming deviation vs. spec:** Spec called the placeholder
`$ringbufThunk:E`. Implementer used `$funcN:dynptr`, consistent with the
existing `$funcN:mapelem` precedent in `FuncShape`. Reviewed and approved
as an improvement — shares the same parser branch and `FuncShape` enum
machinery instead of inventing a one-off placeholder. Memory entry
`reference_method_template_language.md` and `FuncShape` enum-level
javadoc both updated to document the new shape.

**Behavioural note:** `bpf_dynptr_read` failure → thunk returns `1`,
which the libbpf ABI interprets as "stop drain". Therefore one malformed
record aborts the rest of the batch. There is no in-band skip-record
mechanism under the libbpf user-ringbuf callback contract; this is
documented on `BPFUserRingBuffer.drain`.

No fallback triggered.

## Gate decision

✅ **All three sub-tasks green.** Proceed to Step 1 (Task 1: full
`BPFUserRingBuffer<E>` Java implementation with `reserve` / `submit` /
`discard` / `submitNoWakeup`).
