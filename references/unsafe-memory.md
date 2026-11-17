# Pointer and Unsafe Memory Boundaries

## Scope and independent discovery

Ordinary Go pointers, taking addresses or dereferencing valid references are not
security defects. Discover actual escapes from Go's safety/ownership guarantees:
unsafe conversions/arithmetic, pointer-bearing reflection headers, native calls,
manual allocation, syscall/mmap buffers and custom zero-copy/serialization wrappers.
Names and unsafe imports are leads, not findings. Resolve wrappers and implementations.

Prioritize paths reachable from lower-trust lengths, offsets, indexes, buffers,
native handles or concurrent actions. If a dangerous pattern has no established
attacker reach, distinguish a correctness concern from an application vulnerability.

## Establish the violated invariant

For each relevant operation determine:

- Allocated region, actual size/capacity, alignment and object layout; where each
  length/offset comes from and whether overflow or narrowing defeats bounds checks.
- Pointer provenance and validity through conversions. uintptr is an integer, not
  a tracked reference; evaluate Go-version/platform rules rather than assuming any
  round-trip is valid or any occurrence necessarily invalid.
- Ownership and lifetime: Go GC, native allocation/free, mmap/unmap, buffer pools,
  asynchronous callbacks and aliasing. Identify the operation that releases/reuses
  memory and the later access. Do not infer use-after-free from naming alone.
- cgo/native contract, retention/pinning rules and the length/termination expected
  by the actual function. Do not assume either Go bounds checking protects C code
  or every native call is memory-unsafe.
- Whether zero-copy strings/slices can outlive their backing memory or be mutated
  contrary to the consumer's invariants. Prove the alias and relevant mutation.

Account for the actual build tags, architecture, Go/dependency version and native
ABI where material. A safety claim or defect contingent on one platform must name it.
An unavailable native implementation is an explicit contract limit, not permission
to invent an overflow or assume a safe implementation.

## Separate consequences

Distinguish out-of-bounds native/unsafe access, stale references, invalid ownership,
uninitialized/cross-request data exposure, and ordinary checked Go panics. A nil
dereference or checked bounds panic does not by itself establish arbitrary read/write.
For denial of service inspect recovery boundaries and process/worker impact; net/http
handler recovery and application recovery can change effects. Recovery does not
make data corruption or all concurrent/native failures recoverable.

Race-like code needs evidence of actual overlapping accesses and a broken invariant;
not every race is memory corruption or exploitable. Do not claim RCE from the mere
presence of unsafe or a crash. Report demonstrated effect separately from conjecture.

## Evidence and validation

A finding needs the reachable input/action, pointer/buffer flow, exact failed bounds
or lifetime invariant, unsafe/native operation and supported consequence. Relevant
guards, conversion checks and ownership mechanisms must be accounted for. Missing
reachability, native contract or timing assumptions remain named candidates.

Recommend the narrow repair: safe indexed/copied representations, checked arithmetic
and lengths, correct ownership/lifetime, explicit synchronization or valid native
contracts. runtime.KeepAlive, pinning or one extra check is not a universal repair;
it cannot fix unrelated size errors, premature native free or invalid pointer rules.

Static review is the default. Race/checkptr/native sanitizers or a crash fixture may
assist authorized isolated testing, but passing diagnostics does not prove safety
and failures do not automatically prove exploitability. Do not compile/run repository
or native code, mutate target memory or attempt exploitation without authorization.
