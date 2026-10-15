# Outsourcing brief: the contract harness (host-side)

**What this is:** a self-contained work order. Your entire world for
this task is: this brief, the public repository it names, and the
data file `closure.txt` if provided alongside (public binary facts;
optional context, not needed to complete the work). Nothing else is
available to you, nothing else should be assumed. Write all code
independently; code and test comments describe what is covered,
matter-of-fact — no citations, no provenance notes, no references to
documents you were not given.

---

## 1. Background (all you need)

The repository is a from-scratch hobby OS kernel for 32-bit x86,
written in Rust (a no_std kernel; host-side unit tests run under the
normal toolchain). Among its subsystems is a compatibility layer
that implements a fixed surface of 51 classic Win32 API entry points
as **kernel-internal services**: a name-keyed registry in
`kernel/src/compat/kernel32.rs` (`SERVICES`), each entry carrying the
export name, an argument size, and a handler function. Real
console-application binaries built with an era toolchain import these
names; the kernel's loader resolves their import tables against this
surface, and the programs run.

The project's next phase moves these implementations **out of the
kernel and into a user-mode DLL with the same names and the same
observable behavior**. That migration has not started. Your task is
the host-side infrastructure that will make it measurable and
testable — not the migration itself.

## 2. The three deliverables

### D1 — the kernel-boundary abstraction (the "fake kernel")

A trait — host-test-side — that abstracts the kernel-side operations
the current service implementations perform: per-process state and
handle-table semantics (console std handles, file handles, event
objects), the heap regions the memory services manage, the tick
clock, the locale/codepage conversion tables, the termination and
thread-surface operations. Shape it so that a future user-mode
implementation of the 51 exports could be dropped onto a mock of this
boundary and exercised host-side, with the mock standing in for the
kernel.

- Name boundary operations after the **public API surface** they
  correspond to (`Nt*`- and Win32-style names are permitted and
  expected — they are the documented public interface; anything
  else is your own naming).
- Model the **operations the current 51 services actually perform**
  — not a general OS model. Do not invent machinery no current
  service touches.
- Every mock behavior must be grounded in something observable in
  the repository: the existing service implementation, or a
  checked-in fixture capture (see §3). When a behavior cannot be
  grounded, implement the minimum observable surface and record the
  gap in the ledger (D3) with status `unpinned` — never guess.

### D2 — the scenario dump (per API group)

Host tests expressing each export's behavioral contract: argument
validation order, return values, error returns, the callee-pops
(stdcall) argument-size discipline where the current surface pins
it. Tests are organized by **API group** and checked in **disabled
by default** (`#[ignore]`, each test cross-referencing the ledger
entry it belongs to). The point: the full corpus exists from day
one, and individual tests get switched on as implementations migrate
to the future DLL — the dump is the progress bar.

Initial groups, derived from the current surface in
`kernel/src/compat/kernel32.rs` (the `SERVICES` list is the seed; you
should not need any other source for the group membership):

| Group | Members (current surface) |
|---|---|
| termination | ExitProcess, TerminateProcess, GetCurrentProcess, UnhandledExceptionFilter, GetProcAddress, LoadLibraryA |
| command line / startup info | GetCommandLineA, GetStartupInfoA, GetModuleFileNameA, GetVersion |
| console handles | GetStdHandle, GetFileType, SetHandleCount, WriteFile, CloseHandle, FlushFileBuffers, GetLastError, SetFilePointer, SetStdHandle |
| environment | GetEnvironmentStrings, GetEnvironmentStringsW, FreeEnvironmentStringsA, FreeEnvironmentStringsW |
| heap | HeapAlloc, HeapCreate, HeapDestroy, HeapFree, HeapReAlloc |
| locale / string conversion | GetACP, GetOEMCP, GetCPInfo, MultiByteToWideChar, WideCharToMultiByte, LCMapStringA, LCMapStringW, GetStringTypeA, GetStringTypeW |
| threads / sync | CreateThread, CreateEventA, SetEvent, Sleep, WaitForSingleObject, GetTickCount, SetThreadPriority, SuspendThread, ResumeThread |
| file handles | CreateFileA, ReadFile |

Dump the groups whose behavior is already pinned (§3). The mechanism
must make adding future groups trivial — design for growth, and say
in a module comment how a new group joins.

### D3 — the enablement ledger and the report

A data file mapping the whole corpus — export → group → contract
status → test names → enabled — plus a small script that prints a
per-group progress report. Follow the repository's existing
data-driven-script precedent (`scripts/qemu-tests.yaml` and its
runner): the ledger is data, the report is a script, no build-system
logic. Proposed statuses: `pinned` (behavior fully defined from repo
sources), `dumped` (tests written), `enabled` (tests switched on),
`unpinned` (gap recorded, with a one-line reason). The report shows,
per group: contracts pinned, tests dumped, tests enabled, tests
passing, and the unpinned list.

## 3. The behavioral contracts source

- The **existing service implementations** in
  `kernel/src/compat/kernel32.rs` (and their helper modules — the
  user-mode heap, the codepage tables) are the behavior the future
  migration must reproduce. They are the primary contract source.
- The **checked-in fixture captures** under `tests/` — each fixture
  directory carries its captured real-machine output (`output.txt`)
  and its verified import list (`imports.txt`). Where a behavior is
  only observable on the serial line (a console write), the host
  contract models the service-level behavior, not the wire.

## 4. Acceptance

1. `cargo` host tests green, including the new harness and every
   dumped test (the `#[ignore]`d ones must at least compile and be
   listed; those that can pass against the boundary mock + existing
   implementations should pass when run explicitly).
2. The mechanism demonstrated end-to-end on **two groups**: one
   replay-valued group (e.g. command line / startup info) and one
   genuine-behavior group (e.g. heap) — dumped tests running against
   a boundary mock and the existing implementation path, passing.
3. The ledger report script runs and prints the per-group report
   from the data file alone.
4. `make check` and `make fmt-check` green (the repository's
   conventions; match the existing code style — module docs, comment
   density, test naming).
5. **The on-target suite is untouched and green** — this task is
   purely additive host-side machinery: no kernel behavior changes,
   no changes to the existing service implementations, no changes
   to existing tests, no build-pipeline changes beyond what the
   report script needs.

## 5. Out of scope

No DLL images, no loader or boot changes, no implementation of new
exports, no kernel-source modifications, no C code (the project is
Rust; C exists only as prebuilt test fixtures), no new external
dependencies unless a stated need is recorded in the delivery notes.

## 6. Working agreement

Deliver as a branch or patch for review — no direct commits to the
main line. The delivery notes should state: the layout you chose,
the boundary operation list with the service each one serves, the
unpinned list from the ledger, and anything in this brief that
proved wrong on contact with the sources. Expect a provenance review
before landing.
