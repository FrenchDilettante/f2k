# Delivery notes: the contract harness (host-side)

Branch `wip/dll-s1`, uncommitted. The harness itself is purely additive: its only change to an
existing file is the `#[cfg(test)] mod harness;` line in `kernel/src/compat/mod.rs`, and the kernel
ELF was byte-identical with and without it (sha256 `b5eda9ae1179f9d7…` both ways).

**Kernel change, made at the owner's request after delivery:** the two fixture conflicts below are
fixed in `kernel/src/compat/kernel32.rs`. This change is outside the brief's "no kernel behavior
changes" scope:
- `("HeapDestroy", 8, …)` → `("HeapDestroy", 4, …)`
- `svc_lc_map_string_w`: `LCMAP_LOWERCASE` = 0x100, `LCMAP_UPPERCASE` = 0x200 (were swapped)

## Layout

```
kernel/src/compat/harness/          (all #[cfg(test)])
  mod.rs            layout, how an export is switched on
  boundary.rs       D1: KernelBoundary trait, AddressSpace, boundary types
  fake.rs           D1: FakeKernel, the mock (+ its own unit tests)
  surface.rs        Surface trait, SIGNATURES (51 public prototypes), ExistingPath, Fixture
  groups/mod.rs     D2: GROUPS, partition + ledger-agreement checks, "how a new group joins"
  groups/{termination,startup,console,environment,heap,locale,threads,files,virtual_memory}.rs
scripts/kernel32-ledger.yaml        D3: the ledger (data)
scripts/kernel32-ledger.py          D3: the report (--check vs sources, --run for passing)
```

Run: `make run-tests`. Report: `.venv/bin/python scripts/kernel32-ledger.py [--check] [--run]`.

## How the existing implementation path runs host-side

- **Registry route.** The `SERVICES` handlers are called through a trap frame. They dereference
  32-bit user pointers directly, which a 64-bit host cannot map (on macOS the zero page covers
  the low 4 GiB). So every nonzero pointer argument is fenced into the kernel half first. A
  handler that reaches caller memory fails its probe and takes its own failure return. Validation
  order, return values and size queries run for real. Scenarios that need bytes moved fail
  cleanly; nothing crashes.
- **Heap route.** The real allocator core (`alloc_block` / `free_block` / `realloc_block`) runs
  over the heap region, committed through the boundary. The per-call composition around it is
  x86-only in `userheap`, so it is restated in `surface.rs`, along with the region constants.
  Those are `cfg(x86)` and can't be cross-checked on the host, so they could drift silently.
- **Target-only.** Handlers whose host build is a stub (scheduler, handle table, clock, exit,
  VirtualAlloc) panic with the reason.

The fake reuses the kernel's own machinery wherever it runs on the host:
- `HandleTable`
- `Waitable` signal states
- `OpenFiles` / `OpenFile::seek`
- FAT32 `lookup` / `read_at` over a crafted volume carrying the real `fileio.exe`
- the parameters page staged at the loader's offsets
- the shipped cp1252 tables

## Boundary operations → services

| Operation | Services |
|---|---|
| `memory` (host stand-in for the process's own address space) | everything touching caller memory |
| `nt_terminate_process` | ExitProcess |
| `process_parameters` | GetCommandLineA, GetModuleFileNameA, GetEnvironmentStringsW |
| `nt_allocate_virtual_memory` | HeapAlloc / HeapReAlloc (region commits), VirtualAlloc |
| `nt_close` | CloseHandle |
| `nt_create_event`, `nt_set_event` | CreateEventA, SetEvent |
| `nt_wait_for_single_object` | WaitForSingleObject |
| `nt_delay_execution` | Sleep |
| `nt_create_thread` | CreateThread |
| `nt_set_information_thread` (ThreadBasePriority) | SetThreadPriority |
| `nt_suspend_thread`, `nt_resume_thread` | SuspendThread, ResumeThread |
| `ke_query_tick_count`, `ke_query_time_increment` | GetTickCount |
| `nt_create_file`, `nt_read_file` | CreateFileA, ReadFile |
| `nt_query_information_file`, `nt_set_information_file` | SetFilePointer |
| `write_console` (own naming) | WriteFile on console handles |
| `ansi_code_page`, `oem_code_page`, `code_page_table` (own naming) | GetACP, GetOEMCP, GetCPInfo, MB↔WC, LCMapStringW, GetStringTypeW |

The other exports need no kernel: replayed constants, identities, success floors, never-called
floors. Refusal NTSTATUS codes are documented public values, but which one a refusal carries
is not observable through the surface: every service collapses failure to its own return.

## State of the corpus (`kernel32-ledger.py --check --run`)

51 exports, 9 groups. 42 contracts pinned, 9 unpinned. 107 scenarios dumped, 21 enabled, all
21 passing; 59 of the 107 already pass against the existing path when run with
`--include-ignored`. The two demonstration groups:
- **startup** (replay-valued): 6 of 9 enabled. The other 3 move bytes through caller memory, so
  they're target-only on this path.
- **heap** (genuine behavior): 15 of 15 enabled, after the HeapDestroy fix.

## Unpinned (from the ledger)

- termination/TerminateProcess, UnhandledExceptionFilter, GetProcAddress, LoadLibraryA,
  RtlUnwind: never-called floors.
- console/GetLastError: floor; no service sets a last error.
- console/SetStdHandle: never-called floor.
- locale/LCMapStringA, GetStringTypeA: never-called floors.

## Findings in the existing surface (both fixed afterwards, see the top)

Rule: the fixtures (real-machine binaries, traces, captured outputs) are ground truth. Where the
existing code disagrees with them, the code is wrong and the scenarios pin the fixture.

1. **HeapDestroy popped 8 bytes; its callers push 4.** The registry entry was
   `("HeapDestroy", 8, …)`. The public prototype takes one dword, and ret0's call site
   (`0x4019c1: push [_crtheap]; call [HeapDestroy]`, the CRT's heap-init failure path) pushes
   one. The `ret 8` would leave ESP 4 bytes off. The corpus never takes that path, so the
   on-target suite cannot see it. Pinned by `heap_destroy_pops_one_dword`, which reads the
   call site out of `ret0.exe`; enabled since the fix.
2. **LCMapStringW swapped the case flags.** The handler's `LCMAP_UPPERCASE` was 0x100 and
   `LCMAP_LOWERCASE` 0x200. `tests/hello/trace.txt` shows the CRT asking 0x100 for its lower
   case map and 0x200 for its upper one, so the handler is wrong. The C locale never uses those
   maps, so no output shows it. `lc_map_string_w_maps_case` pins the trace's direction; it stays
   disabled only because the existing path can't move bytes through caller memory on the host.
3. Quirks pinned as contract, worth a look: HeapReAlloc growth never commits (it fails where
   HeapAlloc of the same size succeeds); GetCPInfo refuses CP_OEMCP (1); WideCharToMultiByte
   never writes `lpUsedDefaultChar`; GetFileType reports a character device for every handle,
   files included.

## Where the brief proved wrong on contact with the sources

- **The group table covers 48 of the 51 exports.** RtlUnwind joined termination (with the
  other exception-handling floor). VirtualAlloc and VirtualFree became a new `virtual-memory`
  group, which also exercises the add-a-group path.
- **"No kernel-source modifications" vs. reaching the services.** `compat` is a private module,
  so host code that calls the existing implementations has to live inside the crate. That takes
  one `cfg(test)` module line. The kernel binary is unaffected (see the hash above).
- **"Dumped tests running against … the existing implementation path, passing."** This holds
  only where the handlers don't move bytes through caller memory (see the routes above). The
  startup group's success paths that do are disabled with that reason.
- **"Tests passing" can't come from the data file alone.** The report prints the table from the
  data file, and `--run` fills the passing column.
- **"The existing implementations are the primary contract source"** holds only where they agree
  with the fixtures. Where they conflict (findings 1 and 2), the fixtures win.

`closure.txt` was not used.
