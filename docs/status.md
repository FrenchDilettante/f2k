# wip/rearch: status

Snapshot: 2026-10-19. Branch `wip/rearch` at C1, 17 commits over master (`b23f63e`), one per
increment of the rebuild; 326 files, +59.7k/−11.8k lines. The branch rebuilds `wip/tests` (the
reference, whose own status file this one is ported from) from master in vertical increments:
section 1 is what each increment built, and section 2's last decision is how.

**State at the time of writing:**

- **Host tests (`make run-tests`):** all passing, none ignored.
  - kernel: 773;
  - export generator: 16;
  - `rtl`: 94;
  - kernel32: 123.
- **Ledger (`uv run scripts/ledger.py --check --run`):** ok, with 91/91 host scenarios passing.
  - kernel32's 186 exports: 160 complete, 6 host-only, 5 partial, 3 unpinned, 10 forwarders and 2
    F2K-internal (the start thunks). None is served by the kernel.
  - ntdll's 94 exports: 87 complete, 1 partial and 6 unpinned.
  - Every partial export's one gap is `sched`'s yield block, which is still a pending entry in its
    `fixture.toml` (and deselected in every run; see section 4).
- **QEMU suite (`make check-all`, `sched[yield]` deselected):** 169 passed and 7 skipped.
  - The skips are the source-stamp checks, waiting for the Windows 2000 rebuild.
  - "kernel32 never enters the kernel itself" passes: kernel32's code holds no `int 2Eh`.
  - `sync[apc]` and `sched[boost]` fail now and then under heavy parallel load; they pass alone.
- **Repository checks in `tests/test_repository.py`:** no export is a kernel-served Win32 service
  or an unimplemented stub (and `kernel/src/compat` doesn't exist); 3 `current_mut()` call sites.

---

## 1. Work done

Master (`b23f63e`) had 51 kernel32 exports served by the kernel through 12-byte thunk stubs, a
kernel-mode heap, read-only FAT32, 30 YAML smokes over 13 small programs, and a host harness with a
fake kernel. Each increment below lifted the reference's final code for one subsystem, adapted its
seams to what existed so far, moved that subsystem's exports out of the kernel, switched on the
fixture blocks that pin it, and retired master's code nothing needed any more. Every increment ended
with `make check-all` green.

### A1. The test harness, at parity with master

- **The pytest harness** (`tests/f2kboot.py`, `conftest.py`) boots one QEMU per capture block on a
  snapshot disk and compares exactly.
  - Each fixture lives in `tests/<fixture>/` with its C source, the exe, the output captured on a
    real Windows 2000 machine, and a `fixture.toml`. The `fixture.toml` sets the gate, the strict
    pending blocks (each naming the increment that enables it), per-section masks and the timeout.
    Hand-made blocks live in `overrides.txt` and are merged by the parser.
  - **Captured fixtures:** bare, runtime, memory, threads, sync, sched, files and fswrite, plus the
    exit0, ret0 and hello smoke fixtures. All their blocks started pending: none loads on master.
  - **The teardown audit:** every one-process boot ends with the frame database and kernel heap
    audit. A block whose audit fails, which faults after its end, or whose audit never arrives
    fails.
  - **Failure reports** say why the boot stopped (done, exited, timeout, panic or ring-0 halt),
    with QEMU's stderr, which is also kept in the log.
  - **Builds:** one per feature set, lock-free once built; a failed build fails at once; build
    stamps let `--no-build` refuse a build whose features differ; QEMU exits with its parent; stale
    builds and logs are cleaned at session start.
- **Master's 30 YAML cases** became pytest kernel cases (`tests/kernel/test_kernel.py`), and the
  YAML runner went. The kernel command line selects the program from `\CORPUS` and becomes its
  command line, so programs are no longer chosen by build features.
- **The irq-smoke diagnostic** reads the PIC, the PIT, live ticks, the clock DPC and the interrupt
  audit from the hardware. The interrupt-flag asm became a compiler barrier.
- **`make check-all`** runs the host tests, the ledger (from A4b) and the QEMU suite.
  **`KERNEL_PROFILE=dev-opt`** builds the support crates optimized, with debug assertions and
  overflow checks kept.
- **The capture tooling** for the Windows 2000 machine, written but not yet run: `--list` and
  `--source` in each exe, `build.bat` stamping each exe with a source hash, `capture.bat` writing a
  provenance header and iterating over `--list`.

### A2. Kernel memory safety

- **The address-space manager (`mem::vm`) is the only writer of user page tables:** a 1024-region
  table, page states in the PTE (no-access and guard pages are non-present entries keeping their
  frame), reserve, commit, decommit, release, protect, query and guard planting. The loader, the
  system areas, child stacks and TEBs all go through it. Region kinds are metadata, not refusal
  policy.
- **Repository checks:** raw user-memory access only in the copy primitives; user page-table writes
  only in the address-space manager.
- **Folded in:** teardown frees committed non-present frames; GetModuleFileNameA reads the
  parameters through the user copy.

### A3. Objects and processes

- **The object manager** (`kernel/src/ob/`): global typed pools, objects named by
  generation-tagged ids (a stale id fails to resolve), pointer and handle counts with type hooks at
  handle count 0 (the name, file cleanup) and pointer count 0 (delete), references taken by handle,
  and waits holding references across APC and suspend replays.
- **Handle table entries** hold the object, the granted access and the inherit flag (1024 slots).
  Process exit closes every handle through the normal paths.
- **Processes:** a pool of 16 records, each live while its Process object lives (waitable, with an
  exit code, STILL_ACTIVE while it runs); the current process is the running thread's owner;
  disjoint borrows (`parts_mut`) replace aliased `current_mut()` uses (13 sites then, a ratchet);
  teardown in NT's order (close every handle, release the address space, audit the objects, signal
  the end, release the record); a link-time assert that the image fits its 8 MiB window.
- **The object audit** runs at every process end, and a leak fails the kernel case or fixture block.
- **Folded in:** a timer cancelled while waited on, and a replayed wait on a recycled thread record.

### A4a. Real system DLLs

- `userland/` is its own Cargo workspace: `rtl` (a `no_std` library, host-tested), `ntdll`, and
  `kernel32`, a library plus a binary so its logic runs in host tests. ntdll.dll sits at 0x77F80000
  and kernel32.dll at 0x7C4E0000, linked by `rust-lld` in MSVC mode with real headers, export
  directories and forwarders.
- **One export spec per DLL** (`userland/<dll>/exports.toml`) is the single source of truth: name,
  group, typed arguments (the argument bytes derive from them), failure value, implementation, and
  the fixture blocks and host scenarios pinning it. `tools/exportgen` generates the kernel's tables
  and the DLLs' stubs and `.def` files.
- Both DLLs are embedded in the kernel and mapped into every process. A module table backs
  GetProcAddress and import resolution, which walk the real export directories (read from the
  headers alone: parsing a whole image on a gate stack hung every thread-creating boot).
- Master's served exports kept working through generated stubs onto master's own handlers; the
  thunk page went.

### A4b. The NT gate, the ledger and the stubs

- **Only ntdll enters the kernel, by Windows 2000's numbers:** ntdll's `Nt*`/`Zw*` stubs raise
  `int 2Eh` with the service numbers from the public table (`userland/ntdll/w2k-services.txt`), and
  the kernel's NT layer (`kernel/src/nt/`) has typed handlers answering an NTSTATUS. NtClose came
  first, over the object manager.
- **The copy fixup:** a fault inside the kernel's user copy fails the copy with
  STATUS_ACCESS_VIOLATION; a bad argument-block pointer still ends the process.
- **Win32 errors** come from ntdll's `RtlNtStatusToDosError` (`rtl::status`, from Wine's table)
  plus kernel32's own special cases, as on Windows 2000.
- **Every kernel32 export the fixtures import was listed** (184), so every fixture loads: master's
  served ones, nine assembly natives, RtlUnwind forwarded, and 126 unimplemented stubs failing with
  ERROR_CALL_NOT_IMPLEMENTED, each naming the increment that would build it.
- **The ledger** (`scripts/ledger.py`) computes each export's status from its evidence instead of a
  hand-kept list, and `--run` fails on any ignored scenario that starts passing. The fake-kernel
  harness and the YAML ledger went.
- **Repository checks:** kernel32 imports only NTDLL; its code holds no `int 2Eh` (a strict expected
  failure until B10); ratchets on the served and the unimplemented exports.

### B1. Console and process start-up

- **Windows 2000's TEB and PEB:** the self pointer, ClientId, the stack fields, the end-of-chain
  marker; the PEB's image base, process parameters, version fields (5.0.2195, service pack 4, the
  image's subsystem) and CSDVersion.
- **A real RTL_USER_PROCESS_PARAMETERS** at PEB+0x10, with the std handles, the Unicode command
  line, the image path and the captured startup values. The PEB and the parameters are the source
  of truth, not mirrors.
- **The console goes through a CSR stand-in:** kernel32 recognizes console pseudo-handles and calls
  ntdll's CsrClientCallServer, one internal service to a console server in the kernel (`csr.rs`),
  with per-process console handles.
- **kernel32's own code:** the std handles, the console code pages and mode, WriteConsoleA, the
  command line, the startup info, the version calls, the console halves of WriteFile,
  FlushFileBuffers, GetFileType, CloseHandle and DuplicateHandle, TerminateProcess (the current
  process ends with the code; any other handle gives ERROR_INVALID_HANDLE), and the current process
  and thread ids.

### B2. Locale, time, messages and the last error

- **`rtl`'s code pages** (1252 with the captured character-type flags, 437, UTF-8, best fit) and
  time conversions, under kernel32's locale group (18 exports) and FormatMessageA.
- **KUSER_SHARED_DATA** at 0x7FFE0000, updated by the clock interrupt and mapped read-only into
  every process; GetTickCount and the clocks read it.
- **QueryPerformanceCounter** has sub-tick resolution: the PIT runs in mode 2, and QPC adds the
  8254's down-count since the last tick, clamped so it never goes back. Waits stamp interrupt time.
- **Folded in:** the hidden length caps in the NLS calls are gone; the W-side conventions;
  FormatMessageA's line-width byte; LOCALE_RETURN_NUMBER; WC_NO_BEST_FIT_CHARS and MB_USEGLYPHCHARS
  on code page 437; CompareString's last-level tie-break (position, then weight).

### B3. Exceptions

- **Dispatch runs in user mode, as on Windows 2000.**
  - **The kernel's share:** on a user fault, it writes the CONTEXT and the EXCEPTION_RECORD below the
    faulting stack pointer (checked arithmetic, so a fault with ESP near 0 ends the process instead
    of panicking the kernel), clears TF and DF, and enters ntdll's KiUserExceptionDispatcher, with
    real fault codes and parameters. NtContinue and NtRaiseException are its only other exception
    services.
  - **ntdll's share:** RtlDispatchException walks `fs:[0]` with the stack-limit and alignment
    checks, calling each handler under its own registration frame, so nested exceptions and collided
    unwinds work. RtlUnwind follows x86 NT. An exception nobody handles takes the second chance,
    which ends the process with its code. The walk is host-tested on 18 cases (`rtl::seh`).
  - **kernel32's share:** RaiseException over RtlRaiseException; the IsBad\* probes under their own
    frame; BaseProcessStartThunk and BaseProcessStart, so the main thread starts under kernel32's
    frame, which hands an unhandled exception to UnhandledExceptionFilter (the top-level filter).
- **Enabled** `bare`'s fifteen fault blocks and `runtime`'s unhandled block; master's crash fixture
  and fault-user case retired.

### B4. Virtual memory and sections

- **Frames carry holder counts.** Sections own their frames, every view of a mapping shares them,
  and copy-on-write is real: writable image sections and FILE_MAP_COPY views both get it, written
  on the page fault and in the kernel's copy.
- **The system DLLs' pages are made once at boot and shared by every process** (the reference
  copies them into every process), copy-on-write where a protection makes them writable.
- **Stacks follow NT's rule:** a 1 MiB main reservation, a guard below the committed pages, growth
  when a guard inside the TEB's stack range fires, STACK_OVERFLOW at the last page; child stacks are
  their own reservations. A guard page hit during a kernel copy grows the current thread's stack;
  any other guard is consumed and the call fails.
- **The NT virtual-memory and section services** (allocate, free, protect, query; create, open,
  map, unmap, the map-access check), NtQuerySystemInformation's basic, processor and performance
  classes, and kernel32's Virtual\*, GetSystemInfo, GlobalMemoryStatus and paging-file mappings.

### B5a. Synchronization

- **The NT synchronization services:** events, mutants and semaphores (create, open, set, reset,
  pulse, clear, release), the single, multiple and signal-and-wait waits, NtDuplicateObject
  (DUPLICATE_CLOSE_SOURCE closes the source on every outcome; with no target process it only
  closes the source), and NtOpenDirectoryObject. Mutexes recurse, sit on their owner's list and are
  abandoned at its end.
- **One global namespace** for every named kind, with `\BaseNamedObjects` a permanent directory
  object and `Global\` and `Local\` stripped. A name that exists with another type gives
  ERROR_INVALID_HANDLE; an existing name gives a handle plus ERROR_ALREADY_EXISTS.
- **Critical sections are entirely user-mode** (`rtl::critsec`), with Windows 2000's layout and
  protocol: LockCount −1 is free, updated with `lock xadd` and `cmpxchg`; the event is created
  lazily and waited on through NT services. The PEB lock is one.
- **TLS indexes** over the PEB's bitmaps; kernel32's synchronization, waits and DuplicateHandle
  (GetCurrentProcess() works as a source). The /MT fixtures start from here.

### B5b. Timers, sleeps and APCs

- **Waitable timers** (periods, APCs receiving the signal-time FILETIME, absolute due times counted
  from their distance to the wall clock, one clock for wait deadlines and timers), cancelled on
  delete and at their process's end.
- **User APCs** are delivered through ntdll's KiUserApcDispatcher, ending in NtContinue's test
  alert. NtQueueApcThread passes all three arguments.
- **Sleep, SleepEx, SwitchToThread, QueueUserAPC** and SetProcessAffinityMask; the irq-smoke
  diagnostic arms a waitable timer.
- **An interrupt window before a created thread is readied** (see section 4).

### B6. The heap, Local/Global and the environment

- **The heap is user-mode code in ntdll,** built from the host-tested allocator core: the header at
  the handle keeps NT's signature and flags at +0x08/+0x0C/+0x10, a critical section is the lock, it
  grows through NtAllocateVirtualMemory, corruption faults the process instead of hanging the
  machine, HEAP_GENERATE_EXCEPTIONS raises STATUS_NO_MEMORY, and HeapSize is exact after reuse. The
  PEB holds the heap list.
- **Heap\*** are forwarders to ntdll; HeapCreate, HeapDestroy and the 15 Local/Global exports are
  kernel32's over the heap.
- **The environment lives in user memory,** changed by ntdll's Rtl\*Environment\* under the PEB
  lock: sorted insert, in-place replace, and a block that moves to a new allocation when it grows.
  GetEnvironmentStringsW returns the live block, the A form an allocated copy.
- **A minimal LdrInitializeThunk** is delivered before a thread's first instruction and makes the
  process heap. Master's kernel heap retired.

### B7. Threads, thread and process start and exit, scheduling

- **Thread start and end, as Windows 2000 does them:**
  - CreateThread builds the stack and context in kernel32 (BaseCreateStack, BaseInitializeContext)
    and calls NtCreateThread (created suspended) and NtResumeThread; LdrInitializeThunk makes the
    PEB lock, the loader lock and the thread's implicit-TLS block, then continues into the start
    context.
  - The main thread starts at BaseProcessStartThunk (EAX the image's entry point), a child at
    BaseThreadStartThunk (EAX the start address, EBX the parameter). A return from the start routine
    goes to ExitThread.
  - ExitThread ends the process from the last thread, otherwise runs LdrShutdownThread (freeing the
    TLS block and the expansion slots) and terminates it. ExitProcess takes the PEB lock, terminates
    the other threads, runs LdrShutdownProcess, then ends the process.
- **The thread and process query and set services** (basic, priority, base priority, affinity,
  zero-TLS-cell, priority boost, am-I-last-thread; VM counters, hard-error mode, priority class,
  affinity); SuspendThread's errors map from their NT statuses.
- **The balance-set scan** (once a second) for starved threads; 64 child threads per process; a
  process's end waits for threads finishing a critical region.
- **Retired:** the internal thread-exit trampoline and services, and master's spin, suspend,
  respawn and thread smokes.

### B8. Files: objects and the read side

- **File objects:** one per open, with its position, granted rights, share mode, delete-on-close,
  directory search and a synchronous-I/O lock, so threads sharing a handle don't race. **File
  records:** a shared record per directory entry, like NT's FCB, with the size, the chain, the
  attributes and times, NT's share counts and delete-pending.
- **The read-side NT file services** (create and open with a root directory, read, query and set
  position, query directory, query attributes basic and full, query volume information);
  file-backed sections, whose section references the file object, so a mapped file refuses delete
  and truncation (error 1224).
- **ntdll's paths and current directory:** RtlDosPathNameToNtPathName_U, RtlGetFullPathName_U, and
  the current directory as a real handle opened at a process's start, under the PEB lock.
- **kernel32's read-side file calls,** the Find\* functions as heap structures, GetFileType's device
  query; file handles can be duplicated. Master's per-process open-file table and fileio smoke
  retired.
- **Outer critical regions around the file and section services,** and 8-page gate stacks (see
  section 4).

### B9. Files: the FAT32 write side

- **IDE PIO data-out,** with the 400 ns settle after the command; the IDE simulation models
  data-out timing.
- **The FAT32 write layer:** every FAT copy, cluster allocation, extend and truncate (growth all or
  nothing on a full disk; a shrink writes the size before trimming the chain), long names with
  generated aliases in code page 437 and the NT case bits (a valid 8.3 name in mixed case is its own
  short name), create, delete, rename, move, mkdir and rmdir, attributes and times, and the dirty
  mark in every FAT copy at the first change after mount. A corrupt directory entry fails the call
  instead of panicking the kernel.
- **The write-side NT services:** NtWriteFile, NtFlushBuffersFile, NtSetInformationFile's basic,
  rename, disposition, allocation and end-of-file classes, NtCreateFile's creating and overwriting
  dispositions, and deletion at the last cleanup (a delete-pending file refuses new opens).
- **kernel32's write calls:** DeleteFile as an open for delete plus the disposition; CopyFile as a
  user-mode loop (onto the source's own entry under another spelling it fails with
  ERROR_SHARING_VIOLATION); WriteFile on a directory fails with ERROR_INVALID_FUNCTION and zeroes
  its count before any failure; overlapped requests run at the OVERLAPPED's offset and complete at
  once.

### B10. Modules

- **The PEB's module lists** (PEB+0x0C) are Windows 2000's PEB_LDR_DATA and LDR_DATA_TABLE_ENTRYs
  for the exe, ntdll and kernel32, in load, memory and initialization order, built by the kernel at
  process creation, since the loader still runs in the kernel.
- **ntdll's loader calls** (LdrGetDllHandle, LdrLoadDll, LdrUnloadDll, LdrGetProcedureAddress over
  `rtl::modules`) under the loader lock, and kernel32's GetModuleHandleA, LoadLibraryA, FreeLibrary,
  GetProcAddress and GetModuleFileNameA over them.
- The last served exports and the last unimplemented stub went: from here kernel32's code holds no
  `int 2Eh`, and the repository check passes.

### C1. The Win32 layer goes

- `kernel/src/compat` (the empty service registry and the old host harness) is deleted. The gate
  serves ntdll's system services and the console's client-server call; any other number gets
  STATUS_INVALID_SYSTEM_SERVICE, as the empty Win32 range already answered.
- `tools/exportgen` reads only the `syscall`, `native` and `forward` kinds (and the `internal`
  flag); the Win32 registry, its stubs and the harness outputs are gone, and so are the `legacy`,
  `floor` and `unimplemented` kinds.
- The ledger's kernel-harness suite is gone; kernel32's scenarios remain.
- One repository check, that no export is a kernel-served Win32 service or a stub and that
  `kernel/src/compat` doesn't exist, replaces the served and unimplemented ratchets.

---

## 2. Architectural decisions

1. **Mirror Windows 2000's layering.** The goal is binary compatibility, so what programs can see
   follows Windows 2000. That covers the exports, structures read directly, fixed addresses, return
   values, last errors and lifetimes. Internals are F2K's choice.
   - **The split:** kernel32 is user-mode code that imports only ntdll. Only ntdll's stubs enter the
     kernel, and the kernel speaks NT: handles, object attributes, I/O status blocks, 100 ns
     timeouts and NTSTATUS.
   - **Windows 2000's own service numbers** are used, from the public table until the machine's
     ntdll is disassembled.
   - **NTSTATUS only from the kernel.** Win32 errors come from the status table plus kernel32's
     special cases. The fixtures are the check.
   - **The kernel has no Win32 layer.** `kernel/src/compat` is gone.
2. **Real system DLLs, built from Rust.**
   - `userland/` is its own workspace for everything that runs in ring 3.
   - Each DLL owns its export spec, and the kernel only reads it.
   - Directory names carry no `.dll`.
   - The DLLs are embedded in the kernel until the disk image carries `C:\WINNT\system32`.
3. **One spec per DLL generates everything,** and the ledger is derived from tests.
   - Gaps are expected-failure tests: strict pending fixture blocks, or ignored host scenarios.
   - Only gaps no test can show are listed as text, in this file.
4. **A global object manager with fixed pools,** NT's counts, and generation-tagged ids.
   - Files split into a per-open object and a shared per-file record.
   - Sections reference their file.
   - One namespace, with `\BaseNamedObjects` as a directory object.
5. **The process record holds only what EPROCESS holds.**
   - User-mode state lives in user memory and is changed by user code: the environment, the current
     directory, TLS, the heaps, and later the loader.
   - The PEB and process parameters are the source of truth, not mirrors.
6. **One rule for user memory.**
   - The kernel touches it only through the fault-tolerant copy.
   - Only the address-space manager writes user page tables.
   - The kernel's own failure mode is a failed call, never a halt.
7. **The heap and critical sections are user-mode, in ntdll.**
   - Critical sections use Windows 2000's layout and protocol.
   - The heap keeps NT's header fields at their offsets. Its internal layout is F2K's own.
8. **Exception dispatch runs in user mode** (built ahead of the `seh` capture, its guesses listed in
   section 5).
   - The kernel writes the records and redirects to ntdll's dispatcher. The walk, unwind and raise
     run on the real stack with Windows 2000's semantics.
   - The kernel keeps only NtContinue and NtRaiseException.
   - kernel32's BaseProcessStart and BaseThreadStart frames start every thread.
9. **NT's address layout,** from NT's creation order and calibrated by the `layout` capture
   (agreed, waiting for the capture: the one architecture step not built ahead of it). The PEB goes
   to 0x7FFDF000 and the TEBs below it.
10. **The console goes through a CSR stand-in.** kernel32 recognizes console pseudo-handles and
    calls `CsrClientCallServer`, which is one internal service to a console server in the kernel.
    Console handles are per-process console objects, not kernel file objects.
11. **The code-page tables are embedded** in the DLLs and the kernel, not mapped from the `.nls`
    files.
12. **The system DLLs have no writable sections, and DllMain isn't called.** Per-process DLL state
    lives on the PEB page, created lazily on first use under the PEB lock (the named-objects handle
    at PEB+0x880, the console input event at 0x8C0, the narrow command line and the startup info at
    0x8A0/0x8A4, the loader lock at 0x900).
13. **Built ahead of the captures, with every guess flagged.** The architecture work was finished
    against Windows 2000's documented behaviour (MSDN, *Inside Windows 2000*, Pietrek's SEH article,
    Wine and ReactOS read as references) before the next capture session. Each guess is in
    section 5; a capture that disagrees becomes a strict pending test.
14. **The fixtures are ground truth.** Where no capture shows Windows 2000's behaviour, the code
    keeps F2K's earlier behaviour or the documented one, and lists it under section 5. Captures are
    C only; C++ exception handling is deferred.
15. **Work is staged and verified per increment.**
    - Each increment merges only after the host tests, the ledger and the QEMU suite pass.
    - Ratchets only go down.
16. **The branch was rebuilt from master in vertical increments.** The reference's git history
    passed through designs it later replaced (a kernel Win32 layer that grew to 164 services and
    shrank to none, a kernel-mode heap, a kernel exception walk, a fake-kernel harness, a YAML
    ledger, F2K-internal start, exit and APC services). The rebuild built its end state directly,
    as one squashed commit per increment, each a slice through one subsystem (its NT services, ntdll
    and `rtl` code, kernel32's exports, and the fixture blocks that pin them):
    - **Keep only what's needed to build and run, and retire as you go.** Master's served exports
      were the only transitional layer, kept only where a fixture still needed them; each increment
      moved its group to user code and deleted the kernel half in the same commit. Master code
      nothing needed went at once: the YAML runner in A1, the thunk page in A4a, the kernel heap in
      B6. C1 was left with only what the last increments had emptied.
    - **Cheap fixes as you go, notes for the larger work.** A fix that fit its increment's code, and
      had a test, landed in it; larger work is listed in section 4 and section 6.
    - **One commit per increment,** named for it, listing what it built, enabled, retired and folded
      in.
    - **Every export the fixtures import existed from A4b on,** as unimplemented stubs where not yet
      built (no fixture could load on master: the loader stops at the first missing import). The
      stubs and the served exports were ratchets that only went down, to zero at B10.
    - **The DLL increment was split in two** (A4a, the real DLLs; A4b, the spec, the NT gate and
      the stubs), and master's served exports went through generated stubs onto master's own
      handlers: the reference's typed Win32 service layer was never rebuilt.

---

## 3. Known gaps

These are the simplifications taken on purpose, and the gaps no test can show yet. A gap a fixture
or host scenario can show is an expected-failure test instead (see decision 3).

### Processes and threads

- **There's no CreateProcess:**
  - no child processes, handle inheritance or STARTUPINFO std handles;
  - no DuplicateHandle into another process, and no waiting on a child.

  What is still single-process:
  - **Thread records** are global, and a record's index places its TEB, TLS and stack, with record
    0 the main thread's. The ordinals must become per-process.
  - **The object sweep** at process end takes every object as the ending process's.
  - **The loader** maps images only into the current address space.
  - **The kernel's attachment** handles one process at a time.
- **Limits:**
  - The process pool is fixed at 16 records, in the kernel image. The image must fit its 8 MiB
    window, and about 2 MiB is left in the dev build; a link-time assert guards it.
  - Threads are capped at 64 per process.
- **Aliased process access:** `current_mut()` still hands out `&'static mut Process` at 3 call
  sites. That is undefined behaviour in Rust terms until the ratchet reaches 0.

### Objects

- **Fixed capacities:**
  - the handle table has 1024 slots;
  - 128 file objects and 128 file records;
  - the other object pools.

  Running out is a program-visible failure, error 1450, at limits Windows doesn't have.
- **Access masks** are stored, but mostly not checked on synchronization objects. Section map
  access is checked.
- **No security or sessions:** SECURITY_ATTRIBUTES are ignored except bInheritHandle, and there are
  no tokens, ACLs or quotas. There is one session, with `Global\` and `Local\` sharing the
  namespace.
- **Object names** are kept as code page 1252 bytes. Other characters give
  STATUS_OBJECT_NAME_INVALID, and no W-form object call is exported yet.

### Memory and layout

- **The system areas are still at F2K's fixed low addresses** until the `layout` capture:
  - the main stack at 0x201000–0x301000;
  - the first TEB at 0x310000;
  - the process parameters at 0x320000 and the PEB at 0x330000;
  - child TEBs, TLS and child stacks above.

  Images whose preferred base lands there are refused. Only KUSER_SHARED_DATA is at its NT address.
- **File views aren't coherent with ReadFile/WriteFile.** There's no cache manager: a view is
  filled from the file when first touched and never written back.
- **Section limits:**
  - a section names at most 256 MiB of frames;
  - data sections only (no SEC_IMAGE);
  - only read-only, read-write and write-copy protections;
  - a read-write section larger than its file is refused, where Windows 2000 extends the file;
  - no execute views.
- **Virtual-memory limits:** releases are whole reservations only, ZeroBits is ignored, and the
  region table is fixed at 1024 entries.

### The heap

- **Internal layout:** past the NT header fields, the heap's layout (segments, block headers, free
  lists) is F2K's own. Code walking raw heap structures sees differences.
- **Fixed sizes:**
  - RtlCreateHeap takes no caller-supplied base, lock or parameters;
  - a process holds at most 16 heaps;
  - the process heap is a fixed 32 MiB growable heap, not sized from the image header.
- **Thread termination:** a thread ended by TerminateThread keeps its TLS block on the heap, as on
  Windows 2000 (ExitThread frees it).
- **Start-up failure:** a process heap or TLS block that can't be made is left null, and the program
  runs on. Windows 2000 fails the start with STATUS_NO_MEMORY.

### Exceptions and the loader

- **CONTEXT:** the debug-register and floating-point sets are neither filled nor restored, and a
  CONTEXT's segment registers are ignored.
- **A thread with an empty exception chain,** or a process without the system DLLs (the kernel's
  own fault-test processes), still ends in the kernel without entering the user dispatcher.
- **Exception records:** stack-overflow records carry no parameters, `INT_MIN / -1` reports a divide
  error, and x87 faults are always invalid-operation.
- **C++ exception handling (`__CxxFrameHandler`) is unverified.** It needs a Visual Studio 6 `/GX`
  fixture.
- **No debugger:** no first or second chance to a debug port, and no AeDebug; the second chance
  always terminates.
- **The loader:**
  - Mapping images and snapping imports still run in the kernel, which also builds the PEB's module
    lists; on Windows 2000 that is ntdll's LdrpInitialize, in user mode.
  - The system DLLs' DllMain isn't called (their entries' EntryPoint is 0), and LdrShutdownThread
    and LdrShutdownProcess run no DllMain or TLS callbacks.
  - No DLL loads from disk: LdrLoadDll finds only the exe, ntdll and kernel32. No relocations,
    recursive imports or TLS callbacks for other DLLs; the exe's own TLS callbacks don't run, and
    its entry's TlsIndex is 0.
  - The module lists have no hash table, and ordinals find nothing.
- **Thread and process start and exit:**
  - no CSR (basesrv) notification on thread creation or process exit;
  - the thread's Win32 start address isn't recorded;
  - a dead thread's stack is released only when its record is reused;
  - stack sizes ignore the image header (a 1 MiB reservation, 2 pages committed plus a guard);
  - ExitThread and ExitProcess have no host tests, since they never return; the fixtures pin them.
- **Critical sections:**
  - they never spin (F2K runs on one processor, where nothing differs);
  - DebugInfo stays NULL;
  - there's no possible-deadlock status after a long wait.

### Exports

- **Ordinals:** no export carries Windows 2000's ordinal yet; they are sequential, so an import by
  ordinal resolves wrongly.
- **Missing exports:** only the exports the corpus imports are listed (the unimplemented stubs are
  gone with the Win32 layer), so a program importing a function F2K lacks fails to load. ntdll's
  `Nt*` exports are added as needed: Windows 2000 has 248.
- **Argument bytes** come from hand-typed prototypes, not yet checked against the SDK's decorated
  names.
- **Other DLLs:** only kernel32 and ntdll exist (no user32, gdi32 or msvcrt).
- **Host coverage:** services that run on kernel state (the scheduler, the handle table, the
  volume, the live address space, process exit) have no host scenarios. The fixtures pin them.

### The NT layer

- **Service numbers** are Windows 2000's from a public table (the same in service packs 0 through
  4), not yet checked against the capture machine's ntdll.
- **The status table** comes from Wine, generated from a later Windows. A status whose mapping
  changed after Windows 2000 maps the later way.
- **The service gate compares EAX whole,** where Windows 2000 masks the table index and service
  number. F2K's one internal service (0x8000_0010, the console's CSR call) answers a number Windows
  2000 would refuse.
- **System, process and thread queries:** NtQuerySystemInformation answers only the basic,
  processor, performance and time-zone classes; NtQueryInformationProcess the basic, VM-counter,
  hard-error-mode and priority-class ones; NtQueryInformationThread the basic, priority-boost and
  am-I-last-thread ones. Peak counters read as current, and a process's parent id is 0.
- **Priorities:** no realtime-class base priorities beyond ±2, and no privilege check for the
  realtime class.
- **File I/O always completes at once,** overlapped included: an APC completion routine is
  STATUS_NOT_IMPLEMENTED, and there are no completion ports.
- **No csrss:** the console server is a kernel stand-in (no process, no capture buffers; the
  server reads the client's memory in place).
  - GetSystemInfo and GlobalMemoryStatus query the kernel on each call;
  - GetDriveTypeA skips the drive-letter map and opens the volume.
- **The console:** no keyboard input (reads end at once, and the input event never fires); console
  handles' inherit flag and access aren't tracked; at most 32 console handles per process.
- **NLS:** the code-page tables are compiled in, and the PEB's code-page pointers stay null.
- **GetFileInformationByHandle** has no file name, because the kernel keeps no open's name.

### Files and devices

- **FSInfo** is never updated: its free count and next-free hint go stale.
- **Disk cache:** FlushFileBuffers sends no cache flush to the disk. Writes go straight through.
- **Aliases** run `~1` to `~999999` with a shrinking basis, without Windows' hash form.
- **Dirty bit:** a volume F2K has written stays marked dirty. Nothing marks it clean, because
  there's no unmount.
- **Crash consistency:** a shrink is ordered, but there is no general crash-consistency care. Crash
  points are not something a fixture can capture.
- **Timestamps:** the volume keeps local time, and with no time zone, local time is UTC.

---

## 4. Known issues

These are bugs and open findings, not deliberate simplifications.

### Carried from the reference

1. **`sched[yield]` is flaky.** It's deselected in every run, and on this branch its block is still
   a pending entry in `tests/sched/fixture.toml` (the reference has none), which is why five
   kernel32 exports and NtYieldExecution report as partial in the ledger.
   - **On the reference:** it failed about 3 in 144 under heavy load, on the `Sleep(10)` line, where
     thread start-up races the 10 ms sleep; the boost variant about 2 in 72, when a quantum ends
     between CreateThread and the creator's next step.
   - **Ways out:** modelling Windows 2000's foreground quantum stretching (18 units) seemed to remove
     the boost failures, but not the `Sleep(10)` one; under `-icount shift=auto` it failed 0 times in
     192, even at load averages of 15–60; an xdist group could keep the timing fixtures from sharing
     CPUs.
2. **The kernel crate is unsound under optimization.**
   - **The cause:** its intrusive lists are rewritten through raw pointers while a `&mut` borrow of
     their owner is live.
   - **The symptom:** at any opt-level of 1 or more, LLVM keeps a stale bucket head in the timer
     table and the first `Sleep` never returns.
   - **Scope:** the pattern runs through `sched`, and the release profile very likely has it too
     (unchecked). It is undefined behaviour in the dev build as well, just not exploited there.
   - **The fix** is a refactor: it blocks optimizing the kernel crate itself.
3. **A lost wakeup in critical sections or the event wait.** On the reference, `sync[critsec]`
   (4 threads × 100000 increments) hangs 1–2 times in 10 on the dev-opt build, with one waiter never
   woken, and passes 10/10 on dev. The rebuild lifted the same code and didn't re-measure it. This
   is what blocks making dev-opt the default.
4. **File reads are slower since the files moved into kernel32.** Each small read runs kernel32's
   ReadFile, NtReadFile and the synchronous-I/O lock, unoptimized. On the reference, `files[read]`
   went from 12–14 s to about 23 s; it has a 40 s budget, like `fswrite`. It is unprofiled: profile
   it before a budget grows again.
5. **Open review findings, waiting for their packages:**
   - **Memory:**
     - MEM_RESET alone is refused while MEM_RESET|MEM_COMMIT succeeds (inverted);
     - VirtualProtect can raise a view above its mapping's access;
     - PAGE_WRITECOPY is accepted on private memory, where NT returns 87;
     - PAGE_NOCACHE is dropped from reported protections;
     - a commit that runs out of frames halfway leaves the pages it already committed.
   - **Files:**
     - writes never set the ARCHIVE bit, and a time the program set is overwritten by later writes;
     - a case-only rename fails with ERROR_ALREADY_EXISTS.
   - **Runtime:**
     - the PEB's NumberOfProcessors is 0, where Windows 2000 has 1, and the critical sections read
       it;
     - the PEB's ImageProcessAffinityMask and the Win32VersionValue override are unfilled;
     - best fit covers only Latin Extended-A, so À has no code page 437 best fit and becomes `_`.
6. **kernel32 stack frames must stay under 4 KiB.** A larger frame doesn't link: the stack probe
   resolves to an undefined symbol.
7. **New capture probes can't be marked pending.** A pending entry must name a block already in the
   capture, so the probes added to `fswrite`, `files` and `runtime` show only after the next
   recapture. Either the recapture lands them, or the harness gets a way to declare probes awaiting
   capture.
8. **`make fmt-check` fails on about 120 files,** nearly all of them from before this work (the
   export generator alone is clean). A one-off reformat would make it a usable check.
9. **A plain `cargo check` in `kernel/` fails** until `make userland` has run once, because the
   kernel's build script reads the DLLs. This affects rust-analyzer too.
10. **Leftover masks and stubs:**
    - the `threads` fixture keeps a mask for an argument-evaluation-order quirk in the captured
      binary;
    - a few kernel cases still rely on fault stubs built into the kernel behind features; they call
      NT services by number (one builds a thread with raw NtCreateThread, since stub processes have
      no kernel32).
11. **Heavy parallel load causes timeouts and timing failures:** several builds and boots at once
    make the timing blocks and the process suites fail or time out. They pass when rerun alone.

### Changed or found by the rebuild

12. **The object audit fails tests.** A process whose objects or file records outlive it prints an
    object-audit failure line, and the harness fails the block or kernel case on it (the
    reference's harness only judges the teardown audit). So a reference leak anywhere in a fixture's
    run is a test failure here.
13. **Outer critical regions around the file and section services.** A deferred termination can't
    end a thread while it holds a file or section reference mid-service; the reference leaks the
    reference there, which the stricter audit would catch.
14. **An interrupt window before a created thread is readied.** NtCreateThread opens the interrupt
    window before making the new thread ready, so a pending tick or preemption lands first;
    `sync[apc]` failed 1 in 3 without it.
15. **Gate stacks are 8 pages (32 KiB),** as on the reference, raised when every process started
    opening its current directory at start-up, on the gate stack.
16. **The system DLLs' pages are shared, not copied.** They are made once at boot and every process
    maps the same frames, copy-on-write where a protection makes them writable; the reference
    copies them into each process.
17. **GetModuleHandleA matches a path the way Windows 2000 does:** a name with a path is made
    absolute against the current directory and compared case-insensitively with the module's full
    path (no DLL search path, no existence check), and a trailing dot means no extension. Built
    ahead of the `runtime` recapture (see section 5).
18. **Flakes to watch:** `sync[apc]` (the thread-creation race above) and `sched[boost]` fail now and
    then under load and pass alone; `sched[yield]` is always deselected.
19. **Thread creation costs a few milliseconds** (4–11 ms on dev-opt), mostly the region table's
    full scans when a child's stack and TEB are reserved (`AddressSpace::free_range`, `overlaps`,
    `insert`). With 64 child threads per process that matters; it is a candidate for the memory
    package.

---

## 5. Assumptions that need verification on Windows 2000

Each of these was recorded where it was made, and is pinned so far by host tests or by F2K's
earlier behaviour, not by a capture. The next capture session should turn as many as possible into
captured blocks; any block that disagrees becomes a strict pending entry.

### System DLLs and the NT layer

- **ntdll:**
  - the stubs' service numbers;
  - that ntdll exports the PEB-lock, current-directory, environment, RtlRaiseStatus and path
    functions under these names;
  - kernel32's forwarders, among them HeapFree and HeapValidate.
- **Statuses and errors:**
  - the status table, for example STATUS_TIMEOUT → 1460;
  - NLS, environment and name calls with bad pointers fault in the caller, instead of returning
    ERROR_NOACCESS;
  - exhausting the handle table or an object pool gives 1450.
- **kernel32's own code:**
  - kernel32 opens `\BaseNamedObjects` with access 0x2000F and case-insensitively;
  - ResetEvent calls NtClearEvent;
  - an empty name gives an unnamed object on create, and ERROR_INVALID_PARAMETER on open;
  - `CreateEvent("a\\b")` gives ERROR_PATH_NOT_FOUND;
  - the order NtSetTimer and NtReleaseSemaphore check their arguments in;
  - the share and access modes kernel32 uses for its internal opens, and for the current
    directory's handle (the directory can't be deleted while current).
- **System queries:**
  - the info-class length checks;
  - SYSTEM_BASIC_INFORMATION's lowest physical page 1 and timer resolution 100144;
  - GlobalMemoryStatus's memory-load formula (F2K's kept).

### Memory

- **Placement:** VirtualAlloc(NULL) takes the lowest free 64 KiB range, and MEM_TOP_DOWN is
  ignored. A reserve-and-commit with an address commits the whole reservation from its base.
- **Error codes:**
  - VirtualFree on a view or the image gives 487 (Windows 2000 may say 87);
  - decommit past a region's end gives 487;
  - CreateFileMapping on a directory handle gives 6 (maybe 193);
  - running out of frames during a commit gives 8 (likely 1455);
  - VirtualQuery at or above 0x7FFF0000 gives 87.
- **File mappings:**
  - MapViewOfFile with no access bits gives a no-access view;
  - a write view through a read-only mapping handle gives 5, and through a write handle on a
    read-only section 87;
  - unmapping by an address inside a view succeeds;
  - a written write-copy page reports read-write.
- **Guard pages:**
  - a guard consumed during a kernel copy fails the call (the exact error is unconfirmed);
  - an IsBad probe on a non-stack guard consumes it and answers TRUE.
- **The PEB and process parameters:**
  - whether VirtualProtect and VirtualFree on the PEB succeed;
  - the TLS expansion bitmap at PEB+0x150/0x154;
  - the RTL_USER_PROCESS_PARAMETERS header values;
  - MaximumNumberOfHeaps is 16 and the heap array follows the PEB.
- **The heap:**
  - the process heap's Flags are 0x2 and its ForceFlags 0;
  - an unknown heap handle fails quietly (NT would usually fault);
  - HeapAlloc and HeapReAlloc failures leave the last error untouched;
  - HeapFree(NULL) and FreeEnvironmentStringsA(NULL) return TRUE;
  - HEAP_GENERATE_EXCEPTIONS raises 0xC0000017 with the size as its parameter.
- **TLS:** TlsGetValue without expansion slots returns 0 with last error 0; TlsSetValue fails with
  ERROR_NOT_ENOUGH_MEMORY when it can't allocate them.
- **Local/Global:** the moveable-handle layout (an 8-byte entry, handle = entry + 4, an 8-byte data
  prefix). LocalReAlloc may move a locked moveable block. LocalUnlock of an unlocked block gives
  ERROR_NOT_LOCKED.
- **Child stacks:** a 1 MiB default reservation rather than the image's SizeOfStackReserve; 2
  committed pages plus a guard; STACK_SIZE_PARAM_IS_A_RESERVATION rounds to 64 KiB, with a minimum
  of 3 pages.
- **Facts the captures don't print:** GetSystemInfo's processor type 586, level 6, revision 0 and
  active mask 1. The kernel keeps a 256-frame reserve that program allocations can't take.

### Objects and files

- **Names:** `Global\` and `Local\` share one namespace on Professional.
- **Waits:** a waiter keeps waiting when the last handle to its object closes.
- **Delete-pending:**
  - a reopen fails with ERROR_ACCESS_DENIED, and FindFirstFile still lists the file;
  - delete-on-close fails with ERROR_DIR_NOT_EMPTY on a non-empty directory, and with
    ERROR_ACCESS_DENIED on a read-only file;
  - NtQueryAttributesFile on a delete-pending file gives STATUS_DELETE_PENDING.
- **Mapped files:** DeleteFile fails with ERROR_ACCESS_DENIED; CREATE_ALWAYS and a shrinking
  SetEndOfFile fail with 1224; growing is allowed.
- **Rights and dispositions:**
  - SetFileTime denies FILE_WRITE_DATA alone and allows FILE_WRITE_ATTRIBUTES;
  - MAXIMUM_ALLOWED on a read-only file drops the write rights;
  - NtFlushBuffersFile needs write access;
  - a directory opened with a disposition other than open gives ACCESS_DENIED (FastFat may say
    collision);
  - SetEndOfFile on a directory gives 6.
- **Paths:**
  - GetFullPathNameA("") gives 3;
  - RtlGetFullPathName_U's too-small return counts the terminator;
  - a relative name is used only for relative paths;
  - GetCurrentDirectory("C:") gives "C:\CORPUS";
  - trailing dots and spaces are trimmed per path component (probes are in `files.c`).
- **Copy, create and write stamping:**
  - CopyFile ends with last error 0;
  - CopyFile keeps the source's last-write time and attributes (plus ARCHIVE), and stamps creation
    time now;
  - new files get ARCHIVE plus the settable attributes passed;
  - CREATE_ALWAYS on an existing file takes the requested attributes plus ARCHIVE, and refuses to
    drop HIDDEN or SYSTEM.
- **Short names** (probes are in `fswrite.c`'s `names` section):
  - Readme.txt → README.TXT, NOTES.Txt → NOTES.TXT, and "Readme file.txt" → README~1.TXT;
  - cAlternateFileName is set whenever a long name exists;
  - café.txt gets a long name (FastFat may judge case on ASCII letters only);
  - €uro.txt → `_URO~1.TXT`.
- **Volume:**
  - FastFat clears FAT[1]'s clean bit while changing a volume, and leaves the hard-error bit alone;
  - GetVolumeInformation's flags, and the FSInfo fallback;
  - GetVolumeInformationA without a trailing separator gives ERROR_INVALID_NAME;
  - GetDriveTypeA on a directory path answers FIXED;
  - the DOS wildcard rules.

### Scheduling and time

- **Timers:** a timer APC's arguments are the system time at the timer-expiry pass, not the due
  time; for a past-due set, the time of the set.
- **The clock:** the uniprocessor HAL programs the PIT in mode 2, and reads QPC from the latched
  count at 1193182 Hz.
- **Threads:** SuspendThread on a thread whose termination is deferred gives error 5. Windows 2000
  may succeed until the thread reaches its exit.
- **DuplicateHandle:**
  - it probes the target pointer first;
  - with a NULL target process it closes the source, or fails with ERROR_INVALID_PARAMETER without
    DUPLICATE_CLOSE_SOURCE;
  - F2K inserts the new handle before closing the source, which only shows when the table is full.
- **Constants and hand-set lines:**
  - the scheduler constants (balance set, SwitchToThread) follow NT 5.0's documented values;
  - `sched`'s "Sleep(10) does: yes" line was set by hand from a real-hardware run.
- **Real-time clock and time zone:** the RTC is read as UTC, the time-zone names are empty, and
  GetTimeZoneInformation's id is at KUSER_SHARED_DATA+0x240.

### Runtime surface

- **FormatMessageA:**
  - a failure leaves `*lpBuffer` NULL;
  - the allocated block is max(nSize, length+1);
  - MAX_WIDTH_MASK leaves a trailing blank;
  - widths 1–254 wrap at blanks (documented, not observed).
- **Locale:**
  - LOCALE_RETURN_NUMBER needs 2 units for W and 4 bytes for A;
  - a non-numeric type gives 1004;
  - the language id parses as hexadecimal;
  - EnumSystemLocalesA(NULL) gives ERROR_INVALID_PARAMETER.
- **Code pages:**
  - code page 437's glyph table, with 0x00 staying U+0000;
  - code page 850 is not convertible;
  - UTF-8 decoding details.
- **CompareString:** at the last level the apostrophe sorts before the hyphen, by position then
  weight.
- **Values from tables rather than captures:** the locale table values, the FormatMessage texts and
  the CompareString model's approximations.
- **Environment:**
  - the block stays sorted and moves when it grows;
  - a replaced variable takes the spelling of the last set;
  - an unset `%x%` keeps its closing `%`;
  - after an unset reference, F2K resumes past the whole `%UNSET%` (NT may resume after its first
    `%`);
  - deleting a missing variable succeeds.
- **Limits:**
  - RtlInitString refuses strings of 64K or more (Windows 2000 may truncate the length to 16 bits);
  - module names are capped at 260 characters, with error 206;
  - object names are capped at 260;
  - GetStdHandle's error is 6;
  - GetStringTypeW with a count of 0 returns TRUE.
- **Exceptions:**
  - UnhandledExceptionFilter defaults to EXECUTE_HANDLER;
  - int3's parameters are `[0, ecx, edx]`;
  - RaiseException's exception address falls inside its stub.
- **Captured quirks and hand-set values:**
  - LCMapStringA sets last error 122 on success, copied from the capture;
  - kernel32's base, 0x7C4E0000, was measured from the `hello` trace;
  - the entry ESP is the stack top − 8;
  - gate stacks are 32 KiB;
  - the `runtime` console block was predicted, then confirmed by hand, not captured.

### Critical sections

- **Failure statuses:** the status a low-memory enter or leave raises, and the preallocation failure
  status.
- **RtlDeleteCriticalSection's** effect on the other fields.
- **DebugInfo** is non-NULL on Windows 2000.

### Exception dispatch (the `seh` capture)

- **Entry and flags:** a #DB CONTEXT has TF clear; the dispatcher and filters run with TF and DF
  clear while the CONTEXT keeps DF as interrupted; at KiUserExceptionDispatcher's entry `[esp]` is
  the record and `[esp+4]` the context, the record copy trimmed to its parameters, the CONTEXT at
  `(ESP&~3)-0x2CC`; a fault's ContextFlags (F2K: CONTEXT_FULL; Windows 2000 likely adds the debug
  and floating-point sets).
- **While a handler runs:** `fs:[0]` is the dispatcher's frame (Next the establisher, its handler
  and the handler's return address in ntdll, the DispatcherContext between); ExecuteHandler zeroes
  EAX/EBX/ESI/EDI.
- **Nesting and unwinding:**
  - a filter's nested exception re-searches the frames between, flagged 0x10, the flag clearing
    past the establisher (with `_except_handler3` Windows 2000 may re-enter the same filter);
  - a collided unwind runs the finally once, and the outer handler sees the second exception with
    flags 0;
  - RtlUnwind's context keeps EBX/ESI/EDI (Windows 2000's RtlpCaptureContext zeroes them).
- **Raising:**
  - continuing a noncontinuable exception raises 0xC0000025 with flags 1 and the original chained;
  - RtlRaiseException's context pops its argument;
  - RaiseException's address is a return address inside kernel32.
- **Continuing and ending:** NtContinue's EFLAGS mask (the arithmetic flags, DF and TF); the second
  chance without a debugger is ZwTerminateProcess with the code; an empty chain ends with the same
  code as BaseProcessStart's path.
- **IsBad\*:** whether they check NULL first, and how they treat a wrapped range.
- **HEAP_GENERATE_EXCEPTIONS** raises STATUS_NO_MEMORY with one parameter (the size), continuable,
  and continuing returns NULL.

### Thread and process start and exit (the `layout` capture)

- **Stacks and entry:**
  - the initial ESP is StackBase − 4 for every thread;
  - the entry point's ESP is StackBase − 0x3C for the main thread (0x00300FC4 here, like the
    familiar 0x0012FFC4) and − 0x44 for a child, `[esp]` returning into BaseProcessStart or
    BaseThreadStart, `[esp+4]` the child's parameter;
  - INITIAL_TEB is {0, 0, top, top − 2 pages, the reservation's base}.
- **The thunks and frames:** `xor ebp,ebp; push eax; push 0; jmp` for the process and `xor ebp,ebp;
  push ebx; push eax; push 0; jmp` for a thread; the start frame is a 3-word registration (not
  `_except_handler3`'s scope table); the child CONTEXT is CONTEXT_FULL with CS 0x1B, DS/ES/SS 0x23,
  FS 0x3B, GS 0 and EFLAGS 0x200.
- **Exit order:** ExitThread asks ThreadAmILastThread, then LdrShutdownThread (which also frees the
  TLS expansion slots), then NtTerminateThread(NULL), then ExitProcess if refused; ExitProcess takes
  the PEB lock, terminates the other threads, runs LdrShutdownProcess, then ends the process.
- **Details:** NtTerminateThread on an ended thread gives STATUS_INVALID_PARAMETER (the capture's
  87); ThreadAmILastThread ignores the handle; LdrInitializeThunk is entered with `[esp]` 0, three
  zeros, then the CONTEXT at +0x10 (on Windows 2000 it is called from KiUserApcDispatcher).

### Modules

- **The module lists:** the Flags (exe 0x4000, DLLs 0x4004) and whether the static-link or
  attach-called flags are set; the exe's TlsIndex; the exe's FullDllName sharing the ImagePathName
  buffer and length.
- **Lookups:** FreeLibrary of a handle naming no module gives 126; an ordinal not found gives 182; a
  260-character relative path in GetModuleHandleA is matched as a full path (and gives null and
  126); a trailing dot means no extension; LdrGetDllHandle zeroes the handle on failure.

### Thread queries and startup

- SetErrorMode's SEM_FAILCRITICALERRORS inversion, and an initial hard-error mode of 1.
- STARTUPINFOA's hStd\* are INVALID_HANDLE_VALUE without STARTF_USESTDHANDLES; lpDesktop and
  lpTitle are null.
- GetVersionExA zero-fills szCSDVersion past the string; who fills the PEB's CSDVersion and where
  its buffer lives.
- NtSetInformationThread checks the value before the handle, NtSetInformationProcess the handle
  first; THREAD_BASIC_INFORMATION.BasePriority reports ±16 when saturated.

### The console

- FlushFileBuffers on a console output handle fails with 6; a wait on an output handle waits on the
  input event; CloseHandle translates the STD_\* pseudo-values.
- DuplicateHandle of a console handle needs both process handles to be the current process (else
  87), and the first duplicate is 0xF.
- GetFileType on a closed console handle gives FILE_TYPE_UNKNOWN with 6; WriteConsoleA with a
  non-null reserved argument gives 87; GetConsoleMode is 0x17 for input and 0x3 for output;
  SetStdHandle with a bad type gives 6; SetHandleCount returns its argument.

### Captures needed (the next Windows 2000 session)

1. **Bring over the uncaptured fixtures.** The reference has three fixtures written but not yet
   captured, which the rebuild didn't port: `seh` (with `rawret`), `layout` and `objects`. Their
   sources, `build.bat` and `capture.bat` entries come from `wip/tests`.
2. **Rebuild** every fixture with `tests\build.bat` (stamps, `--list`), then turn on the
   source-stamp check in `tests/test_repository.py`.
3. **Run `capture.bat`** for:
   - `seh` and `rawret` (checks the user-mode exception dispatch built ahead of it);
   - `layout` (checks thread and process start, the module lists and the PEB, and unblocks NT's
     address layout);
   - `objects` (names, delete-pending, the mapping pin, delete-on-close at exit).

   Note that delete-on-close at exit spans two runs, which the harness can't check yet: every block
   boots a fresh snapshot disk.
4. **Recapture `files`, `fswrite` and `runtime`,** whose new probes are waiting, and the blocks for
   the early fixes:
   - WriteFile on a directory handle;
   - CopyFile onto itself under another spelling;
   - a fault with ESP near 0;
   - TerminateProcess on the current process.
5. **Dump the export reference:**
   - `dumpbin /exports` of kernel32.dll and ntdll.dll, for names, ordinals and forwarders;
   - `dumpbin /disasm` of ntdll.dll, for the service numbers;
   - `dumpbin /imports` of kernel32.dll;
   - the decorated names in Visual Studio 6's `kernel32.lib`, for the argument bytes.

   Then list every Windows 2000 export (exportgen would need a way to list one it doesn't build:
   the `unimplemented` kind went with the Win32 layer).
6. **Add a small `ntstatus` fixture** printing RtlNtStatusToDosError over the statuses F2K uses, to
   replace Wine's table with Windows 2000's.

---

## 6. What's left

- **The rebuild is done:** every increment of the plan (A1–A4b, B1–B10, C1) has landed, every
  fixture block the reference passes passes here (`sched[yield]` aside, still pending and
  deselected), and the kernel has no Win32 layer.
- **The architecture work is done except NT's address layout.** What remains waits for the
  captures:
  - **NT's address layout** (the PEB at 0x7FFDF000, TEBs below it, the system areas allocated in
    creation order): needs the `layout` capture;
  - **checking what was built ahead of the captures** (section 5's exception-dispatch, start and
    exit, and module lists), once the reference's `seh`, `layout` and `objects` fixtures are ported;
  - **moving the loader itself into ntdll** (LdrpInitialize: mapping, import snapping, the module
    lists) and loading DLLs from `C:\WINNT\system32`;
  - **the export reference and its stubs,** and the status table.
- **Packages that can start now:**
  - the open memory and file findings in section 4;
  - the critical-section lost wakeup;
  - the intrusive-list soundness refactor;
  - the read-performance profile, and thread creation's region-table scans;
  - the formatting cleanup;
  - the pending-probe harness question;
  - `sched[yield]`: its pending entry and the flake.
- **Later:**
  - C++ exception handling;
  - CreateProcess;
  - growable pools and tables;
  - other system DLLs;
  - a PR to master.
