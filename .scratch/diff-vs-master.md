# wip/tests vs master — summary of the full diff

Snapshot: 2026-10-17. Branch `wip/tests` = master (`b23f63e`) + 11 wip commits + the uncommitted
working tree (memory and fswrite work, ~11 new untracked files). Roughly 180 files, +23k/−5k lines.

State at the time of writing:

- `make test` (pytest, `-n 4`): **101 passed, 0 xfail**: every sectioned fixture is gated and green.
  `sched[yield]` is flaky (about 1 run in 5–10, on HEAD too; see Known gaps).
- Host tests (`CARGO_UNSTABLE_BUILD_STD=std cargo test --lib --target aarch64-apple-darwin`):
  **764 passed**, 77 ignored.
- `python3 scripts/kernel32-ledger.py --check`: ok. kernel32 surface: 164 services + 20 natives = 184
  prototypes. CORPUS holds every fixture; UPCOMING is empty.

---

## 1. Work done

### Test infrastructure

- **Legacy smokes retired.** `scripts/qemu-tests.yaml`, `run-qemu-tests.py`, `test-boot.sh` and the
  smokes `bsscheck crash fileio pingpong respawn sleep spin suspend thread` are deleted.
- **Sectioned fixtures added.** `tests/<fixture>/` holds the C source, the exe, the real-machine
  `output.txt` and `test_<fixture>.py`. The fixtures are bare, runtime, memory, threads, sync, sched,
  files and fswrite.
- **Shared pieces:** `tests/common/f2kt.h`, `tests/build.bat`, `tests/capture.bat`, `files/setup.bat`
  and `scripts/gen-files-data.py`.
- **`tests/f2kboot.py` + `conftest.py`:**
  - builds once per feature set;
  - boots QEMU with the disk as `snapshot=on`;
  - `blocks()` takes gate, pending, masks, timeout and retake;
  - `run_block` compares against the capture.
- **`tests/kernel/test_kernel.py`** replaces the YAML kernel cases (12 cases, with feature builds).
- **One `make test`** runs everything (`pytest tests -n 4`; markers `kernel`, `disk`, `corpus`).
  `pyproject.toml` and `uv.lock` were added.
- **`tests/test_repository.py`** holds the repository hygiene checks.

### Kernel: process, threads, scheduling

- **Startup:**
  - kernel command line → user command line (`boot/cmdline.rs`);
  - TEB and PEB with the NT layouts (`user/teb.rs`);
  - per-thread TEBs, TLS slots and expansion pages, implicit `__declspec(thread)` TLS (`user/tls.rs`).
- **Threads:**
  - CreateThread/ExitThread/TerminateThread, suspend and resume, priorities and classes;
  - 32 KiB gate stacks;
  - thread pools per process.
- **Synchronization:**
  - events, semaphores, mutexes (`sched/mutex.rs`), waitable timers (`sched/waitable_timer.rs`);
  - named objects (`process/objects.rs`);
  - multi-object waits, SignalObjectAndWait, PulseEvent;
  - user APCs (`user/apc.rs`), QueueUserAPC;
  - critical sections (`compat/critsec.rs`);
  - DuplicateHandle.
- **Scheduler:**
  - round-robin by quantum, preemption, wake boost, SwitchToThread;
  - balance-set starvation boost (`scan_ready_queues`, `READY_WITHOUT_RUNNING 300`, scan/ready
    limits 16/10).
- **Time:**
  - RTC wall clock at boot (`hw/rtc.rs`);
  - FILETIME and SYSTEMTIME conversions;
  - QueryPerformanceCounter at 1193182 Hz (`compat/time.rs`).

### Kernel: exceptions

- **SEH** (`user/seh.rs`):
  - the kernel walks the fs:[0] chain through 12-byte thunk stubs (SYS_SEH_SEARCH/UNWIND);
  - EXCEPTION_RECORD and CONTEXT are written below the faulting esp;
  - RtlUnwind, RaiseException, and `raise_in_service` (heap exceptions);
  - non-continuable handling;
  - UnhandledExceptionFilter and SetUnhandledExceptionFilter natives.
- **Faults:** guard-page violations (0x80000001) and stack overflow (0xC00000FD) are dispatched to
  handlers.

### Kernel: runtime surface (kernel32)

- **Locale and code pages:**
  - GetVersionExA;
  - code pages 1252, 437 and UTF-8 with best fit (`compat/codepage.rs`);
  - the locale table (`compat/locale.rs`);
  - CompareString model (`compat/collate.rs`);
  - LCMapString and GetStringType.
- **Environment:** `compat/environment.rs` and `envapi.rs`, with block pages at 0x340000 and
  0x350000.
- **Messages and modules:**
  - FormatMessageA (`compat/message.rs`);
  - modules (`compat/modules.rs`): the kernel32 header page at 0x7C4E0000, GetProcAddress,
    GetModuleHandle, LoadLibrary/FreeLibrary;
  - GetModuleFileNameA's truncation rule.
- **Console:** console mode and code page calls.

### Kernel: files (FAT32)

- **Read side:**
  - long names (`fs/fat32/dir.rs`);
  - Win32 path resolution (`compat/path.rs`);
  - current directory;
  - FindFirst/FindNext with DOS wildcards;
  - attributes, times, GetFileInformationByHandle;
  - volume facts;
  - share modes;
  - read-only file mappings.
- **Write side (new today):**
  - IDE PIO data-out (`hw/ide/write.rs`, `Channel::pio_out`, `Io::out_word`);
  - `BlockDevice::write` (Partition delegates; RamDisk for host tests);
  - FAT writes to every FAT copy, cluster allocation (zeroed, with a next-free hint), file
    write/extend/truncate with gap zeroing (`fs/fat32/write.rs`);
  - directory entries: create with long names and generated `~N` aliases, NT case bits for
    lower-case 8.3 names, removal, rename and move (fixing `..`), mkdir/rmdir, emptiness;
  - CreateFileA dispositions (create, truncate, `FILE_FLAG_DELETE_ON_CLOSE`), WriteFile to files,
    SetEndOfFile;
  - DeleteFileA, MoveFileA, CopyFileA, CreateDirectoryA, RemoveDirectoryA, SetFileAttributesA,
    SetFileTime, SystemTimeToFileTime (`compat/filewrite.rs`).

### Kernel: memory (new today)

- **Address-space manager** (`mem/vm.rs`):
  - region table (Private, Mapped{shared}, Image);
  - page state in the PTE: present entries carry a protection index in bits 9–11; committed but
    inaccessible pages (no-access, guard) are non-present entries marked COMMITTED (bit 1), GUARD
    (bit 2), with their frame;
  - reserve, commit, decommit, release, protect, query, `fire_guard`.
- **Services** (`compat/memapi.rs`): VirtualAlloc/Free/Query/Protect, GetSystemInfo,
  GlobalMemoryStatus, IsBadRead/Write/Code/StringPtr.
- **Regions:** the loader seeds regions (the image as MEM_IMAGE with per-section protections, plus
  the system areas). The process teardown skips shared view pages.
- **Heaps** (`user/userheap.rs` rewritten):
  - up to 16 heaps per process, each on its own reservation;
  - growable heaps reserve 32 MiB, with big blocks (above 0x7F000) on their own reservations;
  - capped heaps;
  - exact HeapSize (slack in the header), split on shrink, HeapValidate, HEAP_GENERATE_EXCEPTIONS;
  - the process heap is created by the loader and its handle written to the PEB.
- **Local and Global memory** (`compat/localmem.rs`): fixed blocks; moveable handles where
  `*h == p`, with a lock count and a back-pointer prefix.
- **Mappings:** paging-file sections with a hidden store reservation; views map the store's frames
  (shared); named sections; OpenFileMappingA; views outlive the handle; file-backed views are
  vm reservations too.
- **Stacks:**
  - real guard PTEs (PAGE_GUARD) on the main and child stacks;
  - child stacks reserved through vm with CreateThread's stack size (NT's rounding rule).

### Harness and ledger

- **Registry:** SERVICES and NATIVES grew to 164 and 20.
- **Groups:** every export belongs to a group.
- **Ledger:** `scripts/kernel32-ledger.yaml` lists every export.
- **Retired scenarios:** the heap adapter and the old CRT-region VirtualAlloc scenarios pinned a
  model that the memory fixture contradicts. Heap and virtual-memory scenarios are now
  argument-block checks only; the behaviors are pinned by the memory fixture.

---

## 2. Known gaps

1. **`sched[yield]` is flaky.**
   - What happens: about 1 run in 5–10 prints `SwitchToThread: returned 0, the new thread had run
     yes`.
   - Cause: the creator's quantum ends between CreateThread and SwitchToThread, so the child runs
     first.
   - Reproduced on HEAD (before today's work), so it predates the memory and fswrite changes.
   - Needs a scheduler look: the quantum handling around thread creation and the
     `interrupt_window`.
2. **The disk smoke still holds the only interrupt audit;** three fault stubs are not yet replaced
   by C blocks.
3. **The threads fixture carries a mask** (argument evaluation order in the captured binary). Drop it
   once `threads.exe` is rebuilt and recaptured.
4. **Not host-tested; covered only by the fixtures (QEMU):**
   - the heaps' composition (segment and big blocks), Local/Global, mappings, child stacks;
   - the IDE data-out protocol (the sim has no write model; `Io::out_word` panics in the sims);
   - the kernel32 write services.
   The pure layers do have host tests: the block core, vm, memapi rules, the FAT write layer, and
   the time conversions.
5. **FAT32 write layer limits:**
   - FSInfo free count and next-free are never updated (Windows tolerates stale FSInfo;
     GetDiskFreeSpaceA may report stale numbers);
   - no IDE cache flush (FlushFileBuffers only returns TRUE);
   - alias generation is `~1`..`~999999` with a shrinking basis, without Windows' hash form after
     `~4`;
   - DeleteFileA of an open file is always ERROR_SHARING_VIOLATION (no delete-pending, even when
     every handle shares delete);
   - moving a directory into its own subtree is not refused;
   - RemoveDirectoryA of a process's current directory is not refused;
   - CREATE_ALWAYS does not check hidden or system attribute mismatches;
   - a crash mid-operation can leave orphans (no ordering or journaling care);
   - the volume lock is held per chunk, not per call, so concurrent writers of one file can
     interleave chunks.
6. **Mapping limits:**
   - sections are process-local (no cross-process sharing; named sections are per-process);
   - file-backed views are still copies made at map time (no coherence with later writes, no
     write-back);
   - the store reservation is visible to VirtualQuery as a MEM_MAPPED region.
7. **Heap limits:**
   - a growable heap's segment is capped at 32 MiB of small blocks (a 0x7F000 or larger request
     goes to its own reservation);
   - an in-place growth never absorbs a free neighbour;
   - the kernel touches the heap segment directly, so a program that decommits or write-protects
     its own heap pages can make the kernel fault (not contained). The fixed-region heap before it
     had the same exposure.
8. **IsBad\* read the page tables** instead of probing under SEH: a guard page answers "bad" without
   firing, and a not-yet-grown stack guard is not committed by a probe.

---

## 3. Assumptions that need verification (on a real Windows 2000 machine where possible)

### Memory (today)

- **Reservation placement:** VirtualAlloc(NULL) takes the *lowest* free 64 KiB-aligned range;
  MEM_TOP_DOWN is ignored. The fixture only checks alignment, and two free-region sizes are masked.
- **Reserve + commit with an address** commits the whole reservation from its base (from the
  capture's `region 0x3000` for 0x30001234/0x1000).
- **Refusals:**
  - VirtualFree and decommit refuse non-private regions (views, image) with 487;
  - VirtualQuery at or above 0x7FFF0000 → 87.
- **GetSystemInfo** fields the capture doesn't print: processor type 586, level 6, revision 0,
  active mask 1.
- **GlobalMemoryStatus:**
  - page file = physical memory;
  - available virtual = total virtual (untracked);
  - memory load computed from free frames.
- **Heap sizing and limits:**
  - growable reservation 32 MiB;
  - big-block threshold 0x7F000 (NT's virtual-block threshold);
  - 64 big blocks per heap, 16 heaps per process;
  - a capped heap's reservation = max(initial, max) rounded to pages;
  - a 0x20-byte segment header.
  The capped heap's "7 blocks of 16K" matches.
- **Heap error behaviour:**
  - HeapAlloc and HeapReAlloc failures leave the last error untouched;
  - HeapFree(NULL) → TRUE;
  - HeapDestroy(process heap) → FALSE with ERROR_INVALID_HANDLE;
  - an unknown heap handle fails quietly (NT would usually fault).
- **HEAP_GENERATE_EXCEPTIONS record:** code 0xC0000017, 1 parameter (the size), the address and
  resume point at the service's return. Only the code is in the capture.
- **Local/Global:**
  - the moveable-handle layout (8-byte entry, handle = entry + 4, 8-byte data prefix);
  - LocalReAlloc may move a locked moveable block (NT forbids that without LMEM_MOVEABLE);
  - LocalUnlock of an unlocked block → ERROR_NOT_LOCKED (158).
- **Child stacks:**
  - the default reservation is taken as 1 MiB (the linker default) instead of reading the image's
    SizeOfStackReserve;
  - 2 committed pages plus a guard instead of the requested commit size;
  - STACK_SIZE_PARAM_IS_A_RESERVATION rounds to 64 KiB, minimum 3 pages.
- **Guard page touched by a kernel copy** (a syscall argument): the guard is silently cleared and
  the copy proceeds. NT fails the call.
- **Image pages:**
  - writable sections report PAGE_WRITECOPY, with no actual copy-on-write;
  - the header page is PAGE_READONLY;
  - AllocationProtect is 0x80;
  - kernel32's header page is a MEM_IMAGE region.
- **System areas** (TEB, PEB, params, env blocks, TLS, thunks) are MEM_PRIVATE regions at fixed
  addresses.
- **Frames:** the kernel keeps a 256-frame reserve that program allocations cannot take.

### Files (today and earlier)

- **FAT timestamps** are local time = UTC (no time zone).
- **Write stamping:**
  - a write stamps the last-write time on every chunk;
  - CopyFileA keeps the source's last-write time and attributes (plus archive), with creation time
    = now;
  - new files get ARCHIVE plus the settable attributes passed (`flags & 0x27`).
- **Successful CopyFileA sets last error 0** (from the capture), and so do CreateFileA's creating
  successes.
- **Short-name rules:**
  - a valid 8.3 name with a lower-case base or extension is stored with NT case bits and no long
    name;
  - mixed case gets a long name.
- **DOS wildcard semantics.**
- **GetVolumeInformation** flags and the FSInfo fallback.
- **Read-only file mappings are copies** made at map time.

### Runtime and exceptions (earlier sessions)

- **Values from tables rather than captures:**
  - the locale table values;
  - the FormatMessage texts;
  - the CompareString model's approximations;
  - CP850 is not convertible;
  - Windows 2000's UTF-8 decoding details.
- **Quirks copied from the capture:** the LCMapStringA last-error 122 on success.
- **Measured or set by hand:**
  - kernel32 base 0x7C4E0000 (from `tests/hello/trace.txt`);
  - the env block and view addresses (chosen, not measured);
  - entry ESP = stack top − 8.
- **SEH details:**
  - UnhandledExceptionFilter defaults to EXECUTE_HANDLER;
  - int3 parameters `[0, ecx, edx]`;
  - RaiseException's exception address is its thunk.
- **The runtime `console` block** was predicted and then confirmed by the user, not captured by
  `capture.bat`.

### Scheduling and time (earlier sessions)

- **Waitable timers:**
  - the timer APC's low/high arguments are 0;
  - SetWaitableTimer with resume → ERROR_NOT_SUPPORTED.
- **Clocks:**
  - QueryPerformanceCounter advances only at clock ticks;
  - the RTC is read as UTC, and the time-zone names are empty.
- **Scheduler constants** (balance set, SwitchToThread) follow NT 5.0 values from documentation,
  not from measurement.
- **The `sched yield` capture's "Sleep(10) does: yes"** line was set by hand from a real-hardware
  run (the VirtualBox capture said "no").

### Environment (earlier sessions)

- Name folding is ASCII-only.
- Deleting a missing variable succeeds.

### Process and kernel (earlier sessions)

- Gate stacks are 32 KiB.
- The process environment and view windows use fixed addresses.
