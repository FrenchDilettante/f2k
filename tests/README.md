# F2K Test Corpus

C programs compiled on a real Windows 2000 machine with the era's toolchain.
They are the compatibility baseline: every test is a real PE32 executable whose imports and behavior are dictated by that environment, not by what F2K happens to implement.

## Layout

The tests are grouped by the DLL they exercise, one directory per group:

```text
tests/
├── core/       # the kernel's own boots (kernel/), the Limine, input, screen and shell tests
│               # (test_limine.py, test_input.py, test_textscreen.py and its screens/,
│               # test_cmd.py, test_guikeys.py, test_framebuffer.py, test_textout.py,
│               # test_drawing.py, test_tahoma.py, test_shutdown.py), and the fixtures exit0, ret0,
│               # hello and bare
├── kernel32/   # runtime, memory, threads, sync, sched, files, fswrite, dll, dllmain, msgtable,
│               # console, spawn, pipe, screen, lineedit, ctrl, lstr, utility, toolhelp, batspawn,
│               # shutparm, profile, threx, vmedge, startup, lcid, ntquery, locale, atom
├── user32/     # hellogui, winsta, guiclass, guiwin, guigeo, guimsg, guipaint, guidisp, exitwin,
│               # endsess, dialog, wndlong, wintext, focus, controls, menus, accel, coords,
│               # keyinput, mousein, clipbrd, wsprintf, rects, chars, props, wintree, scroll,
│               # caret, editctl
├── gdi32/      # guidc, gditext, ttfont, bitmaps, mapmode, shapes, regions
├── advapi32/   # registry, token
├── crt/        # msvcrt.dll's: hellomd, crt, seh, fd, wide, process, strings, msvcrt, cxxeh, wmain
│               # (built with /MD)
├── cmd/        # script fixtures, run by cmd.exe: batecho, batset, batlevel, batexit, batcd,
│               # batver, battype, batredir, batcall, batcode, batclr, batpext, batdyn, batquot,
│               # batstd, batops, batline, bathelp, batdir; HAND-CAPTURES.md, the interactive
│               # checks
├── harness/    # checks of the tests and the repository themselves (no QEMU)
└── common/     # f2kt.h, srcsum.c: shared by the fixtures' sources
```

There is no `ntdll/` group: the fixtures that call ntdll directly (`memory`, `files`, `spawn`, `pipe`) reach its exports through `GetProcAddress`, declaring the structures they need themselves, and sit in the group of the DLL whose behaviour they observe.
msvcrt's group is `crt/`: a `tests/msvcrt/` directory would shadow Python's `msvcrt` module, which `subprocess` imports to detect Windows.
Inside its group, each test has its own directory, named after the test:

```text
tests/<dll>/<name>/
├── <name>.c        # the source, built on the real Windows 2000 machine (<name>.cpp for C++)
├── <name>.exe      # the compiled fixture (committed; it is the point)
├── *.dll           # companion DLLs the program loads, if any (committed, built beside it
│                   # from their checked-in source and .def)
├── <other>.exe     # companion programs the program starts, if any (committed, built beside
│                   # it from their checked-in source)
├── fixture.toml    # the declaration: its kind, and how its capture compares (served fixtures)
├── output.txt      # the real-machine capture, where there is one
├── overrides.txt   # blocks the capture script cannot take (an interactive console...), if any
├── test_<name>.py  # sectioned fixtures: binds the fixture's tests (f2kboot.corpus_test)
├── imports.txt     # verified facts from the binary, where relevant
└── <name>.rs       # planned: the same test for F2K's own Rust toolchain
```

The Rust counterpart exists so the same test can be built and run by our own toolchain as well as the reference one; it lands when the toolchain can build it.
Build intermediates (`.obj` etc.) are ignored, not committed.

A fixture's name is unique across the groups: the disk carries every program in one directory, and the declarations, pins and results name a fixture by its name alone (`f2kboot.fixture_directory` finds its directory, and refuses a name two groups declare).

Shared pieces sit beside the groups: `common/f2kt.h` (the reporting and section helpers the sectioned fixtures include), `build.bat`, `capture.bat` (the real-machine capture of the sectioned fixtures), and the pytest side: `conftest.py` and `f2kboot.py` (building, booting, comparing), `core/kernel/test_kernel.py`, the kernel's own boots (the fault stubs, the Limine disk path, the multi-process suite, the RAM disk, the interrupt and IDE diagnostics, and the single-path program smokes below), which have no sectioned capture to compare against, and `core/test_limine.py`, a few corpus blocks booted through Limine instead of QEMU's Multiboot loader.
`core/test_guikeys.py` boots F2K's own `keyshow.exe`, added to a copy of the disk, and types into its window through QMP: the keyboard's keystrokes reach the foreground window as key messages, their characters through `TranslateMessage`, compared line for line.
`core/test_cmd.py` boots into F2K's own `cmd.exe`, added to a copy of the disk (the disk the tests boot leaves it out), types `pwd` and Return at its prompt through QMP, and checks the text screen row by row.
`core/test_shutdown.py` types a file's creation and then `shutdown` at that prompt, on a copy of the disk with cmd.exe added, kept between two boots (`f2kboot.boot`'s `kept`: attached without QEMU's snapshot): the first boot ends the session and halts on "It is now safe to turn off your computer." or restarts (QEMU's `-no-reboot` turns the restart into its exit, which the harness takes for the boot's end after the kernel's restart line); the host then reads the image (`f2kboot.read_volume`: FAT[1]'s clean-shutdown bit, FSInfo's free count against the FAT's), and the second boot finds the file.

## Sectioned fixtures

The sectioned fixtures cover the public API by area rather than one smoke path each.
Each is a list of named sections: `<fixture> <section>` runs one section, and the suite runs every section as its own process; with no argument a fixture runs all its sections except the named-only ones (those that end the process, or whose output depends on an interactive console).

They follow one set of conventions, from `common/f2kt.h`:

- **Observe, don't assert.**
  A line prints what a call returned (`ret=0 err=288`); the real-machine capture is the expectation, and where F2K disagrees, F2K is wrong.
  Nothing machine-specific is printed: no addresses, handle values, thread ids, absolute paths or raw timings (timing-shaped facts print as a verdict against a band).
- **The last error is armed with a sentinel** before the call under observation and printed as `-` when the call left it untouched, so the captures pin which calls set, clear or keep it.
- **One line, one `WriteFile`.**
  Output never interleaves across threads and does not depend on CRT stdio buffering, so a redirected capture matches the console.
- **The A and W forms both run.**
  A section observing an A function calls its W twin on the same inputs right after and prints the result the same way: the W line carries the W function's name, or a `(W)` tag on its label.
  A wide string prints through `ws()`/`wsn()`, which call no API (a unit below 0x100 as its byte, any other as `<U+XXXX>`), so the last error stays as the call left it.
- **Critical paths are covered even where F2K has nothing yet** (structured exception handling, thread-local storage, growable heaps, waitable timers, file writes...): a fixture importing an export F2K lacks fails to load until the export lands, which is the point - the fixtures lead the kernel.

The fixtures:

- `bare` - no C runtime.
  With no argument: `.bss` zeroing (run twice in the multi-process boot, to catch frames reused unzeroed), `.data` and `.rdata` contents, linker pointer tables, entry stack alignment, a stack that grows to 256 KiB; the exit code is a mask of failed checks.
  With a mode: the entry point's return value as the exit code, a full 32-bit exit code, bad buffer pointers to `WriteFile`, code run from `.data`, and fifteen faults (NULL, `.rdata`, code, kernel addresses, divide by zero, `ud2`, `int3`, `hlt`, `cli`, `in`, `into`, stack overflow), each ending the process with its NTSTATUS.
  Replaces `crash` and `bsscheck` (the multi-process suite runs `bare` and `bare null-write` in their place).
- `runtime` - the process environment: argv, version, modules and `GetProcAddress`/`LoadLibraryA`, the TEB/PEB fields compilers and runtimes read, last-error semantics and `FormatMessageA`, the environment, code pages and string conversion, CRT formatting and parsing, structured exception handling (faults, `RaiseException`, filters, `__finally`, unwinding), `OutputDebugStringA`/`W` with no debugger attached (`debugstr`), `VerifyVersionInfoW`/`A` with `VerSetConditionMask` and the version as relations (`verify`), plus named-only `console`, `unhandled` and `exit`.
  Replaces `ret0` and `hello` as coverage (`hello` stays as the CRT smoke and the disk-smoke file).
  Gated; its `console` block was captured by hand in an interactive console (it lives in `runtime/overrides.txt`); `debugstr` and `verify` stay pending while kernel32 exports no `OutputDebugStringA`/`W`, `VerifyVersionInfoW`/`A` or `VerSetConditionMask`.
- `memory` - `malloc`/`calloc`/`realloc`/`free` the way programs use them (thousands of small blocks, past 1 MiB of them, 4/16/32 MiB, realloc doubling to 4 MiB), the Win32 heap with private and capped heaps, `LocalAlloc`/`GlobalAlloc`, `VirtualAlloc`/`VirtualFree`/ `VirtualQuery`/`VirtualProtect` and guard pages, the image's section protections, paging-file mappings, stack growth and thread stack sizes, a console call writing into a thread's stack guard page, and `GlobalFlags` over fixed, moveable, locked, discardable and discarded `GMEM_` blocks and the lock count's ceiling (`globalflags`).
  Gated; two free-region sizes are masked (the real machine's other allocations bound them); `globalflags` stays pending while kernel32 exports no `GlobalFlags`.
- `threads` - creation, exit codes, `ExitThread`/`TerminateThread`, suspend counts and suspension during waits, priorities and classes, scale (32 sequential, 20 concurrent, 100 fire-and-forget threads, hundreds of handles), TLS slots and `__declspec(thread)`, per-thread last error/errno/FPU/SEH, `_beginthreadex`, a thread terminated in a wait (its exit code at once and once it has ended), a suspended thread terminated, `OpenThread` with each access right alone and on an ended thread's id (`open`), `GetThreadTimes` as relations to `GetSystemTimeAsFileTime` and the time a busy loop took (`times`), and named-only `mainexit`/`procexit`.
  Built with `/MT`.
  Replaced the `thread`, `respawn` and `suspend` smokes.
- `sync` - events (`PulseEvent`, named objects), semaphores, mutexes and abandonment, `WaitForMultipleObjects`, user APCs, critical sections, interlocked operations, handle duplication and closing, `pingpong` kept as a section (plus a `SignalObjectAndWait` variant), and threads terminated inside waits on named events (whether the names outlive them).
  Built with `/MT`.
  Replaced the `pingpong` smoke.
- `sched` - sleeps and timed waits in bands, the clocks, waitable timers, round-robin, preemption, yielding, the wake boost, suspension, and the starvation boost; pinned to one CPU.
  Built with `/MT`.
  Replaced the `sleep` and `spin` smokes.
  Gated.
  Its `yield` capture line `Sleep(10) does: yes` comes from real hardware: the VirtualBox capture VM runs at 100% CPU (a normal-priority thread yielding with `Sleep(0)`), so below-normal threads there run only at the balance-set boost, 300 ticks in, and it answered `no`.
- `files` - the read side of the file API over `kernel32/files/DATA` (generated by `scripts/gen-files-data.py`; every byte is formula-defined): path forms and errors, chunked and boundary reads, seeks, metadata, `FindFirstFile` listings, share modes, CRT file I/O, read-only file mappings, concurrent readers, a duplicated handle's shared position while another thread reads, image sections outliving their file's handle.
  Captured on a local FAT32 volume, as F2K's boot volume is (run `kernel32/files/setup.bat` once on the real machine: attributes git cannot carry).
  Gated.
  Replaced the `fileio` smoke.
- `dll` - a program and its companion DLL (`f2kcom.dll`, built beside it from `f2kcom.c` and `f2kcom.def`, with no C runtime and no entry point, so nothing runs at load time): the program-driven dynamic linking - LoadLibraryA from the program's directory, the load reference count, GetProcAddress by name and by ordinal (its .def pins them), a call into the DLL, the counter reset by the unload and reload, FreeLibrary down to the unload; and `LoadLibraryExA`/`W` with flags 0, `LOAD_WITH_ALTERED_SEARCH_PATH`, `LOAD_LIBRARY_AS_DATAFILE` (the DLL loaded and not) and `DONT_RESOLVE_DLL_REFERENCES`, and their refusals (`loadex`).
  Gated; `loadex` stays pending while kernel32 exports no `LoadLibraryExA` or `LoadLibraryExW`.
- `dllmain` - the counterpart of `dll`: companion DLLs with a DllMain each (no C runtime, `DllMain` their entry point), every call recorded in `f2kbase.dll`'s log, which the program prints: the static DLLs' DLL_PROCESS_ATTACH before `main` (lpReserved non-NULL) and in dependency order, a created thread's DLL_THREAD_ATTACH and DETACH and DisableThreadLibraryCalls turning them off, LoadLibraryA and FreeLibrary's attach and detach (a new dependency first), a DllMain answering FALSE, and the search through the program's directory and the current directory (`f2ksub.dll` sits in its `dllsub` subdirectory alone).
  Gated.
- `fswrite` - the write side (create dispositions, writes, truncation, share modes, rename/copy/delete, directories, file times, CRT writes, and `LockFile`/`UnlockFile` between two handles with the reads and writes a lock refuses (`lock`)) in a scratch directory, captured on a local FAT32 volume.
  Gated (the test boots read a copy of the disk in memory or a QEMU snapshot of it, so its writes never reach the image); `lock` stays pending while kernel32 exports no `LockFile` or `UnlockFile`.
- `msgtable` - `FormatMessageW` and `FormatMessageA` over the program's own message table (`msgtable.mc`, compiled by the message compiler into a resource) and over strings: lookup by id and language, inserts through a `va_list` and an argument array, the escapes, line widths, the caller's buffer and an allocated one.
  Gated.
- `console` - the console through `CONOUT$` and `CONIN$`, so the capture script takes it: the screen buffer's size and attributes, the input and output modes, `ReadConsoleW`/`ReadConsoleA` over input the program queues itself, the title, and control handlers.
  Gated; its screens are saved (`screenshots`).
  What a program writes through `CONOUT$` shows on the screen only, not on COM1: as on the real machine, where the capture redirects standard output to a file and `CONOUT$` stays on the console.
- `spawn` - child processes, with its companion program `spawnkid.exe` (built beside it from `spawnkid.c`), the child every section starts, which does what its first argument says and prints through the standard handles it inherits: Windows 2000's fixed addresses (the parent's TEB and PEB and the fields they point to, a second thread's TEB, a child's PEB and TEB through ntdll's queries and `ReadProcessMemory`, printed as values: Windows 2000 has no address randomization), `CreateProcessA`/`CreateProcessW` (the names, the search order, quoting and spaces, the errors), waits and exit codes, process and thread handles (`OpenProcess`, `CREATE_SUSPENDED`, `TerminateProcess`, `DuplicateHandle` into a child), inherited standard handles, environment blocks and the current directory, `ReadProcessMemory` and `WriteProcessMemory`, `GetBinaryTypeA`/`GetBinaryTypeW` (on programs and on made-up headers), a process that has ended, a child terminated before it ran, `DUPLICATE_CLOSE_SOURCE`, another process's memory (`VirtualAllocEx` and the rest, `FlushInstructionCache`), handle flags in a child, msvcrt's descriptor block for a child, msvcrt's `_spawn` family and `_cwait`, `system()`, detached and new-console children, a child terminated twice, a process's exit code when its threads end it in turn, racing terminations, `CreateRemoteThread` into an exiting child, `NtCreateProcess` with no thread, and named-only `overlay` (`_P_OVERLAY`, whose child capture.bat waits for before it closes the block).
  Built with `/MD`, in a scratch directory as `fswrite`'s.
  Gated.
  Its `system` block runs the command processor `COMSPEC` names, which the disk the tests boot does not carry, so the fixture's boot adds F2K's `cmd.exe` to `\WINNT\system32` (`system_programs`).
  Its `detach` block stays pending while F2K's console server holds one console, which every process shares: kernel32's `CreateProcess` takes its stub path for `DETACHED_PROCESS` and `CREATE_NEW_CONSOLE`.
- `pipe` - anonymous pipes, with its companion program `pipekid.exe` (built beside it from `pipekid.c`), which the sections start with pipes for their standard handles: `CreatePipe`'s sizes and how many bytes each takes before a write waits, its ends' file type, inheritance, granted access and name (ntdll's `NtQueryObject`), I/O the wrong way and the file queries on a pipe, reads, writes, zero-byte I/O and `PeekNamedPipe`, ntdll's `NtFsControlFile` with the pipe-peek code (checked only through the bytes it returns, so only a real peek gives the capture), a closed end seen from the other, waits for data and for room (woken, ended by a close or by `TerminateThread`), children joined by pipes as cmd.exe joins them, msvcrt's `_pipe`, `_read` and `_write` in text and binary mode, and `_popen`, `_pclose` and `system()` with COMSPEC naming `pipekid.exe`, whose `/c` mode stands in for the command processor (F2K's disk has no cmd.exe) and prints the command line msvcrt gives it.
  Built with `/MD`.
- `screen` - the screen buffer through `CONOUT$`, each section starting from a buffer cleared the way cls clears it: `SetConsoleCursorPosition` (inside and outside the buffer, the window following the cursor), `SetConsoleTextAttribute` and the cells a write leaves, `FillConsoleOutputCharacterW`/`A` and `FillConsoleOutputAttribute` (past the row's end and the buffer's end, the count written), `ReadConsoleOutputCharacterW`/`A` and `ReadConsoleOutputAttribute`, `ScrollConsoleScreenBufferW`/`A` (overlapping, clipped, the fill, the buffer's edges), and their errors on `CONIN$`, a file and a bogus handle.
  Positions print from the cleared buffer's corner, or relative to its size near its far edges.
  Built with `/MD`.
- `lineedit` - the console's line editing and history in a line-mode read with echo, over key events the program queues itself with `WriteConsoleInputW`/`A` as a keyboard makes them: moving within the line, by word, deleting, Esc, insert and overtype, lines longer than a row and on the buffer's last row, the history keys (Up, Down, PgUp, PgDn, F1, F3, F5, F8), F6 and Alt+F7, each read's result and the echoed rows read back.
  Each section clears its program's history first, which Windows 2000 keeps after a program ends.
  Built with `/MD`.
- `ctrl` - console control events, with its companion program `ctrlkid.exe` (built beside it from `ctrlkid.c`), started in a process group of its own: `GenerateConsoleCtrlEvent` into that group (the handlers' order and thread, the chain's end, the default handler's exit code), `CTRL_C_EVENT` into a group and the ignore flag in a child and a grandchild, the call's refusals, groups no process leads (from a console of its own), and named-only `keys`, real Ctrl+C and Ctrl+Break during a line read and a running child, captured by hand into `overrides.txt`.
  No event ever goes to group 0, which would reach the cmd.exe running the capture.
  Built with `/MD`; its `keys` block's keys are pressed by the harness (`[keys]`).
- `lstr` - kernel32's lstr string functions, `lstrlenA`/`W`, `lstrcpyA`/`W`, `lstrcpynA`/`W` and `lstrcatA`/`W`: lengths and copies of empty, ASCII and non-ASCII strings, `lstrcpyn`'s counts (at most count-1 characters, always a NUL, no padding), appending, and bad pointers (NULL, a no-access page, a read-only destination, a string or a destination running into a no-access page), which Windows 2000 catches inside the call and answers with 0 or NULL.
  Each section sets up the pages it needs and frees them before it ends.
  Built with `/MD`.
  Gated.
- `utility` - small exports programs call in passing: `MulDiv` (rounding, signs, the 64-bit intermediate, overflow), `IsDBCSLeadByte` and `IsDBCSLeadByteEx` over single-byte code pages and one that does not exist, `GetStringTypeExA`/`GetStringTypeExW` against `GetStringTypeA`/`GetStringTypeW`, `GetUserDefaultLangID`, `GetSystemDirectoryA`/`GetSystemDirectoryW` and their buffer sizes, `GetTempPathA`/`GetTempPathW` with `TMP`, `TEMP` and `USERPROFILE` set or removed in turn, `GetTempFileNameA`/`GetTempFileNameW` with a given number and one they choose, `LocalFileTimeToFileTime` against `FileTimeToLocalFileTime`, and `GetProcessVersion`.
  Paths print with `<cwd>` and `<windir>` for the current and Windows directories' prefixes, local times only as relations, and a number `GetTempFileName` chose as `<hex>`, so the capture holds on any machine.
  No DBCS code page is used: which are installed is the machine's choice, and F2K carries no DBCS tables.
  Built with `/MD`.
  Gated.
- `toolhelp` - the ToolHelp snapshot, with its companion program `thkid.exe` (built beside it from `thkid.c`), which holds on named events the program sets, so each snapshot finds it where the section expects: `PROCESSENTRY32`, `PROCESSENTRY32W` and `THREADENTRY32`, and `SYSTEM_PROCESS_INFORMATION` and `SYSTEM_THREAD_INFORMATION` (declared in the program from public documentation, MSVC 6's headers having neither) with the chain `NtQuerySystemInformation` fills read through them; the program's own entry through `Process32First`/`Process32Next` and `Process32FirstW`/`Process32NextW` (its name, thread count, priority class and parent) and its threads through `Thread32First`/`Thread32Next`, after `CreateThread`, `SetThreadPriority` and `SetPriorityClass`; children listed with the program as their parent, ended with their handles open, gone once they are closed, created suspended, and a grandchild outliving its parent; the idle and System processes; the calls' errors; and the snapshot handle's object type, access and inheritance.
  The real machine runs other processes that vary from boot to boot, so only the program's own processes and threads print, found by their ids, and the idle and System processes' ids and thread counts print as relations.
  Built with `/MD`.
  Gated.
  The child block masks its suspended child's exit code after `TerminateProcess(7)`: 7 or 0 on Windows 2000, as its thread had or had not been dispatched up to its suspend before the termination.
- `batspawn` - `CreateProcessA`/`CreateProcessW` on batch files the program writes, with its companion program `blkid.exe` (built beside it from `blkid.c`), a stand-in command processor that prints its command line and its image's path and runs nothing.
  `ComSpec` names it and a copy of it sits in the current directory as `cmd.exe`, so the output shows whether the command processor is found through `ComSpec` or by searching for `cmd`.
  Its cases: the application name NULL and set, a `.cmd`, an upper-case `.BAT`, quoted arguments, a name with a space quoted and not, the name without its extension, an empty `.bat` and a `.txt`.
  Its `realcmd` section runs the machine's own `cmd.exe` on them, with the exit codes `exit` and `exit /b` leave: the disk the tests boot carries no `cmd.exe`, so the fixture's boot adds F2K's (`system_programs`).
  Each section removes its scratch directory at its end, so no `cmd.exe` is left behind.
  Built with `/MD`.
- `shutparm` - a process's shutdown parameters, with its companion program `shutkid.exe` (built beside it from `shutkid.c`): `GetProcessShutdownParameters`' default (level 0x280, no flag), `SetProcessShutdownParameters` at each band's edges with and without `SHUTDOWN_NORETRY`, read back, levels outside 0x100-0x3FF (Windows 2000 keeps them) and flags other than `SHUTDOWN_NORETRY` (TRUE, the parameters unchanged), and a child's own parameters beside its parent's.
  It never calls `ExitWindowsEx`: the parameters only order a session's end, and each process's are its own.
  Built with `/MD`.
  Gated.
- `resource` - the program's own resources (`resource.rc`, compiled by the resource compiler and linked in): `FindResourceA`/`W` and `FindResourceExA`/`W` by number, by `"#number"` and by name in any case, through the module and through NULL, a resource in two languages and one in the neutral language, the arguments in the wrong order, and each level's error (type, name, language), kernel32's module included; `LoadResource`, `LockResource` and `SizeofResource` over each resource found, `FreeResource`'s return, and user32's `LoadStringA`/`W` over a string table (buffers that fit, short ones, missing ids).
  No handle or address prints: a lookup prints whether it found the resource and whether it found the same one as another call, a resource's data its size and bytes.
  Built with `/MD`, linking `user32.lib`.
- `profile` - kernel32's profile functions: `GetProfileIntA`/`W`, `GetProfileStringA`/`W` and `WriteProfileStringA`/`W` on win.ini (defaults, values written and read back as numbers and strings, short buffers, the key list, a key and the section deleted) (`winini`); `GetPrivateProfileStringA`/`W` (`read`), `GetPrivateProfileIntA`/`W` (`int`), and `GetPrivateProfileSectionA`/`W` and `GetPrivateProfileSectionNamesA`/`W` (`sections`) over the fixture's own `profile.ini` (comments, blanks around keys and values, quotes, numbers in several forms, keys and sections repeated in another case, an empty section, short buffers, lists, a missing file); and `WritePrivateProfileStringA`/`W` and `WritePrivateProfileSectionA`/`W` on a copy of it and on files the writes create, with the bytes they leave (`write`, `new`).
  win.ini is touched only through the section `[F2KProfile]`, removed at every section's start and end, and its section names print only as whether `F2KProfile` is among them.
  `profile.ini` (CRLF) sits beside the program and is only read; the writes go to `profwork.ini` (its copy), `profnew.ini` and `profneww.ini`, deleted at every section's start and end.
  Every file is named by a full path, the program's own directory, which never prints.
  F2K's boot adds `profile.ini` to `\CORPUS` beside the program (`data_files`).
  Gated; `winini` stays pending while F2K's disk carries no `\WINNT\win.ini`: win.ini's section list is empty before `[F2KProfile]` is written and after it is deleted.
- `threx` - thread-level exception behavior: the second chance in a worker thread ending the whole process with the exception's code (`unhandled`, named-only), the dispatched CONTEXT's floating-point and debug-register flags (`context`), main's return ending the process through the C runtime's exit before a sleeping worker prints (`mainret`, named-only), `NtQueryInformationThread`'s `ThreadQuerySetWin32StartAddress` class answering the recorded start address (`threadstart`), and whether a thread resumes with the x87 and SSE state of the CONTEXT it resumes from, after an exception's continuation and after `SetThreadContext` (`fpresume`).
  Gated.
- `vmedge` - the virtual-memory and sections corners: a thread of its own walking its stack down to `STATUS_STACK_OVERFLOW`, counting the guard-page exceptions it sees and surveying its reservation before and after (`guardwalk`), `MEM_COMMIT` over a paging-file-backed view and over a file-backed one (`commitview`), and `NtUnmapViewOfSection` of a private region and of a suspended copy's image, which a program can watch where unmapping its own would leave it no code to return to (`unmapimage`).
  Gated.
- `startup` - `GetStartupInfoA`'s `lpDesktop`/`lpTitle`/`lpReserved` converted from the process parameters, never NULL (`startup`).
  Gated; its block fails on F2K while the three fields stay NULL.
- `lcid` - `CompareStringA`/`W` refusing an uninstalled LCID with `ERROR_INVALID_PARAMETER` (0x9999), with the US English LCID as the sanity line (`badlcid`).
  Gated; its block fails on F2K while an unknown locale still compares.
- `ntquery` - the introspection surface called ntdll-direct through `GetProcAddress`: `NtQuerySystemInformation` class 5 (`sysinfo`), `NtQueryInformationProcess` class 0 (`procinfo`), `NtQueryInformationThread` class 0 with its fields as relations and the exact length it requires (`threadinfo`), `ReadProcessMemory` of the section's own PEB with its first fields as relations (`pebread`), and `OpenSCManagerA` (`scmfail`).
  Gated; `scmfail` stays pending while F2K runs no service control manager: `OpenSCManagerA` fails with `ERROR_CALL_NOT_IMPLEMENTED`, where Windows 2000 answers a handle.
- `locale` - kernel32's locale formatting and queries over fixed inputs: `GetDateFormatW`/`A` with the `DATE_` flags, picture strings and three more dates (`date`), `GetTimeFormatW`/`A` with the `TIME_` flags, picture strings, midnight and noon (`time`) and `GetNumberFormatW`/`A` with the locales' own formats and `NUMBERFMT`'s fields, negatives, rounding and strings that are not numbers (`number`), each with the buffer-size query, a short buffer and its errors; `FoldStringW`/`A` and the `MAP_` flags alone and in pairs (`fold`); `EnumSystemCodePagesW`/`A` under `CP_INSTALLED` and `CP_SUPPORTED`, whether 1252, 437, 850 and 65001 are listed, and the counts (`codepages`); and `IsValidLanguageGroup` (`langgroup`).
  Each formatting call runs under `LOCALE_USER_DEFAULT`, `LOCALE_SYSTEM_DEFAULT` and 0x0409, and the machine's default LCIDs print only as whether they are 0x0409.
  Built with `/MD`.
- `atom` - kernel32's global atoms: `GlobalAddAtomW`/`A`, `GlobalFindAtomW`/`A` and `GlobalGetAtomNameW`/`A` on a name added in several cases and outside ASCII (`add`), the reference counts `GlobalDeleteAtom` counts down (`refcount`), integer atoms from `"#123"` and `MAKEINTATOM` and their bounds, and names that only look like numbers (`integer`), names of 255 and 256 characters and short buffers (`length`), and the errors (`errors`).
  The table is the window station's, shared with every other program, so the fixture's names all start with `F2KAtomFixture`, each section removes every reference to them at its start and its end, and a string atom's value prints only as a relation.
  Built with `/MD`.
- `winsta` (user32) - the window station and desktop: their handles, names, types and flags (`GetUserObjectInformation`), and `MessageBeep`.
- `registry` (advapi32) - keys and values under `HKEY_CURRENT_USER\Software\F2K` only, deleted before and after each section: creating, opening and closing keys, setting and querying values of each type, default values, enumeration and deletion.
- `token` (advapi32) - the process token as a program that shuts the machine down prepares it: `OpenProcessToken` (the handle's object type and granted access, `CloseHandle`, and its errors), `LookupPrivilegeValueA`/`W` (the privileges' LUIDs, an unknown or empty name, NULL pointers, an empty or the local computer's system name), `AdjustTokenPrivileges` enabling and disabling `SeShutdownPrivilege` (the return, the error, `PreviousState` and `ReturnLength`), a `PreviousState` too short, `DisableAllPrivileges` and its restore, a privilege the token does not hold, `GetTokenInformation(TokenPrivileges)`, and ntdll's `NtOpenProcessToken` and `NtAdjustPrivilegesToken`.
  Captured on an administrator account; only `SeShutdownPrivilege`, `SeChangeNotifyPrivilege` and `SeTcbPrivilege` print, by their public LUIDs, never the token's whole list, and the computer's name never prints.
  `SeShutdownPrivilege` is enabled only to observe the calls that enable it, and disabled again before the section does anything but adjust or query the token.
  Built with `/MD`.
  Gated.
- `exitwin` (user32) - `ExitWindowsEx` (`EWX_SHUTDOWN`, `EWX_REBOOT` and `EWX_POWEROFF`, with `EWX_FORCE` and `EWX_FORCEIFHUNG`, several action bits, a nonzero `dwReserved`) and ntdll's `NtShutdownSystem` (each action, and out-of-range ones), all refused on the real machine for want of `SeShutdownPrivilege` enabled; and `ExitWindowsEx` with bits Windows 2000 does not define (0x20, 0x40), refused with `ERROR_ACCESS_DENIED` before the privilege check.
  Before each call the program checks that its token holds the privilege disabled (and, but for the undefined bits' section, that its thread has no token of its own), and it never calls a logoff (`EWX_LOGOFF` is 0 and needs no privilege); every section runs only when named.
  F2K checks no shutdown privilege, so the calls refused for want of it would really shut its test boot down: their blocks are skipped on F2K (`[skip]`).
  The undefined bits' block runs on F2K, which refuses them as Windows 2000 does.
  Built with `/MD`.
  Gated.
- `endsess` (user32) - the session's end as a window procedure sees it, with its companion program `endkid.exe` (built beside it from `endkid.c`): `WM_QUERYENDSESSION` and `WM_ENDSESSION` sent with `SendMessageA`/`W` to the program's own windows, lParam 0 and `ENDSESSION_LOGOFF`, to a procedure answering TRUE, FALSE or `DefWindowProc`'s answer (the return, wParam, lParam, the thread it runs on), the window still there after `WM_ENDSESSION`, `DefWindowProcA`/`W`'s answers to both messages, and both sent to another thread's window.
  The real machine's session's end cannot be captured: `endkid.exe`, a window answering `WM_QUERYENDSESSION` TRUE or FALSE that may ask for the session's end itself, is F2K's own, run by the session cases of `core/kernel/test_kernel.py`, never by the capture.
  Built with `/MD`.
  Gated.
- `hellogui` (user32) - the GUI rung end to end: registers a window class, creates and shows a window, paints "Hello, world!" once with `TextOut` in WM_PAINT, then closes itself (WM_CLOSE, WM_DESTROY's PostQuitMessage, GetMessage's 0) and exits 0; the first test to import user32.dll and gdi32.dll.
  Its one block (`hellogui.exe`, no arguments) was captured by hand on the real machine — the exit code 0 alone: a self-closing GUI program's screen cannot be captured — and it boots under FiSH (`boot_under`), which sets the graphics mode before the program runs; its boot's screen is saved under `target/qemu/screens/` like any `screenshots` fixture's (`screenshots`).
- `dialog` (user32) - the dialog manager over the program's own templates (`dialog.rc`, compiled by the resource compiler and linked in: a DIALOG template in the dialog font, a DIALOGEX one and one with no font): `CreateDialogParamW`/`A` and the controls each template becomes (their classes, ids, styles and text, and their positions as the mapped template rectangle less the window's), and the messages the dialog procedure receives (`create`, `ex`); `GetDlgItem`, `GetDlgCtrlID`, `SetDlgItemTextW`/`A`, `GetDlgItemTextW`/`A` and `SendDlgItemMessageW` (`items`); `SetDlgItemInt` and `GetDlgItemInt` over texts that are and are not numbers (`ints`); `CheckDlgButton`, `IsDlgButtonChecked` and `CheckRadioButton` (`buttons`); `DialogBoxParamW`/`A` and `EndDialog`'s value (`modal`); `GetDialogBaseUnits` and `MapDialogRect` (`units`); `IsDialogMessageW`/`A` over Tab, Shift+Tab, Enter and Esc posted to the focus, with the focus after each and the commands the dialog receives (`keys`); and `MessageBoxW`/`A`, their return and the box's controls (`msgbox`).
  Nothing waits for a person: a modal dialog posts itself the command it ends on from `WM_INITDIALOG`, with a 3-second timer of its own as a fallback, and each message box is ended by a watcher thread that finds it by its class and caption and posts it a button's command, then `WM_CLOSE` if the box outlasts the command, then `WM_QUIT` to the section's thread if the box outlasts that or is not found within 5 seconds.
  Only `units` prints base units in pixels, which depend on the dialog font: the capture is to be taken at 96 DPI.
  Its windows show on the screen while `keys`, `modal` and `msgbox` run.
  Gated, every section passing; its batch boots with the system's fonts (`system_fonts`), since `create` and `units` print what the dialog font decides.
- `wndlong` (user32) - a window's data through `GetWindowLongW`/`A` and `SetWindowLongW`/`A`: `GWL_STYLE` and `GWL_EXSTYLE`, with the `WM_STYLECHANGING` and `WM_STYLECHANGED` a change sends (`style`); `GWL_ID`, `GWL_HWNDPARENT` and `GWL_HINSTANCE` (`id`); `GWL_USERDATA` (`userdata`); a class's 12 extra bytes and their bounds, with `GetWindowWord`/`SetWindowWord` (`extra`); subclassing through `GWL_WNDPROC` from both forms, the chain through `CallWindowProcW`/`A` and `IsWindowUnicode` (`wndproc`); a dialog's `DWL_DLGPROC`, `DWL_USER` and `DWL_MSGRESULT`, from a template the program builds in memory for `CreateDialogIndirectParamW` (`dialog`); and the errors on NULL and destroyed windows (`errors`).
  A window procedure prints only as the same as a given procedure or not.
  Gated, every section passing.
- `wintext` (user32) - a window's text: `CreateWindowExA`/`W`'s title, `SetWindowTextA`/`W`, `GetWindowTextA`/`W` and `GetWindowTextLengthA`/`W` (a text, the empty text, NULL, NULL and destroyed windows), buffers of 0, 1, 4, 8, 9 and 64 units, `WM_SETTEXT`, `WM_GETTEXT` and `WM_GETTEXTLENGTH` through `SendMessageA`/`W` and `DefWindowProcA`/`W`, text crossing the A and W forms with U+00E9 and U+4E00, and a procedure answering `WM_GETTEXT` itself or refusing `WM_SETTEXT`.
  Each window procedure records what it receives (the message, wParam, the text, its return), printed after each call; ANSI text prints its bytes outside 0x20-0x7E as `<XX>`.
  `InternalGetWindowText`, found with `GetProcAddress`, into buffers of 0 to 64 units, on the custom window (whether its procedure is asked), an untitled window, NULL and destroyed windows (`internal`).
  Gated; `internal` stays pending while user32 exports no `InternalGetWindowText`.
- `focus` (user32) - keyboard focus, enabling and activation: `SetFocus` and `GetFocus`, `EnableWindow` and `IsWindowEnabled`, `SetActiveWindow` and `GetActiveWindow`, and `DestroyWindow` of the focused and the active window, with the `WM_SETFOCUS`, `WM_KILLFOCUS`, `WM_ENABLE`, `WM_ACTIVATE`, `WM_NCACTIVATE`, `WM_ACTIVATEAPP` and `WM_CANCELMODE` each call brings, in order, and the focus, active and foreground windows after it.
  Its windows show on the screen while a section runs; each section asks for the foreground first and prints whether it got it, since the messages' order may depend on it (`capture.bat`'s console is the foreground, so a program it starts may take it).
  A window prints by its label, never by its handle, and `WM_ACTIVATEAPP`'s thread id never prints.
  Gated; `destroy` stays pending: once the active window is destroyed, Windows 2000 gives the foreground to another program's window (the console window `capture.bat` runs in), and F2K's console has no window, so `GetForegroundWindow` answers NULL.
- `controls` (user32) - the built-in Button and Static controls, driven by messages: a button of each style (push, default push, check box, auto check box, three-state and auto three-state, radio and auto radio buttons, group box), its class, style, `WM_GETDLGCODE` answer and state (`create`); `BM_SETCHECK` on each (`check`); `BM_CLICK` on each, the `BN_CLICKED` its parent receives and the checks after (`click`); `BM_SETSTYLE` making and unmaking the default push button, `BM_SETSTATE` and the focus bit (`default`); a Static of each style and its text through `WM_GETTEXT` and `WM_SETTEXT`, by `SendMessageW` and `SendMessageA` (`static`); and an `SS_ICON` static's `STM_SETICON`/`STM_GETICON` and `STM_SETIMAGE`/`STM_GETIMAGE` (`icon`).
  The controls are children of a visible window of the program's own class, which records the notifications; `click` activates it first and prints whether it is the foreground and the active window.
  Gated, every section passing.
- `menus` (user32) - menus from the program's own MENU resource (`menus.rc`, compiled by the resource compiler and linked in): `LoadMenuW`/`A`, `IsMenu` and `DestroyMenu` (`load`); `GetMenuItemCount`, `GetMenuItemID`, `GetSubMenu`, `GetMenuState` and `GetMenuStringA`/`W` by position and by command, through the bar and a nested popup, with short buffers (`items`); `CheckMenuItem`'s previous states and `CheckMenuRadioItem` by command and by position (`check`); `EnableMenuItem`'s previous states (`enable`); and `GetMenu` and `SetMenu` on a hidden top-level window and a child window, and a menu destroyed with its window (`window`).
  Three more sections settle how the handles of user objects of different kinds relate.
  One object of each kind (a hidden window, `CreateMenu`'s menu and menu 200, a `CreateAcceleratorTableW` table, the stock arrow cursor and application icon, and a `CopyIcon` copy): `IsWindow`, `IsMenu`, `GetMenuItemCount`, `CopyAcceleratorTableW` and `GetWindowLongW` of each, and `DestroyMenu`, `DestroyAcceleratorTable`, `DestroyIcon` and `DestroyWindow` on the other kinds' handles, which Windows refuses (`kinds`).
  40 windows, then 40 menus, then 40 tables made and destroyed one after another while one of each is held: the other kinds' calls on each new handle, each kind's call on the held objects, and the new handles against the earlier, destroyed ones, as counts (`reuse`).
  The slots the handles' low words name: objects of all kinds alive at once, a window, a menu and a window made in turn, and one object made at once after another's destruction, with its high word's change (`slots`).
  A window's menu bar: its height in the non-client area against `SM_CYMENU`, with the menu, after `SetMenu(NULL)` and after `SetMenu` again, `DrawMenuBar`, and `WM_NCHITTEST` down the shown window's middle column (`bar`).
  The keyboard menu loop, driven by `SendInput` into the program's own foreground window, and the menu messages its procedure receives (`WM_SYSCOMMAND`, `WM_ENTERMENULOOP`, `WM_INITMENU`, `WM_INITMENUPOPUP`, `WM_MENUSELECT`, `WM_MENUCHAR`, `WM_UNINITMENUPOPUP`, `WM_EXITMENULOOP`, `WM_COMMAND`): Alt, a mnemonic, Down and Enter (`keyloop`); F10, the arrows and Esc, a key that is no mnemonic, and Alt then Esc (`keyesc`); Alt held over a mnemonic, Up, and Enter on a grayed item (`keychar`).
  A batch is sent only while the window is the foreground window, and a loop still running after 3 seconds is ended with `EndMenu` from a timer.
  Seven more sections edit menus made by `CreateMenu` and `CreatePopupMenu`, printing every item after each step.
  `AppendMenuW`/`A`, `InsertMenuW`/`A` and `ModifyMenuW`/`A` by position and by command, `DeleteMenu` and `RemoveMenu`, and a popup removed against one deleted (`edit`).
  `GetMenuItemInfoW`/`A` of each `MIIM_*` mask, the members each leaves, the string's length and `cch`, `cbSize` 44 and 48, and `SetMenuItemInfoW`/`A` of each mask read back (`info`); `InsertMenuItemW`/`A` (`insitem`).
  `SetMenuDefaultItem` and `GetMenuDefaultItem` with the `GMDI_*` flags (`default`); `GetSystemMenu`'s items for a `WS_OVERLAPPEDWINDOW` window and others, edited and reverted (`sysmenu`).
  `GetMenuItemRect` of a shown window's bar and `GetMenuCheckMarkDimensions`, as relations (`itemrect`).
  `TrackPopupMenu` and `TrackPopupMenuEx`, each menu ended without input by the `WM_CANCELMODE` a watcher thread sends its owner, with the menu messages the owner receives in order (`track`).
  No handle prints: a menu prints as found or not and as the same as another call's or not, the items' states in hex, and a handle's low and high words only as relations; `reuse`'s and `slots`' relations hold while no other process makes a user object meanwhile.
  Gated; `keyloop`, `keyesc` and `keychar` stay pending: the real machine refused the capture's program the foreground (its `SetForegroundWindow` answered 0), so their blocks send no keystroke, where F2K, which has no foreground lock, grants it.
  The menu-editing sections stay pending until user32 has the calls they make: `edit` also while F2K's `AppendMenu` keeps an `MF_STRING` item with no text as a string item, which Windows 2000 makes a separator, and `track` while F2K has no foreground lock.
- `accel` (user32) - keyboard accelerators from the program's own ACCELERATORS resource (`accel.rc`, compiled by the resource compiler and linked in, with a menu holding two of its commands, one grayed): `LoadAcceleratorsW`/`A`, `CopyAcceleratorTableW`/`A`'s entries and `DestroyAcceleratorTable` (`load`); `TranslateAcceleratorW` (`translate`) and `TranslateAcceleratorA` (`ansi`) on `WM_KEYDOWN`, `WM_KEYUP`, `WM_CHAR` and `WM_SYSKEYDOWN` the program posts to its own hidden window, with Ctrl, Shift and Alt set in the thread's key state by `SetKeyboardState`: the return and the `WM_COMMAND` the window receives; and the window holding the menu, a grayed item's command and a disabled window (`menu`).
  No handle prints: a table prints as found or not and as the same as another call's or not, its entries as `fVirt`, key and command.
  Gated.
- `coords` (user32) - window coordinates: `GetClientRect` and `GetWindowRect`, `MapWindowPoints` (the points and the return's two signed halves), `ScreenToClient` and `ClientToScreen`, `ChildWindowFromPoint` and `ChildWindowFromPointEx` (`CWP_ALL`, `CWP_SKIPINVISIBLE`, `CWP_SKIPDISABLED`) over visible, hidden and disabled children and a grandchild, `IsChild`, `OffsetRect`, and `CharNextA`/`W` and `CharPrevA`/`W` walked over plain text, the empty string, combining marks and a surrogate pair, as offsets.
  Its windows are hidden (but for `childpt`'s parent, shown without activation) at fixed screen positions, so their coordinates print as they are; a bordered or captioned window's client area prints only as its offset and size less the border, frame and caption metrics.
  Then the non-client area, in pixels as the standard scheme gives them: the frame, edge, caption, menu and caption-button metrics and `AdjustWindowRect`/`Ex` for fifteen frame styles, with and without a menu (`adjust`); each style's window and client sizes and client origin, against `AdjustWindowRectEx` (`frames`); the default window procedure's `WM_NCCALCSIZE`, both forms (`nccalc`); and its `WM_NCHITTEST` codes along rows and columns across shown windows of five styles, as runs (`nchittest`).
  Gated; `adjust` and `frames` stay pending while F2K's sizing frame on a window without `WS_BORDER` is a pixel wider than Windows 2000's (`frames` also while user32 has no `EqualRect` and F2K takes no scroll bars off the client area), and `nchittest` while F2K's `WM_NCHITTEST` leaves the gaps beside the caption buttons to the caption.
- `keyinput` (user32) - keystrokes injected with `SendInput` into the program's own window, as its procedure receives them: `WM_KEYDOWN`, `WM_KEYUP`, `WM_SYSKEYDOWN`, `WM_SYSKEYUP` and the characters `TranslateMessage` makes of them for the US layout (`WM_CHAR`, `WM_SYSCHAR`), wParam and lParam's repeat count, scan code and flags, and `GetKeyState`'s down bits during each.
  The keys: letters, Shift, a digit, calc's symbols and the keypad's operators (`letters`, `symbols`), Enter, Escape, Backspace, Tab and Ctrl+C (`control`), Alt+F and Alt alone (`alt`), the extended arrows and Delete (`extended`), a scan code alone and a virtual key with no scan code (`scancode`), a key pressed twice before its release (`repeat`), and an A window pumped through `PeekMessageA` and `DispatchMessageA` (`ansi`).
  Each section makes its window the foreground window first and prints whether it is; the input goes only to that window, so when it is not, the section says so and sends nothing.
  Each section prints whether the layout is US English and whether Caps Lock and Num Lock are on, which its characters depend on.
  Gated.
- `mousein` (user32) - mouse input injected with `SendInput` into the program's own window, centred on the screen with a push button: `DefWindowProcW`'s `WM_NCHITTEST` codes on the caption, its boxes, the borders, corners, client area and outside (`hittest`), `WM_MOUSEMOVE`, `WM_LBUTTONDOWN` and `WM_LBUTTONUP` with their client points and `MK_` flags, and `GetCursorPos` (`move`, `click`), `SetCapture`, `GetCapture`, `ReleaseCapture` and `WM_CAPTURECHANGED` between the window and its button, and a press dragged onto the caption under capture (`capture`), and a click on the button and its `BN_CLICKED` (`button`).
  Every point is computed from the window's own rectangle and the system metrics, and prints only as a relation to the points sent, never as coordinates; `SendInput`'s absolute coordinates are normalised to 0-65535 across the screen.
  Each section makes its window the foreground window first and prints whether it is; the input goes only to that window, so when it is not, the section says so and sends nothing, and before each press `WindowFromPoint` must find the window meant, or nothing is pressed.
  Each section puts the cursor back where it found it.
  Gated; every section but `hittest` is pending until F2K has a mouse.
- `clipbrd` (user32) - the clipboard: `OpenClipboard`, `CloseClipboard` and `EmptyClipboard` (with a window, with none, twice, while closed), `GetOpenClipboardWindow` and `GetClipboardOwner`; `SetClipboardData` of `CF_UNICODETEXT`, `CF_TEXT` and `CF_OEMTEXT`, and `IsClipboardFormatAvailable` and `GetClipboardData` of the formats the system synthesises from each (the text, its NUL and its size, `CF_LOCALE`); `CountClipboardFormats` and `EnumClipboardFormats`' order; `RegisterClipboardFormatA`/`W` and `GetClipboardFormatNameA`/`W`; the owner's `WM_DESTROYCLIPBOARD`; and delayed rendering through `WM_RENDERFORMAT` and `WM_RENDERALLFORMATS`.
  Every section leaves the machine's clipboard empty and closed at its start and its end, and retries each open for up to a second while another program holds the clipboard.
  No handle prints: a handle prints as non-NULL or not and as the same as another or not, a registered format as "registered".
  The capture expects code pages 1252 and 437 (each converting section prints whether they are), and no other program using the clipboard while it runs (a VirtualBox VM's shared clipboard disabled).
  Gated; `delayed` stays pending until delayed rendering (`SetClipboardData` with no data, `WM_RENDERFORMAT` and `WM_RENDERALLFORMATS`) is written.
- `wsprintf` (user32) - user32's own formatting, `wsprintfA`/`W` and `wvsprintfA`/`W`: `%d`, `%i`, `%u`, `%x` and `%X` with the `#`, `-` and `0` flags, widths, precisions and the `l` and `h` prefixes (`ints`); `%s`, `%S`, `%hs`, `%ls`, `%c`, `%C`, `%hc` and `%lc` in both forms, NULL strings, text crossing the forms through the ANSI code page and a NUL character (`strings`); `%%` and what wsprintf does not document, given numbers only: `%f`, `%o`, `%p`, `I64`, a `*` width, the `+` and space flags (`others`); the 1024-character limit, as the return, where the terminator lands and the units around unit 1024 (`limit`); and the `va_list` forms (`vprintf`).
  Every buffer is filled with `#` before a call and prints as its first ret+1 units, so the terminator shows.
  Built with `/MD`.
  Not gated: F2K's user32 has no wsprintf yet.
- `rects` (user32) - user32's rectangle helpers, which keep no state: `SetRectEmpty`, `IsRectEmpty` and `EqualRect` over empty, inverted and negative rectangles, and `CopyRect` (`empty`); `InflateRect` outwards, inwards past the middle and past the 32-bit limits (`inflate`); `PtInRect` on the edges and corners (`pt`); `IntersectRect` (`intersect`), `UnionRect` (`union`) and `SubtractRect` (`subtract`) over overlapping, touching, nested, disjoint, empty and inverted pairs and into one of their sources, `SubtractRect` with a rectangle covering a whole side, its middle, a corner or a stripe; and every helper with NULL pointers inside `__try` (`nulls`).
  Every line prints the inputs, the return and the rectangle the call left, a destination starting as (111,222,333,444).
  Built with `/MD`.
  Not gated: F2K's user32 has only `SetRect` and `OffsetRect` of them.
- `chars` (user32) - user32's character case and classification: `CharUpperW`/`A` (`upper`) and `CharLowerW`/`A` (`lower`) on a string converted in place and on single characters in the pointer's low word, over ASCII, Latin-1 (U+00FF, U+00DF), the Turkish i's, Greek, Cyrillic and fullwidth letters and their code page 1252 bytes; `CharUpperBuffW`/`A` and `CharLowerBuffW`/`A` over counts past a NUL, short counts and 0 (`buff`); and `IsCharAlphaNumericW`/`A` over letters, digits, punctuation, superscripts, Arabic-Indic and fullwidth digits, a Roman numeral and a CJK ideograph (`alnum`).
  Each section prints first whether the user and system default locales are 0x0409 and the ANSI code page 1252, which the case mapping and the character types follow.
  Built with `/MD`.
  Not gated: F2K's user32 has none of these calls yet.
- `props` (user32) - window properties, whose names are global atoms: `SetPropW`/`A`, `GetPropW`/`A` and `RemovePropW`/`A` by name, in other case, replacing a value, removing twice and a value of 0 (`string`); by atom, a `GlobalAddAtomW` atom read by name and the reverse, and `"#291"` against `MAKEINTATOM(291)` (`atom`); whether the name's global atom is there (`GlobalFindAtomW`) before and after `SetPropW`, a second `SetPropW`, `RemovePropW` and the window's destruction (`refs`); a second thread reading, setting and removing the first thread's window's properties (`thread`); and NULL, destroyed and another process's windows, a name never set, the empty name, a 300-character name and a NULL name inside `__try` (`errors`).
  Its window is hidden; the values are the program's own constants, and atoms and handles never print.
  Every section deletes the global atoms of its names (`F2KProps...`) at its start and end.
  Built with `/MD`.
  Not gated: F2K's user32 has no window properties yet, nor its kernel32 global atoms.
- `wintree` (user32) - the window tree: `GetParent` against `GetWindow(GW_OWNER)` for an unowned window, an owned pop-up, an owned overlapped window, a child and a grandchild, and an owned pop-up losing `WS_POPUP` (`parent`); `GetWindowThreadProcessId` of the program's own window, a second thread's, the desktop's, NULL and a destroyed window (`ids`); `EnumWindows` and `EnumChildWindows`: the program's windows in the order given, the lParam, a callback stopping early, NULL and destroyed parents (`enum`); `GetTopWindow` and `BringWindowToTop` over a parent's children and over top-level pop-ups (`zorder`); and `GetLastActivePopup` as owned pop-ups are shown, activated, hidden and destroyed (`popup`).
  A window prints by its label, never by its handle, and thread and process ids only as relations to the program's own.
  Enumeration goes over every window on the desktop, so its callbacks keep the program's own windows only; `GetTopWindow(NULL)`, another program's window, is not called.
  Its windows are hidden but for `popup`'s, which asks for the foreground first and prints whether it got it.
  Built with `/MD`.
  Not gated: F2K's user32 has none of these calls yet but `GetWindow`.
- `scroll` (user32) - scroll bars: `SetScrollInfo` and `GetScrollInfo` on a window's `WS_VSCROLL` and `WS_HSCROLL` bars, their returns, the range, the page, the position clamped to `nMax - nPage + 1`, a range the page covers with and without `SIF_DISABLENOSCROLL`, and bad arguments (`info`); a window given bars by `SetScrollInfo` (`added`); `ScrollBar` controls and their `SBM_*` messages (`control`); `SetScrollPos`, `SetScrollRange`, `GetScrollPos` and `GetScrollRange` (`posrange`); `ShowScrollBar` (`show`); `EnableScrollBar` with each `ESB_*` flag, the arrows' state probed through its return (`enable`); and `ScrollWindowEx` and `ScrollWindow`, their returns and the regions left to repaint, with `prcScroll`, `prcClip`, `SW_INVALIDATE`, `SW_ERASE` and `SW_SCROLLCHILDREN` (`scrollex`).
  A bar shows as the borderless window's client area narrower or shorter by a bar's width, never as a size; `scrollex` scrolls a topmost, borderless 200x100 window, so its rectangles, in client coordinates, print as relations to the rectangle each scroll uncovers.
  Not gated: F2K has no scroll bars yet.
- `caret` (user32) - the caret: `CreateCaret` (solid, gray, the default size), `DestroyCaret`, `SetCaretPos` and `GetCaretPos`, and the calls with no caret (`create`); `ShowCaret` and `HideCaret`'s hide count, `NULL` and a window not owning the caret (`show`); and the caret as the focus moves, on `CreateCaret` by another window, on its owner's destruction, in a window procedure making it on `WM_SETFOCUS` and destroying it on `WM_KILLFOCUS`, and against another thread's caret calls (`focus`).
  Whether the caret shows, its window and its rectangle come from `GetGUIThreadInfo` (through `GetProcAddress`), read at once after each call with no message retrieved between, so the caret's blink cannot turn them.
  Not gated: F2K has no caret yet.
- `editctl` (user32) - the built-in Edit control, single-line and `ES_MULTILINE`, driven by messages: its class, style and answers as created (`create`); `WM_SETTEXT`, `WM_GETTEXT` and `WM_GETTEXTLENGTH` through `SendMessageW` and `SendMessageA`, with short buffers (`text`); `EM_SETSEL`, `EM_GETSEL` and `EM_REPLACESEL`, and the caret's moves as relations (`select`); `EM_LIMITTEXT` and `EM_GETLIMITTEXT` (`limit`); `EM_GETLINECOUNT`, `EM_LINEINDEX`, `EM_LINELENGTH`, `EM_LINEFROMCHAR` and `EM_GETLINE` (`lines`); `EM_SETREADONLY` (`readonly`); `EM_CANUNDO`, `EM_UNDO`, `WM_UNDO` and `EM_EMPTYUNDOBUFFER` (`undo`); `EM_GETMODIFY` and `EM_SETMODIFY` (`modify`); `ES_UPPERCASE`, `ES_LOWERCASE` and `ES_NUMBER` (`case`); and the `EN_SETFOCUS`, `EN_KILLFOCUS`, `EN_UPDATE`, `EN_CHANGE` and `EN_MAXTEXT` notifications the parent receives, in order (`notify`).
  Typing is `WM_CHAR` posted to the focused edit; no key is pressed.
  Nothing printed depends on a glyph's width, F2K's fonts being stand-ins: no positions, short texts in `ES_AUTOHSCROLL` edits that never wrap or refuse text, and `EN_HSCROLL` and `EN_VSCROLL` not recorded.
  Not gated: F2K has no Edit control yet.
- `ttfont` (gdi32) - a TrueType font file the program loads itself, `f2ktahom.ttf` beside it: Wine's Tahoma (`fonts/tahoma.ttf`) with its family, full, unique and PostScript names changed to "F2K Tahoma" (`F2KTahoma`) by `scripts/font_rename.py`, and nothing else (`harness/test_fonts.py` checks the committed copy is the script's output).
  The real machine has Microsoft's own Tahoma installed, so the program asks for the copy by its own name, and the capture is Windows 2000's font engine on the bytes F2K reads.
  Every section but `load` adds the copy with `AddFontResourceExW(FR_PRIVATE)` at its start and removes it at its end.
  The sections: `AddFontResourceExA`/`W` and `RemoveFontResourceExA`/`W` with `FR_PRIVATE`, and `AddFontResourceA`/`W` and `RemoveFontResourceA`/`W` without it (`load`); `CreateFontIndirectA`/`W` and `CreateFontA`/`W` at lfHeight -11, -13, -16, -24 and +16, weights 400 and 700, `GetObjectA`/`W` and `GetTextFaceA`/`W`, and an unknown face's fallback as a relation (`create`); every `TEXTMETRIC` field and `GetOutlineTextMetricsA`/`W` (`metrics`); `GetCharWidth32A`/`W`, `GetCharABCWidthsA`/`W` and `GetTextExtentPoint32A`/`W` (`widths`); `EnumFontFamiliesExA`/`W` and `EnumFontFamiliesA`/`W` for the copy's face alone (`enum`); `GetFontData`'s tables, the whole file and partial reads, as sizes, bytes and CRC-32s (`data`); `GetGlyphOutlineA`/`W` with `GGO_METRICS` and `GGO_BITMAP`, the rows in hex (`glyphs`); the faces "MS Shell Dlg 2" and "MS Shell Dlg" resolve to (`mapper`); and `TextOutW` into a memory DC's DIB section, read back with `GetPixel` as rows of `#` and `.` (`pixels`).
  F2K's boot adds the font to `\CORPUS` beside the program (`data_files`).
  Gated; `glyphs` stays pending while F2K scan-converts outlines unhinted (two pixels at lfHeight -24 differ), `pixels` until memory DCs and bitmaps exist.
- `bitmaps` (gdi32) - bitmaps and blits, read back pixel by pixel, with the program's own bitmap (`bitmaps.rc`, compiled by the resource compiler and linked in, with `bitmaps.bmp`, an 8x8 bitmap of 4 bits in the VGA colors, checked in beside it).
  The sections: `CreateCompatibleDC` and the 1x1 monochrome bitmap a new memory DC holds, `CreateCompatibleBitmap` of the screen DC, of a memory DC and of one holding a DIB section, and one bitmap selected into two DCs (`compat`); `CreateBitmap` at 1 to 32 bits per pixel and its refusals, with `GetObjectA`/`W` (`create`); `CreateDIBSection` top-down, bottom-up, palettized and `BI_BITFIELDS`, its `DIBSECTION`, its bits written through the pointer and read back after `GetPixel` and `PatBlt` (`dibsect`); `BitBlt` with twelve raster operations over fixed values, offsets, overlaps, the surface's edge and no source DC (`blit`); monochrome to color through the destination's text and background colors, color to monochrome through the source's background color, and a 1-bit DIB section's color table (`mono`); `SetStretchBltMode`/`GetStretchBltMode` and `StretchBlt` shrinking under each mode, enlarging and mirroring (`stretch`); `GetDIBits` and `SetDIBits` across formats, scan lines and color tables (`dibits`); `SetDIBitsToDevice` and `StretchDIBits` from bottom-up, top-down and 1-bit DIBs (`todevice`); `CreateDIBitmap` (`createdib`); `CreatePatternBrush` with `SetBrushOrgEx`/`GetBrushOrgEx` (`pattern`); `GetObjectType` of each kind of object (`objtype`); and user32's `LoadBitmapA`/`W` and `LoadImageA`/`W` of `OBM_CLOSE`, `OBM_CHECK` and the program's bitmap, as a DIB section, stretched, as a device bitmap and monochrome (`load`).
  Every pixel it prints is read from a DIB section or a bitmap of an explicit format, as hex values or rows of letters; a bitmap of the screen's format (`CreateCompatibleBitmap` and `CreateDIBitmap` of the screen DC, `LoadBitmap`'s) prints its size, and its depth and pixels only as relations (the screen's depth, read back as written).
  Built with `/MD`.
  Not gated: F2K's gdi32 has no memory DCs, bitmaps or blits yet.
- `mapmode` (gdi32) - a memory DC's coordinate spaces and saved states: `SetMapMode`/`GetMapMode` across every mode and two invalid ones (`modes`); `SetWindowExtEx`, `SetViewportExtEx`, `SetWindowOrgEx` and `SetViewportOrgEx` with their `Get` forms in `MM_TEXT` and `MM_ANISOTROPIC`, and `LPtoDP` and `DPtoLP` of points whose mapping falls on halves (`extorg`); `OffsetViewportOrgEx`, `OffsetWindowOrgEx`, `ScaleViewportExtEx` and `ScaleWindowExtEx` (`offset`); `MM_ISOTROPIC`'s adjustment of the viewport (`isotropic`); `PatBlt` and `Rectangle` through a window origin and a scaling mapping into a DIB section, upright and flipped (`drawing`); and `SaveDC`/`RestoreDC`, relative and absolute, over the mapping, the colors, the modes and the selected objects (`savedc`).
  The metric modes' extents and `MM_ISOTROPIC`'s adjusted viewport follow the screen's size in millimeters and in pixels, which differ between machines: they print only as relations (their signs, the units per pixel the mode means within 1%, the same as another mode's).
  Built with `/MD`.
  Not gated: F2K's gdi32 has no mapping modes or memory DCs yet.
- `shapes` (gdi32) - pens, lines and shapes, each drawn into a 32-bit DIB section in a memory DC and read back through its bits pointer as rows of letters: `CreatePen` in each style at widths 0, 1 and 3 with `GetObjectW`'s `LOGPEN`, and each style drawn (`pens`); `ExtCreatePen`, cosmetic (solid, alternate, a user style, dotted) and geometric (end caps, a dash, miter, bevel and round joins), with `GetObjectW`'s `EXTLOGPEN` (`extpen`); `MoveToEx`, `LineTo` with its end pixel left out, and `GetCurrentPositionEx`, diagonals drawn both ways (`lines`); `Polyline`, and `Polygon` under `ALTERNATE` and `WINDING` (`SetPolyFillMode`/`GetPolyFillMode`) and with the null pen and brush (`poly`); `Rectangle`, `Ellipse` and `RoundRect` with the null pen and brush, at small sizes, and with a width-3 `PS_SOLID` and `PS_INSIDEFRAME` pen (`shapes`); and `SetROP2`/`GetROP2` over all sixteen mix modes, in hex (`rop2`).
  Built with `/MD`.
  Not gated: F2K's gdi32 has no pens, lines or shapes yet.
- `regions` (gdi32) - regions and a DC's clipping: `CreateRectRgn`, `CreateRectRgnIndirect`, `SetRectRgn`, `OffsetRgn`, `GetRgnBox`, `PtInRegion` and `EqualRgn` over plain, reversed, empty and deleted regions (`rect`); `CombineRgn` in each mode and the region type it answers (`combine`); `CreatePolygonRgn` under `ALTERNATE` and `WINDING` (`polygon`); `GetRegionData`'s sizes, header and rectangles (`data`); `FillRgn` (`fill`); `SelectClipRgn`, `IntersectClipRect`, `ExcludeClipRect`, `OffsetClipRgn`, `GetClipBox`, `GetClipRgn`, `PtVisible` and `RectVisible` (`clip`) and `ExtSelectClipRgn` in each mode (`extclip`), each with a drawing clipped into a DIB section and read back; and user32's `InvalidateRgn` and `GetUpdateRgn` on the program's own window (`update`).
  A region prints as its type, its box, its rectangles or a grid of `PtInRegion` answers.
  The `update` window is a topmost 64x48 popup at the screen's corner, shown, since a hidden window keeps no update region; its update region prints as its type and as the same as a region the program built or not.
  Built with `/MD`.
  Not gated: F2K's gdi32 has no regions or clipping yet.

The `crt` fixtures (msvcrt.dll's) are built with `/MD`: their C runtime is msvcrt.dll's rather than a static copy linked into the program.

- `hellomd` - `hello` built with `/MD` (`hellomd.c` includes `core/hello/hello.c`): msvcrt's startup protocol and `printf`.
  Gated.
- `crt` - startup and exit: `argv` and `envp` as `__getmainargs` builds them, `_fmode`, `_commode` and `_controlfp`, the initializers `_initterm` runs, and the exit paths (`exit` and its `atexit` handlers, `_exit`, `main`'s return, an unhandled exception).
  Gated.
- `seh` - structured exception handling compiled against msvcrt's `_except_handler3`: faults, filters, `__finally`, nesting, `RaiseException`, `setjmp`/`longjmp`, `longjmp` out of `__try` blocks, faults inside msvcrt's locked calls (`printf`, `fprintf`, `fgets`, `_write`) unwinding out of them, and `printf` from an `__except` filter.
  Gated.
- `fd` - the descriptor layer: `_open_osfhandle`/`_get_osfhandle`, `_dup`/`_dup2`, `_setmode` and `_tell`, the standard streams in `_iob`, `fgets`, `fread`, `fwrite`, `fseek`, `ftell` and `clearerr` in text and binary mode (CR LF translation, short reads, partial items, the end of the file, Ctrl-Z, a `w+` stream switching direction), `fgetws` and `fputws`, and `_getch` over console input the program queues itself.
  Gated.
- `wide` - the wide string, character-class and conversion functions, `iswctype` over each class mask, `swprintf` and `swscanf`, number parsing, the allocator, `qsort`, `rand`, `setlocale` and `time`, `gmtime`, `localtime` and `mktime` under time zones the program sets itself through `TZ` and `_tzset`, and `wcstok` (`wcstok`, each thread's position its own), `wcstod` (the double's bits, the end pointer and `errno`, `wcstod`) and `wcsftime` over fixed `struct tm` values in the "C" locale (`wcsftime`).
  Those times are fixed values, so they depend on neither the machine's clock nor its zone.
  Gated; `wcstok`, `wcstod` and `wcsftime` stay pending while msvcrt exports none of them.
- `strings` - `_itow`, `_ltow` and `_ultow` in several radixes, `_wtoi` and `atol` with `errno`, `abs` and `labs`, `strstr`, `wcspbrk` and `wcscspn`, `_wcsdup`, `_wcsrev` and `_strcmpi`, `strncat` and `_strdup`, `_splitpath` and `_wsplitpath`, `vswprintf`, and `wprintf` and `fwprintf` to the standard output and into a file in text and binary mode, its bytes read back.
  Radix 2 converts only values below 65536: Windows 2000's `_itow` overruns an internal buffer on longer radix-2 conversions.
  Gated.
- `process` - msvcrt's view of its process: the data exports `_acmdln`, `_wcmdln`, `__argc` and `__argv` against `GetCommandLineA`/`GetCommandLineW` and the `__p___argc`/`__p___argv` accessors, `getenv` over variables the program sets itself (`_putenv`, and `SetEnvironmentVariableA` behind the C runtime's back), operator `new` and `delete`, `_msize` and `_expand`, and `_beginthreadex`'s threads: their exit codes through the handle the C runtime leaves open, `_endthreadex`, and each thread's own `errno` (`beginthread`).
  The data exports and the C++ operators are reached through `GetProcAddress`, so the program stays C rather than C++; `_beginthreadex` and `_endthreadex` too, so the program loads where F2K's msvcrt lacks them.
  Gated; `beginthread` stays pending while msvcrt exports no `_beginthreadex` or `_endthreadex`.
- `msvcrt` - the exports no other crt fixture takes in: `ceil`, `floor`, `fabs` and `modf` over halves, signed zeros, infinities and NaNs, `_ftol`, the compiler's conversion to an integer, `_wfullpath` and `_getdcwd` against kernel32's answers, and `_ismbblead` over every byte under the single-byte code pages `_setmbcp` sets (1252, 437, 850, `_MB_CP_SBCS`, `_MB_CP_OEM`, `_MB_CP_ANSI`) (`mbblead`).
  Its paths print only as relations, so nothing depends on the machine's directories.
  Its program shares the DLL's name: the loader tells `msvcrt.exe` from `MSVCRT.dll` by the full name.
  Gated; `mbblead` stays pending while msvcrt exports no `_ismbblead`, `_setmbcp` or `_getmbcp`.
- `cxxeh` - C++ exception handling, the corpus's one C++ fixture (`cxxeh.cpp`, built with `/GX` and `/GR`): throw and catch by value, reference and pointer, derived classes caught by their bases (an ambiguous and a private base too) and `catch (...)` (`catch`, `derived`), rethrow (`rethrow`), nested try blocks (`nested`), the destructors unwinding runs for locals, temporaries and partly built objects and arrays (`unwind`), a C++ exception through `__try`/`__except` and `__finally` and what the filter sees (`seh`), `typeid` and `type_info`'s `name`, `raw_name`, `==`, `!=` and `before`, and `bad_typeid` (`typeid`).
  Its `purecall`, `terminate` and `abort` sections run the program itself as a child (`cxxeh kid <mode>`, not a section), its standard output and error one pipe the section reads once the child has ended: `_purecall`, `terminate` with and without `set_terminate`'s handler and with one that returns, an exception nothing catches, and `abort`, each with the child's exit code.
  Its `prolog` section is a second translation unit, `cxxehopt.cpp`, compiled with `/O1`, where Visual C++ calls msvcrt's `_EH_prolog` for a function's C++ frame instead of building it inline.
  It prints whether the program's own import table names `_EH_prolog`, then throws past a local, catches in a function's own try, calls a `__thiscall` member function whose `this` must survive the call, nests three frames, rethrows from a catch block, and returns through frames with no exception, the exception registration list as it was before.
- `wmain` - the wide startup, as a program whose main is `wmain` meets it (cmd.exe's): `argv` as `__wgetmainargs` splits a child's own command line (`args`), `envp` from a child's own environment block, against `__p___winitenv`, `__p__wenviron`, `_wgetenv` and the narrow environment `getenv` builds (`env`), the `__p___` accessors against `wmain`'s arguments and `envp` against `GetEnvironmentStringsW` (`accessors`), and `__wgetmainargs` and `__getmainargs` called directly (`getmainargs`).
  Its children are the program itself (`wmain kid <what>`, not a section), so neither the machine's paths nor its environment print.

Capture `files` and `fswrite` from a local FAT32 volume: F2K's boot volume is FAT32, and file-system details differ elsewhere — NTFS has its own names and timestamps, and a VirtualBox shared folder has no short names, no attribute bits and reports a remote drive.

### Capturing

After `build.bat`, run `capture.bat` on the real machine: it runs every section as its own process and writes each fixture's `output.txt` as blocks of `>>> <command line>`, the output, and `<<< exit code=N` (ERRORLEVEL, signed), after a provenance header (the OS build, the machine, the date, and the binary's source stamp).
The fixtures built on `common/f2kt.h` list their own sections (`<fixture>.exe --list`), so the script captures whatever the binary declares; `bare`'s modes are listed in the script.
Both scripts take a fixture's name (`build.bat dll`, `capture.bat dll`) to rebuild or recapture only that one.

`build.bat` stamps each of those binaries with the CRC-32 of its sources (a C++ fixture's every `.cpp` file, its own first) and `f2kt.h` (`common/srcsum.c` computes it; `<fixture>.exe --source` prints it), and `harness/test_repository.py` checks the stamp against the checked-in source, so a stale binary shows.
Binaries built before the stamp existed skip that check; once `build.bat` has rebuilt them all, set `REQUIRE_SOURCE_STAMPS = True` in `harness/test_repository.py`.

A block the script cannot take goes in the fixture's `overrides.txt` (same format, its reasons in the header): `runtime console` needs an interactive console, and `sched yield`'s `Sleep(10) does: yes` is the real-hardware answer the VirtualBox capture VM cannot give.
The suite merges it over `output.txt` (a block replaces the captured block with the same command line, or comes after them), so a recapture never drops it.

### Running against F2K

Each sectioned fixture's capture runs on the kernel, one pytest test per block (`make test` runs them with everything else; `-m corpus` selects them alone): one boot per fixture, the kernel command line listing the selected blocks' command lines in the capture's order (`-- CORPUS\runtime.exe crt ;; CORPUS\runtime.exe env`), and the kernel running each as its own process, one after another, each torn down and audited before the next starts.
The kernel announces each process's start on COM1 (`F2K: process 2 of 12: CORPUS\runtime.exe env`); the harness splits the boot's log there and compares each block's own part, the program's output line for line and its exit code.
The batch boots with the kernel option `redirected`: the programs' standard handles stand for the file capture.bat redirects them to, their writes reaching COM1 alone and never the screen, so a program that reads the screen back (through CONOUT$) finds what the real machine's screen held.
The first of a fixture's tests to run boots the batch, the others read its log; a run of one block (`uv run pytest tests/kernel32/runtime -k crt`) boots that block alone.
If the boot stops early (a kernel panic, a timeout, QEMU exiting), the block it stopped in fails with the reason and every later block fails as not run, naming it.
Each block keeps its `timeout` (the boot's start counts against the first).
Every boot's bounds, a block's and a kernel case's, count the boot's own time: the wall clock less what the host's load took from its QEMU, the time it waited for a core and, on macOS, the time its work took beyond what it would on the performance cores (`f2kboot.BootClock`).
So a bound means about what it means on an idle machine at `-n 12` too, while a guest that waits or hangs still runs out of it on the wall clock.
The disk build puts the sectioned fixtures in `\CORPUS` (the files fixture's data tree beside them), the way each runs from its own directory on the real machine.
The fixture's declaration, `fixture.toml`, states what its comparison allows: `gate = true` once F2K passes every block, `[pending]` for the blocks still on the work list (each with its reason: `search = "not yet implemented"`), both run as strict expected failures (a block that starts passing fails the run, so the marker goes with the fix; `--runxfail` shows each failure's first differing line), `[masks]` for the few capture lines that carry machine-specific values (per section, `"virtual" = ["... region * ..."]`: each `*` one value, a run of non-blank characters, each `**` any text, blanks included, and only in that section's block), `[pins]` for the exports each section pins (`event = ["kernel32.CreateEventA", "ntdll.NtCreateEvent"]`, `"*"` for every block: what the C runtime's startup calls; `scripts/compat.py` reports each export's coverage from them), a `timeout`, `retake` for a capture to be retaken (its blocks skipped), and `screenshots = true` for a fixture whose blocks deal with the screen: its boot pauses as each block's process ends (the kernel option `screens`), the harness saves the screen as QEMU shows it to `target/qemu/screens/<fixture>/<section>.png` and lets the boot go on (through a CMOS byte it writes with QEMU's monitor).
The screenshots are recorded only, never compared.
`[skip]` names the blocks that must never run on F2K, each with its reason (`actions = "F2K checks no shutdown privilege; the call would shut the test boot down"`): a call the real machine refuses, which F2K would carry out.
The batch boot leaves those blocks out, and each is reported as skipped with its reason, never compared.
A section both pending and skipped is an error.
`system_programs` names F2K's own programs, built by `make userland` from `userland/<name>`, that the fixture's boot needs in `\WINNT\system32` and the disk the tests boot leaves out (`system_programs = ["cmd"]`, for a section running the machine's own `cmd.exe`): its batch boots a copy of the disk with them added (`f2kboot.corpus_disk`), all its blocks in that one boot.
`data_files` names files of the fixture's own directory that its program reads beside it, as on the real machine (`data_files = ["f2ktahom.ttf"]`, a font the program loads): its batch boots a copy of the disk with them in `\CORPUS` (`f2kboot.corpus_disk`), so the disk the tests boot carries none of them.
`system_fonts = true` gives the fixture's boot the system's fonts, `fonts/*.ttf` (Wine's Tahoma, Tahoma Bold, MS Sans Serif, System and Marlett), in `\WINNT\Fonts`, where the kernel loads them at its start: its batch boots a copy of the disk with them added (`f2kboot.corpus_disk`), for a fixture whose capture shows the System font's metrics (`guidc`'s default font) or the dialog faces.
The disk the tests boot carries no fonts, so every other fixture's text is the kernel's built-in 8x16 font.
`harness/test_repository.py` checks each name is a program the Makefile builds and the base disk does not carry.
`boot_under` names one program on the boot volume, with no arguments (`boot_under = "WINNT\\system32\\fish.exe"`): the batch's command line wraps each of the fixture's block commands as `<boot_under> \\CORPUS\\<command>` (the corpus path rooted, so CreateProcess finds it from the program's own directory), so the boot runs that program first — FiSH sets the graphics mode before the block's program runs, which `hellogui` and `guidc` need (the screen DC's clipping region is empty until a mode is set) — and the process ends with the block's exit code, which is what the block compares (`f2kboot.block_command`, where the batch command line is built and where the run is judged).
`harness/test_repository.py` checks that only a sectioned fixture declares it and that its value is one program path with no arguments.
`storage = "ide"` boots the fixture's batch from the IDE disk (see the disk's two ways below), for a fixture that exercises the IDE path or prints what the storage device reports; `storage = "ram"` keeps it in memory even in an IDE run.
No fixture declares it today: none prints the device's bus or properties, and what they do print (the drive type, the volume's free space and serial, its names and times) is the same either way.
`[keys]` gives an interactive block the keys a person presses on the real machine while it runs: per section, a list of steps, each a table of what it waits for and what it presses, taken in order:

- `after`: the line of the block's own output to wait for, after the line the step before waited for (the block's markers: `ctrl keys` prints `step N: ...` before each of its waits);
- `screen`: the text the screen's last line (the last one holding anything but blanks, its trailing blanks dropped) must read, as the harness reads the text page through QMP: the program's echo, say, which shows a read is waiting;
- `press`: chords pressed and released one after another;
- `hold`: a chord pressed and held, released at the next step once that step's waits are met (or before the next block's keys), as a person's hand stays on the keys while the program looks at the input.

A chord is QEMU's key names (its qcodes: `a`, `ctrl`, `pause`, `ret`...) joined by `-`, pressed in order and released in reverse: `ctrl-c`, and `ctrl-pause` for Ctrl+Break.
The keys go through QMP's `input-send-event`, each press and release sent explicitly, in order: the monitor's `sendkey` queues each release behind a hold time of its own, which a chord held from another command would overtake.
As `tests/core/test_input.py` found, the emulator never repeats a held key, sends Pause's make and break together (`E1 1D 45 E1 9D C5`), and with Ctrl held sends Break's, together too (`E0 46 E0 C6`).
A step whose wait never comes leaves the rest of its block's keys unpressed: the block fails on its output, or its timeout.
A `[pending]`, `[skip]`, `[masks]`, `[pins]` or `[keys]` section with no captured block is an error, as is a mask that matches none of its block's lines.
The fixture's `test_<name>.py` only binds `f2kboot.corpus_test("<name>")`.
A sectioned fixture may be declared ahead of its real-machine files (`<name>.exe` and `output.txt`, both absent; its sources may come first, for the real machine to build): it is then one skipped test, and the disk build leaves it out; `harness/test_repository.py` refuses a fixture holding only one of them.
A fixture's companion DLLs and programs (`tests/<dll>/<name>/*.dll`, and the `*.exe` other than its own) go into `\CORPUS` beside its program, by their uppercase names (8.3, and distinct across the fixtures: `harness/test_repository.py` checks both), as they sit beside it on the real machine, and the DLLs in a subdirectory of the fixture's (`tests/<dll>/<name>/<sub>/*.dll`) into that subdirectory of `\CORPUS`.
Every corpus boot goes through QEMU's Multiboot loader (`-kernel`, the command line by `-append`), except `core/test_limine.py`'s: a few blocks (the scenarios the retired smokes ran on both paths, the command line, the memory map, and hellogui under FiSH) booted from the disk through Limine, together in one boot, on a copy of the disk whose Limine entry carries their command lines (`cmdline:`), each compared against its own capture with its own declaration.
A `-kernel` boot reads its disk from guest memory: the image is loaded as a Multiboot module named `f2k-disk` (`-initrd "<image> f2k-disk"`), the kernel's RAM disk (`kernel/src/block/ramdisk.rs`) reads and writes it in place, its writes vanishing with the boot, no disk is attached, and the guest has 256M (`f2kboot.storage_args`).
That takes the IDE controller's per-sector interrupts out of every disk read, about half of a corpus boot's time.
The IDE disk, attached as a QEMU snapshot, stays with the boots that test it: the kernel cases declaring `storage="ide"` (`nest-smoke`, whose diagnostic drives the disk's interrupt, and `fault-exitio`, which needs a read that blocks), every Limine boot (Limine reads the disk through the BIOS), every kept disk (`f2kboot.kept_disk`: its writes must reach the image), and a fixture declaring `storage = "ide"`.
`F2K_STORAGE=ide` boots every test that declares no storage from the IDE disk, as every boot did before the RAM disk: `F2K_STORAGE=ide make test` is the full IDE run (`ramdisk-smoke`, the RAM disk's own case, declares `storage="ram"` and keeps it).
The Makefile's corpus derives from the declarations too: a new fixture is its directory, in its DLL's group, and its `fixture.toml`.
Every boot's COM1 log stays under `target/qemu/logs/`, a batch's named after its fixture (`limine.log` for the Limine blocks).

### Tracing a slow block

`--perf-trace` builds the kernel with its `perf-trace` cargo feature and, once each boot is done, turns its COM1 log into a performance profile beside it: `target/qemu/profiles/<test id>.json` (a batch's `<fixture>.json`), one file per boot, loadable at profiler.firefox.com (Load profile from file).
The kernel's interval clock then samples the interrupted context and its call stack on every tick and dumps the samples before the line the harness stops the boot on; nothing of the trace compiles without the feature.
The stack walk follows the frame-pointer chain, which the perf build forces (the Makefile passes the flag; the first perf build rebuilds core and alloc), and every step of a user stack is validated against the process's own regions before it is read.
The converter, scripts/perf_profile.py — runnable by hand on any kept log — writes the profile: the kernel's samples one thread, the ring-3 samples another, the flame graph a call tree over real stacks.

The sampling rate is `SAMPLES_PER_TICK` in kernel/src/perf.rs (samples per platform tick, 1, 2, 4, 8, or 16).
Above 1 the interrupt source runs faster, which can quantize a timed wait one tick longer, so the tick-exact pins (the sleep smoke's) hold only at the default 1 — a profiling build is for inspection, not verification.
A boot longer than the buffer's 1024 samples keeps its most recent ones, up to 24 frames deep.
Every booting suite gets its profile — the corpus blocks, the Limine blocks, and the kernel cases alike; a boot that halts before its teardown (a fault case's kernel halt) has no dump to take, and a case whose last expectation passes before the teardown may cut the dump short.

## Script fixtures

A script fixture, `cmd/<name>/`, is a batch script, `<name>.cmd` (CRLF line endings), whose output under Windows 2000's own cmd.exe is the expectation for F2K's cmd.exe.
It holds the script, `fixture.toml` (`kind = "script"`), `test_<name>.py` binding `corpus_test("<name>")` as the sectioned fixtures' do, and, once captured, `output.txt`; nothing is built.
Its capture is one block, `>>> cmd /c <name>.cmd`: `capture.bat` runs the script by a cmd.exe of its own from the fixture's directory, its standard output and error into `output.txt` in order, and refuses to capture unless a cmd.exe started afresh has command extensions on, Windows 2000's default.
On F2K the block's boot attaches a copy of the disk with F2K's cmd.exe in `\WINNT\system32` and in `\CORPUS`, and the script in `\CORPUS` (`f2kboot.script_disk`), and runs `CORPUS\cmd /c <name>.cmd`: the kernel starts a program in its image's directory, so the script runs from `\CORPUS`, as on the real machine it runs from its own directory.
The disk the tests boot carries neither.
A script may run `spawnkid.exe`, the spawn fixture's companion: it sits in `\CORPUS` on F2K, and `capture.bat` copies it beside the script for the capture.
A script that needs other batch files (one to `call`, a `.bat` twin, a name `PATHEXT` searches for) writes them itself with `echo` and redirections, named after it: the disk carries the script alone.
A script prints nothing machine-specific where it can (`@echo off` first, no absolute paths), creates its files under its own name, and deletes them at its start and its end.
Its `masks` are a list, its one block's (`masks = ["**>echo two"]`), and its `pending` a string, its one block's reason, beside `gate = true` (`pending = "redirection not implemented"`); its declaration takes `gate`, `timeout` and `retake` too, and no per-section field.
A script fixture without its capture is awaited: one skipped test, and no boot.
A script's name is no internal command's, since cmd.exe reads `echo.cmd` as `echo` followed by `.cmd`: the scripts are named `bat` and what they observe.
What no script can capture (the interactive prompt, Ctrl+C and Ctrl+Break, a case that would open a window) is a checklist done by hand on the real machine, `cmd/HAND-CAPTURES.md`, each result pasted under its item there, since a script's capture holds its one block only.

## Legacy fixtures

The single-path smokes below predate the sectioned fixtures.
Each one's scenario reappears in a sectioned fixture (named above); they retire once the suite passes the sectioned fixture's blocks in their place (`tests/core/test_limine.py` names each successor).
`exit0` (the one-import boot smoke) and `hello` (the CRT smoke, the pinned import trace, and the disk-smoke checksum file) stay.
Their checks are the kernel cases in `core/kernel/test_kernel.py`; `exit0`, `ret0` and `hello` carry a `fixture.toml` of kind `smoke` (no capture).

- `exit0` - no C runtime: the entry point calls `ExitProcess(0)`; a single import, so it exercises process creation, image mapping and the exit path and nothing else.
- `ret0` - the default MSVC 6 `/ML` CRT startup around `int main() { return 0; }`; exercises the full CRT initialization surface (35 KERNEL32.dll imports; see `core/ret0/imports.txt`).
- `hello` - the console rung: the same CRT startup, then `printf` writes "Hello, world!" to stdout and exits 0; the first test with observable output.
  Also carries `trace.txt`, the real-machine import trace (21 of the watched imports called on the happy path, one WriteFile, exit 0 — the real-machine baseline for the console-observable corpus).

## Building

Run `build.bat` from a command prompt that has the MSVC 6 compiler on PATH (the VS command prompt sets this up, e.g. via `vcvars32.bat`).
The exact per-test command lines live in `build.bat`; expected exit code 0 means pass.
Each fixture builds inside its own directory, `<dll>\<name>`; the fixtures built on `common/f2kt.h` include it as `"../common/f2kt.h"`, which `build.bat`'s `/I ..` (the group's directory) resolves.

## How F2K consumes these

F2K loads every fixture from its boot disk: the disk build copies the single-path fixtures into the FAT32 volume's root directory by their 8.3 names (`EXIT0.EXE`, `RET0.EXE`, ...; see `DISK_FIXTURES` in the Makefile; the root's one cluster is full) and the sectioned fixtures into `\CORPUS`, and the kernel reads the selected program off the volume by path before loading it.
The disk's system directory, `\WINNT\system32`, holds the system DLLs the userland workspace builds: ntdll loads every program's DLLs from the volume, kernel32, msvcrt, advapi32 and user32 from there, the fixtures' companions from beside the program.
The suite attaches that disk to every case, kernel-path cases included.

A boot chooses its programs by command line: the text after `--` on the kernel command line is the programs' own command lines, `<program> [arguments]`, several separated by ` ;; ` (QEMU's `-append "-- CORPUS\sync.exe event ;; CORPUS\sync.exe mutex"`, the Limine entry's `cmdline:`, a kernel case's `cmdline`), run one after another, each its own process.
A command line's first token is the image's root-relative volume path (`.exe` added when it has no extension); the program's GetCommandLineA reports its command line verbatim and its GetModuleFileNameA the volume path.
Without a command line the kernel runs `exit0`.
The multi-process case lists `exit0`, `ret0`, `bare`, `bare`, `bare null-write`, `exit0`: the second `bare` catches frames reused without re-zeroing, `bare null-write` a fault that must end its process (through kernel32's start frame, with the access violation's code) before the last `exit0` runs.
Each process's start is announced on COM1 (`F2K: process 1 of 6: exit0`); its end prints the observed exit code and then the teardown audit (`F2K: teardown audit: frame database ok`; with several programs, each line names the process's index, and a summary line follows the last).
A child, a process another process starts, ends with its own line, `F2K: child process <pid> (<name>) exited normally (exit code=N)` or `F2K: child process <pid> (<name>) ended by fault (vector V, exit code=X)` (`<name>` its image's file name without the extension, as a listed program's), and no teardown audit line follows it.
The harness never takes that line as a program's end, and takes the child's own output, which the real machine's capture shows inside its parent's block, as its parent's output.
A block ends when its whole process tree has ended: the kernel prints a program's teardown audit line, and starts the next program, only once the program and every process descended from it have ended, and the harness takes the program's output up to that line, past the program's own end line (a `_P_OVERLAY` child prints after its parent has ended, as capture.bat's block holds it); the block's exit code is the program's own.
A kernel case can pass the kernel its own options, the text before `--` (`screens`), through its `kernel_options`.
The options `end-session=<flags>` and `session-wait=<ms>` drive the session's end (the `session-*` cases of `core/kernel/test_kernel.py`): the boot's first generated control event is taken for `ExitWindowsEx(<flags>)`, and each process's wait is shortened; a restart ends QEMU (its `-no-reboot`), which the harness takes for the boot's end after the kernel's restart line.
The `session-windows` cases need no option: their program, the `endsess` fixture's companion `endkid.exe`, asks for the session's end itself; they run on both boot paths.
Host unit tests still read the checked-in `.exe` files directly (`include_bytes!`, test builds only).
