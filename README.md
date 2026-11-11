# F2K - Fenêtre 2000

A Windows 2000-compatible operating system written in Rust.

## What runs today

F2K boots on a PC (QEMU or VirtualBox) from a FAT32 disk and runs Win32 console programs built for Windows 2000, unmodified.
Seven of Windows 2000's system DLLs are F2K's own code:

- **ntdll**: the system calls into the kernel, the program loader, and the runtime library the other DLLs build on.
- **kernel32**: processes (child processes included) and threads, synchronization, memory, files, the console, the environment, code pages and locale, messages.
- **msvcrt**: the C runtime for programs built against msvcrt.dll: start-up and exit, exception handling and `setjmp`, the C++ exception frame `_EH_prolog` builds, files and stdio, `printf` and `scanf`, narrow and wide strings, `_putenv`, the allocator, rounding and the compiler's `_ftol`, full paths and the current directory, the time functions (`gmtime`, `localtime`, `mktime` and `TZ`), and starting child processes (`_spawn`, `_cwait`).
- **advapi32**: the registry calls, over a registry the kernel keeps in memory, and the process token's calls (`OpenProcessToken`, `LookupPrivilegeValue`, `AdjustTokenPrivileges`, `GetTokenInformation` for the privileges), which keep the privileges' state but check none.
- **user32**: window stations and desktops; window classes and windows (their creation and destruction, place, size and visibility, their coordinates and children); the non-client area (the frame, the caption and its buttons, and the menu bar, drawn in the classic look, `AdjustWindowRectEx`, `WM_NCCALCSIZE` and `WM_NCHITTEST`); menus opened by the keyboard (Alt, F10 and mnemonics, the arrows, Enter and Esc), not yet by the mouse; the message loop, sent and posted messages and the default window procedure; keyboard input (the keyboard's keystrokes and `SendInput`'s to the foreground window's focus, the key states, `TranslateMessage`'s characters for the US layout); painting (`BeginPaint`, the update regions) and the `GetDC` family, their DCs drawing at the window's client area; the drawing calls (`FillRect`, `FrameRect`, `InvertRect`, `DrawFocusRect`, `DrawEdge`, `DrawText`); the clipboard, its text converted between its ANSI, OEM and Unicode forms; the display's settings, devices, monitor, metrics and system colors and their brushes; `MessageBeep`; the rectangle and character-walk helpers.
- **gdi32**: device contexts of the screen and of windows, drawn on the VBE framebuffer, and their capabilities: text in a built-in 8x16 font or in TrueType fonts, the stock objects, solid brushes and `PatBlt`, the text and background colors, single pixels.
  TrueType fonts (monochrome, unhinted, a font's embedded bitmaps at their sizes) load from a file a program names (`AddFontResourceEx`), or at boot from `\WINNT\Fonts` when the disk carries them: the five faces in [`fonts/`](fonts/README.md), which the disk `make run` boots carries and the disk the tests boot does not.
- **shell32**: only `ShellAboutW`, a stub that answers FALSE, so programs that import it (Windows 2000's `calc.exe`) load.

F2K's own programs, written in Rust, live under `userland/<name>` and run from `\WINNT\system32`: [`pwd`](userland/pwd/README.md), [`ps`](userland/ps/README.md), [`shutdown`](userland/shutdown/README.md), [`cmd.exe`](userland/cmd/README.md), `fish` (FiSH), which sets the graphics mode (the VBE framebuffer) and runs the one program its command line names, ending with that program's exit code, and [`drawdemo`](userland/drawdemo/README.md), a window of user32's drawing calls for a screenshot.
Five test programs are built beside them and kept off the disk: [`keyshow`](userland/keyshow/README.md), which prints the keyboard messages its window receives, [`fontshow`](userland/fontshow/README.md), which draws text in Tahoma on the screen, [`dlgshow`](userland/dlgshow/README.md), a dialog of buttons and static text driven by the keyboard, [`menushow`](userland/menushow/README.md), a window with a caption, a border and a menu bar, its menus opened by the keyboard, and [`ehprolog`](userland/ehprolog/README.md), which checks the C++ exception frame msvcrt's `_EH_prolog` builds.

Windows 2000's own `cmd.exe` starts, runs its built-in commands (`dir`, `copy`, `set`, `type`, `md`...) and starts other programs, redirecting their input and output to files.
Up to 16 processes run at once.
Pipes (`|`) and new consoles for child processes are not there yet.
Functions F2K does not have yet are either absent or stubs that log their call (see the compatibility report below).

## Prerequisites

This project uses Nightly Rust via the `rust-toolchain` file, which also pulls in the `rust-src`, `clippy` and `rustfmt` components.
Your default toolchain remains unaffected.

Rust must come from [rustup](https://rustup.rs): it is what reads the `rust-toolchain` file and installs the pinned nightly.
A distribution `rustc`/`cargo` (Homebrew's `rust`, apt's `rustc cargo`) ignores the file and cannot build the kernel (`-Z build-std`, JSON target specs).

### macOS (ARM64 or x86_64)

```bash
brew install rustup x86_64-elf-binutils mtools qemu uv
rustup-init
# The Python tooling (pytest for the on-target tests) in a
# repository-local .venv, from pyproject.toml
uv sync
```

### Linux (x86_64)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
sudo apt install binutils mtools qemu-system-x86
curl -LsSf https://astral.sh/uv/install.sh | sh && uv sync
```

## Building

The system DLLs (`userland/`) are real PE32 DLLs, built at Windows 2000's base addresses.
They build first, into `target/userland/`: the kernel embeds ntdll, and the disk image carries all five in its system directory, `\WINNT\system32`, where ntdll loads the others from when a program starts, as on Windows 2000.
`userland/` is its own Cargo workspace with its own target (`userland/i686-f2k-pe.json`).
The kernel's build reads the built DLLs, so a bare `cargo check` or `cargo build` in `kernel/` (and rust-analyzer) fails until `make userland` has run once.

```bash
# Build the system DLLs only
make userland

# Build the kernel (the system DLLs first)
make kernel

# Build the disk image the tests boot (Limine on an MBR/FAT32 hard disk)
make disk

# Clean build artifacts
make clean
```

## Running

A boot runs the program its kernel command line names (`-- <program> [arguments]`; `exit0` without one).
Several programs, ` ;; ` between two, run one after another, or side by side with the kernel option `concurrent` before the `--` (`concurrent -- CORPUS\sched.exe sleep ;; hello`).
A program ends the session with `ExitWindowsEx` (`shutdown /l /y` does, from the command line): each program is asked to end, a program with windows through them (`WM_QUERYENDSESSION`, then `WM_ENDSESSION`; a window answering FALSE cancels the session's end), a console program through `CTRL_SHUTDOWN_EVENT` (its default handler ending it); then the boot volume is flushed and marked clean, the disk is told to write its cache out, and the machine halts on "It is now safe to turn off your computer." or restarts.
A program the boot runs starts in its program's directory with the same environment (`kernel/src/user/params.rs`): `COMPUTERNAME=QEMU`, `ComSpec=C:\WINNT\system32\cmd.exe`, `PATH=C:\WINNT\system32;C:\WINNT`, `PATHEXT=.COM;.EXE;.BAT;.CMD`, `SystemRoot=C:\WINNT`, `USERNAME=jeb` and `windir=C:\WINNT`.
A child process starts with what its parent hands it: its environment, its current directory and its inheritable handles.

### QEMU and VirtualBox

`make run` boots into F2K's `cmd.exe` in a QEMU window: the window shows the screen and takes the keyboard, and COM1, the kernel's log, goes to the terminal.
It boots `target/x86-f2k/debug/f2k-cmd-disk.img` (`make cmd-disk`), the disk with `cmd.exe` added to `\WINNT\system32` and the system's fonts ([`fonts/`](fonts/README.md)) in `\WINNT\Fonts`, through Limine.
`CMDLINE` overrides what the boot runs, the program's path on the volume and its arguments:

```bash
make run
make run CMDLINE='CORPUS\sync.exe event'
```

A GUI program runs under `fish`, which sets the graphics mode first: `fish <program>` at `cmd.exe`'s prompt, or `make run CMDLINE='WINNT\system32\fish.exe \WINNT\system32\drawdemo.exe'`.

`make vbox-image` writes the same disk as a VirtualBox disk, `target/f2k.vdi` (with `qemu-img`), with every file under `vbox-image/` laid over its volume at the same path; nothing there is committed.
A file there replaces the disk's own: `vbox-image/WINNT/system32/cmd.exe` replaces F2K's `cmd.exe`.

The VDI keeps the same UUID across rebuilds, so a VM keeps it attached: rebuild with the VM powered off.
F2K's disk driver is IDE, so the VM's disk goes on an IDE controller:

```bash
VBoxManage createvm --name F2K --ostype Other --register
VBoxManage storagectl F2K --name IDE --add ide --controller PIIX4 --bootable on
VBoxManage storageattach F2K --storagectl IDE --port 0 --device 0 --type hdd --medium target/f2k.vdi
VBoxManage modifyvm F2K --memory 256
VBoxManage startvm F2K
```

## Testing

### Host unit tests

```bash
make run-tests
```

### The export specs and the compatibility report

Each system DLL's exports are declared once, in `userland/<dll>/exports.toml` (the file's header documents its records): name, API group, prototype and implementation.
`tools/exportgen` reads the specs and generates what derives from them: the kernel's system-call tables, the `.def` files, and the system-call stubs.

As on Windows 2000, only three DLLs call into the kernel: ntdll for the NT system calls, and user32 and gdi32 for the window manager's and GDI's.
Both tables use Windows 2000's own call numbers (`userland/ntdll/w2k-services.txt`, `userland/user32/w2k-services.txt`).
Every other DLL is user-mode code on top of them, and the kernel has no Win32 layer.

A stub (`impl = { stub = "<reason>" }` in the spec) is an export that exists but does nothing yet: when called, it writes a line to COM1 with its arguments and the reason, then fails the way the real function fails (one that returns nothing just returns).
Code that reaches a case it doesn't handle yet can do the same, through `stub::stubbed`.
Stubs log through ntdll's `DbgPrint`, which Windows 2000's msvcrt and user32 do not import: the import check allows that one import (`STUB_LOG_IMPORT` in `scripts/compat.py`).

The host scenarios (`userland/kernel32/src/scenarios/`, all `#[cfg(test)]`) call kernel32's exports as a program does, against stand-ins for ntdll.
A known gap is an expected-failure test: a scenario marked `#[ignore = "<gap id>: <why>"]`, or a pending block in its fixture's `fixture.toml`.

The tests declare which exports they pin, as `dll.Export`: a corpus fixture in its `fixture.toml`'s `[pins]` (per section; `"*"` for every block), a host scenario in its doc comment's `/// Pins:` lines.
`scripts/compat.py` derives each export's status from its pinning tests' last results:

- grey: not implemented; darker grey, marked !: a stub;
- green: implemented, and a test passed;
- red, marked ×: implemented, and a test failed;
- yellow: implemented, with no test that passed or failed.

A border marks an export a pending or skipped corpus test pins: work in progress.
Every `make test` keeps its results (`target/test-results/pytest.json`); `make compat` runs the host scenarios and draws the report from both, `target/compat/report.html`, a treemap of every DLL with one square per export.
Below the treemap, one card per real program in `tests/compat/` shows its imports the same way.
A DLL among those programs is a compatibility target: F2K runs the real one, copied off the machine, instead of building its own (MFC42u.DLL), so it shows as a card, not in the treemap.
`--check` checks the pins against the specs and the captures, and that each DLL F2K builds imports only what Windows 2000's imports; `--run` runs every scenario, ignored ones included, and fails once a gap's test passes (the marker goes with the fix).

```bash
uv run scripts/compat.py --check
uv run scripts/compat.py --run
make compat          # both, and the report (after a `make test`, for its latest results)
```

Each spec lists every export of Windows 2000's own DLL (SP4's: ntdll, kernel32, advapi32, user32, gdi32, msvcrt, ole32, oleaut32, rpcrt4, psapi and version): an export F2K doesn't implement yet is a catalogued record (its name and ordinal only), and every implemented export keeps its Windows 2000 ordinal.
`scripts/dump_exports.py` reads a real DLL's export and import tables into `userland/<dll>/exports-<version>.txt` and `imports-<version>.txt`; `scripts/catalogue_exports.py` folds the export dump into the spec, after which the dump goes.
The import tables stay, for the import check.
The real DLLs never enter the repository.

### Everything

`make check-all` runs the test systems in turn, fastest first, stopping at the first failure: the host unit tests (`make run-tests`), the pins, the host scenarios and the report (`make compat`) and the on-target suite (`make test`; `PYTEST_FLAGS` passes through).

```bash
make check-all PYTEST_FLAGS="-n 2"
```

### On-target QEMU tests

The on-target tests run through pytest, so an IDE lists and runs them one by one:

- **The corpus.**
  Each fixture's `tests/<dll>/<name>/test_<name>.py` compares F2K with the fixture's real-machine capture (see `tests/README.md`): one test per captured block, the fixture's `fixture.toml` stating what the comparison allows and which blocks are still pending.
  A fixture's blocks share one boot, each block's program its own process, and each test compares its own part of the boot's COM1 log (`target/qemu/logs/<fixture>.log`).
  Selecting one block (`-k crt`) boots that block alone; if the boot stops early, the block it stopped in fails with the reason and the later ones fail as not run.
  Fixtures that draw on the screen can save a screenshot per block (`target/qemu/screens/`), not compared yet.
- **The kernel's own boots** (the fault stubs, the Limine disk path, the program smokes, the multi-process suite and its concurrent runs, the interrupt and IDE diagnostics) are cases in `tests/core/kernel/test_kernel.py`: the kernel features to build with, the image to boot, the program's command line, the COM1 strings expected (anywhere, in order, as one block of lines) or forbidden.
  A kernel panic fails every case.
- **The shutdown's boots** (`tests/core/test_shutdown.py`) type a file's creation, then `shutdown`, at cmd.exe's prompt, and read the disk image from the host after the halt or the restart: FAT[1]'s clean-shutdown bit, and FSInfo's free count against the FAT's; a second boot of the same disk finds the file.

Each test builds the kernel and disk for its feature set (once per run, cached under `target/qemu/builds/`); each run removes earlier runs' builds and logs older than two days.
Boots read the disk from guest memory (the kernel's RAM disk, over the image loaded as a Multiboot module) or, for the tests of the IDE path and the Limine boots, attach it as a snapshot, so tests run in parallel (`-n 4` by default in `make test`; `--dist loadgroup`, set in `pyproject.toml`, keeps a fixture's tests on one worker).
`F2K_STORAGE=ide make test` boots every test from the IDE disk instead (`tests/README.md`).
A boot whose writes must outlast it (the shutdown's) attaches a private copy of the disk instead, removed once its test is done.

```bash
make test        # every on-target test: the kernel boots and the corpus
uv run pytest --collect-only -q                     # list every test
uv run pytest tests/core/kernel -k fault-ud         # one kernel case
uv run pytest tests/core/bare                       # one fixture's blocks, one boot
uv run pytest tests/kernel32/runtime -k crt         # one block
uv run pytest tests/kernel32 -n 4                   # one DLL's fixtures
uv run pytest tests/kernel32/runtime --runxfail     # see why the work list fails
uv run pytest --no-build ...                        # reuse the last make disk (its features only)
make test KERNEL_PROFILE=dev-opt                    # the kernel's dependencies optimized
```

`KERNEL_PROFILE` picks the kernel's cargo profile (`make kernel`, `disk`, `run`, `test`...; the suite reads it as `F2K_KERNEL_PROFILE`): `dev`, the default, or `dev-opt` (Cargo.toml), which optimizes the kernel's dependencies (core, alloc, memcpy and memset) and keeps the debug assertions and overflow checks.
The kernel crate itself stays unoptimized: an optimized kernel hangs (see the profile's comment).

### Check code

```bash
make check
```

### Formatting

Rust sources are formatted with rustfmt (settings in `rustfmt.toml`): 100 columns for code and comments, imports grouped (std/core, external, crate) and sorted.
It splits overlong comment lines but never joins short ones, so wrap new comments at 100 yourself.
Hand-laid tables opt out with `#[rustfmt::skip]`.
Markdown files are formatted with rumdl (settings in `pyproject.toml`): one sentence per line, the editor wraps, and tables aligned.

```bash
make fmt         # format everything
make fmt-check   # fail if anything is unformatted
```

## Project Structure

```text
f2k/
├── rust-toolchain    # Nightly Rust for this project
├── rustfmt.toml      # rustfmt settings (make fmt)
├── Cargo.toml        # Workspace manifest
├── Makefile          # Build system
├── x86-f2k.json      # Rust target: 32-bit x86 bare metal
│
├── boot/             # Bootloader files
│   ├── *.asm, *.S        # Early custom boot sector experiments (unused)
│   ├── limine.conf       # Limine config (the disk images)
│   └── limine/           # Limine bootloader (git submodule)
│
├── scripts/          # Build and test scripts
│   ├── x86-elf-ld         # Linker wrapper
│   ├── linker.x86         # The kernel's linker script: its image's layout at 0x80400000
│   ├── loader.x86         # The boot loader's linker script: the loader and the image it carries
│   ├── create_partition_table.py  # MBR partition table for the disk image
│   ├── gen-files-data.py  # The files fixture's data tree (tests/kernel32/files/DATA)
│   ├── gen-nt-tables.py   # Windows 2000's service numbers and the status table, regenerated
│   ├── compat.py          # The DLL compatibility: the pins checked, the scenarios run, the report
│   ├── dump_exports.py    # A real DLL's export and import tables, dumped
│   ├── catalogue_exports.py  # A dumped export table folded into its DLL's spec
│   └── vbox_image.py      # The cmd disk as a VirtualBox disk (make vbox-image)
│
├── pyproject.toml    # The Python tooling (uv): pytest for the on-target tests
├── tests/            # Windows 2000 test corpus and the pytest suite (see tests/README.md)
│   ├── core/             # The kernel's own boots and the smoke fixtures
│   ├── kernel32/         # The kernel32 fixtures
│   ├── user32/           # The user32 fixtures (hellogui, winsta, the gui* fixtures)
│   ├── gdi32/            # The gdi32 fixtures (guidc, gditext)
│   ├── advapi32/         # The advapi32 fixtures (registry, token)
│   ├── crt/              # The msvcrt fixtures, built against msvcrt.dll (/MD)
│   ├── cmd/              # The script fixtures, batch files run by cmd /c
│   ├── harness/          # Checks of the tests and the repository (no QEMU)
│   └── common/           # The fixtures' shared header (f2kt.h) and stamp tool
│
├── tools/exportgen/  # The export specs' reader and generator, and the kernel's PE32 image's
│                     # emitter (a host crate, outside the workspace)
├── userland/         # The system DLLs (own workspace and target): rtl (the shared runtime),
│                     # ntdll, kernel32, msvcrt, advapi32, user32, gdi32, shell32; each DLL's
│                     # export spec in userland/<dll>/exports.toml, the DLLs F2K doesn't build
│                     # their spec alone;
│                     # F2K's own programs (pwd, ps, shutdown, cmd, drawdemo, keyshow, dlgshow,
│                     # menushow, ehprolog), each with its README
├── vbox-image/       # Files make vbox-image adds to the VirtualBox disk (not committed)
│
└── kernel/           # F2K Kernel
    ├── Cargo.toml        # Kernel package
    ├── build.rs          # The service tables from the export specs; the embedded ntdll
    ├── exports.toml      # ntoskrnl.exe's export spec
    ├── loader/           # The boot loader: the Multiboot image the loaders boot, carrying the
    │                     # kernel's image, ntoskrnl.exe, which it maps, relocates and enters
    └── src/
        ├── block/        # Block devices, partitions, the device registry, and the RAM disk
        ├── boot/         # Boot-related code
        ├── cm/           # The configuration manager: the registry, in kernel memory
        ├── cpu/          # The CPU tables
        ├── exec/         # Executable loading, and ntdll, the DLL every process maps
        ├── fs/           # FAT32 over the block devices, and the open files
        ├── hw/           # The hardware layer: devices the kernel drives directly
        ├── interrupt/    # The interrupt core (hardware-neutral, host-testable)
        ├── mem/          # Memory management
        ├── nt/           # The NT system services, by Windows 2000's numbers
        ├── ob/           # The object manager: handles and the objects they name
        ├── process/      # Process lifetime
        ├── sched/        # The scheduler
        ├── user/         # Ring 3: the user-mode boundary
        ├── win32k/       # Window stations and desktops, window classes and windows, the
                          # clipboard, the display-mode service behind the VBE framebuffer, and
                          # the screen DCs and their text: win32k's services, user32's and
                          # gdi32's calls
        ├── c_lib.rs      # C library stubs (linker support)
        ├── lib.rs        # Kernel library: kmain and all modules (unit-testable)
        └── main.rs       # Kernel binary: links the kernel (ntoskrnl); panic handler
```

## Targets

| Target            | Description                                                                      |
| ----------------- | -------------------------------------------------------------------------------- |
| `make userland`   | Build the system DLLs (`target/userland/`)                                       |
| `make kernel`     | Build the kernel, its image `ntoskrnl.exe` and the boot loader, the DLLs first   |
| `make test`       | Run every on-target QEMU test (pytest: the kernel boots and the corpus)          |
| `make run-tests`  | Run host unit tests                                                              |
| `make compat`     | Check the tests' pins, run the host scenarios, write the compatibility report    |
| `make check-all`  | `run-tests`, `compat` and `test`, in that order                                  |
| `make check`      | `cargo check` + clippy (the kernel, the boot loader and the userland crates)     |
| `make fmt`        | Format the Rust sources and the Markdown files                                   |
| `make fmt-check`  | Fail if a Rust source or a Markdown file is unformatted                          |
| `make limine`     | Download Limine bootloader                                                       |
| `make disk`       | Create Limine-bootable disk image, the one the tests boot                        |
| `make cmd-disk`   | The disk with `cmd.exe` added, its boot running `CMDLINE` (default `cmd.exe`)    |
| `make run`        | Boot the cmd disk in a QEMU window, into `cmd.exe` or what `CMDLINE` names       |
| `make vbox-image` | The cmd disk as a VirtualBox disk (`target/f2k.vdi`), `vbox-image/` laid over it |
| `make clean`      | Clean build artifacts                                                            |
| `make clobber`    | Remove all build artifacts                                                       |
