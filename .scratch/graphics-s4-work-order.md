# Work order — graphics S4: the gdi32.dll crate, the win32k DC objects, and TextOut onto the framebuffer

For one implementation agent, working only from this order and the repository it
lives in. Everything the task needs is stated here or already in the tree;
nothing else is assumed. This file lives in `.scratch/`; it is a work order,
not product documentation, and it is deleted when the work lands.

## Standing rules

- This repository is a no_std i686 kernel plus its user-mode DLLs. Match the
  existing style of the file you touch. Comments describe what and why, never
  how, and never cite other operating systems or codebases. The one exception
  to external naming: documented public Win32 API names and types (export
  names, `DEVMODE`, `TEXTMETRIC`, the `Nt*` service names, handle and
  `NTSTATUS` spellings) are required naming — binary compatibility depends on
  matching them.
- Never commit. Leave the work in the working tree and report.
- The behaviors this order states are the contract. Public Win32
  documentation is fine as background, but do not consult or derive from any
  other implementation's source — reimplementations of this system's
  interfaces are ruled out on licensing and correctness grounds alike.
- The gates: `make run-tests` (host unit tests) and `make test` (the on-target
  QEMU suite) green, and `uv run scripts/compat.py --check` ok, when you
  report. Do not weaken an existing test to make it pass; report instead.
- Do not touch anything outside the scope fence at the end of this order.

## Where things stand (the file map)

- The userland workspace: `userland/Cargo.toml` lists its member crates. Each
  system DLL is a crate `userland/<dll>/` with `exports.toml` — the one source
  of its export surface, every list of exports derives from it (the format is
  documented at the top of `userland/kernel32/exports.toml`; records carry
  name, ordinal, args, and an `impl`; `impl = { syscall = "..." }` with
  `internal = true` marks a win32k service stub the DLL raises itself).
  `kernel/build.rs` (its `DLLS` list, today ntdll/kernel32/msvcrt/advapi32/
  user32) reads every spec through `tools/exportgen` and generates the
  kernel's two service tables (`NT_SERVICES`, `WIN32K_SERVICES`) and each
  DLL's export stubs. The Makefile builds the DLLs (`SYSTEM_DLLS`) and copies
  them to `\WINNT\system32` on the disk, where the loader resolves a
  program's imports from.
- `userland/gdi32/` today holds only `exports.toml` (543 records catalogued
  from GDI32.dll 5.0.2195.6660: name + ordinal, none implemented) and
  `imports-5.0.2195.6660.txt` (the real DLL's import list — the harness pins
  every built DLL's imports within it). The crate does not exist yet; mirror
  `userland/user32/`'s skeleton (`Cargo.toml`, `build.rs`, `src/lib.rs`) and
  add `"gdi32"` to `userland/Cargo.toml`'s members, the Makefile's
  `SYSTEM_DLLS` (and its help text), and `kernel/build.rs`'s `DLLS`.
- How a DLL enters the kernel: only through its own `int 2Eh` stubs on
  win32k's service numbers (table 1: numbers from 0x1000, bits 12-13 of the
  number), routed by `user::syscall` into `win32k::lookup`. The landed
  precedent is user32's display family: `userland/user32/src/display.rs` and
  `userland/user32/src/imports.rs` (S1's `NtUserChangeDisplaySettings`),
  with the `internal` syscall records in `userland/user32/exports.toml`.
  The harness pins this: `tests/harness/test_repository.py`'s
  `WIN32K_CLIENTS = {"user32", "gdi32"}` already expects gdi32's stubs to be
  win32k-numbered, and the import-shape tests apply to gdi32 as to the others.
- The kernel's win32k side: `kernel/src/win32k/mod.rs` (the table and
  dispatcher, the generated `WIN32K_SERVICES`), with two landed modules as
  the handler pattern — `winsta.rs` (typed handlers
  `fn(&mut NtCall, ...) -> NtResult`, taking `Handle`/`UserPtr` from
  `crate::nt::call`, objects behind the object manager) and `display.rs`
  (S1's display service; note its one deliberate exception: it answers the
  `DISP_CHANGE` code in EAX, not an NTSTATUS — do not copy that shape, it is
  specific to that API).
- The object manager: `kernel/src/ob/` — typed pools behind generation-tagged
  `ObjectId`s, with the per-process handle table over them.
  `win32k/winsta.rs`'s `init()` shows creating objects and publishing them.
- The framebuffer seam: `kernel/src/hw/vbe/mod.rs` — `Bios` and
  `PixelMemory` traits (`put_pixel`, `fill_rect`, `clear`, `memory()`), the
  `Geometry` (address, pitch, width, height, bpp), `graphics_mode_set()`. Host
  tests drive the seams against fakes (the `FakeBios` tests in that module);
  the LFB is mapped uncached in the kernel's `FRAMEBUFFER` region, and the
  console stops presenting to the VGA text page once `graphics_mode_set()`
  (COM1 stays the serial log the suite asserts). S1's `test_framebuffer.py` boots
  `fish.exe \CORPUS\pipe.exe create`, which sets the mode through user32 and
  asserts the QMP screendump — the on-target precedent.
- The win32k service numbers are in `userland/user32/w2k-services.txt`
  (Windows 2000 SP4's table). The ones this slice needs: `NtUserGetDC`
  0x1186, `NtUserGetDCEx` 0x1187, `NtUserGetWindowDC` 0x11a7,
  `NtUserBeginPaint` 0x112a, `NtUserEndPaint` 0x1168, `NtGdiExtTextOutW`
  0x108e, `NtGdiEngTextOut` 0x1257, `NtGdiSetPixel` 0x1110, `NtGdiGetPixel`
  0x10bb, `NtGdiGetStockObject` 0x10c4. (The table has no `NtUserReleaseDC`:
  in the minimal subset `ReleaseDC`/`DeleteDC` stay client-side unless a
  fixture forces kernel state to be freed.)
- The fixtures: `tests/gdi32/guidc/` — `guidc.c` (315 lines, MSVC 6 build
  checked in with its real-machine `output.txt`) pins the DC surface: screen DCs, `TextOutA/W`, `ExtTextOutA/W`, `SetPixel`/`GetPixel`,
  `SetBkMode`/`SetBkColor`/`SetTextColor`, `GetTextMetricsA/W`,
  `GetTextExtentPoint32A/W`, `SelectObject`/`GetStockObject`/`DeleteObject`,
  `GetWindowDC`/`ReleaseDC`, `BeginPaint`/`EndPaint`. Its blocks are declared
  pending (`gate = false`) and flip when the imports they use are served.
  `tests/user32/hellogui/imports.txt` pins the rung's closure: gdi32's
  `TextOutA` is its only gdi32 import.

## The task

S4, in four parts. Screen DCs only — window DCs and
`BeginPaint` come with the window slices, do not build them here.

### A. `gdi32.dll` as a built crate

Create the crate (skeleton of user32's) and implement, as real exports in
`userland/gdi32/exports.toml` (records flip from catalogue to `impl`, keeping
the real ordinals), the minimal genuine subset that guidc exercises on
the gdi32 side: `CreateDCA`/`CreateDCW` (and `CreateCompatibleDC*` if guidc
calls it), `DeleteDC`, `TextOutA`/`TextOutW`, `ExtTextOutA`/`ExtTextOutW`,
`SetPixel`/`GetPixel` (gdi32 exports whose bodies call the
`NtGdiSetPixel`/`NtGdiGetPixel` services), `SetBkMode`,
`SetBkColor`/`GetBkColor`, `SetTextColor`/`GetTextColor`, `SelectObject`,
`GetStockObject`, `DeleteObject`, `GetTextMetricsA`/`GetTextMetricsW`,
`GetTextExtentPoint32A`/`GetTextExtentPoint32W`. Each body marshals to its
win32k service through gdi32's own `int 2Eh` stub on the service's number
(internal syscall record in gdi32's `exports.toml`), exactly as user32's
display bodies do. The narrow forms convert A→W with the platform's own
conversion (the real gdi32 imports it from ntdll — check
`imports-5.0.2195.6660.txt` and stay within it). Everything else in gdi32's
catalogue stays stubbed.

### B. The win32k DC objects and their services

- A DC is a typed-pool object (the `ob` pattern) holding: the target
  (the screen — the whole framebuffer, clip = full geometry), the text color,
  the background color, the background mode (OPAQUE/TRANSPARENT), and the
  selected stock object. It gets a handle-table entry in the creating process,
  so `NtUserGetDC` (0x1186) answers a handle, and the handle closes with the
  process like every other (teardown audit covers DC objects).
- Handlers in a new `kernel/src/win32k/dc.rs`, at the numbers above:
  `NtUserGetDC`/`NtUserGetDCEx` create the screen DC (the display's geometry
  comes from `hw::vbe` — the `InitOnce` geometry set before the mode state
  says set), `NtUserGetWindowDC` (0x11a7) same for now (no windows exist;
  answer as a screen DC, recorded as the seam where window binding lands with
  the window slices). Reading caller arguments uses the `UserPtr`/`UserAddr`
  discipline of `nt::call` — never raw pointers.
- `NtGdiSetPixel` (0x1110) / `NtGdiGetPixel` (0x10bb): one pixel through the
  DC's target via the `PixelMemory` seam, clipped to the DC's clip rect.
- `NtGdiGetStockObject` (0x10c4): the stock ids guidc uses answer with a
  well-known constant handle value per id (recorded as the seam where real
  stock objects land); `SelectObject` stores it on the DC.
- Color/mode services the DC state needs are whatever guidc's calls marshal
  to; keep the DC's state as plain fields with host-testable setters.

### C. The rasterizer and the font

- The font is a built-in public-domain 8x16 VGA bitmap as plain data: 256
  glyphs × 16 bytes, row-major, bit 7 of each byte the leftmost pixel. It
  enters as data, no citation (public font facts). New
  `kernel/src/win32k/font.rs` with host tests.
- `NtGdiExtTextOutW` (0x108e) is the one text service: the `NtGdiEngTextOut`
  (0x1257) engine entry collapses into the same handler. The handler
  rasterizes the wide string at (x, y) into the DC's target through
  `PixelMemory`: glyph pixels in the DC's text color, and — for the minimal
  OPAQUE behavior — the glyph cell's background in the DC's background color
  (TRANSPARENT leaves the background). Clip every pixel to the DC's clip rect.
  Host tests drive it against a fake `PixelMemory` and assert exact pixels.
- `GetTextMetricsA/W` and `GetTextExtentPoint32A/W` answer from the font's
  fixed metrics (8x16 cells: height 16, average width 8, overhang 0, and the
  rest zeroed as the platform's defaults) — the extent of a string is its
  length × 8 × 16. Host-testable.

### D. The on-target smoke

Extend the S1 precedent: a core test (beside `tests/core/test_framebuffer.py`)
that boots FiSH running a corpus program which creates a screen DC and paints
with `TextOutA`, asserting its exit code on COM1 and — via the QMP screendump
machinery in `tests/f2kboot.py` (`read_png`) — that the painted glyphs are
visible (the screenshot comparison itself stays deferred; assert the dump is
640x480 and no longer solid desktop color, and record the PNG as an artifact).
Pick the smallest existing corpus binary that fits, or add a tiny one under
`tests/gdi32/` the way `guidc` is declared; the boot's `CMDLINE` runs
`WINNT\system32\fish.exe <program>` so the mode is set first.

## Scope fence

Do not touch: the window/event slices (classes, windows, queues, `BeginPaint`'s
window path, `GetDC`/`GetWindowDC`/`ReleaseDC` user32 bodies — later slices),
user32's crate beyond what the harness already pins, the console and text
screen, the loader and disk, the VBE driver and trampoline, `hw::pic`/the
interrupt core, the scheduler, the corpus captures and the other fixtures'
declarations. gdi32's export surface beyond the guidc/hellogui subset named
above stays stubbed. Pixel comparison stays deferred (a ruling to respect):
assertions are exit codes, serial lines, and the screendump artifact's presence. Public
API naming only where the ABI demands it.

## Done means

- Host unit tests green: the font data's shape (256×16), the rasterizer
  (exact pixels for a known string, OPAQUE vs TRANSPARENT, clipping at every
  edge, wide-string handling), the DC object lifecycle (create, handle,
  teardown), the pixel services, the metrics/extent answers, and the A→W
  conversion path.
- `make run-tests`, `make test` and `uv run scripts/compat.py --check` green;
  no existing test weakened or removed.
- The guidc blocks whose imports this slice serves go green under FiSH (flip
  their `gate`), with their screenshots recorded; the rest stay pending.
- A report: what landed, the seams left for the window slices (window DCs,
  `BeginPaint`, real stock objects), any deviation from this order with its
  reason.
