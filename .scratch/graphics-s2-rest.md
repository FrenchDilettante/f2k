# Work order — graphics S2 remainder: the geometry/show services and the display-side services

For one implementation agent, working only from this order and the repository it
lives in. Everything the task needs is stated here or already in the tree;
nothing else is assumed. This file lives in `.scratch/`; it is a work order,
not product documentation, and it is deleted when the work lands.

## Standing rules

- This repository is a no_std i686 kernel plus its user-mode DLLs. Match the
  existing style of the file you touch. Comments describe what and why, never
  how, and never cite other operating systems or codebases. The one exception
  to external naming: documented public Win32 API names and types (export
  names, `DEVMODE`, the `Nt*` service names, handle and `NTSTATUS` spellings)
  are required naming — binary compatibility depends on matching them.
- Do not consult or derive from any other implementation's source. The
  fixtures' real-machine captures, the in-tree tests, and public Win32
  documentation are the behavior contract.
- Work on the branch `wip/graphics-s2`: commit there with plain feat-style
  messages and push the branch when done. Never touch `master`, never merge.
- The gates, when you report: `make check` clean, `make run-tests` green,
  `uv run scripts/compat.py --check` ok. Do not weaken an existing test to
  make it pass; report instead.
- Do not touch anything outside the scope fence at the end.

## Where things stand (the file map)

- `kernel/src/win32k/` on master: `class.rs` and `window.rs` (the class and
  window registries, wired into the service table with typed handlers —
  NtUserRegisterClassExWOW, NtUserUnregisterClass, NtUserGetClassInfo,
  NtUserGetClassName, NtUserSetClassLong/Word, NtUserCreateWindowEx,
  NtUserDestroyWindow), `winsta.rs` (window station/desktop, the boot's
  desktop and message windows), `display.rs` (the mode-set service and the
  VBE mode info), `dc.rs`/`font.rs`/`raster.rs` (GDI's DC side). One shared
  lock (`window::WindowManager`) guards the window manager's state.
- `window.rs`'s `Pump` trait is the message seam: the S3 slice owns the queue;
  keep the seam — make the show/setpos/geometry decisions real, but route
  message delivery through `Pump`.
- How a service is served: an `internal = true` record in
  `userland/user32/exports.toml` with
  `impl = { syscall = "crate::win32k::<module>::<handler>" }`;
  `kernel/build.rs` generates `WIN32K_SERVICES` (included in
  `kernel/src/win32k/mod.rs`) and user32's `int 2Eh` stubs. The handler is
  `fn(&mut NtCall, <args per the record's kinds>) -> NtResult` — see
  `winsta.rs`, `display.rs`, `class.rs`. Service numbers are Windows 2000's,
  listed in `userland/user32/w2k-services.txt`.
- Oracles: the fixtures' real-machine captures and pins —
  `tests/user32/guiwin/`, `tests/user32/guigeo/`, `tests/user32/guidisp/`
  (`fixture.toml` pins, `output.txt` captures). Those blocks stay
  expected-fail until the S5 user32 bodies land; do not try to make them
  pass. DEVMODE/DEVMODEW layouts and the CDS_/DISP_CHANGE values live in
  the userland rtl (`rtl::display`) — reuse them.

## The task

1. The geometry/show services the G2/G3 fixtures pin: `NtUserSetWindowPos`
   0x120F, `NtUserShowWindow` 0x1218, `NtUserShowWindowAsync` 0x1219, plus
   the window-geometry queries their pins name (e.g. `NtUserGetWindowRect` —
   pull the exact set from the fixtures' pins and the numbers from
   `w2k-services.txt`). Implement in `window.rs`: the decisions (z-order,
   show/hide state, move/size, the flags), message delivery through `Pump`.
2. The display-side services the G7 `guidisp` fixture pins:
   `NtUserEnumDisplaySettings` 0x116B, `NtUserEnumDisplayDevices` 0x1169,
   `NtUserEnumDisplayMonitors` 0x116A, `NtUserSetSysColors` 0x1204,
   `NtUserSystemParametersInfo` 0x121C — answering from the VBE mode info
   (`kernel/src/hw/vbe`) and the set mode's geometry (`display.rs`).
3. The review follow-ups recorded in the graphics plan under S2:
   - make the destroy cascade iterative (it recurses, about 1.7 KiB a level
     at opt-level 0; only ~15 of the 100 nesting levels fit the 32 KiB gate
     stack);
   - refuse the `REGISTER_SYSTEM_CLASS`/server-side-proc flags from
     user-mode register calls (only the window manager registers system
     classes, via its internal boot path);
   - update the primary monitor's work area in `display.rs` when the
     display mode changes;
   - wire process end into the window manager: destroy the process's
     classes and windows at teardown (`class::destroy_owner_classes` has
     no caller yet; the teardown audit counts them).
   - note: `NtUserCreateWindowEx`'s argument block is exactly the gate's
     `MAX_ARG_BYTES` — new records must stay within it.

## Scope fence

- user32's exported bodies (`ShowWindow`, `SetWindowPos`, `EnumDisplaySettingsA`,
  ...) are the S5 slice: do not implement them; catalogued records stay as they are.
- The message queue (`Pump` implementations, GetMessage/PostMessage bodies) is
  the S3 slice on `wip/graphics-s3`: keep the seam.
- Do not touch the GDI side (`dc.rs`/`font.rs`/`raster.rs`) beyond reading,
  the fixtures and their captures under `tests/`, or the harness.

## Report

`.scratch/graphics-s2-rest-assumptions.md`: one line per decision — what was
decided, why, and what would settle it — plus the gates' output and any open
questions.
