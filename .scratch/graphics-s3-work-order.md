# Work order — graphics S3: the message/event layer (queue, timers, paint)

For one implementation agent, working only from this order and the repository it
lives in. Everything the task needs is stated here or already in the tree;
nothing else is assumed. This file lives in `.scratch/`; it is a work order,
not product documentation, and it is deleted when the work lands.

## Standing rules

- This repository is a no_std i686 kernel plus its user-mode DLLs. Match the
  existing style of the file you touch. Comments describe what and why, never
  how, and never cite other operating systems or codebases. The one exception
  to external naming: documented public Win32 API names and types (export
  names, `MSG`, `PAINTSTRUCT`, the `Nt*` service names, `WM_*`, handle and
  `NTSTATUS` spellings) are required naming — binary compatibility depends on
  matching them.
- Do not consult or derive from any other implementation's source. The
  fixtures' real-machine captures, the in-tree tests, and public Win32
  documentation are the behavior contract.
- Work on the branch `wip/graphics-s3`: commit there with plain feat-style
  messages and push the branch when done. Never touch `master`, never merge.
- The gates, when you report: `make check` clean, `make run-tests` green,
  `uv run scripts/compat.py --check` ok. Do not weaken an existing test to
  make it pass; report instead.
- Do not touch anything outside the scope fence at the end.

## Where things stand (the file map)

- `kernel/src/win32k/` on master: `class.rs`, `window.rs` (the class and
  window registries, their services wired), `winsta.rs`, `display.rs`, and
  the GDI side (`dc.rs`, `font.rs`, `raster.rs` — a screen DC is an object in
  the process's handle table, `NtUserGetDC*`/`NtGdiOpenDCW` make one).
- `window.rs`'s `Pump` trait is the message seam the S2 slice left: `send`
  delivers a `Message` to a window (the default procedure answers 1 to
  WM_NCCREATE and 0 to the rest), plus `show`, `set_window_pos`,
  `attach_input`, `post_destroy_event` and friends. This slice makes them
  real by routing through the queue you build.
- Thread records live in the window manager (`window.rs`'s `Thread`), keyed
  by the thread object's pool index and generation; map them to the
  scheduler's thread where the pump names one.
- How a service is served: an `internal = true` record in
  `userland/user32/exports.toml` with
  `impl = { syscall = "crate::win32k::<module>::<handler>" }`;
  `kernel/build.rs` generates `WIN32K_SERVICES` and user32's `int 2Eh` stubs.
  The handler is `fn(&mut NtCall, <args per the record's kinds>) -> NtResult`.
  Service numbers are Windows 2000's, in `userland/user32/w2k-services.txt`.
- Oracles: the fixtures' real-machine captures and pins —
  `tests/user32/guimsg/`, `tests/user32/guipaint/` (`fixture.toml` pins,
  `output.txt` captures). Those blocks stay expected-fail until the S5
  user32 bodies land; do not try to make them pass. Host tests plus the
  gates are the acceptance.

## The task

1. **The queue**: a per-thread message queue as a typed-pool object inside the
   window manager (one shared lock as on master). Posted messages
   (`NtUserPostMessage` 0x11CB and the `PostThreadMessage` variant — numbers
   in `w2k-services.txt`) enqueue; `NtUserGetMessage` 0x119A (and
   `NtUserPeekMessage`) dequeue with the documented filter semantics (hwnd,
   wMsgFilterMin/Max, the remove flags) and block on an empty queue — the
   scheduler's wait machinery is the mechanism (look at how other services
   block). WM_QUIT: `PostQuitMessage` is client-side over
   `NtUserCallOneParam`; serve whatever the pins need.
2. **Sent messages**: `Pump::send` becomes the real dispatcher — the
   window's wndproc is called through the queue's send path, and the
   creation/destroy/show/setpos calls in `window.rs` route their messages
   through it (replacing the default-procedure stubs where the pins require).
3. **Timers**: `NtUserSetTimer`/`NtUserKillTimer` (numbers in
   `w2k-services.txt`) posting WM_TIMER on expiry — the console's timer
   machinery (the PIT/scheduler timeouts) is the mechanism.
4. **Paint**: the invalidate/validate path — `NtUserInvalidateRect`/
   `NtUserValidateRect`/`NtUserGetUpdateRect` (numbers in the txt) tracking
   the window's invalid region, generating WM_PAINT when the queue is read,
   and `NtUserBeginPaint` 0x112A / `NtUserEndPaint` 0x1168: BeginPaint hands
   out the window's DC (the GDI side's `dc.rs` — extend it from screen-only
   to a window's DC clipped to the window, if the pins need it) with the
   `PAINTSTRUCT` filled (`rcPaint` = the invalid region), EndPaint validates.
5. Input translation stays out (ruled for this rung): the key-event →
   WM_KEYDOWN/WM_CHAR seam remains a seam in `Pump`.

## Scope fence

- user32's exported bodies (`GetMessageA`, `PostMessageA`, `BeginPaint`,
  ...) are the S5 slice: do not implement them.
- The geometry/show and display-side services are the S2-remainder slice on
  `wip/graphics-s2`: do not implement them.
- No hooks, DDE, menus, clipboard beyond what the fixture pins trip; no
  window decoration. Do not touch the fixtures/captures under `tests/` or the
  harness.

## Report

`.scratch/graphics-s3-assumptions.md`: one line per decision — what was
decided, why, and what would settle it — plus the gates' output and any open
questions.
