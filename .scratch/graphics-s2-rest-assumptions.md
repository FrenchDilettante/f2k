# Geometry/show and display-side services: assumptions, deviations, questions

One line per decision: what was decided — why — what would settle it.

## The destroy cascade

- The WM_DESTROY walk, the children's free and the owned windows' destroys are iterative, their
  state kept in the window record (`Walk`) — the order's follow-up (1.7 KiB a level, 100 levels) —
  settled: the host tests pin the order the recursive code had (`the_full_cascade_order`,
  `a_handler_destroying_a_sibling_stops_the_loop`, `owned_windows_go_first`) plus 99-deep child
  and 40-deep owner chains.
- An owned window whose destroy a hook vetoes now loses its owner, as one whose destroy fails did
  — the recursive scan restarted from the list's head and found the vetoed window again forever —
  a capture of a CBT hook vetoing an owned popup's destroy would settle what Windows does.
- The parent-depth check's subtree walk counts the window's own descendants only; the recursive
  one also walked its later siblings' subtrees — nothing calls it with a window yet (SetParent's
  path will) — public docs say nothing; SetParent's fixture would settle it.
- The destroy's hide runs through the new decisions: a child through ShowWindow(SW_HIDE) (so
  WM_SHOWWINDOW, WM_WINDOWPOSCHANGING, WM_WINDOWPOSCHANGED precede WM_DESTROY), a top-level window
  through SetWindowPos(SWP_HIDEWINDOW | NOACTIVATE | NOMOVE | NOSIZE | NOZORDER), no WM_SHOWWINDOW
  — the order the previous slice recorded, now with real messages — a capture of a destroyed
  visible window's message trace would settle the exact traffic.

## Class registration

- A user-mode NtUserRegisterClassExWOW with REGISTER_SYSTEM_CLASS or REGISTER_SERVER_SIDE_PROC is
  refused with ERROR_INVALID_PARAMETER (STATUS_INVALID_PARAMETER) before any memory is read — the
  order's wording; the error code is mine (no public source names one) — REGISTER_SERVER_CLASS
  stays allowed (the order names only the other two).

## A process's end

- The window manager learns of a process's end at its teardown (the idle thread's reap), for a
  process that ever entered win32k: its windows go, then its classes, then its threads' records —
  the order's wording; Windows 2000 destroys a thread's windows at the thread's end, which F2K's
  window manager does not hear about — a multi-threaded GUI fixture whose thread ends before its
  process would show the difference.
- Its threads' records are marked in cleanup first, so no hook vetoes their destroys — Windows
  2000's thread cleanup does the same (the in-cleanup flag the previous slice recorded).
- Each window is destroyed as its own thread, the top of each tree among the process's windows
  first; a zombie (a window another reference holds) is left to that reference — nothing takes a
  second reference yet.
- A child of another thread's window, whose destroy event found no queue (the message slice owns
  it), stays live with a dead parent; its own process's end destroys it as a top-level window
  (its parent link cleared) — settled once the queue delivers the posted destroy.
- At a quiescent teardown the object audit counts the processes' live windows and classes as
  leaks, in its "object audit FAILED" line, without sweeping them — the order's "the teardown audit
  counts them"; they hold no frames, so nothing needs giving back.

## Show and position

- ShowWindow's answer is the former WS_VISIBLE bit in the style's state byte: 16 for a visible
  window — the guigeo capture (ShowWindow(SW_HIDE) answers 16) — settled.
- ShowWindowAsync is carried out at once and answers success — no queue to post it to (the message
  slice's); the capture drains the queue before reading the visibility, so its lines match either
  way — the queue branch should post it to the window's thread instead (see Questions).
- A show command past SW_MAX (11, SW_FORCEMINIMIZE) is ERROR_INVALID_PARAMETER — no public source
  names the error — a capture of ShowWindow(h, 12) would settle it.
- WM_SHOWWINDOW (wParam TRUE/FALSE, lParam 0) is sent only when the visibility changes, and not for
  SW_SHOWNORMAL — the WM_SHOWWINDOW documentation ("not sent ... when SW_SHOWNORMAL is
  specified") — a message-trace capture would settle it.
- SetWindowPos with SWP_SHOWWINDOW or SWP_HIDEWINDOW neither moves nor sizes the window — the
  SetWindowPos documentation's remark; widely reported behaviour says Windows moves it anyway —
  a capture of SetWindowPos(h, 0, x, y, cx, cy, SWP_SHOWWINDOW) followed by GetWindowRect would
  settle it (see Questions).
- A visible window shown again (an activating command) is activated through the seam and nothing
  else is sent; an already hidden window's SW_HIDE does nothing at all — public docs say nothing
  about the messages — a message-trace capture would settle it.
- The non-activating commands are SW_HIDE, SW_SHOWNA, SW_SHOWNOACTIVATE, SW_SHOWMINNOACTIVE,
  SW_MINIMIZE and SW_FORCEMINIMIZE (SW_MINIMIZE "activates the next top-level window", per its
  documentation, which the min/max seam owns); a child's show never activates — ShowWindow's
  documentation.
- The minimizing and maximizing commands, and the restoring ones (SW_SHOWNORMAL, SW_RESTORE,
  SW_SHOWDEFAULT) of a minimized or maximized window, go through `Pump::min_maximize` first; the
  min/max geometry itself (the maximized rectangle, the iconic position) is that seam's, as the
  create path already treats it — the default pump does nothing, so SW_MAXIMIZE shows a window
  without maximizing it until the seam is filled.
- SW_SHOWDEFAULT does not read the startup info's wShowWindow — the thread records keep no show
  command — settled when the startup info carries it.
- A tiled window's first ShowWindow (whatever the command) sends the WM_SIZE and WM_MOVE its
  creation deferred, after the show, and clears the deferral; WM_MOVE carries the client area's
  position (parent-client coordinates for a child) — the previous slice's "deferred to show time".
- Hiding a thread's active top-level window activates the next one through `Pump::activate(window,
  Activate::Skip)` — ShowWindow's documentation (SW_HIDE "activates another window").
- SetWindowPos fills WINDOWPOS's x/y/cx/cy with the window's current values for SWP_NOMOVE and
  SWP_NOSIZE, and WM_WINDOWPOSCHANGED's flags gain SWP_NOMOVE/SWP_NOSIZE for what did not change —
  so the default procedure's WM_WINDOWPOSCHANGED handling can tell which of WM_MOVE/WM_SIZE to send.
- WM_SIZE and WM_MOVE after a SetWindowPos are the default window procedure's answer to
  WM_WINDOWPOSCHANGED (its documentation), not the decision's: `DefaultProcedure` sends none yet —
  the message slice's default procedure should.
- WM_NCCALCSIZE is sent with wParam FALSE and the new window rectangle (Payload::Rect), only when
  the size changes or SWP_FRAMECHANGED is given; otherwise the client rectangle moves with the
  window — the create path's form; Windows sends wParam TRUE with NCCALCSIZE_PARAMS on SetWindowPos
  — the queue branch's marshalling decides whether that matters.
- The WINDOWPOS the WM_WINDOWPOSCHANGING handler returns is taken whole (position, size, flags,
  insert-after) — the WM_WINDOWPOSCHANGING documentation.
- A handler that destroys the window during WM_WINDOWPOSCHANGING or WM_NCCALCSIZE ends the call
  with ERROR_INVALID_WINDOW_HANDLE — my choice.
- A negative cx/cy is taken as 0 — the create path's rule.
- Z-order: the topmost windows head their parent's list; HWND_TOP puts an ordinary window below
  them; HWND_BOTTOM makes a topmost window ordinary (documented); HWND_NOTOPMOST leaves an ordinary
  window alone (documented); a window to go after that sits in the other pile lands at the
  boundary; a window to go after that is no live sibling (or the window itself) changes nothing —
  the last two are my choices — a capture of SetWindowPos(h, <non-sibling>, ...) would settle them.
- Children have no topmost status: HWND_TOPMOST is HWND_TOP for them, HWND_NOTOPMOST nothing.
- An invalid insert-after handle is ERROR_INVALID_WINDOW_HANDLE unless SWP_NOZORDER — Windows
  validates hWndInsertAfter as a window handle — a capture would settle it.
- Owned windows do not move with their owner in the z-order (SWP_NOOWNERZORDER is the only
  behaviour) — left for later; ShowOwnedPopups' fixture would need it.
- SWP_NOREDRAW, SWP_NOCOPYBITS, SWP_DEFERERASE and SWP_ASYNCWINDOWPOS change nothing: nothing is
  painted yet (the paint side is the message slice's), and the async flag is carried out at once.
- SetWindowPos and ShowWindow work on any thread's window (no owner check), at once — Windows sends
  to another thread's window; without the queue the decision runs on the caller's thread.
- The desktop window is visible from the boot on, the message window is not — the desktop window
  of a running desktop is visible on Windows; it makes IsWindowVisible true for a visible top-level
  window and false for every message-only window.
- IsWindowVisible walks the parent chain; its bogus-handle answer is ERROR_INVALID_WINDOW_HANDLE
  (STATUS_INVALID_HANDLE from the kernel), as the capture's errors block shows (err=1400) — user32
  maps it.
- GetWindowRect and IsWindowVisible have no Windows 2000 service (user32 reads the window manager's
  records mapped into the process); F2K answers them through NtUserQueryWindow (0x11D2), with an
  index of F2K's own: 0 the documented WINDOWINFO (GetWindowRect reads rcWindow), 1 the visibility —
  the order's "window-geometry queries", there being no NtUserGetWindowRect — see Questions.
- NtUserQueryWindow checks the index (STATUS_INVALID_INFO_CLASS) and the length (exactly the
  answer's, STATUS_INFO_LENGTH_MISMATCH) before the handle, as the NT query services do.
- WINDOWINFO's borders are the client area's inset from the window's left and bottom edges (0 in
  the subset), its wCreatorVersion 0x0400 for a 4.0-or-later creator and 0x030A otherwise — the
  records keep no finer version.
- NtUserMoveWindow is SetWindowPos with SWP_NOZORDER | SWP_NOACTIVATE (| SWP_NOREDRAW when not
  repainting) — the MoveWindow documentation.

## Display

- The current mode (ENUM_CURRENT_SETTINGS and ENUM_REGISTRY_SETTINGS) is the mode that was set, or
  the default 640x480x32 before one is — the boot's work area assumes that mode; the registry holds
  no display settings.
- The listed modes are the BIOS list's 32-bpp linear modes, each resolution once, in its order — the
  only ones the driver sets; the capture's mode 0 (800x600x8) is the capture machine's driver's —
  a machine fact.
- The VBE driver lists its modes once: from the mode set's BIOS answers, or through a trampoline run
  when asked before the mode set; a caller arriving while another lists or sets is answered at once
  (STATUS_UNSUCCESSFUL), never made to wait, as the mode set already does.
- dmFields: 0x7C0000 for a listed mode, 0x7E0020 (DM_POSITION | DM_LOGPIXELS too) for the current
  one — the guidisp capture; dmLogPixels 96, dmPosition (0,0), dmDisplayFrequency 1 (the hardware's
  default, as EnumDisplaySettings' documentation allows; ChangeDisplaySettings takes it back),
  dmSpecVersion 0x0401, dmDriverExtra 0, dmDeviceName empty — the last two names are my choice.
- The DEVMODEW is written as far as the caller's dmSize goes, dmSize kept (the capture prints the
  caller's 124/188); a dmSize short of the display fields is STATUS_INVALID_PARAMETER.
- A mode number past the list is STATUS_NO_MORE_ENTRIES; the capture's EnumDisplaySettingsA(9999)
  sets no last error (err=-), so user32's body must not map it into one.
- Display devices: \\.\DISPLAY1 (the VBE adapter: attached to the desktop, primary, VGA-compatible,
  "VBE Display Adapter") and \\.\DISPLAY2 (the VGA text display the console uses before the
  graphics mode: on no desktop, "VGA Text Display") — the capture's EnumDisplayDevicesA(NULL, 1)
  answers TRUE, so a second device exists on Windows 2000 too (most likely a mirror driver there) —
  see Questions.
- EnumDisplayDevices(\\.\DISPLAY1, 0) answers its monitor, \\.\DISPLAY1\Monitor0, "Default
  Monitor", active and attached — EnumDisplayDevices' documentation (an adapter's name enumerates
  its monitors).
- DeviceID and DeviceKey are empty strings (no device has an interface name or a registry key in
  F2K); written only when the caller's cb covers them; a cb short of StateFlags is
  STATUS_INVALID_PARAMETER; past the devices STATUS_NO_MORE_ENTRIES.
- NtUserEnumDisplayMonitors does not call the callback (the kernel calls nothing back in user
  mode): it fills the caller's arrays of handles and rectangles (at most Count) and answers how many
  monitors qualify; user32 calls the callback — F2K's own argument list.
- The one monitor is the whole screen; its HMONITOR is 0x00010001 — F2K's own value, in a user
  handle's shape — MonitorFromWindow/Point/Rect (user32, later) must answer the same.
- A non-null HDC must name a DC of the caller's (STATUS_INVALID_HANDLE otherwise); a screen DC's
  coordinates are the screen's, so the clip is intersected as given.
- System colors: Windows 2000's "Windows Standard" scheme, 29 entries (COLOR_SCROLLBAR to
  COLOR_GRADIENTINACTIVECAPTION); index 25, unnamed, 0xB5B5B5 — the capture pins COLOR_WINDOW,
  COLOR_DESKTOP and COLOR_BTNTEXT; the rest are the scheme's documented registry defaults; index 25
  is a guess — a GetSysColor capture of every index would settle it.
- SetSysColors stores the RGB alone (the COLORREF's high byte dropped), checks every index before
  changing any (one past the table refuses the whole call, STATUS_INVALID_PARAMETER), ignores its
  flags, and sends no WM_SYSCOLORCHANGE (the queue's) — the refusal is my choice.
- The system colors are one table for every desktop, as Windows 2000 keeps them.
- SystemParametersInfo serves SPI_GETWORKAREA alone; any other action is STATUS_INVALID_PARAMETER
  — the pinned action; the rest come with their fixtures.
- A successful mode change sets the primary monitor's work area to the whole new screen and every
  desktop window to cover it, without WM_DISPLAYCHANGE (the queue's) — the order's follow-up.

## The message seam (`Pump`) and `window.rs`'s shared lines

- `Pump`'s signatures are unchanged and no method was added.
- `Pump::show` and `Pump::set_window_pos` are no longer called: the create's final show and the
  destroy's hide now call `Windows::show_window` / `Windows::set_window_pos`, which send their
  messages through `Pump::send` and reach `Pump::activate` / `Pump::min_maximize`.
- `Payload` gained a variant, `Payload::WindowPos(WindowPos)` (WM_WINDOWPOSCHANGING's and
  WM_WINDOWPOSCHANGED's WINDOWPOS, from rtl::window).
- The test pump `Rec` records WINDOWPOS payloads, can answer WM_WINDOWPOSCHANGING and
  WM_NCCALCSIZE, and vetoes one window's destroy (`veto_window`); its `show`/`set_window_pos` hooks
  stay but are no longer reached.

## Gates

- `make check`: clean (exit 0; no warning in the files this work touches — the one clippy note in
  `kernel/src/process/mod.rs`, a redundant closure in `release_address_space_of`, predates it).
- `make run-tests`: green (inside `make check-all`).
- `uv run scripts/compat.py --check`: "Compatibility check: ok".
- `make check-all PYTEST_FLAGS="-n 2"`: 647 passed, 3 skipped, 60 xfailed, 1 failed —
  `tests/harness/test_repository.py::test_the_spec_lists_every_fixture_import` (token.exe's advapi32
  imports), the known failure the shutdown branch fixes.
- The guidisp, guigeo and guiwin blocks stay expected failures: user32's bodies are not written.

## Questions

1. GetWindowRect/IsWindowVisible (and later IsWindow, GetClientRect, GetWindowLong...) read shared
   window records on Windows 2000. I put them behind NtUserQueryWindow (0x11D2) with F2K's own
   indexes, answering a WINDOWINFO or the visibility. Would you rather have a read-only shared
   mapping of the records (Windows 2000's design), or another service number?
2. EnumDisplayDevicesA(NULL, 1) answers TRUE on the capture machine. I list the VGA text display as
   \\.\DISPLAY2 (on no desktop) so F2K matches; the alternative is one device and a pending line.
   Which do you want?
3. SetWindowPos with SWP_SHOWWINDOW/SWP_HIDEWINDOW: I followed the documentation (no move, no size).
   A capture of SetWindowPos(SWP_SHOWWINDOW) with a new position would settle it; shall I add the
   line to guigeo's next capture?
4. `Pump::show` and `Pump::set_window_pos` are dead now. Remove them at the merge with the queue
   branch, or keep them for the queue's own use?
5. GetSysColor's read path: the table lives in the kernel (`display::sys_color`) but no service
   reads it (Windows 2000's user32 reads it from shared memory). The user32 slice needs one — the
   same question as 1.
6. ShowWindowAsync should post its show to the window's thread queue. The queue branch could add a
   `Pump` method (e.g. `post_show(thread, window, command) -> bool`, default false = carry it out
   now) and `WindowManager::show_window_async` would call it first.
