# The message layer: assumptions, decisions, deviations

What the queue, sent-message, timer and paint work on `wip/graphics-s3` decided where the
captures, the pins and the order did not settle it. One line each: the decision, why, and what
would settle it. The order is `.scratch/graphics-s3-work-order.md`.

## How a sent message reaches a window procedure

- **No kernel-to-user callback.** F2K has no KeUserModeCallback (nothing calls user code and
  returns into the kernel). Why: the window manager's decisions run under its `ShortLock` with
  `&mut Windows` borrowed through every `Pump` call, so a synchronous call into user mode would
  need the create/destroy paths split at every send (Windows 2000's `xxx` re-validation). Settle:
  the owner's call on whether a real callback (trap frame nesting, NtCallbackReturn) is wanted
  later.
- **The window manager's sends are queued for the window's thread.** `QueuePump::send` queues
  every message to a window with a client procedure as a sent message (no sender) and answers as
  the default procedure (1 to WM_NCCREATE, 0 otherwise). The thread's next GetMessage/PeekMessage
  hands them out first, with the procedure and a copy of the structure (`rtl::user::Receipt`).
  Why: the order's "in the receiving thread's own GetMessage" option; the guimsg counts (6, 12,
  last message WM_NCDESTROY) only need the messages to arrive in order. Settle: user32's
  message-loop bodies passing guimsg.
- **Limits of the deferral, recorded:** a procedure's answer never reaches the decision (a 0 to
  WM_NCCREATE does not cancel, -1 to WM_CREATE does not fail); changes a procedure makes to
  WM_NCCALCSIZE's rectangle or CREATESTRUCT are lost; a title set during WM_NCCREATE is not seen
  by WM_CREATE; a handler destroying a sibling runs after the cascade. Settle: a real callback.
- **user32's side (for the user32 bodies):** after any service that can send (CreateWindowEx,
  DestroyWindow, ShowWindow, SetWindowPos, UpdateWindow, DefWindowProc's WM_CLOSE), user32 drains
  with `NtUserPeekMessage(&receipt, 0, 0, 0, PM_REMOVE | PM_QS_SENDMESSAGE)` until it answers
  RECEIVED_NONE, calling `receipt.proc(msg.hwnd, msg.message, msg.wparam, msg.lparam)` for each
  RECEIVED_SENT and then `NtUserCallOneParam(answer, ONE_PARAM_END_SENT_MESSAGE, &r)`. GetMessage
  and PeekMessage loop the same way over RECEIVED_SENT before returning. The receipt's `proc` is
  the class's procedure value as registered: ANSI/Unicode translation is user32's. Why: one
  protocol for every sent message. Settle: user32's bodies.
- **The window manager's own sends are delivered even after the window is gone** (WM_NCDESTROY
  arrives after DestroyWindow freed the record, as the defproc capture's IsWindow=no after
  shows); a send from another thread to a window destroyed before it is read is answered 0 and
  never handed out. Why: the capture needs the first; the second matches Windows 2000's refusal to
  call a dead window's procedure for another thread. Settle: a cross-thread capture.
- **SendMessage to the caller's own window** answers the procedure (`NtUserMessageCall`'s
  `Proc`) and user32 calls it, as Windows 2000's user32 calls a same-thread procedure directly.
  To a window whose procedure is the window manager's (the desktop, a zombie) it answers the
  default procedure's answer. Why: the send capture is same-thread. Settle: user32's bodies.
- **SendMessage to another thread's window** queues it on that thread and the sender waits (on
  its own queue's event) for the answer. The waiting sender does not deliver messages sent to it
  meanwhile: two threads sending to each other deadlock. Why: the order's scope is the queue's
  send path; nested delivery inside a wait would need the sender to return to user mode
  mid-wait. Settle: a cross-thread SendMessage fixture.
- **Cross-process sends carry the four values only:** a pointer lParam is not marshalled. Why: no
  fixture sends across processes. Settle: one that does.
- **ReplyMessage** (`ONE_PARAM_REPLY_MESSAGE`) answers the innermost message being delivered when
  another thread sent it and it is not answered yet (TRUE), FALSE otherwise; the delivery's end
  then drops its own answer. Why: ReplyMessage's documentation ("nonzero if the calling thread was
  processing a message sent from another thread"). Settle: a capture of ReplyMessage twice.
- **The sent-message pools are bounded:** 128 sends on their way, 16 of them creation messages
  carrying their create parameters; a send the full pool cannot take is dropped (the decision
  goes on with the default answer). Why: no heap; a creation's messages are drained right after
  the service returns. Settle: a fixture creating deep trees without pumping.

## The queue

- **A queue per window-manager thread record**, made at the thread's first win32k service
  (`winsta::connect_thread` calls `queue::attach`), as Windows 2000's first win32k call makes the
  thread a GUI thread with a queue. A record reused by another thread ends the old queue (posted
  messages dropped, pending sends answered 0, timers killed). Settle: the thread-end wiring (see
  Questions).
- **Posted messages share one pool of 512 entries**; a full pool fails the post with
  STATUS_INSUFFICIENT_RESOURCES (user32 should report ERROR_NOT_ENOUGH_QUOTA, 1816, Windows 2000's
  answer at its per-queue limit; rtl has no STATUS_QUOTA_EXCEEDED). Settle: a flood fixture.
- **The read's order:** sent messages (whatever the filter), posted messages the filter takes,
  WM_QUIT, WM_PAINT, WM_TIMER; input would come after the posted ones (there is none). Why:
  GetMessage's documented processing order; WM_QUIT is made only when nothing posted comes before
  it (public descriptions of PostQuitMessage). Settle: the guimsg/guipaint captures with user32's
  bodies.
- **WM_QUIT ignores the message range but not the window filter:** it is a thread message, taken
  by a null window filter or -1, not by a window's. Why: GetMessage's documentation ("always
  retrieves WM_QUIT ... no matter which values you specify for wMsgFilterMin and wMsgFilterMax")
  speaks of the range only. Settle: a capture of GetMessage(hwnd) after PostQuitMessage.
- **A posted WM_QUIT** (PostMessage with WM_QUIT) is a posted message like any other, but its
  receipt kind is RECEIVED_QUIT, so GetMessage answers 0 for it. Why: GetMessage's documentation
  (0 when it retrieves WM_QUIT). Settle: a capture.
- **The window filter matches the window itself, not its children;** -1 takes the thread messages
  only; a handle naming no window is STATUS_INVALID_HANDLE (GetMessage's -1 and
  `ERROR_INVALID_WINDOW_HANDLE` in user32). A window of another thread is taken as a filter and
  never matches (GetMessage would wait for ever): the documentation says the window "must belong
  to the current thread", not what happens otherwise. Why: GetMessage's documentation names the
  window; children are not mentioned. Settle: a capture filtering on a parent, and on another
  thread's window.
- **The range is inclusive; both bounds zero takes everything; a minimum above the maximum takes
  nothing** (WM_QUIT aside). Why: documentation covers the first two only. Settle: a capture.
- **PeekMessage's PM_QS_* bits** restrict the queued kinds; sent messages are always delivered
  first ("During this call, the system delivers pending, nonqueued messages"); PM_QS_SENDMESSAGE
  alone looks at nothing else; PM_NOYIELD is ignored. Settle: a capture.
- **PostMessage(NULL, ...)** posts a thread message to the caller (its documentation);
  **HWND_BROADCAST** posts to every top-level window of the caller's desktop that has a client
  procedure. Messages below WM_USER carrying pointers are not refused (Windows 2000 fails them with
  ERROR_MESSAGE_SYNC_ONLY): there is no list of which messages carry pointers. Settle: a capture.
- **PostThreadMessage** finds the queue by client id and checks the thread object still lives
  (its slot's generation); an id with no queue is STATUS_INVALID_CID (user32 should report
  ERROR_INVALID_THREAD_ID, 1444, as the documentation says for a thread without a queue). Settle: a
  capture of PostThreadMessage to a dead thread.
- **MSG.time** is the interrupt time in milliseconds when the message was posted (made, for
  WM_QUIT/WM_PAINT/WM_TIMER); **MSG.pt** is (0, 0): there is no cursor. Why: GetMessageTime's
  documentation. Settle: the cursor's arrival.
- **Posted messages to a window go with the window** (purged at its free, from every queue).
  Why: a read never hands out a dead window's posted message on Windows 2000. Settle: a capture.
- **DispatchMessage** (`NtUserDispatchMessage`) names the procedure: WM_TIMER's lParam when
  non-zero (the TimerProc, not checked against the thread's timers), else the window's procedure,
  0 for a thread message or a window manager's procedure; no check that the window is the
  caller's. Settle: a capture dispatching another thread's message.
- **The waits:** each queue has a synchronization event, embedded in a static table beside the
  window manager (named by address, like the console control thread's), set after the lock is let
  go for every queue an operation gave something (posts, sends, answers, timers set,
  invalidations). GetMessage and a cross-thread SendMessage wait on their own queue's event,
  user-mode, not alertable, with GetMessage's timeout the thread's next timer due. Spurious wakes
  loop. Why: the brief's "wait outside the lock"; the console's precedent. Settle: none needed.
- **The NtUserCallOneParam routines and the receipt layout are F2K's own** (`rtl::user`), since
  only F2K's user32 calls them; numbers 0..2 for PostQuitMessage, ReplyMessage, end of delivery.
- **A creation message's CREATESTRUCTW** carries the final position, lpCreateParams, the name
  (pointing at the receipt's copy, 128 units at most, as the window record holds) and, for
  lpszClass, the class's atom (MAKEINTATOM), even for a class named by string. Why: CREATESTRUCT's
  documentation allows an atom; the string would double the receipt. Settle: a capture reading
  lpszClass in WM_CREATE.
- **A post to the window manager's own windows** (the desktop window, the message window) fails
  STATUS_INVALID_PARAMETER: their thread record has no queue. Windows 2000's desktop thread takes
  them. Settle: a capture posting to GetDesktopWindow().
- **Input stays a seam:** the read has no input stage (its place, after the posted messages, is
  marked in `queue::take`), and TranslateMessage has no kernel side (NtUserTranslateMessage is not
  served: TranslateMessage of a non-key message answers FALSE in user32, the dispatch capture's
  ret=0). No `Pump` method was added for key events: they come from the keyboard, not from the
  window manager's decisions. Settle: the input slice.
- **The `Pump` calls the queue does not serve** stay the trait's defaults: `post_destroy_event`
  (a cross-thread child's destroy), `attach_input`, `repost_quit` and the rest. Settle: the slices
  that need them.

## Timers

- **No timer DPC:** a read of the thread's queue marks due timers ready and makes WM_TIMER; a
  waiting thread waits no longer than its next due; SetTimer wakes the target thread. Why: the
  order names the scheduler's timeouts as the mechanism; touching window-manager state from a DPC
  is impossible under its passive lock. Settle: none needed.
- **Missed expirations coalesce into one WM_TIMER**, the next due an interval from the read that
  found it due. Why: public descriptions of WM_TIMER as a low-priority, coalesced message.
- **Intervals are held between 1 ms and USER_TIMER_MAXIMUM.** A 0 interval would come due on
  every read and spin a thread whose filter leaves WM_TIMER out. Windows 2000 has no documented
  minimum (USER_TIMER_MINIMUM came later). Settle: a capture of SetTimer(0).
- **SetTimer's answer:** the given id for a window timer (1 for a zero id, as the answer must be
  nonzero); for a thread timer the given id when it names one of the caller's, a fresh one
  otherwise (the later documentation's wording). Settle: a capture of SetTimer's answers.
- **A window timer on another process's window** is STATUS_ACCESS_DENIED; another thread of the
  same process may set one (WM_TIMER goes to the window's thread). Why: Windows 2000 refuses
  other processes' windows. Settle: a capture.
- **KillTimer of a timer there is not** is STATUS_INVALID_PARAMETER (user32: FALSE,
  ERROR_INVALID_PARAMETER). Why: the documentation says FALSE with an error; which error is not
  documented. Settle: a capture. KillTimer drops a ready WM_TIMER with the timer.
- **64 timers system-wide.** Settle: a fixture setting more.

## Paint

- **The update region is one rectangle, its bounding box**, in client coordinates; validation
  takes out only what covers the box whole or a band across a side, else leaves the box. Why: no
  region object in GDI yet; never paints less than needed. Settle: real regions with the GDI
  objects.
- **A hidden window takes no invalidation** (it or a parent below the desktop window lacks
  WS_VISIBLE; message-only windows never take one). Why: the invalidate/subrect/beginend captures
  (GetUpdateRect=0 with rc 0 0 0 0, BeginPaint's fErase=0 and rcPaint 0 0 0 0 on a hidden window).
- **Children are invalidated and validated through their client areas unless the parent has
  WS_CLIPCHILDREN** (RedrawWindow's rule without RDW_ALLCHILDREN/RDW_NOCHILDREN); hidden children
  are skipped; BeginPaint validates the window alone. Settle: a capture with child windows.
- **The erase is reported, not sent:** BeginPaint's fErase is the pending erase and GetUpdateRect
  answers UPDATE_ERASE (once) when asked; user32 sends WM_ERASEBKGND with the DC and sets fErase
  from the answer. Why: the kernel cannot call the procedure (above); the paint capture's fErase=0
  comes from DefWindowProc erasing. Settle: user32's bodies passing guipaint's paint block.
- **BeginPaint's DC is a screen DC clipped to the update box on the screen**, coordinates the
  screen's (no client origin). Why: the order extends dc.rs only "if the pins need it", and they
  need a non-NULL DC only; a DC with a client origin is GetDC-for-a-window work. Settle: see
  Questions.
- **EndPaint** checks the window, reads the PAINTSTRUCT (a NULL one faults:
  STATUS_ACCESS_VIOLATION, 998 in user32, the errors capture), closes its DC (a DC already gone is
  no failure). BeginPaint and EndPaint take any thread's window. Settle: a capture.
- **InvalidateRect(NULL)** invalidates every shown top-level window of the caller's desktop (and
  their children); **ValidateRect(NULL)** does the same, as its documentation says ("the system
  invalidates and redraws all windows"). Neither sends WM_ERASEBKGND/WM_NCPAINT synchronously.
- **UpdateWindow** (`NtUserCallHwndLock(HWND_LOCK_UPDATE_WINDOW)`) queues a sent WM_PAINT to the
  window when its update box is not empty, the window alone (its documentation does not mention
  children). Settle: the paint capture with user32's bodies.
- **WM_PAINT is made for any window of the thread with an update box**, in record order (no
  parent-first ordering); it stays until the window is validated.
- **Showing a window does not invalidate it here:** showing is the geometry branch's; it should
  call `paint::invalidate(windows, id, None, true)` when a window becomes visible (Windows 2000
  paints a newly shown window).

## Changes to shared code (for the merge with `wip/graphics-s2`)

- **The `Pump` trait is unchanged** (no signature or default changed). `QueuePump` overrides
  `send` and `window_teardown` only; the other methods stay the trait's defaults, so show/setpos
  logic the geometry branch puts in the defaults or in `Windows` methods reaches it. If the
  geometry branch makes its own pump for the services, the services must keep `QueuePump`
  (fold the geometry pump's methods into it).
- `window.rs`: `Windows` gains `pub queues: super::queue::Queues` and its line in
  `Windows::write_empty`; a new section after `view_of` ("The message layer's view") with
  read-only accessors (`is_live`, `window_thread`, `window_process`, `client_proc`,
  `window_style`, `client_rect`, `parent_of`, `first_child`, `next_sibling`, `desktop_roots`,
  `thread_desktop_window`, `thread_key`, `thread_process`) and the test-only
  `set_visible_for_tests`; the services `create_window_ex` and `destroy_window` run under
  `queue::with_manager` with `QueuePump` instead of `lock(..)` with `DefaultProcedure`; the
  module notes' seam paragraph and `DefaultProcedure`'s doc reworded; a `QueuePump` import.
- `class.rs`: `Registry::atom(ClassId)`.
- `winsta.rs`: `connect_thread` reads the client id and attaches the queue inside its existing
  `locked` call; `init` names the queues' events before the boot's desktop.
- `dc.rs`: `screen_dc` split into `publish_dc`, plus `paint_dc` and `release_paint_dc`.
- `rtl`: a new `user` module; `lib.rs` lists it.
- `userland/user32/exports.toml`: a `message` group and 15 internal service records.
- Process end (the geometry branch's): it should call `queue::detach(windows, thread)` for each
  of the process's thread records, so their posted messages, pending sends and timers go.

## Questions

1. **A kernel-to-user callback:** should F2K grow KeUserModeCallback (and NtCallbackReturn) so a
   procedure's answer reaches the decisions (WM_NCCREATE's veto, WM_CREATE's -1, WM_NCCALCSIZE's
   rectangle), or is the deferred delivery the design to keep?
2. **Thread end:** nothing ends a thread's window-manager record, so a thread's queue lives until
   another thread takes its record. Should thread exit call `queue::detach` (with the process-end
   wiring), or is a record's reuse enough for now?
3. **The paint DC's origin:** BeginPaint's DC draws in screen coordinates. Should it get a client
   origin now (a small change to `Dc` and the four drawing services), or wait for GetDC on a
   window?
4. **Error codes user32 must map:** STATUS_INSUFFICIENT_RESOURCES for a full posted pool
   (ERROR_NOT_ENOUGH_QUOTA?), STATUS_INVALID_CID for PostThreadMessage (ERROR_INVALID_THREAD_ID),
   STATUS_INVALID_HANDLE for windows (1400): is user32's own mapping (as for `Failure::code`) the
   way, or should rtl's status table grow the codes?

## Gates

- `make check`: clean (no warning from the new or touched win32k/rtl files).
- `make run-tests`: green (kernel lib 1164 passed, among them 28 new queue, timer and paint
  tests; rtl 285; the DLLs' and programs' host tests).
- `uv run scripts/compat.py --check`: ok.
- `make check-all PYTEST_FLAGS="-n 2"`: 647 passed, 3 skipped, 60 xfailed, 1 failed — the known
  `tests/harness/test_repository.py::test_the_spec_lists_every_fixture_import` (token.exe's
  advapi32 imports, fixed on the shutdown branch). guimsg and guipaint stay expected failures until
  user32's bodies land.
