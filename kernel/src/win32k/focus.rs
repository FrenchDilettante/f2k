//! Focus, enabling and activation: each thread's queue's focus window and active window, the
//! foreground thread, and the decisions that move them — SetFocus, SetActiveWindow,
//! SetForegroundWindow, EnableWindow, the activation the show, position and destroy paths ask for
//! ([`Pump::activate`]), and the focus check of the destroy cascade ([`Pump::check_focus`]).
//!
//! The state lives in the window registry's thread records ([`super::window::Thread`]'s `active`
//! and `focus`, one queue a thread: F2K shares no input state between threads yet) and in the
//! registry's foreground thread ([`Windows::foreground_thread`]); the foreground window is that
//! thread's active window, as Windows 2000's is its foreground queue's.
//!
//! Activation ([`activate_this`]) moves a thread's active window: the window losing it is sent
//! WM_NCACTIVATE (FALSE) and WM_ACTIVATE (WA_INACTIVE, the window gaining it), the window gaining
//! it comes to the top of the z-order and is sent WM_NCACTIVATE (TRUE) and WM_ACTIVATE (WA_ACTIVE,
//! the window losing it). A thread that gains its first active window, or loses its last, sends
//! its top-level windows WM_ACTIVATEAPP; one that loses it loses its focus too (WM_KILLFOCUS to
//! NULL), in that order (the focus capture's destroy block). Activation itself does not move the
//! focus to the window: the default window procedure's WM_ACTIVATE does, as its documentation
//! gives it ([`activate_focus`]), and without the checks SetFocus makes — the focus capture shows a
//! disabled window activated and given the focus that SetFocus would refuse it.
//!
//! The focus moves ([`move_focus`]) with WM_KILLFOCUS to the window losing it (wParam the window
//! gaining it) and WM_SETFOCUS to the window gaining it (wParam the window losing it). SetFocus
//! ([`set_focus`]) refuses a window that is disabled or has a disabled ancestor, and activates the
//! window's top-level window first when it is not the active one.
//!
//! The messages go through the pump: the services' pump queues them for the window's thread, which
//! receives them once the service returns, before the call does ([`super::queue`]). So a window
//! procedure's answer reaches none of these decisions, and what the default procedure does with
//! WM_ACTIVATE happens after the activation's other messages are queued, not inside it: SetFocus
//! to a window of an inactive top-level window queues its focus messages before the activation's
//! default WM_ACTIVATE runs, which then leaves the focus where it is, inside the window activated.
//!
//! The services, user32's calls (F2K's argument lists, see [`crate::win32k`]; Windows 2000's
//! numbers):
//!
//! - NtUserSetFocus (0x11F0) and NtUserSetActiveWindow (0x11E4): the window (0 for none), the
//!   window that had the focus or was active through the last pointer;
//! - NtUserGetForegroundWindow (0x1189): the foreground window through its pointer;
//! - NtUserGetThreadState (0x11A3): the calling thread's focus or active window, by rtl::user's
//!   THREAD_STATE_* routine;
//! - NtUserCallHwndParamLock (0x1135): EnableWindow, by rtl::user's HWND_PARAM_LOCK_* routine;
//! - NtUserCallHwndLock's SetForegroundWindow and DefWindowProc's WM_ACTIVATE routines
//!   ([`call_hwnd_lock`], through [`super::paint`]'s service, which serves the others).

use rtl::user::{
    WA_ACTIVE,
    WA_INACTIVE,
    WM_ACTIVATE,
    WM_ACTIVATEAPP,
    WM_CANCELMODE,
    WM_ENABLE,
    WM_KILLFOCUS,
    WM_NCACTIVATE,
    WM_SETFOCUS,
};

use super::class;
use super::window::{
    Activate,
    InsertAfter,
    Message,
    Payload,
    Pump,
    WParam,
    WindowId,
    Windows,
    SWP_NOACTIVATE,
    SWP_NOMOVE,
    SWP_NOSIZE,
    WS_CHILD,
    WS_DISABLED,
    WS_MINIMIZE,
    WS_VISIBLE,
};
use crate::sched::thread::ThreadId;

// --- The state's reads ---------------------------------------------------------------------------

/// The thread's focus window.
pub fn focus_window(windows: &Windows, thread: ThreadId) -> Option<WindowId> {
    windows.thread(thread).focus.filter(|&w| windows.is_live(w))
}

/// The thread's active window.
pub fn active_window(windows: &Windows, thread: ThreadId) -> Option<WindowId> {
    windows
        .thread(thread)
        .active
        .filter(|&w| windows.is_live(w))
}

/// The foreground window: the foreground thread's active window.
pub fn foreground_window(windows: &Windows) -> Option<WindowId> {
    let thread = windows.foreground_thread?;
    windows
        .thread(thread)
        .live
        .then(|| active_window(windows, thread))
        .flatten()
}

/// The handle of a window, 0 for none: what a message's wParam or lParam names it by.
fn handle(windows: &Windows, window: Option<WindowId>) -> u32 {
    window
        .filter(|&w| windows.is_live(w))
        .map_or(0, |w| windows.handle_of(w))
}

/// The top-level window `window` belongs to: itself, or the parent its chain of child windows ends
/// at.
fn top_level(windows: &Windows, window: WindowId) -> WindowId {
    let mut top = window;
    while windows.window_style(top) & WS_CHILD != 0 {
        match windows.parent_of(top) {
            Some(parent) => top = parent,
            None => break,
        }
    }
    top
}

/// Whether `window` is `ancestor` or one of its descendants.
fn is_within(windows: &Windows, window: WindowId, ancestor: WindowId) -> bool {
    let mut current = Some(window);
    while let Some(w) = current {
        if w == ancestor {
            return true;
        }
        current = windows.parent_of(w);
    }
    false
}

/// A message with no payload sent to `target`.
fn send(
    windows: &mut Windows,
    classes: &mut class::Registry,
    pump: &mut dyn Pump,
    target: WindowId,
    message: u32,
    wparam: WParam,
    lparam: u32,
) {
    pump.send(
        windows,
        classes,
        target,
        &mut Message {
            message,
            wparam,
            lparam: lparam as i32,
            payload: Payload::None,
        },
    );
}

// --- The focus -----------------------------------------------------------------------------------

/// Move the thread's focus to `new` (none: no window has it), unchecked: WM_KILLFOCUS to the
/// window that had it, then WM_SETFOCUS to `new`. Nothing when the focus is there already.
pub fn move_focus(
    windows: &mut Windows,
    classes: &mut class::Registry,
    thread: ThreadId,
    new: Option<WindowId>,
    pump: &mut dyn Pump,
) {
    let old = focus_window(windows, thread);
    if old == new {
        return;
    }
    windows.thread_mut(thread).focus = new;
    if let Some(old) = old {
        let to = handle(windows, new);
        send(windows, classes, pump, old, WM_KILLFOCUS, to, 0);
    }
    if let Some(new) = new {
        if windows.is_live(new) && windows.thread(thread).focus == Some(new) {
            let from = handle(windows, old);
            send(windows, classes, pump, new, WM_SETFOCUS, from, 0);
        }
    }
}

/// SetFocus's decision for the calling thread `caller`: the focus to `target` (none: taken from
/// every window). The answer is the window that had the focus, or none when the call failed: a
/// window of another thread's, or one that is disabled or has a disabled ancestor (the focus
/// capture's enable block: a disabled child, and a child of a disabled top-level window, are both
/// refused, the focus left where it was). The window that has the focus already is answered
/// without a message, once the checks pass. A window whose top-level window is not the thread's
/// active window has it activated first. A hidden window takes the focus (the focus capture).
pub fn set_focus(
    windows: &mut Windows,
    classes: &mut class::Registry,
    caller: ThreadId,
    target: Option<WindowId>,
    pump: &mut dyn Pump,
) -> Option<WindowId> {
    let previous = focus_window(windows, caller);
    let Some(window) = target else {
        move_focus(windows, classes, caller, None, pump);
        return previous;
    };
    if windows.window_thread(window) != caller {
        return None;
    }
    let mut current = Some(window);
    while let Some(w) = current {
        if windows.window_style(w) & WS_DISABLED != 0 {
            return None;
        }
        current = (windows.window_style(w) & WS_CHILD != 0)
            .then(|| windows.parent_of(w))
            .flatten();
    }
    if previous == Some(window) {
        return previous;
    }
    let top = top_level(windows, window);
    if active_window(windows, caller) != Some(top) {
        activate_this(windows, classes, caller, Some(top), pump);
        if !windows.is_live(window) || active_window(windows, caller) != Some(top) {
            return None;
        }
    }
    move_focus(windows, classes, caller, Some(window), pump);
    previous
}

/// The default window procedure's WM_ACTIVATE for a window being activated: the focus to it, when
/// it is still its thread's active window, is not minimized, and neither it nor one of its
/// descendants has the focus already. No enabled check (see the module notes).
pub fn activate_focus(
    windows: &mut Windows,
    classes: &mut class::Registry,
    window: WindowId,
    pump: &mut dyn Pump,
) {
    let thread = windows.window_thread(window);
    if active_window(windows, thread) != Some(window)
        || windows.window_style(window) & WS_MINIMIZE != 0
    {
        return;
    }
    if focus_window(windows, thread).is_some_and(|f| is_within(windows, f, window)) {
        return;
    }
    move_focus(windows, classes, thread, Some(window), pump);
}

/// The destroy cascade's focus check of `window`, before its WM_DESTROY and after its children's:
/// when it has its thread's focus, the focus goes to its parent (a child window, as SetFocus
/// would move it there: the focus capture's destroy block) or to no window (a top-level window).
pub fn check_focus(
    windows: &mut Windows,
    classes: &mut class::Registry,
    window: WindowId,
    pump: &mut dyn Pump,
) {
    let thread = windows.window_thread(window);
    if focus_window(windows, thread) != Some(window) {
        return;
    }
    let parent = windows.parent_of(window);
    match parent {
        Some(parent) if windows.window_style(window) & WS_CHILD != 0 => {
            set_focus(windows, classes, thread, Some(parent), pump);
        }
        _ => move_focus(windows, classes, thread, None, pump),
    }
}

// --- Enabling ------------------------------------------------------------------------------------

/// EnableWindow's decision: whether `window` was disabled before. Disabling sends WM_CANCELMODE
/// first, whatever the state; a window that has its thread's focus loses it (to no window; the
/// focus inside a disabled ancestor stays); a window that was enabled is marked WS_DISABLED and
/// sent WM_ENABLE (FALSE). Enabling a disabled window clears the mark and sends WM_ENABLE (TRUE).
/// Nothing else is sent (the focus capture's enable block).
pub fn enable_window(
    windows: &mut Windows,
    classes: &mut class::Registry,
    window: WindowId,
    enable: bool,
    pump: &mut dyn Pump,
) -> bool {
    let was_disabled = windows.window_style(window) & WS_DISABLED != 0;
    if enable {
        if was_disabled {
            windows.set_disabled(window, false);
            send(windows, classes, pump, window, WM_ENABLE, 1, 0);
        }
        return was_disabled;
    }
    send(windows, classes, pump, window, WM_CANCELMODE, 0, 0);
    if !windows.is_live(window) {
        return was_disabled;
    }
    let thread = windows.window_thread(window);
    if focus_window(windows, thread) == Some(window) {
        move_focus(windows, classes, thread, None, pump);
    }
    if !was_disabled && windows.is_live(window) {
        windows.set_disabled(window, true);
        send(windows, classes, pump, window, WM_ENABLE, 0, 0);
    }
    was_disabled
}

// --- Activation ----------------------------------------------------------------------------------

/// WM_ACTIVATE's wParam: the state in the low word, whether the window is minimized in the high.
fn activate_wparam(windows: &Windows, window: WindowId, state: u32) -> WParam {
    let minimized = (windows.window_style(window) & WS_MINIMIZE != 0) as u32;
    state | minimized << 16
}

/// WM_ACTIVATEAPP (`active`) to each top-level window of the thread's, `first` before the others,
/// the others in z-order. Its lParam names the other thread: 0, as F2K does not name it yet.
fn activate_app(
    windows: &mut Windows,
    classes: &mut class::Registry,
    thread: ThreadId,
    first: WindowId,
    active: bool,
    pump: &mut dyn Pump,
) {
    send(
        windows,
        classes,
        pump,
        first,
        WM_ACTIVATEAPP,
        active as u32,
        0,
    );
    let Some(desktop) = windows.thread_desktop_window(thread) else {
        return;
    };
    let mut current = windows.first_child(desktop);
    while let Some(w) = current {
        // Read before the send: the pump never runs a procedure, but the list is the registry's.
        current = windows.next_sibling(w);
        if w != first && windows.window_thread(w) == thread {
            send(windows, classes, pump, w, WM_ACTIVATEAPP, active as u32, 0);
        }
    }
}

/// Make `new` the thread's active window (none: the thread has none), as Windows 2000's
/// activation of a window does (see the module notes for the messages). False when `new` is gone.
pub fn activate_this(
    windows: &mut Windows,
    classes: &mut class::Registry,
    thread: ThreadId,
    new: Option<WindowId>,
    pump: &mut dyn Pump,
) -> bool {
    if new.is_some_and(|w| !windows.is_live(w)) {
        return false;
    }
    let old = active_window(windows, thread);
    if old == new {
        return true;
    }
    if let Some(old) = old {
        send(windows, classes, pump, old, WM_NCACTIVATE, 0, 0);
        let wparam = activate_wparam(windows, old, WA_INACTIVE);
        let other = handle(windows, new);
        send(windows, classes, pump, old, WM_ACTIVATE, wparam, other);
    }
    {
        let t = windows.thread_mut(thread);
        t.active_prev = old;
        t.active = new;
    }
    let Some(new) = new else {
        if let Some(old) = old {
            activate_app(windows, classes, thread, old, false, pump);
        }
        move_focus(windows, classes, thread, None, pump);
        return true;
    };
    if old.is_none() {
        activate_app(windows, classes, thread, new, true, pump);
    }
    // The window comes to the top of the z-order.
    let _ = windows.set_window_pos(
        classes,
        new,
        InsertAfter::Top,
        0,
        0,
        0,
        0,
        SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
        pump,
    );
    if !windows.is_live(new) || windows.thread(thread).active != Some(new) {
        return false;
    }
    send(windows, classes, pump, new, WM_NCACTIVATE, 1, 0);
    let wparam = activate_wparam(windows, new, WA_ACTIVE);
    let other = handle(windows, old);
    send(windows, classes, pump, new, WM_ACTIVATE, wparam, other);
    true
}

/// Whether `thread` may take the foreground: no thread has it, it has it, the thread that has it
/// is gone, or that thread is of the same process (SetForegroundWindow's documented conditions, as
/// far as F2K has them: there is no input yet to have received last, nor a process that started
/// another as the foreground one).
fn may_take_foreground(windows: &Windows, thread: ThreadId) -> bool {
    match windows.foreground_thread {
        None => true,
        Some(f) => {
            f == thread
                || !windows.thread(f).live
                || windows.thread(f).process == windows.thread(thread).process
        }
    }
}

/// The foreground to `thread`, when it may take it: the thread that had it loses its active
/// window.
fn take_foreground(
    windows: &mut Windows,
    classes: &mut class::Registry,
    thread: ThreadId,
    pump: &mut dyn Pump,
) -> bool {
    if !may_take_foreground(windows, thread) {
        return false;
    }
    if let Some(f) = windows.foreground_thread {
        if f != thread && windows.thread(f).live {
            activate_this(windows, classes, f, None, pump);
        }
    }
    windows.foreground_thread = Some(thread);
    true
}

/// The next top-level window after `window` in the z-order that can be activated: visible and
/// enabled. The windows above it are not looked at (the focus capture: a window shown above the
/// active one is not activated when the active one is destroyed).
fn next_top_window(windows: &Windows, window: WindowId) -> Option<WindowId> {
    let mut current = windows.next_sibling(window);
    while let Some(w) = current {
        let style = windows.window_style(w);
        if style & WS_VISIBLE != 0 && style & (WS_DISABLED | WS_CHILD) == 0 {
            return Some(w);
        }
        current = windows.next_sibling(w);
    }
    None
}

/// The activation the show, position and destroy paths ask for ([`Pump::activate`]), on the
/// window's thread. [`Activate::Try`] activates a visible top-level window, and takes the
/// foreground for its thread when it may. [`Activate::Skip`] activates the next window below it
/// instead ([`next_top_window`]): of the same thread, as the thread's active window; of another
/// thread, by giving that thread the foreground when this one had it, this thread left with no
/// active window; with none, the thread is left with no active window. False when nothing could be
/// activated as asked.
pub fn activate(
    windows: &mut Windows,
    classes: &mut class::Registry,
    target: WindowId,
    command: Activate,
    pump: &mut dyn Pump,
) -> bool {
    let thread = windows.window_thread(target);
    match command {
        Activate::Try => {
            let style = windows.window_style(target);
            if style & WS_CHILD != 0 || style & WS_VISIBLE == 0 {
                return false;
            }
            let activated = activate_this(windows, classes, thread, Some(target), pump);
            if activated {
                take_foreground(windows, classes, thread, pump);
            }
            activated
        }
        Activate::Skip => match next_top_window(windows, target) {
            Some(next) if windows.window_thread(next) == thread => {
                activate_this(windows, classes, thread, Some(next), pump)
            }
            Some(next) => {
                let other = windows.window_thread(next);
                let had_foreground = windows.foreground_thread == Some(thread);
                activate_this(windows, classes, thread, None, pump);
                if had_foreground {
                    windows.foreground_thread = Some(other);
                    activate_this(windows, classes, other, Some(next), pump);
                }
                true
            }
            None => activate_this(windows, classes, thread, None, pump),
        },
    }
}

/// SetActiveWindow's decision for the calling thread `caller`: the window that was active (none
/// when the call failed). A window of another thread's is refused; a child window activates
/// nothing and answers the active window (the focus capture's active block); a top-level window
/// is activated, disabled or not (the same block), and none deactivates the thread.
pub fn set_active_window(
    windows: &mut Windows,
    classes: &mut class::Registry,
    caller: ThreadId,
    target: Option<WindowId>,
    pump: &mut dyn Pump,
) -> Option<WindowId> {
    let previous = active_window(windows, caller);
    if let Some(window) = target {
        if windows.window_thread(window) != caller {
            return None;
        }
        if windows.window_style(window) & WS_CHILD != 0 {
            return previous;
        }
    }
    activate_this(windows, classes, caller, target, pump);
    previous
}

/// SetForegroundWindow's decision for the calling thread `caller`: the window's top-level window
/// made its thread's active window, and its thread the foreground one; false when the caller may
/// not take the foreground (see [`may_take_foreground`]). A window that is the foreground already
/// is left as it is, in its place in the z-order.
pub fn set_foreground_window(
    windows: &mut Windows,
    classes: &mut class::Registry,
    caller: ThreadId,
    window: WindowId,
    pump: &mut dyn Pump,
) -> bool {
    if !may_take_foreground(windows, caller) {
        return false;
    }
    let top = top_level(windows, window);
    let thread = windows.window_thread(top);
    if windows.foreground_thread != Some(thread) {
        if let Some(f) = windows.foreground_thread {
            if windows.thread(f).live {
                activate_this(windows, classes, f, None, pump);
            }
        }
        windows.foreground_thread = Some(thread);
    }
    activate_this(windows, classes, thread, Some(top), pump)
}

// --- The services --------------------------------------------------------------------------------

/// NtUserCallHwndLock's routines served here (rtl::user's HWND_LOCK_*), for [`super::paint`]'s
/// service, on the window `window` and for the calling thread `caller`: SetForegroundWindow
/// (STATUS_ACCESS_DENIED when the caller may not take the foreground) and the default procedure's
/// WM_ACTIVATE ([`activate_focus`]); none for another routine.
pub fn call_hwnd_lock(
    windows: &mut Windows,
    classes: &mut class::Registry,
    caller: ThreadId,
    window: WindowId,
    routine: u32,
    pump: &mut dyn Pump,
) -> Option<Result<(), crate::status::NtStatus>> {
    use rtl::user::{HWND_LOCK_ACTIVATE_FOCUS, HWND_LOCK_SET_FOREGROUND_WINDOW};
    match routine {
        HWND_LOCK_SET_FOREGROUND_WINDOW => Some(
            if set_foreground_window(windows, classes, caller, window, pump) {
                Ok(())
            } else {
                Err(crate::status::STATUS_ACCESS_DENIED)
            },
        ),
        HWND_LOCK_ACTIVATE_FOCUS => {
            activate_focus(windows, classes, window, pump);
            Some(Ok(()))
        }
        _ => None,
    }
}

#[cfg(target_arch = "x86")]
mod services {
    use rtl::user::{
        HWND_PARAM_LOCK_ENABLE_WINDOW,
        THREAD_STATE_ACTIVE_WINDOW,
        THREAD_STATE_FOCUS_WINDOW,
    };

    use super::*;
    use crate::nt::call::{Handle, NtCall, NtResult, UserPtr};
    use crate::status::*;
    use crate::win32k::queue::{with_manager, QueuePump};
    use crate::win32k::window::WindowManager;
    use crate::win32k::winsta::gui_thread;

    /// The window a handle names, none for 0; STATUS_INVALID_HANDLE for a handle naming no window.
    fn optional_window(windows: &Windows, handle: Handle) -> Result<Option<WindowId>, NtStatus> {
        match handle.raw() {
            0 => Ok(None),
            raw => windows
                .window_from_handle(raw)
                .map(Some)
                .ok_or(STATUS_INVALID_HANDLE),
        }
    }

    /// NtUserSetFocus(Window, Previous): [`set_focus`]; the window that had the focus (0 for
    /// none, or for a refusal) into `previous`, written once the lock is let go.
    pub fn set_focus(call: &mut NtCall, window: Handle, previous: UserPtr<u32>) -> NtResult {
        let caller = gui_thread(call)?.thread;
        let answer = with_manager(call.passive(), |m| {
            let WindowManager {
                windows, classes, ..
            } = m;
            let target = optional_window(windows, window)?;
            let had = super::set_focus(windows, classes, caller, target, &mut QueuePump);
            Ok::<_, NtStatus>(handle(windows, had))
        })?;
        previous.write(answer)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserSetActiveWindow(Window, Previous): [`set_active_window`]; the window that was active
    /// (0 for none, or for a refusal) into `previous`.
    pub fn set_active_window(
        call: &mut NtCall,
        window: Handle,
        previous: UserPtr<u32>,
    ) -> NtResult {
        let caller = gui_thread(call)?.thread;
        let answer = with_manager(call.passive(), |m| {
            let WindowManager {
                windows, classes, ..
            } = m;
            let target = optional_window(windows, window)?;
            let had = super::set_active_window(windows, classes, caller, target, &mut QueuePump);
            Ok::<_, NtStatus>(handle(windows, had))
        })?;
        previous.write(answer)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserGetForegroundWindow(Window): the foreground window (0 for none) into `window`.
    pub fn get_foreground_window(call: &mut NtCall, window: UserPtr<u32>) -> NtResult {
        gui_thread(call)?;
        let answer = with_manager(call.passive(), |m| {
            handle(&m.windows, foreground_window(&m.windows))
        });
        window.write(answer)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserGetThreadState(Routine, Result): the calling thread's focus window or active window
    /// (0 for none) into `result`; STATUS_INVALID_PARAMETER for another routine.
    pub fn get_thread_state(call: &mut NtCall, routine: u32, result: UserPtr<u32>) -> NtResult {
        let caller = gui_thread(call)?.thread;
        let answer = with_manager(call.passive(), |m| {
            let window = match routine {
                THREAD_STATE_FOCUS_WINDOW => focus_window(&m.windows, caller),
                THREAD_STATE_ACTIVE_WINDOW => active_window(&m.windows, caller),
                _ => return Err(STATUS_INVALID_PARAMETER),
            };
            Ok(handle(&m.windows, window))
        })?;
        result.write(answer)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserCallHwndParamLock(Window, Param, Routine, Result): EnableWindow ([`enable_window`],
    /// `param` its bEnable): the window's former WS_DISABLED as the style's state byte holds it
    /// into `result` — 8 for a window that was disabled, 0 for one that was not, as Windows 2000's
    /// EnableWindow answers (the focus capture); STATUS_INVALID_PARAMETER for another routine.
    pub fn call_hwnd_param_lock(
        call: &mut NtCall,
        window: Handle,
        param: u32,
        routine: u32,
        result: UserPtr<u32>,
    ) -> NtResult {
        gui_thread(call)?;
        let answer = with_manager(call.passive(), |m| {
            let WindowManager {
                windows, classes, ..
            } = m;
            let id = windows
                .window_from_handle(window.raw())
                .ok_or(STATUS_INVALID_HANDLE)?;
            match routine {
                HWND_PARAM_LOCK_ENABLE_WINDOW => {
                    let was = enable_window(windows, classes, id, param != 0, &mut QueuePump);
                    Ok(if was { WS_DISABLED >> 24 } else { 0 })
                }
                _ => Err(STATUS_INVALID_PARAMETER),
            }
        })?;
        result.write(answer)?;
        Ok(STATUS_SUCCESS)
    }
}

#[cfg(target_arch = "x86")]
pub use services::{
    call_hwnd_param_lock,
    get_foreground_window,
    get_thread_state,
    set_active_window as set_active_window_service,
    set_focus as set_focus_service,
};

// The host builds have no processes and no user memory: the services answer nothing (the host
// tests drive the decisions themselves).
#[cfg(not(target_arch = "x86"))]
mod services {
    use crate::nt::call::{Handle, NtCall, NtResult, UserPtr};
    use crate::status::*;

    pub fn set_focus(_: &mut NtCall, _: Handle, _: UserPtr<u32>) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn set_active_window(_: &mut NtCall, _: Handle, _: UserPtr<u32>) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn get_foreground_window(_: &mut NtCall, _: UserPtr<u32>) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn get_thread_state(_: &mut NtCall, _: u32, _: UserPtr<u32>) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn call_hwnd_param_lock(
        _: &mut NtCall,
        _: Handle,
        _: u32,
        _: u32,
        _: UserPtr<u32>,
    ) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }
}

#[cfg(not(target_arch = "x86"))]
pub use services::{
    call_hwnd_param_lock,
    get_foreground_window,
    get_thread_state,
    set_active_window as set_active_window_service,
    set_focus as set_focus_service,
};

#[cfg(test)]
mod tests {
    use rtl::user::PM_QS_SENDMESSAGE;

    use super::*;
    use crate::win32k::queue::rig::*;
    use crate::win32k::queue::{end_sent, receipt_head, Filter, QueuePump, Taken};
    use crate::win32k::window::{
        Hwnd,
        WindowManager,
        SW_SHOW,
        SW_SHOWNOACTIVATE,
        WS_CAPTION,
        WS_POPUP,
    };

    /// The messages the focus fixture's procedure records.
    const RECORDED: [u32; 7] = [
        WM_SETFOCUS,
        WM_KILLFOCUS,
        WM_ENABLE,
        WM_ACTIVATE,
        WM_NCACTIVATE,
        WM_ACTIVATEAPP,
        WM_CANCELMODE,
    ];

    /// A record: the window, the message, its wParam and lParam.
    type Record = (Hwnd, u32, u32, i32);

    /// The focus fixture's windows, made and shown as its setup makes them.
    struct Rig {
        m: &'static mut WindowManager,
        t: ThreadId,
        top1: Hwnd,
        top2: Hwnd,
        child1: Hwnd,
        child2: Hwnd,
        hidden: Hwnd,
    }

    impl Rig {
        fn id(&self, handle: Hwnd) -> WindowId {
            self.m.windows.window_from_handle(handle).unwrap()
        }

        /// Deliver the sent messages as user32 does for the fixture's procedure, which hands each
        /// to DefWindowProc: a WM_ACTIVATE activating a window gives it the focus. The recorded
        /// ones, in order.
        fn settle(&mut self) -> Vec<Record> {
            let only_sent = Filter::new(0, 0, 0, PM_QS_SENDMESSAGE);
            let mut got = Vec::new();
            while let Taken::Sent(id) = read(self.m, self.t, &only_sent, 0) {
                let msg = receipt_head(&self.m.windows, self.t, id, 0x1000, 0)
                    .unwrap()
                    .msg;
                if RECORDED.contains(&msg.message) {
                    got.push((msg.hwnd, msg.message, msg.wparam, msg.lparam));
                }
                assert!(end_sent(&mut self.m.windows, self.t, 0));
                if msg.message == WM_ACTIVATE && msg.wparam == WA_ACTIVE {
                    let window = self.m.windows.window_from_handle(msg.hwnd).unwrap();
                    let WindowManager {
                        windows, classes, ..
                    } = &mut *self.m;
                    activate_focus(windows, classes, window, &mut QueuePump);
                }
            }
            got
        }

        fn set_focus(&mut self, target: Option<Hwnd>) -> (Hwnd, Vec<Record>) {
            let target = target.map(|h| self.id(h));
            let WindowManager {
                windows, classes, ..
            } = &mut *self.m;
            let had = set_focus(windows, classes, self.t, target, &mut QueuePump);
            let had = handle(windows, had);
            (had, self.settle())
        }

        fn set_active(&mut self, target: Hwnd) -> (Hwnd, Vec<Record>) {
            let target = self.id(target);
            let WindowManager {
                windows, classes, ..
            } = &mut *self.m;
            let had = set_active_window(windows, classes, self.t, Some(target), &mut QueuePump);
            let had = handle(windows, had);
            (had, self.settle())
        }

        fn enable(&mut self, target: Hwnd, enable: bool) -> (bool, Vec<Record>) {
            let target = self.id(target);
            let WindowManager {
                windows, classes, ..
            } = &mut *self.m;
            let was = enable_window(windows, classes, target, enable, &mut QueuePump);
            (was, self.settle())
        }

        fn destroy(&mut self, target: Hwnd) -> Vec<Record> {
            let WindowManager {
                windows, classes, ..
            } = &mut *self.m;
            assert_eq!(
                windows.destroy_window_handle(classes, self.t, target, &mut QueuePump),
                Ok(true)
            );
            self.settle()
        }

        /// GetFocus, GetActiveWindow and GetForegroundWindow.
        fn state(&self) -> (Hwnd, Hwnd, Hwnd) {
            let w = &self.m.windows;
            (
                handle(w, focus_window(w, self.t)),
                handle(w, active_window(w, self.t)),
                handle(w, foreground_window(w)),
            )
        }
    }

    /// The focus fixture's setup: top1 with its children (child1 and child2 visible, hidden not),
    /// a window made and destroyed, top2 when asked for; top1 shown, top2 shown without
    /// activation, top1 made the foreground window; the messages delivered.
    fn setup(with_top2: bool) -> Rig {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let top1 = window_at(m, atom, t, WS_POPUP | WS_CAPTION, 0, 40, 40, 200, 120);
        let child = WS_CHILD | WS_VISIBLE;
        let child1 = window_at(m, atom, t, child, top1, 10, 10, 60, 30);
        let child2 = window_at(m, atom, t, child, top1, 80, 10, 60, 30);
        let hidden = window_at(m, atom, t, WS_CHILD, top1, 10, 60, 60, 30);
        let dead = popup(m, atom, t);
        let mut rig = Rig {
            m,
            t,
            top1,
            top2: 0,
            child1,
            child2,
            hidden,
        };
        rig.destroy(dead);
        if with_top2 {
            rig.top2 = window_at(rig.m, atom, t, WS_POPUP | WS_CAPTION, 0, 260, 40, 200, 120);
        }
        rig.m.show_window(top1, SW_SHOW, &mut QueuePump).unwrap();
        if with_top2 {
            rig.m
                .show_window(rig.top2, SW_SHOWNOACTIVATE, &mut QueuePump)
                .unwrap();
        }
        let id = rig.id(top1);
        let WindowManager {
            windows, classes, ..
        } = &mut *rig.m;
        assert!(set_foreground_window(
            windows,
            classes,
            t,
            id,
            &mut QueuePump
        ));
        rig.settle();
        assert_eq!(rig.state(), (top1, top1, top1));
        rig
    }

    /// The focus capture's focus block: each SetFocus answers the window that had the focus and
    /// sends WM_KILLFOCUS and WM_SETFOCUS, nothing for the focus window itself; NULL takes the
    /// focus from every window; a hidden child takes it; the active window stays top1.
    #[test]
    fn the_focus_block() {
        let mut r = setup(false);
        let (top1, child1, child2, hidden) = (r.top1, r.child1, r.child2, r.hidden);
        let moved =
            |from: Hwnd, to: Hwnd| vec![(from, WM_KILLFOCUS, to, 0), (to, WM_SETFOCUS, from, 0)];
        assert_eq!(r.set_focus(Some(child1)), (top1, moved(top1, child1)));
        assert_eq!(r.set_focus(Some(child2)), (child1, moved(child1, child2)));
        assert_eq!(r.set_focus(Some(child2)), (child2, vec![]));
        assert_eq!(r.set_focus(Some(top1)), (child2, moved(child2, top1)));
        assert_eq!(r.set_focus(Some(child1)), (top1, moved(top1, child1)));
        assert_eq!(
            r.set_focus(None),
            (child1, vec![(child1, WM_KILLFOCUS, 0, 0)])
        );
        assert_eq!(
            r.set_focus(Some(child2)),
            (0, vec![(child2, WM_SETFOCUS, 0, 0)])
        );
        assert_eq!(r.set_focus(Some(hidden)), (child2, moved(child2, hidden)));
        assert_eq!(r.state(), (hidden, top1, top1));
    }

    /// The focus capture's enable block: disabling sends WM_CANCELMODE every time, takes the
    /// focus from the window disabled (not from a child of a disabled window), and sends
    /// WM_ENABLE on a change; SetFocus refuses a disabled window and a child of one.
    #[test]
    fn the_enable_block() {
        let mut r = setup(false);
        let (top1, child1, child2) = (r.top1, r.child1, r.child2);
        r.set_focus(Some(child1));
        assert_eq!(
            r.enable(child1, false),
            (
                false,
                vec![
                    (child1, WM_CANCELMODE, 0, 0),
                    (child1, WM_KILLFOCUS, 0, 0),
                    (child1, WM_ENABLE, 0, 0)
                ]
            )
        );
        assert_eq!(r.state(), (0, top1, top1));
        assert_eq!(
            r.enable(child1, false),
            (true, vec![(child1, WM_CANCELMODE, 0, 0)])
        );
        assert_eq!(r.set_focus(Some(child1)), (0, vec![]));
        assert_eq!(
            r.enable(child1, true),
            (true, vec![(child1, WM_ENABLE, 1, 0)])
        );
        assert_eq!(r.enable(child1, true), (false, vec![]));
        assert_eq!(
            r.set_focus(Some(child2)),
            (0, vec![(child2, WM_SETFOCUS, 0, 0)])
        );
        assert_eq!(
            r.enable(top1, false),
            (
                false,
                vec![(top1, WM_CANCELMODE, 0, 0), (top1, WM_ENABLE, 0, 0)]
            )
        );
        assert_eq!(r.state(), (child2, top1, top1));
        assert_eq!(r.set_focus(Some(child2)), (0, vec![]));
        assert_eq!(r.state(), (child2, top1, top1));
        assert_eq!(r.enable(top1, true), (true, vec![(top1, WM_ENABLE, 1, 0)]));
    }

    /// The focus capture's active block: SetActiveWindow deactivates the active window and
    /// activates the other (each one's WM_NCACTIVATE, then its WM_ACTIVATE naming the other), and
    /// the default procedure's WM_ACTIVATE moves the focus; the window active already and a child
    /// change nothing; a disabled window is activated and given the focus all the same.
    #[test]
    fn the_active_block() {
        let mut r = setup(true);
        let (top1, top2, child1) = (r.top1, r.top2, r.child1);
        let switch = |from: Hwnd, to: Hwnd| {
            vec![
                (from, WM_NCACTIVATE, 0, 0),
                (from, WM_ACTIVATE, WA_INACTIVE, to as i32),
                (to, WM_NCACTIVATE, 1, 0),
                (to, WM_ACTIVATE, WA_ACTIVE, from as i32),
                (from, WM_KILLFOCUS, to, 0),
                (to, WM_SETFOCUS, from, 0),
            ]
        };
        assert_eq!(r.set_active(top2), (top1, switch(top1, top2)));
        assert_eq!(r.state(), (top2, top2, top2));
        assert_eq!(r.set_active(top1), (top2, switch(top2, top1)));
        assert_eq!(r.set_active(top1), (top1, vec![]));
        assert_eq!(r.set_active(child1), (top1, vec![]));
        assert_eq!(r.state(), (top1, top1, top1));
        r.enable(top2, false);
        assert_eq!(r.set_active(top2), (top1, switch(top1, top2)));
        assert_eq!(r.state(), (top2, top2, top2));
    }

    /// The focus capture's destroy block: destroying the focused child moves the focus to its
    /// parent; destroying the active window, with top2 shown above it, deactivates the thread —
    /// its WM_NCACTIVATE and WM_ACTIVATE naming no window, WM_ACTIVATEAPP to it and then to top2,
    /// the focus taken — and leaves no active or foreground window.
    #[test]
    fn the_destroy_block() {
        let mut r = setup(true);
        let (top1, top2, child1, child2) = (r.top1, r.top2, r.child1, r.child2);
        r.set_focus(Some(child1));
        assert_eq!(
            r.destroy(child1),
            vec![
                (child1, WM_KILLFOCUS, top1, 0),
                (top1, WM_SETFOCUS, child1, 0)
            ]
        );
        assert_eq!(r.state(), (top1, top1, top1));
        r.set_focus(Some(child2));
        assert_eq!(
            r.destroy(top1),
            vec![
                (top1, WM_NCACTIVATE, 0, 0),
                (top1, WM_ACTIVATE, WA_INACTIVE, 0),
                (top1, WM_ACTIVATEAPP, 0, 0),
                (top2, WM_ACTIVATEAPP, 0, 0),
                (child2, WM_KILLFOCUS, 0, 0),
            ]
        );
        assert_eq!(r.state(), (0, 0, 0));
    }

    /// SetFocus to a child of an inactive top-level window activates that window first; the
    /// default WM_ACTIVATE then leaves the focus inside it, where SetFocus put it.
    #[test]
    fn the_focus_into_an_inactive_window_activates_it() {
        let mut r = setup(true);
        let (top1, top2, child1) = (r.top1, r.top2, r.child1);
        r.set_active(top2);
        assert_eq!(r.state(), (top2, top2, top2));
        let (had, records) = r.set_focus(Some(child1));
        assert_eq!(had, top2);
        assert!(records.contains(&(top1, WM_ACTIVATE, WA_ACTIVE, top2 as i32)));
        assert_eq!(
            records.last(),
            Some(&(child1, WM_SETFOCUS, top2, 0)),
            "{records:?}"
        );
        assert_eq!(r.state(), (child1, top1, top1));
    }

    /// Hiding the active window activates the next one below it; SetForegroundWindow from another
    /// process's thread is refused while this one has the foreground.
    #[test]
    fn hiding_and_the_foreground_rule() {
        let mut r = setup(true);
        let (top1, top2) = (r.top1, r.top2);
        // top2 is above top1: activate it, so top1 is below.
        r.set_active(top2);
        r.m.show_window(top2, crate::win32k::window::SW_HIDE, &mut QueuePump)
            .unwrap();
        r.settle();
        assert_eq!(r.state(), (top1, top1, top1));
        let other = thread_of(r.m, 2, 0x200, OTHER_OWNER);
        let id = r.id(top1);
        let WindowManager {
            windows, classes, ..
        } = &mut *r.m;
        assert!(!set_foreground_window(
            windows,
            classes,
            other,
            id,
            &mut QueuePump
        ));
    }
}
