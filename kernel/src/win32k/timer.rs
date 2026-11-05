//! Timers: SetTimer's records, and the WM_TIMER a thread's read makes for one that came due.
//!
//! A timer is a record of the window manager's ([`Timers`], beside the queues, behind its one
//! lock): a window's (named by the window and its id) or a thread's (a null window: the id is the
//! timer's own, made by SetTimer), its interval, its TimerProc, and its due, on the interrupt
//! time's clock. Nothing runs when a timer comes due: a read of its thread's queue
//! ([`super::queue::take`]) marks every due timer of the thread's ready and moves its due an
//! interval on (expirations missed meanwhile coalesce into one, as Windows 2000's do), and makes a
//! WM_TIMER for a ready one when nothing comes before it (wParam the id, lParam the TimerProc).
//! A thread waiting on its empty queue waits no longer than its next timer's due — the scheduler's
//! wait timeouts are the clock that wakes it — and SetTimer sets the queue's event, so a waiting
//! thread a timer is set for looks again.
//!
//! The services, user32's calls (F2K's argument lists, see [`crate::win32k`]):
//!
//! - NtUserSetTimer(handle Window, u32 IdEvent, u32 Elapse, u32 TimerFunc, ptr<u32> Id): the timer
//!   set (or reset), its id into `Id`;
//! - NtUserKillTimer(handle Window, u32 IdEvent): the timer gone.

use rtl::user::WM_TIMER;

use super::queue::Filter;
use super::window::{Hwnd, WindowId, Windows};
use crate::sched::thread::ThreadId;
use crate::status::*;

/// How many timers can be set at once.
pub const TIMERS: usize = 64;

/// The longest interval SetTimer takes, in milliseconds (USER_TIMER_MAXIMUM); a longer one is
/// cut to it.
pub const USER_TIMER_MAXIMUM: u32 = 0x7FFF_FFFF;

/// The shortest interval, in milliseconds: a zero interval comes due at every read, and a thread
/// whose WM_TIMER its filter leaves out would never wait.
pub const SHORTEST_INTERVAL: u32 = 1;

/// The interrupt time's units (100 ns) in a millisecond.
const UNITS_PER_MS: u64 = 10_000;

/// One timer.
#[derive(Clone, Copy)]
struct Timer {
    live: bool,
    /// The thread whose queue gets the WM_TIMER: the window's, or the setter's for a thread timer.
    thread: ThreadId,
    /// The window, for a window's timer.
    window: Option<WindowId>,
    hwnd: Hwnd,
    id: u32,
    /// The interval, in interrupt-time units.
    interval: u64,
    /// When it next comes due (interrupt time).
    due: u64,
    /// The TimerProc, WM_TIMER's lParam.
    func: u32,
    /// It came due, and its WM_TIMER has not been taken yet.
    ready: bool,
}

impl Timer {
    const EMPTY: Self = Timer {
        live: false,
        thread: ThreadId(0),
        window: None,
        hwnd: 0,
        id: 0,
        interval: 0,
        due: 0,
        func: 0,
        ready: false,
    };
}

/// The timers.
pub struct Timers {
    timers: [Timer; TIMERS],
    /// The next id a thread timer may take.
    next_id: u32,
}

impl Timers {
    /// Write an empty table at `timers`, field by field.
    ///
    /// # Safety
    ///
    /// `timers` is valid for writes, aligned, and the records' final address; its previous
    /// contents are overwritten, not dropped.
    pub unsafe fn write_empty(timers: *mut Timers) {
        use core::ptr::addr_of_mut;
        // SAFETY: the caller's contract; every field is written, the array element by element.
        unsafe {
            let records = addr_of_mut!((*timers).timers) as *mut Timer;
            for index in 0..TIMERS {
                records.add(index).write(Timer::EMPTY);
            }
            addr_of_mut!((*timers).next_id).write(1);
        }
    }

    /// The live timer of the window `window` with the id `id`, or the thread `thread`'s thread
    /// timer of that id when there is no window.
    fn find(&self, window: Option<WindowId>, thread: ThreadId, id: u32) -> Option<usize> {
        self.timers.iter().position(|t| {
            t.live && t.id == id && t.window == window && (window.is_some() || t.thread == thread)
        })
    }

    /// An id for a new thread timer of `thread`: none of its timers' (a counter's next value,
    /// skipping 0 and the ids in use).
    fn fresh_id(&mut self, thread: ThreadId) -> u32 {
        loop {
            let id = self.next_id;
            self.next_id = self.next_id.wrapping_add(1).max(1);
            if self.find(None, thread, id).is_none() {
                return id;
            }
        }
    }

    /// Mark every timer of `thread` that came due by `now` ready, its due moved an interval on
    /// from `now`.
    pub fn expire(&mut self, thread: ThreadId, now: u64) {
        for timer in self.timers.iter_mut() {
            if timer.live && timer.thread == thread && timer.due <= now {
                timer.ready = true;
                timer.due = now + timer.interval;
            }
        }
    }

    /// The first ready timer of `thread` the filter takes a WM_TIMER of: its window, its id and its
    /// TimerProc; no longer ready when `remove`.
    pub fn next_ready(
        &mut self,
        thread: ThreadId,
        filter: &Filter,
        remove: bool,
    ) -> Option<(Hwnd, u32, u32)> {
        let timer = self
            .timers
            .iter_mut()
            .find(|t| t.live && t.ready && t.thread == thread && filter.takes(t.hwnd, WM_TIMER))?;
        if remove {
            timer.ready = false;
        }
        Some((timer.hwnd, timer.id, timer.func))
    }

    /// When `thread`'s next timer comes due (interrupt time); none when it has no timer.
    pub fn next_due(&self, thread: ThreadId) -> Option<u64> {
        self.timers
            .iter()
            .filter(|t| t.live && t.thread == thread)
            .map(|t| t.due)
            .min()
    }

    /// The window `window` is being freed: its timers go.
    pub fn window_gone(&mut self, window: WindowId) {
        for timer in self.timers.iter_mut() {
            if timer.live && timer.window == Some(window) {
                *timer = Timer::EMPTY;
            }
        }
    }

    /// The thread record `thread`'s queue ended: the timers whose WM_TIMER went to it go.
    pub fn thread_gone(&mut self, thread: ThreadId) {
        for timer in self.timers.iter_mut() {
            if timer.live && timer.thread == thread {
                *timer = Timer::EMPTY;
            }
        }
    }
}

/// SetTimer at `now`: the window `hwnd`'s timer `id` (a null window: a thread timer of `caller`'s),
/// due every `elapse` milliseconds, its WM_TIMER's lParam `func`. A timer already set with that
/// window and id (or that thread and id) is reset: its interval, its TimerProc, its due from now,
/// and a WM_TIMER not taken yet goes. The answer is the timer's id: the given one for a window's
/// timer (1 for a zero id, as the answer must not be zero), the given one for a thread timer that
/// matches one, a fresh one otherwise. STATUS_INVALID_HANDLE for a handle naming no window,
/// STATUS_ACCESS_DENIED for another process's window, STATUS_INSUFFICIENT_RESOURCES when the table
/// is full.
#[allow(clippy::too_many_arguments)]
pub fn set(
    windows: &mut Windows,
    caller: ThreadId,
    hwnd: Hwnd,
    id: u32,
    elapse: u32,
    func: u32,
    now: u64,
) -> Result<u32, NtStatus> {
    let window = owned_window(windows, caller, hwnd)?;
    let thread = window.map_or(caller, |w| windows.window_thread(w));
    let timers = &mut windows.queues.timers;
    let (slot, id, answer) = match timers.find(window, caller, id) {
        Some(slot) => (slot, id, if window.is_some() { id.max(1) } else { id }),
        None => {
            let slot = timers
                .timers
                .iter()
                .position(|t| !t.live)
                .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
            let id = if window.is_some() {
                id
            } else {
                timers.fresh_id(caller)
            };
            (slot, id, if window.is_some() { id.max(1) } else { id })
        }
    };
    let interval = u64::from(elapse.clamp(SHORTEST_INTERVAL, USER_TIMER_MAXIMUM)) * UNITS_PER_MS;
    timers.timers[slot] = Timer {
        live: true,
        thread,
        window,
        hwnd: if window.is_some() { hwnd } else { 0 },
        id,
        interval,
        due: now + interval,
        func,
        ready: false,
    };
    windows.queues.wake_thread(thread);
    Ok(answer)
}

/// KillTimer: the window `hwnd`'s timer `id` (a null window: `caller`'s thread timer) goes, with a
/// WM_TIMER of it not taken yet. STATUS_INVALID_HANDLE for a handle naming no window,
/// STATUS_ACCESS_DENIED for another process's window, STATUS_INVALID_PARAMETER for a timer there
/// is not.
pub fn kill(windows: &mut Windows, caller: ThreadId, hwnd: Hwnd, id: u32) -> Result<(), NtStatus> {
    let window = owned_window(windows, caller, hwnd)?;
    let timers = &mut windows.queues.timers;
    let slot = timers
        .find(window, caller, id)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    timers.timers[slot] = Timer::EMPTY;
    Ok(())
}

/// The window a timer call names: none for a null handle (a thread timer), the window for a handle
/// naming one of the caller's process's.
fn owned_window(
    windows: &Windows,
    caller: ThreadId,
    hwnd: Hwnd,
) -> Result<Option<WindowId>, NtStatus> {
    if hwnd == 0 {
        return Ok(None);
    }
    let window = windows
        .window_from_handle(hwnd)
        .ok_or(STATUS_INVALID_HANDLE)?;
    if windows.window_process(window) != windows.thread_process(caller) {
        return Err(STATUS_ACCESS_DENIED);
    }
    Ok(Some(window))
}

// --- The services --------------------------------------------------------------------------------

#[cfg(target_arch = "x86")]
mod services {
    use super::*;
    use crate::nt::call::{Handle, NtCall, NtResult, UserPtr};
    use crate::win32k::queue::{now, with_manager};
    use crate::win32k::winsta::gui_thread;

    /// NtUserSetTimer(Window, IdEvent, Elapse, TimerFunc, Id): see [`set`]; the id is
    /// written first (0), so a fault never leaves a timer unreported.
    pub fn set_timer(
        call: &mut NtCall,
        window: Handle,
        id: u32,
        elapse: u32,
        func: u32,
        out: UserPtr<u32>,
    ) -> NtResult {
        let caller = gui_thread(call)?.thread;
        out.write(0)?;
        let now = now();
        let set = with_manager(call.passive(), |m| {
            set(&mut m.windows, caller, window.raw(), id, elapse, func, now)
        })?;
        out.write(set)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserKillTimer(Window, IdEvent): see [`kill`].
    pub fn kill_timer(call: &mut NtCall, window: Handle, id: u32) -> NtResult {
        let caller = gui_thread(call)?.thread;
        with_manager(call.passive(), |m| {
            kill(&mut m.windows, caller, window.raw(), id)
        })?;
        Ok(STATUS_SUCCESS)
    }
}

pub use services::{kill_timer, set_timer};

// The host builds have no processes: the services answer nothing (the host tests drive the timers
// themselves).
#[cfg(not(target_arch = "x86"))]
mod services {
    use crate::nt::call::{Handle, NtCall, NtResult, UserPtr};
    use crate::status::*;

    pub fn set_timer(
        _: &mut NtCall,
        _: Handle,
        _: u32,
        _: u32,
        _: u32,
        _: UserPtr<u32>,
    ) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn kill_timer(_: &mut NtCall, _: Handle, _: u32) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }
}

#[cfg(test)]
mod tests {
    use rtl::user::{WM_PAINT, WM_USER};

    use super::*;
    use crate::win32k::queue::rig::*;
    use crate::win32k::queue::{post, take, Taken};
    use crate::win32k::window::WindowManager;

    /// A millisecond of interrupt time.
    const MS: u64 = UNITS_PER_MS;

    /// A thread timer: a fresh id; no WM_TIMER before its due; at its due a WM_TIMER with no
    /// window, the id and the TimerProc, taken once; expirations missed meanwhile make one; the
    /// next due an interval from the read that found it due.
    #[test]
    fn a_thread_timer_comes_due() {
        let (m, _) = manager();
        let t = thread(m, 1, 0x100);
        let id = set(&mut m.windows, t, 0, 99, 10, 0x0040_2000, 0).unwrap();
        assert_ne!(id, 0);
        assert_eq!(
            read(m, t, &all(), 5 * MS),
            Taken::Nothing { due: Some(10 * MS) }
        );
        let msg = msg_of(read(m, t, &all(), 55 * MS));
        assert_eq!(
            (msg.hwnd, msg.message, msg.wparam, msg.lparam),
            (0, WM_TIMER, id, 0x0040_2000)
        );
        assert_eq!(msg.time, 55, "made when read");
        assert_eq!(
            read(m, t, &all(), 56 * MS),
            Taken::Nothing { due: Some(65 * MS) },
            "one for the five intervals missed"
        );
        // A second thread timer takes another id.
        let other = set(&mut m.windows, t, 0, 0, 10, 0, 0).unwrap();
        assert_ne!(other, id);
        // Set again with its id, a thread timer is reset, not doubled.
        assert_eq!(set(&mut m.windows, t, 0, id, 100, 0, 60 * MS), Ok(id));
        kill(&mut m.windows, t, 0, other).unwrap();
        assert_eq!(
            read(m, t, &all(), 61 * MS),
            Taken::Nothing {
                due: Some(160 * MS)
            }
        );
    }

    /// A window's timer answers its id (1 for a zero id), is reset by the same window and id,
    /// and goes with KillTimer — a WM_TIMER not taken yet with it; a timer there is not, a
    /// handle naming no window and another process's window are refused.
    #[test]
    fn a_windows_timer_is_named_by_window_and_id() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let h = popup(m, atom, t);
        deliver(m, t);
        assert_eq!(set(&mut m.windows, t, h, 7, 10, 0, 0), Ok(7));
        assert_eq!(set(&mut m.windows, t, h, 0, 10, 0, 0), Ok(1));
        assert_eq!(set(&mut m.windows, t, h, 7, 20, 0, 0), Ok(7));
        let msg = msg_of(read(m, t, &all(), 15 * MS));
        assert_eq!((msg.hwnd, msg.message, msg.wparam), (h, WM_TIMER, 0));
        assert_eq!(
            read(m, t, &all(), 16 * MS),
            Taken::Nothing { due: Some(20 * MS) }
        );
        // Due but not taken: the kill takes the WM_TIMER with it.
        take(&mut m.windows, t, &all(), false, 21 * MS).unwrap();
        kill(&mut m.windows, t, h, 7).unwrap();
        assert_eq!(
            read(m, t, &all(), 22 * MS),
            Taken::Nothing { due: Some(25 * MS) }
        );
        assert_eq!(kill(&mut m.windows, t, h, 7), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(
            set(&mut m.windows, t, 0x7FFF_FFFC, 1, 10, 0, 0),
            Err(STATUS_INVALID_HANDLE)
        );
        let stranger = thread_of(m, 2, 0x200, OTHER_OWNER);
        assert_eq!(
            set(&mut m.windows, stranger, h, 1, 10, 0, 0),
            Err(STATUS_ACCESS_DENIED)
        );
        assert_eq!(
            kill(&mut m.windows, stranger, h, 0),
            Err(STATUS_ACCESS_DENIED)
        );
    }

    /// A window's timers go with the window.
    #[test]
    fn a_windows_timers_go_with_it() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let h = popup(m, atom, t);
        deliver(m, t);
        set(&mut m.windows, t, h, 1, 10, 0, 0).unwrap();
        let WindowManager {
            windows, classes, ..
        } = &mut *m;
        windows
            .destroy_window_handle(classes, t, h, &mut crate::win32k::queue::QueuePump)
            .unwrap();
        deliver(m, t);
        assert_eq!(read(m, t, &all(), 100 * MS), Taken::Nothing { due: None });
    }

    /// The order a read keeps: what was posted, then WM_PAINT, then WM_TIMER; a filter that
    /// leaves the WM_TIMER out finds nothing, and its wait ends at the next due.
    #[test]
    fn timers_come_last() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let h = popup(m, atom, t);
        deliver(m, t);
        m.windows
            .set_visible_for_tests(m.windows.window_from_handle(h).unwrap(), true);
        set(&mut m.windows, t, h, 1, 10, 0, 0).unwrap();
        let w = m.windows.window_from_handle(h).unwrap();
        crate::win32k::paint::invalidate(&mut m.windows, w, None, false);
        post(&mut m.windows, t, h, WM_USER, 0, 0, 0).unwrap();
        let now = 10 * MS;
        assert_eq!(msg_of(read(m, t, &all(), now)).message, WM_USER);
        assert_eq!(msg_of(read(m, t, &all(), now)).message, WM_PAINT);
        let not_timers = crate::win32k::queue::Filter::new(0, WM_USER, WM_USER, 0);
        assert_eq!(
            take(&mut m.windows, t, &not_timers, true, now),
            Ok(Taken::Nothing { due: Some(20 * MS) })
        );
        crate::win32k::paint::begin_validate(&mut m.windows, w);
        assert_eq!(msg_of(read(m, t, &all(), now)).message, WM_TIMER);
    }

    /// The interval is held between the shortest and USER_TIMER_MAXIMUM; setting a timer wakes
    /// the thread its WM_TIMER goes to, so a wait looks at the new due.
    #[test]
    fn the_interval_is_clamped_and_the_thread_woken() {
        let (m, _) = manager();
        let t = thread(m, 1, 0x100);
        m.windows.queues.take_wakes();
        let id = set(&mut m.windows, t, 0, 0, 0, 0, 0).unwrap();
        assert_eq!(m.windows.queues.take_wakes()[0], 1 << t.0);
        assert_eq!(read(m, t, &all(), 0), Taken::Nothing { due: Some(MS) });
        set(&mut m.windows, t, 0, id, u32::MAX, 0, 0).unwrap();
        assert_eq!(
            read(m, t, &all(), 0),
            Taken::Nothing {
                due: Some(u64::from(USER_TIMER_MAXIMUM) * MS)
            }
        );
    }
}
