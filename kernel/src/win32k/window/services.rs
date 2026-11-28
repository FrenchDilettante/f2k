//! The target's side: the kernel's window manager behind its lock, and the services.

#[cfg(target_arch = "x86")]
use super::*;
use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
use crate::status::*;
#[cfg(target_arch = "x86")]
use crate::win32k::class;
#[cfg(target_arch = "x86")]
use crate::win32k::text::Staged;

/// The kernel's one window manager, behind its short lock. Built in place at its first
/// acquisition, the boot's ([`crate::win32k::winsta::init`]): by value it would pass through the
/// stack, which is smaller than it.
#[cfg(target_arch = "x86")]
mod target {
    use super::*;
    use crate::level::{At, Passive};
    use crate::sync::{ShortGuard, ShortLock};

    static MANAGER: ShortLock<WindowManager> =
        // SAFETY: `write_empty` writes a whole window manager at the address it is handed, and
        // takes no lock.
        unsafe { ShortLock::in_place(WindowManager::write_empty) };

    /// The window manager, locked for as long as the guard lives.
    pub fn lock(passive: &mut At<Passive>) -> ShortGuard<'_, WindowManager> {
        MANAGER.lock(passive)
    }

    /// Run `f` on the locked window manager: the bridge for code that holds no passive token.
    ///
    /// # Panics
    ///
    /// The processor is above the passive level: inside the window manager's lock already, or at
    /// a raised level, where nothing may wait for it.
    pub fn locked<R>(f: impl FnOnce(&mut WindowManager) -> R) -> R {
        assert_eq!(
            crate::pcr::pcr().current(),
            crate::interrupt::irql::PASSIVE,
            "the window manager's bridge entered above the passive level"
        );
        // SAFETY: a passive entry (see `At::enter`): the ledger reads the passive level, and the
        // token stays on this thread, dropped with this frame.
        let mut passive = unsafe { At::<Passive>::enter() };
        let mut manager = MANAGER.lock(&mut passive);
        let result = f(&mut manager);
        crate::win32k::input::publish(&manager.windows);
        result
    }
}

#[cfg(target_arch = "x86")]
pub use target::*;

#[cfg(target_arch = "x86")]
#[allow(clippy::too_many_arguments)]
pub fn create_window_ex(
    call: &mut NtCall,
    ex_style: u32,
    class_name: u32,
    window_name: UserAddr,
    style: u32,
    x: i32,
    y: i32,
    cx: i32,
    cy: i32,
    parent: Handle,
    menu: u32,
    instance: u32,
    param: u32,
    version: u32,
    window: UserPtr<u32>,
) -> NtResult {
    window.write(0)?;
    let mut class_units = [0u16; class::MAX_ATOM_NAME];
    let class_name = class::read_name(class_name, &mut class_units)?;
    let name = Staged::read(window_name)?;
    let caller = crate::win32k::winsta::gui_thread(call)?.thread;
    let mut args = CreateArgs {
        ex_style,
        class_name,
        class_atom: 0,
        name: name.units(),
        style,
        x,
        y,
        cx,
        cy,
        parent: None,
        menu: MenuInput::of(style, menu),
        instance,
        params: param,
        version,
    };
    let created = crate::win32k::queue::with_session(call.passive(), |s| {
        WindowManager::create_window(s, caller, parent.raw(), &mut args)
    });
    let created = match created {
        // The procedure's refusal: NULL, the last error untouched.
        Err(Failure::Refused) => 0,
        // A window destroyed inside its WM_NCCREATE: its dead handle, and the error's status,
        // which user32 makes the last error while answering the handle.
        Err(failure @ Failure::DestroyedInNcCreate(handle)) => {
            window.write(handle)?;
            return Err(failure.status());
        }
        created => created.map_err(Failure::status)?,
    };
    window.write(created)?;
    Ok(STATUS_SUCCESS)
}

/// NtUserDestroyWindow(Window): destroy the window, owned windows and children with it. Only its
/// thread may; a destroy a hook vetoes answers STATUS_UNSUCCESSFUL, the window untouched.
#[cfg(target_arch = "x86")]
pub fn destroy_window(call: &mut NtCall, window: Handle) -> NtResult {
    let caller = crate::win32k::winsta::gui_thread(call)?.thread;
    let destroyed = crate::win32k::queue::with_session(call.passive(), |s| {
        Windows::destroy_window_handle(s, caller, window.raw())
    })
    .map_err(Failure::status)?;
    if destroyed {
        Ok(STATUS_SUCCESS)
    } else {
        Err(STATUS_UNSUCCESSFUL)
    }
}

/// NtUserSetWindowPos(Window, InsertAfter, X, Y, Width, Height, Flags): SetWindowPos's arguments
/// as they are ([`Windows::set_window_pos_handle`]), its messages and its activation through the
/// queue's session.
#[cfg(target_arch = "x86")]
#[allow(clippy::too_many_arguments)]
pub fn set_window_pos(
    call: &mut NtCall,
    window: Handle,
    insert_after: Handle,
    x: i32,
    y: i32,
    cx: i32,
    cy: i32,
    flags: u32,
) -> NtResult {
    crate::win32k::winsta::gui_thread(call)?;
    crate::win32k::queue::with_session(call.passive(), |s| {
        Windows::set_window_pos_handle(s, window.raw(), insert_after.raw(), x, y, cx, cy, flags)
    })
    .map_err(Failure::status)?;
    Ok(STATUS_SUCCESS)
}

/// NtUserMoveWindow(Window, X, Y, Width, Height, Repaint): MoveWindow's arguments as they are
/// ([`WindowManager::move_window`]).
#[cfg(target_arch = "x86")]
pub fn move_window(
    call: &mut NtCall,
    window: Handle,
    x: i32,
    y: i32,
    cx: i32,
    cy: i32,
    repaint: u32,
) -> NtResult {
    crate::win32k::winsta::gui_thread(call)?;
    crate::win32k::queue::with_session(call.passive(), |s| {
        WindowManager::move_window(s, window.raw(), x, y, cx, cy, repaint != 0)
    })
    .map_err(Failure::status)?;
    Ok(STATUS_SUCCESS)
}

/// NtUserShowWindow(Window, Command, Previous): ShowWindow's arguments, and its answer through
/// `previous` ([`WindowManager::show_window`]), written once the window manager's lock is let go;
/// its messages and its activation through the queue's session.
#[cfg(target_arch = "x86")]
pub fn show_window(
    call: &mut NtCall,
    window: Handle,
    command: i32,
    previous: UserPtr<u32>,
) -> NtResult {
    crate::win32k::winsta::gui_thread(call)?;
    let answer = crate::win32k::queue::with_session(call.passive(), |s| {
        WindowManager::show_window(s, window.raw(), command)
    })
    .map_err(Failure::status)?;
    previous.write(answer)?;
    Ok(STATUS_SUCCESS)
}

/// NtUserShowWindowAsync(Window, Command): ShowWindowAsync's arguments
/// ([`WindowManager::show_window_async`]).
#[cfg(target_arch = "x86")]
pub fn show_window_async(call: &mut NtCall, window: Handle, command: i32) -> NtResult {
    crate::win32k::winsta::gui_thread(call)?;
    crate::win32k::queue::with_session(call.passive(), |s| {
        WindowManager::show_window_async(s, window.raw(), command)
    })
    .map_err(Failure::status)?;
    Ok(STATUS_SUCCESS)
}

/// NtUserGetWindowPlacement(Window, Placement): the window's WINDOWPLACEMENT into the caller's
/// ([`WindowManager::window_placement`]), its length the structure's whatever the caller's said.
#[cfg(target_arch = "x86")]
pub fn get_window_placement(call: &mut NtCall, window: Handle, placement: UserAddr) -> NtResult {
    let answer = lock(call.passive())
        .window_placement(window.raw())
        .map_err(Failure::status)?;
    placement
        .cast::<rtl::window::WindowPlacement>()
        .write(answer)?;
    Ok(STATUS_SUCCESS)
}

/// NtUserSetWindowPlacement(Window, Placement): the caller's WINDOWPLACEMENT made the window's
/// ([`WindowManager::set_window_placement`]), its messages through the queue's session.
#[cfg(target_arch = "x86")]
pub fn set_window_placement(call: &mut NtCall, window: Handle, placement: UserAddr) -> NtResult {
    crate::win32k::winsta::gui_thread(call)?;
    let placement = placement.cast::<rtl::window::WindowPlacement>().read()?;
    crate::win32k::queue::with_session(call.passive(), |s| {
        WindowManager::set_window_placement(s, window.raw(), &placement)
    })
    .map_err(Failure::status)?;
    Ok(STATUS_SUCCESS)
}

/// NtUserEndDeferWindowPosEx(Positions, Count): the `count` WINDOWPOS structures a
/// BeginDeferWindowPos batch gathered, at `positions`, carried out in order
/// ([`WindowManager::end_defer_window_pos`]); STATUS_INVALID_PARAMETER for more than
/// [`DEFER_POSITIONS`] (user32 hands a longer batch over in parts).
#[cfg(target_arch = "x86")]
pub fn end_defer_window_pos(call: &mut NtCall, positions: UserAddr, count: u32) -> NtResult {
    crate::win32k::winsta::gui_thread(call)?;
    let count = count as usize;
    if count > DEFER_POSITIONS {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let mut batch = [WindowPos::default(); DEFER_POSITIONS];
    let size = core::mem::size_of::<WindowPos>() as u32;
    for (at, pos) in batch[..count].iter_mut().enumerate() {
        *pos = positions
            .offset(size * at as u32)
            .cast::<WindowPos>()
            .read()?;
    }
    crate::win32k::queue::with_session(call.passive(), |s| {
        WindowManager::end_defer_window_pos(s, &batch[..count])
    })
    .map_err(Failure::status)?;
    Ok(STATUS_SUCCESS)
}

/// NtUserQueryWindow(Window, Index, Information, Length): `index`'s answer (rtl::window's QUERY_*)
/// into `information`, whose `length` must be the answer's own. STATUS_INVALID_INFO_CLASS for an
/// unknown index, STATUS_INFO_LENGTH_MISMATCH for another length (both before the window, as NT's
/// query services check), then STATUS_INVALID_HANDLE. Copied out once the lock is let go.
#[cfg(target_arch = "x86")]
pub fn query_window(
    call: &mut NtCall,
    window: Handle,
    index: u32,
    information: UserAddr,
    length: u32,
) -> NtResult {
    query_accepts(index, length as usize)?;
    if index == rtl::window::QUERY_WINDOW_THREAD {
        return query_window_thread(call, window, information);
    }
    if index == rtl::window::QUERY_WINDOW_SCROLL_BARS {
        return crate::win32k::scroll::query_window_scroll_bars(call, window, information);
    }
    if index == rtl::window::QUERY_WINDOW_TEXT {
        return query_window_text(call, window, information, length);
    }
    let caller = call.process().object().index;
    let answer = lock(call.passive())
        .query_window(window.raw(), index, length as usize, caller)
        .map_err(Failure::status)?;
    information.write(answer.bytes())?;
    Ok(STATUS_SUCCESS)
}

/// QUERY_WINDOW_TEXT: the window's text's length, then as many of its units as the answer's
/// `length` bytes hold after it (no terminator), copied under the lock and written once it is let
/// go.
#[cfg(target_arch = "x86")]
fn query_window_text(
    call: &mut NtCall,
    window: Handle,
    information: UserAddr,
    length: u32,
) -> NtResult {
    let room = (length as usize - 4) / 2;
    let (full, units) = {
        let manager = lock(call.passive());
        let id = manager
            .windows
            .window_of(window.raw())
            .map_err(Failure::status)?;
        let text = manager.windows.window_text(id);
        let fits = &text[..text.len().min(room)];
        (text.len(), Staged::copy_of(fits).ok_or(STATUS_NO_MEMORY)?)
    };
    information.cast::<u32>().write(full as u32)?;
    information
        .offset(4)
        .write(rtl::pod::slice_bytes(units.units()))?;
    Ok(STATUS_SUCCESS)
}

/// QUERY_WINDOW_THREAD: the client ids of the window's thread and process
/// (GetWindowThreadProcessId). The desktop's own windows answer the raw input thread in the
/// System process; Windows 2000 answers its desktop thread in CSRSS, another process's thread
/// either way (the wintree capture's ids block).
#[cfg(target_arch = "x86")]
fn query_window_thread(call: &mut NtCall, window: Handle, information: UserAddr) -> NtResult {
    use crate::level::Dispatch;
    use crate::sched::DISPATCHER;
    let (client_id, owner) = {
        let manager = lock(call.passive());
        let id = manager
            .windows
            .window_of(window.raw())
            .map_err(Failure::status)?;
        let thread = manager.windows.window_thread(id);
        (
            crate::win32k::queue::client_id_of(&manager.windows, thread),
            manager.windows.window_process(id),
        )
    };
    let answer = match client_id {
        Some(thread) if owner != class::SYSTEM_OWNER => rtl::window::WindowThread {
            process: crate::process::pool::record(owner).id(),
            thread,
        },
        _ => {
            let mut dispatch = call.passive().raise::<Dispatch>();
            rtl::window::WindowThread {
                process: crate::process::SYSTEM_PROCESS_ID,
                thread: DISPATCHER
                    .get(&mut dispatch)
                    .thread(crate::sched::database::RAW_INPUT_THREAD)
                    .thread_id(),
            }
        }
    };
    information.cast().write(answer)?;
    Ok(STATUS_SUCCESS)
}

/// NtUserSetWindowLong(Window, Index, NewLong, Ansi, Previous, PreviousAnsi): SetWindowLong's
/// change ([`Windows::set_window_long`]): the old value into `previous`, and for GWL_WNDPROC
/// whether the old procedure was narrow into `previous_ansi` (0 otherwise). Both are written once
/// the lock is let go.
#[cfg(target_arch = "x86")]
pub fn set_window_long(
    call: &mut NtCall,
    window: Handle,
    index: i32,
    value: u32,
    ansi: u32,
    previous: UserPtr<u32>,
    previous_ansi: UserPtr<u32>,
) -> NtResult {
    let caller = crate::win32k::winsta::gui_thread(call)?.owner;
    let (old, old_ansi) = crate::win32k::queue::with_session(call.passive(), |s| {
        Windows::set_window_long(s, caller, window.raw(), index, value, ansi != 0)
    })
    .map_err(Failure::status)?;
    previous.write(old)?;
    previous_ansi.write(old_ansi as u32)?;
    Ok(STATUS_SUCCESS)
}

/// NtUserSetWindowWord(Window, Index, NewWord, Previous): SetWindowWord's change of the word at
/// `index` in the window's extra bytes ([`Windows::set_window_word`]); the word it held into
/// `previous`.
#[cfg(target_arch = "x86")]
pub fn set_window_word(
    call: &mut NtCall,
    window: Handle,
    index: i32,
    value: u32,
    previous: UserPtr<u32>,
) -> NtResult {
    let old = lock(call.passive())
        .windows
        .set_window_word(window.raw(), index, value as u16)
        .map_err(Failure::status)?;
    previous.write(old as u32)?;
    Ok(STATUS_SUCCESS)
}

/// NtUserDefSetText(Window, Text): the window's text set to the NUL-terminated UTF-16 string at
/// `text` (null: the empty text), whole: DefWindowProc's WM_SETTEXT and the title its WM_NCCREATE
/// sets. The text is read before the window manager's lock is taken.
#[cfg(target_arch = "x86")]
pub fn def_set_text(call: &mut NtCall, window: Handle, text: UserAddr) -> NtResult {
    let text = Staged::read(text)?;
    lock(call.passive())
        .windows
        .set_window_text(window.raw(), text.units())
        .map_err(Failure::status)?;
    Ok(STATUS_SUCCESS)
}

/// NtUserChildWindowFromPointEx(Parent, X, Y, Flags, Child): the child of `parent` holding the
/// point of its client area into `child` ([`WindowManager::child_window_from_point`]): 0 for a
/// point outside it; STATUS_INVALID_HANDLE for a handle naming no window.
#[cfg(target_arch = "x86")]
pub fn child_window_from_point_ex(
    call: &mut NtCall,
    parent: Handle,
    x: i32,
    y: i32,
    flags: u32,
    child: UserPtr<u32>,
) -> NtResult {
    let found = lock(call.passive())
        .child_window_from_point(parent.raw(), x, y, flags)
        .map_err(Failure::status)?;
    child.write(found.unwrap_or(0))?;
    Ok(STATUS_SUCCESS)
}

/// NtUserSetWindowFNID(Window, Fnid): the window marked as the kind of window `fnid` names
/// (rtl::window's FNID_*: user32's dialog manager marks its dialogs) for the window's life
/// ([`Windows::set_window_fnid`]): STATUS_ACCESS_DENIED for another process's window,
/// STATUS_INVALID_PARAMETER for a window marked already.
#[cfg(target_arch = "x86")]
pub fn set_window_fnid(call: &mut NtCall, window: Handle, fnid: u32) -> NtResult {
    let caller = crate::win32k::winsta::gui_thread(call)?.owner;
    let mut manager = lock(call.passive());
    let id = manager
        .windows
        .window_of(window.raw())
        .map_err(Failure::status)?;
    manager
        .windows
        .set_window_fnid(id, fnid, caller)
        .map_err(Failure::status)?;
    Ok(STATUS_SUCCESS)
}

/// NtUserFindWindowEx(Parent, ChildAfter, ClassName, WindowName, Found): the window
/// [`WindowManager::find_window`] finds into `found` (0 for none): `ClassName` a string's address
/// or an atom (0: any class), `WindowName` a string's address (0: any title). The names are read
/// before the window manager's lock is taken.
#[cfg(target_arch = "x86")]
pub fn find_window_ex(
    call: &mut NtCall,
    parent: Handle,
    after: Handle,
    class_name: u32,
    window_name: UserAddr,
    found: UserPtr<u32>,
) -> NtResult {
    let mut class_units = [0u16; class::MAX_ATOM_NAME];
    let class = match class_name {
        0 => None,
        raw => Some(class::read_name(raw, &mut class_units)?),
    };
    let title = match window_name.is_null() {
        true => None,
        false => Some(Staged::read(window_name)?),
    };
    let caller = crate::win32k::winsta::gui_thread(call)?.thread;
    let optional = |handle: Handle| (handle.raw() != 0).then(|| handle.raw());
    let answer = lock(call.passive())
        .find_window(
            caller,
            optional(parent),
            optional(after),
            class,
            title.as_ref().map(Staged::units),
        )
        .map_err(Failure::status)?;
    found.write(answer.unwrap_or(0))?;
    Ok(STATUS_SUCCESS)
}

// The host builds have no processes and no user memory: the services answer nothing (the host
// tests drive the window manager itself).

#[cfg(not(target_arch = "x86"))]
#[allow(clippy::too_many_arguments)]
pub fn create_window_ex(
    _: &mut NtCall,
    _: u32,
    _: u32,
    _: UserAddr,
    _: u32,
    _: i32,
    _: i32,
    _: i32,
    _: i32,
    _: Handle,
    _: u32,
    _: u32,
    _: u32,
    _: u32,
    _: UserPtr<u32>,
) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

#[cfg(not(target_arch = "x86"))]
pub fn destroy_window(_: &mut NtCall, _: Handle) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

#[cfg(not(target_arch = "x86"))]
#[allow(clippy::too_many_arguments)]
pub fn set_window_pos(
    _: &mut NtCall,
    _: Handle,
    _: Handle,
    _: i32,
    _: i32,
    _: i32,
    _: i32,
    _: u32,
) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

#[cfg(not(target_arch = "x86"))]
pub fn move_window(_: &mut NtCall, _: Handle, _: i32, _: i32, _: i32, _: i32, _: u32) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

#[cfg(not(target_arch = "x86"))]
pub fn show_window(_: &mut NtCall, _: Handle, _: i32, _: UserPtr<u32>) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

#[cfg(not(target_arch = "x86"))]
pub fn show_window_async(_: &mut NtCall, _: Handle, _: i32) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

#[cfg(not(target_arch = "x86"))]
pub fn get_window_placement(_: &mut NtCall, _: Handle, _: UserAddr) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

#[cfg(not(target_arch = "x86"))]
pub fn set_window_placement(_: &mut NtCall, _: Handle, _: UserAddr) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

#[cfg(not(target_arch = "x86"))]
pub fn end_defer_window_pos(_: &mut NtCall, _: UserAddr, _: u32) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

#[cfg(not(target_arch = "x86"))]
pub fn query_window(_: &mut NtCall, _: Handle, _: u32, _: UserAddr, _: u32) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

#[cfg(not(target_arch = "x86"))]
pub fn set_window_long(
    _: &mut NtCall,
    _: Handle,
    _: i32,
    _: u32,
    _: u32,
    _: UserPtr<u32>,
    _: UserPtr<u32>,
) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

#[cfg(not(target_arch = "x86"))]
pub fn child_window_from_point_ex(
    _: &mut NtCall,
    _: Handle,
    _: i32,
    _: i32,
    _: u32,
    _: UserPtr<u32>,
) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

#[cfg(not(target_arch = "x86"))]
pub fn set_window_word(_: &mut NtCall, _: Handle, _: i32, _: u32, _: UserPtr<u32>) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

#[cfg(not(target_arch = "x86"))]
pub fn def_set_text(_: &mut NtCall, _: Handle, _: UserAddr) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

#[cfg(not(target_arch = "x86"))]
pub fn set_window_fnid(_: &mut NtCall, _: Handle, _: u32) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

#[cfg(not(target_arch = "x86"))]
pub fn find_window_ex(
    _: &mut NtCall,
    _: Handle,
    _: Handle,
    _: u32,
    _: UserAddr,
    _: UserPtr<u32>,
) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}
