//! Window properties: the (atom, data) pairs SetProp hangs on a window, and the services user32's
//! property calls come through.
//!
//! A property is named by an atom, the global atom of its name or an integer atom: user32 turns
//! a name into its atom itself (GlobalAddAtom for SetProp, GlobalFindAtom for GetProp and
//! RemoveProp, as Windows 2000's user32 does), so the window manager sees atoms only, and a
//! property set by name is found by its atom and the reverse. The atom's reference belongs to
//! user32's calls, never to the property: a window destroyed with its properties still set leaves
//! their atoms in the table (the props capture's refs block).
//!
//! The properties of every window are one table ([`Props`]), each entry naming its window by id;
//! Windows 2000 keeps an array per window in its desktop's heap. A destroyed window's entries are
//! not visited at its destruction: its id names no live window any more (the id carries the
//! record's generation), so nothing finds them, and a set that finds the table full takes them
//! back first.
//!
//! The services (F2K's argument lists, see [`crate::win32k`]; Windows 2000's numbers):
//!
//! - NtUserSetProp (0x1200): the window's property `atom` set to `data`, a new one or replaced;
//! - NtUserRemoveProp (0x11DA): the property taken off the window, its data through the last
//!   pointer (0 when the window has none of that atom);
//! - NtUserBuildPropList (0x1130): the window's properties as PROPSETs (rtl::window's
//!   [`PropSet`](rtl::window::PropSet)), as many as fit, their count through the last pointer; what
//!   GetProp reads and EnumProps walks (Windows 2000's user32 reads GetProp's answer from the
//!   window's array, mapped into its process).
//!
//! A property belongs to its window's process: SetProp and RemoveProp on another process's window
//! are refused (ERROR_ACCESS_DENIED), as Windows 2000's NtUserSetProp and NtUserRemoveProp refuse
//! them; reading another process's window's properties is allowed. Any thread of the window's
//! process may set and remove them (the props capture's thread block).

use super::class::Owner;
use super::window::{Failure, WindowId};
use crate::status::*;

/// How many properties every window together can hold.
pub const PROPS: usize = 512;

/// One property: its window, its atom and its data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Prop {
    /// The window the property hangs on; none for a free entry.
    window: Option<WindowId>,
    atom: u16,
    data: u32,
}

impl Prop {
    const FREE: Self = Prop {
        window: None,
        atom: 0,
        data: 0,
    };
}

/// The windows' properties, every window's in one table.
pub struct Props {
    entries: [Prop; PROPS],
}

impl Props {
    /// Write an empty table at `props`, entry by entry (by value it would pass through the stack).
    ///
    /// # Safety
    ///
    /// `props` is valid for writes, aligned, and the table's final address; its previous contents
    /// are overwritten, not dropped.
    pub unsafe fn write_empty(props: *mut Props) {
        // SAFETY: the caller's contract; every entry is written.
        unsafe {
            let entries = core::ptr::addr_of_mut!((*props).entries) as *mut Prop;
            for index in 0..PROPS {
                entries.add(index).write(Prop::FREE);
            }
        }
    }

    /// The entry of `window`'s property `atom`, if it has one.
    fn find(&self, window: WindowId, atom: u16) -> Option<usize> {
        self.entries
            .iter()
            .position(|p| p.window == Some(window) && p.atom == atom)
    }

    /// The data of `window`'s property `atom`; none when it has no such property (the host tests'
    /// look: the services list the properties instead).
    #[cfg(test)]
    pub fn get(&self, window: WindowId, atom: u16) -> Option<u32> {
        self.find(window, atom)
            .map(|index| self.entries[index].data)
    }

    /// SetProp's decision: `window`'s property `atom` set to `data`, replacing the data of one it
    /// has. Atom 0 names no property (ERROR_INVALID_PARAMETER, a NULL name's: the props capture's
    /// errors block). A full table first takes back the entries of the windows `is_live` says are
    /// gone; ERROR_OUTOFMEMORY when it is still full.
    pub fn set(
        &mut self,
        window: WindowId,
        atom: u16,
        data: u32,
        is_live: impl Fn(WindowId) -> bool,
    ) -> Result<(), Failure> {
        if atom == 0 {
            return Err(Failure::InvalidParameter);
        }
        if let Some(index) = self.find(window, atom) {
            self.entries[index].data = data;
            return Ok(());
        }
        let free = |entries: &[Prop]| entries.iter().position(|p| p.window.is_none());
        let index = match free(&self.entries) {
            Some(index) => index,
            None => {
                for entry in self.entries.iter_mut() {
                    if entry.window.is_some_and(|w| !is_live(w)) {
                        *entry = Prop::FREE;
                    }
                }
                free(&self.entries).ok_or(Failure::OutOfMemory)?
            }
        };
        self.entries[index] = Prop {
            window: Some(window),
            atom,
            data,
        };
        Ok(())
    }

    /// RemoveProp's decision: `window`'s property `atom` taken off, its data answered; none when
    /// it has no such property (atom 0 names none).
    pub fn remove(&mut self, window: WindowId, atom: u16) -> Option<u32> {
        let index = self.find(window, atom)?;
        let data = self.entries[index].data;
        self.entries[index] = Prop::FREE;
        Some(data)
    }

    /// `window`'s properties, as (atom, data) pairs, in the order they were set.
    pub fn list(&self, window: WindowId) -> impl Iterator<Item = (u16, u32)> + '_ {
        // A freed entry is reused before the table grows past it, so the entries' order is not
        // the order of setting: an entry's place in the table is, among those of one window, as
        // good an order as Windows 2000's (its array's, which a removal reorders too).
        self.entries
            .iter()
            .filter(move |p| p.window == Some(window))
            .map(|p| (p.atom, p.data))
    }

    /// How many entries are taken (the host tests' count).
    #[cfg(test)]
    pub fn live(&self) -> usize {
        self.entries.iter().filter(|p| p.window.is_some()).count()
    }
}

/// The property calls' window check: the window `window` names, for a change by the process
/// `caller`; another process's window is ERROR_ACCESS_DENIED.
fn own_window(
    windows: &super::window::Windows,
    window: u32,
    caller: Owner,
) -> Result<WindowId, Failure> {
    let id = windows.window_of(window)?;
    if windows.window_process(id) != caller {
        return Err(Failure::AccessDenied);
    }
    Ok(id)
}

/// NtUserSetProp's decision over the window manager: see [`Props::set`] and [`own_window`].
pub fn set_window_prop(
    manager: &mut super::window::WindowManager,
    window: u32,
    atom: u16,
    data: u32,
    caller: Owner,
) -> Result<(), Failure> {
    let id = own_window(&manager.windows, window, caller)?;
    let windows = &manager.windows;
    manager.props.set(id, atom, data, |w| windows.is_live(w))
}

/// NtUserRemoveProp's decision over the window manager: the property's data, 0 for none; see
/// [`Props::remove`] and [`own_window`].
pub fn remove_window_prop(
    manager: &mut super::window::WindowManager,
    window: u32,
    atom: u16,
    caller: Owner,
) -> Result<u32, Failure> {
    let id = own_window(&manager.windows, window, caller)?;
    Ok(manager.props.remove(id, atom).unwrap_or(0))
}

// --- The services
// --------------------------------------------------------------------------------------

#[cfg(target_arch = "x86")]
mod services {
    use core::mem::size_of;

    use rtl::window::PropSet;

    use super::*;
    use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
    use crate::win32k::queue::with_manager;
    use crate::win32k::winsta::gui_thread;

    /// The properties copied out at a time, through a buffer on the stack.
    const CHUNK: usize = 32;

    /// NtUserSetProp(Window, Atom, Data): see [`set_window_prop`]. An atom above 0xFFFF is
    /// STATUS_INVALID_PARAMETER.
    pub fn set_prop(call: &mut NtCall, window: Handle, atom: u32, data: u32) -> NtResult {
        let owner = gui_thread(call)?.owner;
        let atom = u16::try_from(atom).map_err(|_| STATUS_INVALID_PARAMETER)?;
        with_manager(call.passive(), |m| {
            set_window_prop(m, window.raw(), atom, data, owner)
        })
        .map_err(Failure::status)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserRemoveProp(Window, Atom, Data): see [`remove_window_prop`]; the data into `data`.
    pub fn remove_prop(
        call: &mut NtCall,
        window: Handle,
        atom: u32,
        data: UserPtr<u32>,
    ) -> NtResult {
        let owner = gui_thread(call)?.owner;
        let answer = match u16::try_from(atom) {
            Ok(atom) => with_manager(call.passive(), |m| {
                remove_window_prop(m, window.raw(), atom, owner)
            })
            .map_err(Failure::status)?,
            Err(_) => 0,
        };
        data.write(answer)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserBuildPropList(Window, List, Max, Count): the window's properties, the first `max`
    /// of them as PROPSETs into `list`, and how many it has into `count`;
    /// STATUS_BUFFER_TOO_SMALL (the count still written) when they do not all fit.
    pub fn build_prop_list(
        call: &mut NtCall,
        window: Handle,
        list: UserAddr,
        max: u32,
        count: UserPtr<u32>,
    ) -> NtResult {
        let mut done = 0usize;
        loop {
            // A chunk at a time: gathered under the lock, written once it is let go.
            let mut chunk = [PropSet::default(); CHUNK];
            let (total, n) = with_manager(call.passive(), |m| {
                let id = m.windows.window_of(window.raw())?;
                let mut total = 0usize;
                let mut n = 0usize;
                for (index, (atom, data)) in m.props.list(id).enumerate() {
                    total += 1;
                    if index >= done && n < CHUNK && index < max as usize {
                        chunk[n] = PropSet {
                            data,
                            atom: u32::from(atom),
                        };
                        n += 1;
                    }
                }
                Ok::<_, Failure>((total, n))
            })
            .map_err(Failure::status)?;
            for (index, set) in chunk[..n].iter().enumerate() {
                list.offset((size_of::<PropSet>() * (done + index)) as u32)
                    .cast::<PropSet>()
                    .write(*set)?;
            }
            done += n;
            if n < CHUNK {
                count.write(total as u32)?;
                return if total > max as usize {
                    Err(STATUS_BUFFER_TOO_SMALL)
                } else {
                    Ok(STATUS_SUCCESS)
                };
            }
        }
    }
}

// The host builds have no processes and no user memory: the services answer nothing (the host
// tests drive the table themselves).
#[cfg(not(target_arch = "x86"))]
mod services {
    use super::*;
    use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};

    pub fn set_prop(_: &mut NtCall, _: Handle, _: u32, _: u32) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn remove_prop(_: &mut NtCall, _: Handle, _: u32, _: UserPtr<u32>) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn build_prop_list(
        _: &mut NtCall,
        _: Handle,
        _: UserAddr,
        _: u32,
        _: UserPtr<u32>,
    ) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }
}

pub use services::{build_prop_list, remove_prop, set_prop};

#[cfg(test)]
mod tests {
    use std::boxed::Box;
    use std::vec::Vec;

    use super::*;

    fn table() -> Box<Props> {
        let mut props = Box::<Props>::new_uninit();
        // SAFETY: the box's memory is the table's final address, written whole.
        unsafe {
            Props::write_empty(props.as_mut_ptr());
            props.assume_init()
        }
    }

    const A: WindowId = WindowId::for_tests(1);
    const B: WindowId = WindowId::for_tests(2);

    fn live(_: WindowId) -> bool {
        true
    }

    /// The string block: a property set, read, replaced and removed (its data answered, then
    /// nothing); a second property of another atom beside it; a value of 0 set and read back.
    #[test]
    fn set_get_replace_remove() {
        let mut p = table();
        assert_eq!(p.set(A, 0xC001, 0x1111, live), Ok(()));
        assert_eq!(p.get(A, 0xC001), Some(0x1111));
        assert_eq!(p.set(A, 0xC002, 0x2222, live), Ok(()));
        assert_eq!(p.set(A, 0xC001, 0x3333, live), Ok(()));
        assert_eq!(p.get(A, 0xC001), Some(0x3333));
        assert_eq!(p.get(A, 0xC002), Some(0x2222));
        assert_eq!(p.live(), 2, "a replacement takes no second entry");
        assert_eq!(p.remove(A, 0xC001), Some(0x3333));
        assert_eq!(p.remove(A, 0xC001), None);
        assert_eq!(p.get(A, 0xC001), None);
        assert_eq!(p.set(A, 0xC003, 0, live), Ok(()));
        assert_eq!(p.get(A, 0xC003), Some(0));
    }

    /// A property is its window's: another window's of the same atom is another property; atom 0
    /// names none (ERROR_INVALID_PARAMETER for a set, nothing for the others).
    #[test]
    fn windows_and_atom_zero() {
        let mut p = table();
        p.set(A, 291, 0x6666, live).unwrap();
        p.set(B, 291, 0x7777, live).unwrap();
        assert_eq!(p.get(A, 291), Some(0x6666));
        assert_eq!(p.get(B, 291), Some(0x7777));
        assert_eq!(p.set(A, 0, 0x9999, live), Err(Failure::InvalidParameter));
        assert_eq!(p.get(A, 0), None);
        assert_eq!(p.remove(A, 0), None);
        let listed: Vec<_> = p.list(A).collect();
        assert_eq!(listed, [(291, 0x6666)]);
    }

    /// A full table takes back the entries of the windows that are gone, and refuses a set when
    /// every entry is a live window's.
    #[test]
    fn a_full_table_reclaims_dead_windows() {
        let mut p = table();
        for index in 0..PROPS {
            p.set(A, 0xC000 + index as u16, 1, live).unwrap();
        }
        assert_eq!(p.set(B, 1, 2, live), Err(Failure::OutOfMemory));
        assert_eq!(
            p.set(A, 0xC000, 5, live),
            Ok(()),
            "a replacement needs no entry"
        );
        assert_eq!(p.set(B, 1, 2, |w| w != A), Ok(()));
        assert_eq!(p.live(), 1);
        assert_eq!(p.get(A, 0xC000), None);
        assert_eq!(p.get(B, 1), Some(2));
    }
}
