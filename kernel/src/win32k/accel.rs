//! Keyboard accelerators: the accelerator tables behind HACCELs, the translation of a keyboard
//! message into the command it stands for, and the services user32's accelerator calls come
//! through.
//!
//! A table is a record in the table pool ([`Accelerators`], a slot pool: [`crate::slots`]), named
//! by an id with a uniqueness count ([`TableId`]), with a handle into the user handle table
//! ([`super::handle`]). It holds its entries (rtl::accel's ACCEL, a character entry's key a UTF-16
//! unit) and belongs to the process that made it, which takes it at its end. The pool grows a
//! chunk of the nonpaged pool at a time and keeps its peak; only memory bounds it. An id a table
//! was destroyed under, or one naming no slot at all, finds nothing.
//!
//! LoadAccelerators answers the same table for every load of one resource, until as many
//! DestroyAcceleratorTable calls as loads have gone (Windows documents DestroyAcceleratorTable's
//! answer as nonzero only then; the load section's capture shows the same handle four times).
//! Windows 2000's user32 keeps that cache of loaded tables itself, a list in the process; F2K keeps
//! it with the table, its resource (the module and the resource data's address, which names the
//! resource in the module) and its load count in the record, behind the window manager's lock, so
//! user32 has no process-wide list to lock.
//!
//! TranslateAccelerator ([`find_command`], [`translate`]) matches the message against the table
//! (rtl::accel's [`find`](rtl::accel::find), the modifiers from the thread's key state) and sends
//! the window WM_COMMAND, its wParam's high word 1, its low word the command. When the window's
//! menu holds an item of that command, WM_INITMENU and WM_INITMENUPOPUP are sent first, as if the
//! menu were being opened, and a grayed or disabled item, or a disabled window, gets no WM_COMMAND:
//! the accelerator is still translated. The messages go through the session
//! ([`super::queue::QueueSession`]), queued for the window's thread as every message the window
//! manager sends is; so a WM_INITMENUPOPUP handler that enables the item comes too late for this
//! translation (the item's state is read when the decision runs), which Windows 2000's synchronous
//! send would see.
//!
//! The modifiers are the thread's key state's ([`modifiers`], [`super::input`]). Seam recorded:
//! the window menu (the system menu), whose commands are sent as WM_SYSCOMMAND: there is none
//! yet.
//!
//! The services (F2K's argument lists, see [`crate::win32k`]; Windows 2000's numbers):
//!
//! - NtUserCreateAcceleratorTable (0x1148): a table of the caller's ACCEL entries; with a resource
//!   (LoadAccelerators's), the table already loaded from it, its load count up;
//! - NtUserCopyAcceleratorTable (0x1146): a table's entry count, or its entries;
//! - NtUserDestroyAcceleratorTable (0x1155): a table's load count down, the table destroyed with
//!   its last;
//! - NtUserTranslateAccelerator (0x1223): a keyboard message translated for a window.
//!
//! A failure names the Win32 error code of the decision ([`Failure`]'s variants), which the
//! service answers in a FACILITY_NTWIN32 status ([`Failure::status`]) for user32 to report as is:
//! ERROR_INVALID_WINDOW_HANDLE for a window naming nothing, ERROR_INVALID_ACCEL_HANDLE for a table
//! naming nothing.

use rtl::accel::{Accel, Modifiers, ACCEL_BITS};
use rtl::menu::{MF_DISABLED, MF_GRAYED};

use super::class::Owner;
use super::handle::{UserHandles, UserObject};
use super::menu::ItemRef;
use super::window::{Message, Payload, Session, WindowId, WindowManager};
use crate::sched::thread::ThreadId;
use crate::slots::{Id, KernelId, Record, Slots, KERNEL_PAGES, PAGE};
use crate::status::*;

/// How many entries one table holds.
pub const MAX_ENTRIES: usize = 128;

/// The messages a translation sends (winuser.h).
pub const WM_COMMAND: u32 = 0x0111;
pub const WM_INITMENU: u32 = 0x0116;
pub const WM_INITMENUPOPUP: u32 = 0x0117;

/// WS_DISABLED: the window takes no input.
const WS_DISABLED: u32 = 0x0800_0000;

/// Why an accelerator operation failed: the Win32 error code (winerror.h) the decision reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// ERROR_NOT_ENOUGH_MEMORY (8): the pool could not grow.
    NotEnoughMemory,
    /// ERROR_INVALID_PARAMETER (87): no entries, or more than a table holds.
    InvalidParameter,
    /// ERROR_INVALID_WINDOW_HANDLE (1400).
    InvalidWindowHandle,
    /// ERROR_INVALID_ACCEL_HANDLE (1403).
    InvalidAccelHandle,
}

impl Failure {
    /// The Win32 error code (winerror.h) the decision reports.
    pub const fn code(self) -> u32 {
        match self {
            Failure::NotEnoughMemory => 8,
            Failure::InvalidParameter => 87,
            Failure::InvalidWindowHandle => 1400,
            Failure::InvalidAccelHandle => 1403,
        }
    }

    /// The NTSTATUS the service answers: the Win32 error itself ([`Failure::code`]) in a
    /// FACILITY_NTWIN32 status, which user32 hands to GetLastError as is.
    pub const fn status(self) -> NtStatus {
        NtStatus::from_win32(self.code())
    }
}

/// The table pool's kind of id.
pub enum TableTag {}

/// A table's id: its slot in the pool and the slot's uniqueness count.
pub type TableId = Id<TableTag>;

impl TableId {
    /// The id of the slot `index`, its first count (the handle table's tests).
    #[cfg(test)]
    pub const fn for_tests(index: u16) -> Self {
        Id::new(index, 1)
    }
}

/// Tables to a chunk: one page's worth, a slot being its record and 8 bytes.
const TABLES_PER_CHUNK: usize = PAGE / (core::mem::size_of::<Table>() + 8);

// Measured (788-byte tables); the record holds no pointer, so this is the target's and the host's
// alike.
const _: () = assert!(TABLES_PER_CHUNK == 5);
const _: () = assert!(Slots::<Table, KernelId<TableTag>, TABLES_PER_CHUNK>::CHUNK_PAGES == 1);

/// The resource a table was loaded from: its module and its data's address (0 for a table
/// CreateAcceleratorTable made).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Source {
    pub module: u32,
    pub resource: u32,
}

/// One table's record.
struct Table {
    handle: u32,
    owner: Owner,
    source: Source,
    /// How many loads of its resource it answers for (1 for a created table).
    loads: u32,
    count: u16,
    entries: [Accel; MAX_ENTRIES],
}

impl Table {
    const EMPTY: Self = Table {
        handle: 0,
        owner: 0,
        source: Source {
            module: 0,
            resource: 0,
        },
        loads: 0,
        count: 0,
        entries: [Accel {
            virt: 0,
            pad: 0,
            key: 0,
            cmd: 0,
        }; MAX_ENTRIES],
    };
}

// SAFETY: `write_fresh` writes a whole record.
unsafe impl Record for Table {
    unsafe fn write_fresh(at: *mut Self, _: u32) {
        // SAFETY: the caller's contract.
        unsafe { at.write(Self::EMPTY) };
    }
}

/// The accelerator registry: the table pool. Its tables' handles are the user handle table's
/// ([`UserHandles`], the window registry's), which the calls that make, find or destroy a table
/// are lent.
pub struct Accelerators {
    tables: Slots<Table, KernelId<TableTag>, TABLES_PER_CHUNK>,
}

impl Accelerators {
    /// An empty registry: no table, no chunk made.
    pub const fn new() -> Self {
        Accelerators {
            tables: Slots::new(),
        }
    }

    /// Write an empty registry at `accels`.
    ///
    /// # Safety
    ///
    /// `accels` is valid for writes and aligned; its previous contents are overwritten, not
    /// dropped.
    pub unsafe fn write_empty(accels: *mut Accelerators) {
        // SAFETY: the caller's contract.
        unsafe { accels.write(Self::new()) };
    }

    /// The table `handle` names in `handles`, when it is live; ERROR_INVALID_ACCEL_HANDLE
    /// otherwise (another kind's handle among them).
    pub fn table_of(&self, handles: &UserHandles, handle: u32) -> Result<TableId, Failure> {
        handles
            .accelerator_table(handle)
            .filter(|&id| self.tables.get(id).is_some())
            .ok_or(Failure::InvalidAccelHandle)
    }

    /// The table the process `owner` loaded from `source` and has not destroyed as often as it
    /// loaded it, its load count up: LoadAccelerators's answer for a resource it loaded before.
    /// The resource data's address names the resource, whatever handle named its module (NULL
    /// or the module's own).
    pub fn load_again(&mut self, owner: Owner, source: Source) -> Option<u32> {
        if source.resource == 0 {
            return None;
        }
        let (_, table) = self
            .tables
            .iter_mut()
            .find(|(_, t)| t.owner == owner && t.source.resource == source.resource)?;
        table.loads += 1;
        Some(table.handle)
    }

    /// A new, empty table of the process `owner`, loaded from `source` (none: made); its handle.
    pub fn create(
        &mut self,
        handles: &mut UserHandles,
        owner: Owner,
        source: Source,
    ) -> Result<u32, Failure> {
        if handles.is_full() {
            return Err(Failure::NotEnoughMemory);
        }
        let (id, table) = self
            .tables
            .allocate_or_grow(0, &KERNEL_PAGES)
            .map_err(|_| Failure::NotEnoughMemory)?;
        let handle = handles.insert(UserObject::AcceleratorTable(id));
        // Field by field: a whole record would cross the gate stack as a temporary. The entries
        // past the count are never read.
        table.handle = handle;
        table.owner = owner;
        table.source = source;
        table.loads = 1;
        table.count = 0;
        Ok(handle)
    }

    /// Append `entries` to the table `id` (their fVirt cut to the bits a table keeps);
    /// ERROR_INVALID_PARAMETER when they do not fit, ERROR_INVALID_ACCEL_HANDLE when `id` names
    /// no live table.
    pub fn append(&mut self, id: TableId, entries: &[Accel]) -> Result<(), Failure> {
        let table = self.tables.get_mut(id).ok_or(Failure::InvalidAccelHandle)?;
        let count = table.count as usize;
        let end = count + entries.len();
        if end > MAX_ENTRIES {
            return Err(Failure::InvalidParameter);
        }
        for (slot, entry) in table.entries[count..end].iter_mut().zip(entries) {
            *slot = Accel {
                virt: entry.virt & ACCEL_BITS,
                pad: 0,
                ..*entry
            };
        }
        table.count = end as u16;
        Ok(())
    }

    /// The table's entries (none when `id` names no live table).
    pub fn entries(&self, id: TableId) -> &[Accel] {
        self.tables
            .get(id)
            .map_or(&[], |table| &table.entries[..table.count as usize])
    }

    /// DestroyAcceleratorTable: the table's load count down, the table destroyed with its last
    /// load; whether it was destroyed (false too when `id` names no live table).
    pub fn destroy(&mut self, handles: &mut UserHandles, id: TableId) -> bool {
        let Some(table) = self.tables.get_mut(id) else {
            return false;
        };
        if table.loads > 1 {
            table.loads -= 1;
            return false;
        }
        handles.close(table.handle);
        self.tables.free(id)
    }

    /// Destroy every table of the process `owner`, at its end, whatever its load count.
    pub fn destroy_owner(&mut self, handles: &mut UserHandles, owner: Owner) {
        let mut from = 0;
        loop {
            let next = self
                .tables
                .iter_mut()
                .find(|(id, table)| id.index >= from && table.owner == owner);
            let Some((id, table)) = next else {
                break;
            };
            table.loads = 1;
            self.destroy(handles, id);
            from = id.index;
        }
    }

    /// How many tables are live.
    pub fn live(&self) -> usize {
        self.tables.live() as usize
    }
}

/// The modifiers down for a translation on the thread `thread`: its key state's Shift, Ctrl and
/// Alt, as of its last key message read or as SetKeyboardState set them.
pub fn modifiers(manager: &WindowManager, thread: ThreadId) -> Modifiers {
    manager.windows.thread(thread).keys.modifiers()
}

/// TranslateAccelerator's match: the message `message` (its wParam `key`) on the thread `thread`,
/// matched against the table `table` for the window `window`; the window and the matched entry's
/// command, none when nothing matched. A null window translates nothing; a table naming nothing is
/// ERROR_INVALID_ACCEL_HANDLE, checked first (the translate section's capture: a null table is
/// 1403, a null window answers FALSE with no error).
pub fn find_command(
    manager: &WindowManager,
    thread: ThreadId,
    window: u32,
    table: u32,
    message: u32,
    key: u32,
) -> Result<Option<(WindowId, u32)>, Failure> {
    let table = manager.accels.table_of(&manager.windows.handles, table)?;
    if window == 0 {
        return Ok(None);
    }
    let target = manager
        .windows
        .window_from_handle(window)
        .ok_or(Failure::InvalidWindowHandle)?;
    let modifiers = modifiers(manager, thread);
    Ok(
        rtl::accel::find(manager.accels.entries(table), message, key, modifiers)
            .map(|entry| (target, u32::from(entry.cmd))),
    )
}

/// TranslateAccelerator's decision once an entry matched ([`find_command`]): the command `command`
/// sent to the window `target`, its menu's messages first when it holds an item of the command.
pub fn translate(s: &mut dyn Session, target: WindowId, command: u32) {
    let send = |s: &mut dyn Session, message: u32, wparam: u32, lparam: i32| {
        s.send(
            target,
            &mut Message {
                message,
                wparam,
                lparam,
                payload: Payload::None,
            },
        );
    };

    // The window's menu, when it holds an item of the command: opened, as far as its messages go.
    let mut enabled = true;
    let windows = s.windows();
    let bar = windows.window_menu(target);
    if !windows.window_is_child(target) && bar != 0 {
        if let Ok(bar_id) = windows.menu_of(bar) {
            if let Some((holder, position)) = windows.menus.find(bar_id, ItemRef::Command(command))
            {
                let state = windows
                    .menus
                    .query_item(holder, ItemRef::Position(position as u32))
                    .map_or(0, |item| item.state);
                enabled = state & (MF_GRAYED | MF_DISABLED) == 0;
                let popup = (holder != bar_id).then(|| {
                    let index = windows.menus.position_in(bar_id, holder).unwrap_or(0);
                    (windows.menus.handle_of(holder), index)
                });
                send(s, WM_INITMENU, bar, 0);
                if let Some((popup, index)) = popup {
                    send(s, WM_INITMENUPOPUP, popup, index as i32);
                }
            }
        }
    }
    let windows = s.windows();
    if enabled && windows.is_live(target) && windows.window_style(target) & WS_DISABLED == 0 {
        send(s, WM_COMMAND, (1 << 16) | command, 0);
    }
}

// --- The services
// --------------------------------------------------------------------------------------

#[cfg(target_arch = "x86")]
mod services {
    use rtl::user::Msg;

    use super::*;
    use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
    use crate::win32k::queue::{with_manager, with_session};
    use crate::win32k::winsta::gui_thread;

    /// The entries copied in or out at a time, through a buffer on the stack.
    const CHUNK: usize = 64;

    /// NtUserCreateAcceleratorTable(Entries, Count, Module, Resource, Table): a table of the
    /// `count` ACCEL entries at `entries` into `table`; with a resource (LoadAccelerators's: the
    /// module and the resource data's address), the table the caller's process already loaded from
    /// it, the entries unread. STATUS_INVALID_PARAMETER for no entries or more than a table holds.
    pub fn create_accelerator_table(
        call: &mut NtCall,
        entries: UserAddr,
        count: u32,
        module: u32,
        resource: u32,
        table: UserPtr<u32>,
    ) -> NtResult {
        let owner = gui_thread(call)?.owner;
        let source = Source { module, resource };
        if let Some(handle) = with_manager(call.passive(), |m| m.accels.load_again(owner, source)) {
            table.write(handle)?;
            return Ok(STATUS_SUCCESS);
        }
        if count == 0 || count as usize > MAX_ENTRIES {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let handle = with_manager(call.passive(), |m| {
            m.accels.create(&mut m.windows.handles, owner, source)
        })
        .map_err(Failure::status)?;
        // The entries, a chunk at a time: read at the passive level, appended under the lock. A
        // fault takes the table back.
        let mut buffer = [Accel::default(); CHUNK];
        let mut done = 0;
        while done < count as usize {
            let n = (count as usize - done).min(CHUNK);
            let mut read = Ok(());
            for (index, slot) in buffer[..n].iter_mut().enumerate() {
                match entries
                    .offset((6 * (done + index)) as u32)
                    .cast::<Accel>()
                    .read()
                {
                    Ok(entry) => *slot = entry,
                    Err(fault) => {
                        read = Err(fault);
                        break;
                    }
                }
            }
            let appended = with_manager(call.passive(), |m| {
                let id = m
                    .accels
                    .table_of(&m.windows.handles, handle)
                    .map_err(Failure::status)?;
                if read.is_err() {
                    m.accels.destroy(&mut m.windows.handles, id);
                    return Err(STATUS_ACCESS_VIOLATION);
                }
                m.accels.append(id, &buffer[..n]).map_err(Failure::status)
            });
            appended?;
            done += n;
        }
        table.write(handle)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserCopyAcceleratorTable(Table, Entries, Count, Copied): with no entries' buffer, the
    /// table's entry count; else its first `count` entries (as many as it has, at most) into
    /// `entries`, their number into `copied`.
    pub fn copy_accelerator_table(
        call: &mut NtCall,
        table: Handle,
        entries: UserAddr,
        count: u32,
        copied: UserPtr<u32>,
    ) -> NtResult {
        gui_thread(call)?;
        let total = with_manager(call.passive(), |m| {
            let id = m.accels.table_of(&m.windows.handles, table.raw())?;
            Ok(m.accels.entries(id).len())
        })
        .map_err(Failure::status)?;
        if entries.is_null() {
            copied.write(total as u32)?;
            return Ok(STATUS_SUCCESS);
        }
        let wanted = total.min(count as usize);
        let mut buffer = [Accel::default(); CHUNK];
        let mut done = 0;
        while done < wanted {
            let n = (wanted - done).min(CHUNK);
            with_manager(call.passive(), |m| {
                let id = m.accels.table_of(&m.windows.handles, table.raw())?;
                let source = m.accels.entries(id);
                let n = n.min(source.len().saturating_sub(done));
                buffer[..n].copy_from_slice(&source[done..done + n]);
                Ok(())
            })
            .map_err(Failure::status)?;
            for (index, entry) in buffer[..n].iter().enumerate() {
                entries
                    .offset((6 * (done + index)) as u32)
                    .cast::<Accel>()
                    .write(*entry)?;
            }
            done += n;
        }
        copied.write(wanted as u32)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserDestroyAcceleratorTable(Table, Destroyed): the table's load count down, the table
    /// destroyed with its last load; whether it was, into `destroyed`.
    pub fn destroy_accelerator_table(
        call: &mut NtCall,
        table: Handle,
        destroyed: UserPtr<u32>,
    ) -> NtResult {
        gui_thread(call)?;
        let gone = with_manager(call.passive(), |m| {
            let id = m.accels.table_of(&m.windows.handles, table.raw())?;
            Ok(m.accels.destroy(&mut m.windows.handles, id))
        })
        .map_err(Failure::status)?;
        destroyed.write(gone as u32)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserTranslateAccelerator(Window, Table, Msg, Translated): the MSG at `msg` translated
    /// for the window through the table ([`translate`]); whether it was an accelerator, into
    /// `translated`. The messages the translation sent are queued for the window's thread.
    pub fn translate_accelerator(
        call: &mut NtCall,
        window: Handle,
        table: Handle,
        msg: UserAddr,
        translated: UserPtr<u32>,
    ) -> NtResult {
        let caller = gui_thread(call)?.thread;
        let msg = msg.cast::<Msg>().read()?;
        let answer = with_session(call.passive(), |s| {
            let found = find_command(
                s.manager(),
                caller,
                window.raw(),
                table.raw(),
                msg.message,
                msg.wparam,
            )?;
            let Some((target, command)) = found else {
                return Ok(false);
            };
            translate(s, target, command);
            Ok(true)
        })
        .map_err(Failure::status)?;
        translated.write(answer as u32)?;
        Ok(STATUS_SUCCESS)
    }
}

// The host builds have no processes and no user memory: the services answer nothing (the host
// tests drive the registry and the translation themselves).
#[cfg(not(target_arch = "x86"))]
mod services {
    use super::*;
    use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};

    pub fn create_accelerator_table(
        _: &mut NtCall,
        _: UserAddr,
        _: u32,
        _: u32,
        _: u32,
        _: UserPtr<u32>,
    ) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn copy_accelerator_table(
        _: &mut NtCall,
        _: Handle,
        _: UserAddr,
        _: u32,
        _: UserPtr<u32>,
    ) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn destroy_accelerator_table(_: &mut NtCall, _: Handle, _: UserPtr<u32>) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn translate_accelerator(
        _: &mut NtCall,
        _: Handle,
        _: Handle,
        _: UserAddr,
        _: UserPtr<u32>,
    ) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }
}

pub use services::{
    copy_accelerator_table,
    create_accelerator_table,
    destroy_accelerator_table,
    translate_accelerator,
};

#[cfg(test)]
mod tests {
    use std::boxed::Box;

    use super::*;

    const OWNER: Owner = 3;

    /// The accelerator registry and the handle table its tables' handles are in.
    struct Fixture {
        accels: Box<Accelerators>,
        handles: Box<UserHandles>,
    }

    impl Fixture {
        fn create(&mut self, owner: Owner, source: Source) -> Result<u32, Failure> {
            self.accels.create(&mut self.handles, owner, source)
        }

        fn table_of(&self, handle: u32) -> Result<TableId, Failure> {
            self.accels.table_of(&self.handles, handle)
        }

        fn destroy(&mut self, id: TableId) -> bool {
            self.accels.destroy(&mut self.handles, id)
        }

        fn destroy_owner(&mut self, owner: Owner) {
            self.accels.destroy_owner(&mut self.handles, owner);
        }
    }

    impl core::ops::Deref for Fixture {
        type Target = Accelerators;

        fn deref(&self) -> &Accelerators {
            &self.accels
        }
    }

    impl core::ops::DerefMut for Fixture {
        fn deref_mut(&mut self) -> &mut Accelerators {
            &mut self.accels
        }
    }

    fn accelerators() -> Fixture {
        let mut boxed = Box::<Accelerators>::new_uninit();
        let mut handles = Box::<UserHandles>::new_uninit();
        // SAFETY: the boxes' memory, valid and aligned, written whole before it is assumed.
        unsafe {
            Accelerators::write_empty(boxed.as_mut_ptr());
            UserHandles::write_empty(handles.as_mut_ptr());
            Fixture {
                accels: boxed.assume_init(),
                handles: handles.assume_init(),
            }
        }
    }

    /// A resource's table answers every load until it is destroyed as often; a made one goes at
    /// once, and the process's end takes what is left.
    #[test]
    fn loads_share_a_table_until_destroyed_as_often() {
        let mut a = accelerators();
        let source = Source {
            module: 0x40_0000,
            resource: 0x40_A000,
        };
        assert_eq!(a.load_again(OWNER, source), None);
        let table = a.create(OWNER, source).unwrap();
        let id = a.table_of(table).unwrap();
        let f5 = Accel {
            virt: 0x81,
            pad: 0,
            key: 116,
            cmd: 303,
        };
        a.append(id, &[f5]).unwrap();
        assert_eq!(
            a.entries(id)[0].virt,
            0x01,
            "the last-entry flag is not kept"
        );
        assert_eq!(a.load_again(OWNER, source), Some(table));
        assert_eq!(
            a.load_again(OWNER + 1, source),
            None,
            "another process's own"
        );
        assert!(!a.destroy(id));
        assert_eq!(a.table_of(table), Ok(id));
        assert!(a.destroy(id));
        assert_eq!(a.table_of(table), Err(Failure::InvalidAccelHandle));
        let made = a
            .create(
                OWNER,
                Source {
                    module: 0,
                    resource: 0,
                },
            )
            .unwrap();
        assert_eq!(
            a.load_again(
                OWNER,
                Source {
                    module: 0,
                    resource: 0
                }
            ),
            None
        );
        a.load_again(OWNER, source);
        a.create(OWNER, source).unwrap();
        a.load_again(OWNER, source);
        a.destroy_owner(OWNER);
        assert_eq!(a.live(), 0);
        assert_eq!(a.table_of(made), Err(Failure::InvalidAccelHandle));
        assert_eq!(
            a.table_of(0x7FFC),
            Err(Failure::InvalidAccelHandle),
            "a slot holding nothing"
        );
    }

    /// No more entries than a table holds.
    #[test]
    fn tables_hold_what_they_hold() {
        let mut a = accelerators();
        let table = a
            .create(
                OWNER,
                Source {
                    module: 0,
                    resource: 0,
                },
            )
            .unwrap();
        let id = a.table_of(table).unwrap();
        let entries = [Accel::default(); MAX_ENTRIES];
        a.append(id, &entries).unwrap();
        assert_eq!(a.append(id, &entries[..1]), Err(Failure::InvalidParameter));
    }

    /// A destroyed table's id names nothing: no entries, nothing appended, no second destroy.
    #[test]
    fn a_destroyed_tables_id_names_nothing() {
        let mut a = accelerators();
        let made = Source {
            module: 0,
            resource: 0,
        };
        let table = a.create(OWNER, made).unwrap();
        let id = a.table_of(table).unwrap();
        a.append(id, &[Accel::default(); 3]).unwrap();
        assert!(a.destroy(id));
        assert_eq!(a.entries(id), &[]);
        assert_eq!(
            a.append(id, &[Accel::default()]),
            Err(Failure::InvalidAccelHandle)
        );
        assert!(!a.destroy(id));
        assert_eq!(a.live(), 0);

        // The slot is taken again, its count moved on: the old id and handle name nothing.
        let again = a.create(OWNER, made).unwrap();
        let again_id = a.table_of(again).unwrap();
        assert_eq!((again_id.index, again_id.uniq), (id.index, id.uniq + 1));
        assert_eq!(a.entries(again_id), &[], "a fresh table holds no entry");
        assert_eq!(a.table_of(table), Err(Failure::InvalidAccelHandle));
    }

    /// An id past every slot made, through a handle naming it, finds nothing and panics nowhere
    /// (the old fixed array was indexed unchecked).
    #[test]
    fn an_id_past_the_pool_names_nothing() {
        let mut a = accelerators();
        for forged in [TableId::for_tests(200), Id::new(0xFFFF, 1), Id::new(0, 0)] {
            let handle = a.handles.insert(UserObject::AcceleratorTable(forged));
            assert_eq!(a.table_of(handle), Err(Failure::InvalidAccelHandle));
            a.handles.close(handle);
            assert_eq!(a.entries(forged), &[]);
            assert!(!a.destroy(forged));
        }
    }

    /// The pool grows past a chunk, and the process's end takes every table it made.
    #[test]
    fn the_pool_grows_and_ends_with_the_process() {
        let mut a = accelerators();
        let mut tables = std::vec::Vec::new();
        for resource in 0..4 * TABLES_PER_CHUNK as u32 {
            let source = Source {
                module: 0x40_0000,
                resource: 0x40_A000 + 16 * resource,
            };
            tables.push(a.create(OWNER, source).unwrap());
        }
        let other = a
            .create(
                OWNER + 1,
                Source {
                    module: 0,
                    resource: 0,
                },
            )
            .unwrap();
        assert_eq!(a.live(), 4 * TABLES_PER_CHUNK + 1);
        a.destroy_owner(OWNER);
        assert_eq!(a.live(), 1);
        for table in tables {
            assert_eq!(a.table_of(table), Err(Failure::InvalidAccelHandle));
        }
        assert!(a.table_of(other).is_ok());
    }
}
