//! Keyboard accelerators: the accelerator tables behind HACCELs, the translation of a keyboard
//! message into the command it stands for, and the services user32's accelerator calls come
//! through.
//!
//! A table is a record in the table pool ([`Accelerators`]), named by a generation-tagged id
//! ([`TableId`]), the object manager's pattern, with a handle into the table handle table. It holds
//! its entries (rtl::accel's ACCEL, a character entry's key a UTF-16 unit) and belongs to the
//! process that made it, which takes it at its end.
//!
//! LoadAccelerators answers the same table for every load of one resource, until as many
//! DestroyAcceleratorTable calls as loads have gone (Windows documents DestroyAcceleratorTable's
//! answer as nonzero only then; the load section's capture shows the same handle four times).
//! Windows 2000's user32 keeps that cache of loaded tables itself, a list in the process; F2K keeps
//! it with the table, its resource (the module and the resource data's address, which names the
//! resource in the module) and its load count in the record, behind the window manager's lock, so
//! user32 has no process-wide list to lock.
//!
//! TranslateAccelerator ([`translate`]) matches the message against the table (rtl::accel's
//! [`find`](rtl::accel::find), the modifiers from the thread's key state) and sends the window
//! WM_COMMAND, its wParam's high word 1, its low word the command. When the window's menu holds an
//! item of that command, WM_INITMENU and WM_INITMENUPOPUP are sent first, as if the menu were being
//! opened, and a grayed or disabled item, or a disabled window, gets no WM_COMMAND: the
//! accelerator is still translated. The messages go through the pump ([`super::queue::QueuePump`]),
//! queued for the window's thread as every message the window manager sends is; so a
//! WM_INITMENUPOPUP handler that enables the item comes too late for this translation (the item's
//! state is read when the decision runs), which Windows 2000's synchronous send would see.
//!
//! Seams recorded: the key state. win32k keeps no key state yet (the keyboard input comes later),
//! so no modifier is down for a translation ([`modifiers`]). The window menu (the system menu),
//! whose commands are sent as WM_SYSCOMMAND: there is none yet.
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
//! A failure names the Win32 error code of the decision ([`Failure`]'s variants); a window naming
//! nothing answers STATUS_INVALID_HANDLE, as for every window service, and a table naming nothing
//! STATUS_OBJECT_TYPE_MISMATCH (the handle names no table).

use rtl::accel::{Accel, Modifiers, ACCEL_BITS};
use rtl::menu::{MF_DISABLED, MF_GRAYED};

use super::class::Owner;
use super::menu::ItemRef;
use super::window::{Message, Payload, Pump, WindowManager};
use crate::sched::object::HandleTable;
use crate::sched::thread::ThreadId;
use crate::status::*;

/// How many tables can exist at once, and how many entries one holds.
pub const TABLES: usize = 64;
pub const MAX_ENTRIES: usize = 128;

/// The high word of a table's handle: the handle table's value in the low word, this tag above it,
/// so no table handle is a window's or a menu's.
const TABLE_TAG: u32 = 0x0004_0000;

/// The messages a translation sends (winuser.h).
pub const WM_COMMAND: u32 = 0x0111;
pub const WM_INITMENU: u32 = 0x0116;
pub const WM_INITMENUPOPUP: u32 = 0x0117;

/// WS_DISABLED: the window takes no input.
const WS_DISABLED: u32 = 0x0800_0000;

/// Why an accelerator operation failed: the Win32 error code (winerror.h) the decision reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// ERROR_NOT_ENOUGH_MEMORY (8): the pool is full.
    NotEnoughMemory,
    /// ERROR_INVALID_PARAMETER (87): no entries, or more than a table holds.
    InvalidParameter,
    /// ERROR_INVALID_WINDOW_HANDLE (1400).
    InvalidWindowHandle,
    /// ERROR_INVALID_ACCEL_HANDLE (1403).
    InvalidAccelHandle,
}

impl Failure {
    /// The NTSTATUS the service answers (see the module's description); user32's body reports
    /// the code.
    pub const fn status(self) -> NtStatus {
        match self {
            Failure::NotEnoughMemory => STATUS_NO_MEMORY,
            Failure::InvalidParameter => STATUS_INVALID_PARAMETER,
            Failure::InvalidWindowHandle => STATUS_INVALID_HANDLE,
            Failure::InvalidAccelHandle => STATUS_OBJECT_TYPE_MISMATCH,
        }
    }
}

/// A table's id: its record in the pool and the record's generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TableId {
    index: u16,
    generation: u16,
}

/// The resource a table was loaded from: its module and its data's address (0 for a table
/// CreateAcceleratorTable made).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Source {
    pub module: u32,
    pub resource: u32,
}

/// One table's record.
#[derive(Clone, Copy)]
struct Table {
    live: bool,
    generation: u16,
    handle: u32,
    owner: Owner,
    source: Source,
    /// How many loads of its resource it answers for (1 for a created table).
    loads: u32,
    count: u16,
    entries: [Accel; MAX_ENTRIES],
}

impl Table {
    const DEAD: Self = Table {
        live: false,
        generation: 0,
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

/// A handle-table entry naming a table.
#[derive(Clone, Copy)]
struct TableEntry {
    id: TableId,
}

/// The accelerator registry: the table pool and the handle table over it.
pub struct Accelerators {
    tables: [Table; TABLES],
    handles: HandleTable<TableEntry>,
}

impl Accelerators {
    /// Write an empty registry at `accels`, element by element (by value it would pass through the
    /// stack, which is smaller than it).
    ///
    /// # Safety
    ///
    /// `accels` is valid for writes and aligned; its previous contents are overwritten, not
    /// dropped.
    pub unsafe fn write_empty(accels: *mut Accelerators) {
        use core::ptr::addr_of_mut;
        // SAFETY: the caller's contract; every field is written, the array element by element.
        unsafe {
            let tables = addr_of_mut!((*accels).tables) as *mut Table;
            for index in 0..TABLES {
                tables.add(index).write(Table::DEAD);
            }
            HandleTable::write_empty(addr_of_mut!((*accels).handles));
        }
    }

    fn at(&self, id: TableId) -> &Table {
        &self.tables[id.index as usize]
    }

    fn at_mut(&mut self, id: TableId) -> &mut Table {
        &mut self.tables[id.index as usize]
    }

    /// The table `handle` names, when it is live; ERROR_INVALID_ACCEL_HANDLE otherwise.
    pub fn table_of(&self, handle: u32) -> Result<TableId, Failure> {
        if handle & 0xFFFF_0000 != TABLE_TAG {
            return Err(Failure::InvalidAccelHandle);
        }
        let entry = self
            .handles
            .lookup(handle & 0xFFFF)
            .ok_or(Failure::InvalidAccelHandle)?;
        let table = &self.tables[entry.id.index as usize];
        if table.live && table.generation == entry.id.generation {
            Ok(entry.id)
        } else {
            Err(Failure::InvalidAccelHandle)
        }
    }

    /// The table the process `owner` loaded from `source` and has not destroyed as often as it
    /// loaded it, its load count up: LoadAccelerators's answer for a resource it loaded before.
    /// The resource data's address names the resource, whatever handle named its module (NULL
    /// or the module's own).
    pub fn load_again(&mut self, owner: Owner, source: Source) -> Option<u32> {
        if source.resource == 0 {
            return None;
        }
        let table = self
            .tables
            .iter_mut()
            .find(|t| t.live && t.owner == owner && t.source.resource == source.resource)?;
        table.loads += 1;
        Some(table.handle)
    }

    /// A new, empty table of the process `owner`, loaded from `source` (none: made); its handle.
    pub fn create(&mut self, owner: Owner, source: Source) -> Result<u32, Failure> {
        let index = self
            .tables
            .iter()
            .position(|t| !t.live)
            .ok_or(Failure::NotEnoughMemory)?;
        if self.handles.is_full() {
            return Err(Failure::NotEnoughMemory);
        }
        let generation = self.tables[index].generation;
        let id = TableId {
            index: index as u16,
            generation,
        };
        let handle = self.handles.insert(TableEntry { id }) | TABLE_TAG;
        // Field by field: a whole record would cross the gate stack as a temporary. The entries
        // past the count are never read.
        let table = &mut self.tables[index];
        table.live = true;
        table.handle = handle;
        table.owner = owner;
        table.source = source;
        table.loads = 1;
        table.count = 0;
        Ok(handle)
    }

    /// Append `entries` to the table `id` (their fVirt cut to the bits a table keeps);
    /// ERROR_INVALID_PARAMETER when they do not fit.
    pub fn append(&mut self, id: TableId, entries: &[Accel]) -> Result<(), Failure> {
        let table = self.at_mut(id);
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

    /// The table's entries.
    pub fn entries(&self, id: TableId) -> &[Accel] {
        let table = self.at(id);
        &table.entries[..table.count as usize]
    }

    /// DestroyAcceleratorTable: the table's load count down, the table destroyed with its last
    /// load; whether it was destroyed.
    pub fn destroy(&mut self, id: TableId) -> bool {
        let table = self.at_mut(id);
        if table.loads > 1 {
            table.loads -= 1;
            return false;
        }
        let handle = table.handle;
        table.live = false;
        table.count = 0;
        table.generation = table.generation.wrapping_add(1);
        self.handles.close(handle & 0xFFFF);
        true
    }

    /// Destroy every table of the process `owner`, at its end, whatever its load count.
    pub fn destroy_owner(&mut self, owner: Owner) {
        for index in 0..TABLES {
            let table = &self.tables[index];
            if table.live && table.owner == owner {
                let id = TableId {
                    index: index as u16,
                    generation: table.generation,
                };
                self.at_mut(id).loads = 1;
                self.destroy(id);
            }
        }
    }

    /// How many tables are live.
    pub fn live(&self) -> usize {
        self.tables.iter().filter(|t| t.live).count()
    }
}

/// The modifiers down for a translation on the thread `thread`, from its key state. win32k keeps
/// no key state yet (the keyboard input comes later): none is down.
pub fn modifiers(_manager: &WindowManager, _thread: ThreadId) -> Modifiers {
    Modifiers::default()
}

/// TranslateAccelerator's decision: the message `message` (its wParam `key`) on the thread
/// `thread`, matched against the table `table` for the window `window`; whether it was an
/// accelerator. A null window translates nothing; a table naming nothing is
/// ERROR_INVALID_ACCEL_HANDLE, checked first (the translate section's capture: a null table is
/// 1403, a null window answers FALSE with no error).
pub fn translate(
    manager: &mut WindowManager,
    thread: ThreadId,
    window: u32,
    table: u32,
    message: u32,
    key: u32,
    pump: &mut dyn Pump,
) -> Result<bool, Failure> {
    let table = manager.accels.table_of(table)?;
    if window == 0 {
        return Ok(false);
    }
    let target = manager
        .windows
        .window_from_handle(window)
        .ok_or(Failure::InvalidWindowHandle)?;
    let modifiers = modifiers(manager, thread);
    let Some(entry) = rtl::accel::find(manager.accels.entries(table), message, key, modifiers)
    else {
        return Ok(false);
    };
    let command = u32::from(entry.cmd);
    let WindowManager {
        windows, classes, ..
    } = manager;
    let mut send =
        |windows: &mut super::window::Windows, message: u32, wparam: u32, lparam: i32| {
            pump.send(
                windows,
                classes,
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
    let bar = windows.window_menu(target);
    if !windows.window_is_child(target) && bar != 0 {
        if let Ok(bar_id) = windows.menus.menu_of(bar) {
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
                send(windows, WM_INITMENU, bar, 0);
                if let Some((popup, index)) = popup {
                    send(windows, WM_INITMENUPOPUP, popup, index as i32);
                }
            }
        }
    }
    if enabled && windows.window_style(target) & WS_DISABLED == 0 {
        send(windows, WM_COMMAND, (1 << 16) | command, 0);
    }
    Ok(true)
}

// --- The services
// --------------------------------------------------------------------------------------

#[cfg(target_arch = "x86")]
mod services {
    use rtl::user::Msg;

    use super::*;
    use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
    use crate::win32k::queue::{with_manager, QueuePump};
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
        let handle = with_manager(call.passive(), |m| m.accels.create(owner, source))
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
                let id = m.accels.table_of(handle).map_err(Failure::status)?;
                if read.is_err() {
                    m.accels.destroy(id);
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
            let id = m.accels.table_of(table.raw())?;
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
                let id = m.accels.table_of(table.raw())?;
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
            let id = m.accels.table_of(table.raw())?;
            Ok(m.accels.destroy(id))
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
        let answer = with_manager(call.passive(), |m| {
            translate(
                m,
                caller,
                window.raw(),
                table.raw(),
                msg.message,
                msg.wparam,
                &mut QueuePump,
            )
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

    fn accelerators() -> Box<Accelerators> {
        let mut boxed = Box::<Accelerators>::new_uninit();
        // SAFETY: the box's memory, valid and aligned, written whole before it is assumed.
        unsafe {
            Accelerators::write_empty(boxed.as_mut_ptr());
            boxed.assume_init()
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
            a.table_of(4),
            Err(Failure::InvalidAccelHandle),
            "no window's handle"
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
}
