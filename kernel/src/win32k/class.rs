//! Window classes: the atom-named registry of window classes, and the services user32's
//! RegisterClass family, GetClassInfo, UnregisterClass and the SetClassLong/SetClassWord family
//! come through.
//!
//! A window class is a record in the class pool ([`Registry`]), named by an atom: a global string
//! atom in 0xC000..=0xFFFF for a string name, or the integer atom the caller gave. Records are
//! named by generation-tagged ids ([`ClassId`]), the object manager's pattern, and sit in lists:
//! a process's private and public class lists (head-inserted, so a newer registration shadows an
//! older one in the same list) and the system class list. A lookup runs five passes
//! ([`Registry::class_ptr`]): the caller's private list, its public list, both again under the
//! user32 module (the classes user32 itself registers), then the system list. A private class of
//! another module is invisible, and only the high word of the module handle is compared.
//!
//! Registering a class copies the caller's [`WndClassExW`] fields into the record by value. The
//! menu name and the ANSI class name are copied into the record's own buffers (an empty
//! menu-name string becomes none; an integer menu id is kept as a value); the class-extra area
//! comes with the record and is zeroed, never copied from the caller. Icon and cursor handles are
//! validated against the handle table and locked into the record; a handle naming no cursor
//! fails the registration for a 4.0-compatible caller and is silently dropped for an older one.
//!
//! The services (F2K's argument lists, see [`crate::win32k`]; Windows 2000's numbers):
//!
//! - NtUserRegisterClassExWOW (0x11D5): register, the class-name atom as the answer (a caller
//!   asking for a system class or a server-side procedure is refused: only the window manager
//!   registers those, on its own boot path);
//! - NtUserUnregisterClass (0x1229): unregister, refused while the class still has windows;
//! - NtUserGetClassInfo (0x1178): the class's fields back into a WNDCLASSEXW;
//! - NtUserGetClassName (0x1179): the name of a window's class;
//! - NtUserSetClassLong (0x11E7) and NtUserSetClassWord (0x11E8): the class-data changes.
//!
//! A failure carries the Win32 error code of the decision (winerror.h, [`Failure::code`]); the
//! service answers the closest documented NTSTATUS ([`Failure::status`]), and user32's body maps
//! the failure back for GetLastError.
//!
//! The registry sits in the window manager, behind one lock with the window registry
//! ([`super::window::WindowManager`]): the window a class change names is the window registry's
//! record, and the icon-change notification visits that registry's windows
//! ([`super::window::Windows::class_views`]). Seams recorded: the cursor/icon objects (the GDI
//! slice) — until they land, their handles are validated against the class registry's own handle
//! table; what the icon-change notice does to a window (the painting) — the window records cache
//! no small icon and draw no caption yet.

// Parts of the registry have no caller yet: the SetClassLongPtr form, the pinned atoms, the
// process-end teardown.
#![allow(dead_code)]

use rtl::pod::Pod;

use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
use crate::status::*;

/// An atom: a global string atom in 0xC000..=0xFFFF, or an integer atom below that.
pub type Atom = u16;

/// A process, as the class registry keys its per-process lists: the process object's pool index.
pub type Owner = u16;

// --- The public ABI and constants (winuser.h)
// ---------------------------------------------------------

/// WNDCLASSEXW, the 32-bit form the services take: twelve 32-bit fields, 48 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WndClassExW {
    pub cb_size: u32,
    pub style: u32,
    pub wnd_proc: u32,
    pub cb_cls_extra: i32,
    pub cb_wnd_extra: i32,
    pub instance: u32,
    pub icon: u32,
    pub cursor: u32,
    pub background: u32,
    pub menu_name: u32,
    pub class_name: u32,
    pub icon_sm: u32,
}

// SAFETY: twelve 32-bit fields, no padding, and every bit pattern of 48 bytes is a value.
unsafe impl Pod for WndClassExW {}

const _: () = assert!(core::mem::size_of::<WndClassExW>() == 48);

/// The class styles (winuser.h's CS_*).
pub const CS_VREDRAW: u32 = 0x0001;
pub const CS_HREDRAW: u32 = 0x0002;
pub const CS_DBLCLKS: u32 = 0x0008;
pub const CS_OWNDC: u32 = 0x0020;
pub const CS_CLASSDC: u32 = 0x0040;
pub const CS_PARENTDC: u32 = 0x0080;
pub const CS_NOCLOSE: u32 = 0x0200;
pub const CS_SAVEBITS: u32 = 0x0800;
pub const CS_BYTEALIGNCLIENT: u32 = 0x1000;
pub const CS_BYTEALIGNWINDOW: u32 = 0x2000;
pub const CS_GLOBALCLASS: u32 = 0x4000;
pub const CS_IME: u32 = 0x0001_0000;

/// The union of the public CS_* bits: the style a class answers with (the byte-align bits are
/// stored on registration but no longer honored).
pub const CS_PUBLIC: u32 = CS_VREDRAW
    | CS_HREDRAW
    | CS_DBLCLKS
    | CS_OWNDC
    | CS_CLASSDC
    | CS_PARENTDC
    | CS_NOCLOSE
    | CS_SAVEBITS
    | CS_BYTEALIGNCLIENT
    | CS_BYTEALIGNWINDOW
    | CS_GLOBALCLASS
    | CS_IME;

/// The class-data indexes (winuser.h's GCL_*/GCLP_*/GCW_*).
pub const GCLP_MENUNAME: i32 = -8;
pub const GCL_HBRBACKGROUND: i32 = -10;
pub const GCL_HCURSOR: i32 = -12;
pub const GCLP_HCURSOR: i32 = -12;
pub const GCL_HICON: i32 = -14;
pub const GCLP_HICON: i32 = -14;
pub const GCL_HMODULE: i32 = -16;
pub const GCL_CBWNDEXTRA: i32 = -18;
pub const GCL_CBCLSEXTRA: i32 = -20;
pub const GCL_WNDPROC: i32 = -24;
pub const GCLP_WNDPROC: i32 = -24;
pub const GCL_STYLE: i32 = -26;
pub const GCW_ATOM: i32 = -32;
pub const GCLP_HICONSM: i32 = -34;

/// The largest background handle that is a system color rather than a GDI brush: winuser.h's
/// COLOR_* indexes run 0..=28 and a system color's brush is the handle `color + 1`, so every
/// handle up to 28 is a system color, never deleted at the class's end.
pub const MAX_SYSTEM_COLOR_HANDLE: u32 = 28;

/// The window manager's own module handle: an application may not register a class under it. A
/// sentinel no image maps at (images map in the user half, below this).
pub const WINDOW_MANAGER_MODULE: u32 = 0xF000_0000;

/// user32's module handle, at its documented base: the module a null hInstance looks classes up
/// as, under which the classes user32 itself registers sit.
pub const CLIENT_MODULE: u32 = 0x77E1_0000;

/// The flags word of NtUserRegisterClassExWOW (F2K's own argument list).
pub const REGISTER_WIN40_COMPAT: u32 = 0x1;
pub const REGISTER_SERVER_SIDE_PROC: u32 = 0x2;
pub const REGISTER_SYSTEM_CLASS: u32 = 0x4;
pub const REGISTER_SERVER_CLASS: u32 = 0x8;

/// Why a class operation failed: the Win32 error code (winerror.h) the decision reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// ERROR_ACCESS_DENIED (5): the window belongs to another process.
    AccessDenied,
    /// ERROR_OUTOFMEMORY (14): a record, an atom or a name buffer could not be made.
    OutOfMemory,
    /// ERROR_INVALID_PARAMETER (87).
    InvalidParameter,
    /// ERROR_INVALID_CURSOR_HANDLE (1402).
    InvalidCursorHandle,
    /// ERROR_CANNOT_FIND_WND_CLASS (1407).
    CannotFindWindowClass,
    /// ERROR_CLASS_ALREADY_EXISTS (1410).
    ClassAlreadyExists,
    /// ERROR_CLASS_DOES_NOT_EXIST (1411).
    ClassDoesNotExist,
    /// ERROR_CLASS_HAS_WINDOWS (1412).
    ClassHasWindows,
    /// ERROR_INVALID_INDEX (1413).
    InvalidIndex,
    /// ERROR_INVALID_ICON_HANDLE (1414).
    InvalidIconHandle,
}

impl Failure {
    /// The Win32 error code (winerror.h) the decision reports.
    pub const fn code(self) -> u32 {
        match self {
            Failure::AccessDenied => 5,
            Failure::OutOfMemory => 14,
            Failure::InvalidParameter => 87,
            Failure::InvalidCursorHandle => 1402,
            Failure::CannotFindWindowClass => 1407,
            Failure::ClassAlreadyExists => 1410,
            Failure::ClassDoesNotExist => 1411,
            Failure::ClassHasWindows => 1412,
            Failure::InvalidIndex => 1413,
            Failure::InvalidIconHandle => 1414,
        }
    }

    /// The NTSTATUS the service answers. The class-specific codes have no NTSTATUS counterpart
    /// (nothing maps to them in RtlNtStatusToDosError's table), so the closest documented status
    /// stands in; user32's body reports [`Failure::code`] for GetLastError.
    pub const fn status(self) -> NtStatus {
        match self {
            Failure::AccessDenied => STATUS_ACCESS_DENIED,
            Failure::OutOfMemory => STATUS_NO_MEMORY,
            Failure::InvalidParameter | Failure::ClassHasWindows | Failure::InvalidIndex => {
                STATUS_INVALID_PARAMETER
            }
            Failure::InvalidCursorHandle | Failure::InvalidIconHandle => STATUS_INVALID_HANDLE,
            Failure::CannotFindWindowClass | Failure::ClassDoesNotExist => {
                STATUS_OBJECT_NAME_NOT_FOUND
            }
            Failure::ClassAlreadyExists => STATUS_OBJECT_NAME_EXISTS,
        }
    }
}

// --- Names ----------------------------------------------------------------------------------------------

/// A class name as the caller's WNDCLASSEXW holds it: `lpszClassName` is a pointer to a
/// NUL-terminated UTF-16 string when its high word is nonzero, an integer atom (the low word)
/// otherwise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClassName {
    Text(UserAddr),
    Atom(Atom),
}

impl ClassName {
    /// The raw `lpszClassName` value.
    pub fn of(raw: u32) -> Self {
        if raw & !0xFFFF == 0 {
            ClassName::Atom(raw as u16)
        } else {
            ClassName::Text(UserAddr(raw))
        }
    }
}

/// A name as the registry works with it: the string's units (without the terminator), or an
/// integer atom.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Name<'a> {
    Text(&'a [u16]),
    Atom(Atom),
}

impl Name<'_> {
    /// The atom the name resolves to for a lookup: the string's global atom (0 when the table has
    /// none), or the integer atom itself.
    fn atom(&self, atoms: &Atoms) -> Atom {
        match self {
            Name::Text(units) => atoms.find(units),
            Name::Atom(atom) => *atom,
        }
    }
}

/// A menu name as the caller passes it in WNDCLASSEXW: a string pointer, an integer id, or null.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MenuArg<'a> {
    None,
    Text(&'a [u16]),
    Id(u16),
}

// --- The atom table
// ---------------------------------------------------------------------------------------

/// How many string atoms the table holds.
const ATOM_TABLE: usize = 256;
/// The longest atom name, in UTF-16 units.
pub const MAX_ATOM_NAME: usize = 128;
/// The first global string atom.
const FIRST_STRING_ATOM: Atom = 0xC000;

/// One atom-table entry.
#[derive(Clone, Copy)]
struct AtomEntry {
    live: bool,
    pinned: bool,
    atom: Atom,
    len: u16,
    units: [u16; MAX_ATOM_NAME],
}

impl AtomEntry {
    const EMPTY: Self = AtomEntry {
        live: false,
        pinned: false,
        atom: 0,
        len: 0,
        units: [0; MAX_ATOM_NAME],
    };
}

/// The global string-atom table: names and their atoms in 0xC000..=0xFFFF, with a pin flag each
/// and the pinned range, whose atoms are never deleted.
struct Atoms {
    entries: [AtomEntry; ATOM_TABLE],
    next: Atom,
    pinned_first: Atom,
    pinned_last: Atom,
}

impl Atoms {
    /// Write an empty table at `atoms`, entry by entry (by value it would pass through the stack,
    /// which is smaller than it).
    ///
    /// # Safety
    ///
    /// `atoms` is valid for writes and aligned; its previous contents are overwritten, not
    /// dropped.
    unsafe fn write_empty(atoms: *mut Atoms) {
        use core::ptr::addr_of_mut;
        // SAFETY: the caller's contract; every field is written, the entries one by one.
        unsafe {
            let entries = addr_of_mut!((*atoms).entries) as *mut AtomEntry;
            for index in 0..ATOM_TABLE {
                entries.add(index).write(AtomEntry::EMPTY);
            }
            addr_of_mut!((*atoms).next).write(FIRST_STRING_ATOM);
            addr_of_mut!((*atoms).pinned_first).write(1);
            addr_of_mut!((*atoms).pinned_last).write(0);
        }
    }

    /// The pinned range: atoms in it are never deleted. F2K pins none at boot; the range is set
    /// when the atoms that must survive teardown are registered.
    pub fn set_pinned_range(&mut self, first: Atom, last: Atom) {
        self.pinned_first = first;
        self.pinned_last = last;
    }

    /// Add `name`, pinned when `pin` asks: the atom it already has, or a fresh one in
    /// 0xC000..=0xFFFF; 0 when the table is full or the name does not fit.
    fn add(&mut self, name: &[u16], pin: bool) -> Atom {
        if name.len() > MAX_ATOM_NAME {
            return 0;
        }
        let found = self.find(name);
        if found != 0 {
            if pin {
                self.pin(found);
            }
            return found;
        }
        if self.next == 0 {
            return 0; // exhausted: the numbering ran past 0xFFFF
        }
        let Some(slot) = self.entries.iter_mut().find(|e| !e.live) else {
            return 0;
        };
        let atom = self.next;
        self.next = if atom == 0xFFFF { 0 } else { atom + 1 };
        slot.live = true;
        slot.pinned = pin;
        slot.atom = atom;
        slot.len = name.len() as u16;
        slot.units[..name.len()].copy_from_slice(name);
        atom
    }

    /// The atom `name` has; 0 when the table has none.
    fn find(&self, name: &[u16]) -> Atom {
        self.entries
            .iter()
            .find(|e| e.live && &e.units[..e.len as usize] == name)
            .map_or(0, |e| e.atom)
    }

    /// Delete `atom`: 0 on success, the atom itself when it cannot be deleted. Atoms in the
    /// pinned range are never deleted (and answer 0).
    fn delete(&mut self, atom: Atom) -> Atom {
        if atom >= self.pinned_first && atom <= self.pinned_last {
            return 0;
        }
        let Some(entry) = self.entries.iter_mut().find(|e| e.live && e.atom == atom) else {
            return atom;
        };
        entry.live = false;
        0
    }

    /// `atom`'s name into `out` (no terminator), the units written; 0 when `atom` has none.
    fn name(&self, atom: Atom, out: &mut [u16]) -> usize {
        let Some(entry) = self.entries.iter().find(|e| e.live && e.atom == atom) else {
            return 0;
        };
        let len = entry.len as usize;
        let written = len.min(out.len());
        out[..written].copy_from_slice(&entry.units[..written]);
        written
    }

    /// Whether `atom` is in the table.
    fn contains(&self, atom: Atom) -> bool {
        self.entries.iter().any(|e| e.live && e.atom == atom)
    }

    /// Pin `atom`.
    fn pin(&mut self, atom: Atom) {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.live && e.atom == atom) {
            entry.pinned = true;
        }
    }

    /// Whether `atom` is pinned.
    fn is_pinned(&self, atom: Atom) -> bool {
        self.entries
            .iter()
            .any(|e| e.live && e.atom == atom && e.pinned)
    }
}

// --- The cursor/icon handle table
// ---------------------------------------------------------------------------

/// How many cursor and icon records the table holds.
pub const CURSORS: usize = 64;

/// A cursor or icon's id: its record in the pool and the record's generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CursorId {
    index: u16,
    generation: u16,
}

/// One cursor/icon record's header.
#[derive(Clone, Copy)]
struct CursorHeader {
    live: bool,
    generation: u16,
}

impl CursorHeader {
    const DEAD: Self = CursorHeader {
        live: false,
        generation: 0,
    };
}

/// One cursor or icon record.
#[derive(Clone, Copy)]
struct Cursor {
    handle: u32,
    locks: u32,
    /// A system-created copy, which apps never see (hidden as null by GetClassInfo).
    secret: bool,
    is_icon: bool,
}

impl Cursor {
    const EMPTY: Self = Cursor {
        handle: 0,
        locks: 0,
        secret: false,
        is_icon: false,
    };
}

/// A handle-table entry naming a cursor or icon.
#[derive(Clone, Copy)]
struct CursorEntry {
    id: CursorId,
}

/// The cursor/icon handle table: records behind generation-tagged ids, handles over them (the
/// object manager's handle-table shape). The seam where the GDI cursor objects land: until then
/// this is the whole table.
struct CursorTable {
    headers: [CursorHeader; CURSORS],
    records: [Cursor; CURSORS],
    handles: crate::sched::object::HandleTable<CursorEntry>,
}

impl CursorTable {
    /// Write an empty table at `table`, element by element (by value it would pass through the
    /// stack, which is smaller than it).
    ///
    /// # Safety
    ///
    /// `table` is valid for writes and aligned; its previous contents are overwritten, not
    /// dropped.
    unsafe fn write_empty(table: *mut CursorTable) {
        use core::ptr::addr_of_mut;
        // SAFETY: the caller's contract; every field is written, the arrays element by element.
        unsafe {
            let headers = addr_of_mut!((*table).headers) as *mut CursorHeader;
            let records = addr_of_mut!((*table).records) as *mut Cursor;
            for index in 0..CURSORS {
                headers.add(index).write(CursorHeader::DEAD);
                records.add(index).write(Cursor::EMPTY);
            }
            crate::sched::object::HandleTable::write_empty(addr_of_mut!((*table).handles));
        }
    }

    /// A new cursor or icon record with its handle; none when the pool is full.
    fn make(&mut self, is_icon: bool, secret: bool) -> Option<(CursorId, u32)> {
        let index = self.headers.iter().position(|h| !h.live)?;
        let header = &mut self.headers[index];
        header.live = true;
        let id = CursorId {
            index: index as u16,
            generation: header.generation,
        };
        let handle = self.handles.insert(CursorEntry { id });
        self.records[index] = Cursor {
            handle,
            locks: 0,
            secret,
            is_icon,
        };
        Some((id, handle))
    }

    /// The cursor or icon `handle` names, when the handle is live (its record's generation
    /// matches); none otherwise.
    fn validate(&self, handle: u32) -> Option<CursorId> {
        let entry = self.handles.lookup(handle)?;
        let header = self.headers.get(entry.id.index as usize)?;
        (header.live && header.generation == entry.id.generation).then_some(entry.id)
    }

    /// The same, for an old handle about to be answered: a cursor destroyed meanwhile answers
    /// none.
    fn revalidate(&self, handle: u32) -> Option<CursorId> {
        self.validate(handle)
    }

    /// The handle of `id` (0 for none): the inverse of [`CursorTable::validate`].
    fn handle_of(&self, id: Option<CursorId>) -> u32 {
        id.map_or(0, |id| self.records[id.index as usize].handle)
    }

    /// Lock `id` (its reference count up), for a class holding it.
    fn lock(&mut self, id: CursorId) {
        self.records[id.index as usize].locks += 1;
    }

    /// Set `slot` to `id`: the old value is unlocked, the new one locked; the slot's previous
    /// value.
    fn lock_slot(&mut self, slot: &mut Option<CursorId>, id: Option<CursorId>) -> Option<CursorId> {
        let old = *slot;
        *slot = id;
        if let Some(old) = old {
            let locks = &mut self.records[old.index as usize].locks;
            *locks = locks.saturating_sub(1);
        }
        if let Some(id) = id {
            self.lock(id);
        }
        old
    }

    /// Unlock `slot` (its reference count down), clearing it.
    fn unlock_slot(&mut self, slot: &mut Option<CursorId>) {
        if let Some(id) = *slot {
            let locks = &mut self.records[id.index as usize].locks;
            *locks = locks.saturating_sub(1);
        }
        *slot = None;
    }

    /// Destroy `id`: its record goes, its handle with it.
    fn destroy(&mut self, id: CursorId) {
        let handle = self.records[id.index as usize].handle;
        self.handles.close(handle);
        let header = &mut self.headers[id.index as usize];
        header.live = false;
        header.generation = header.generation.wrapping_add(1);
    }

    /// A copy of `id`'s image as a small icon: a synthesized record, hidden from apps; none when
    /// the pool is full (the lock then simply does not land).
    fn copy_image(&mut self, id: CursorId, as_icon: bool) -> Option<CursorId> {
        let _ = id;
        self.make(as_icon, true).map(|(id, _)| id)
    }

    fn secret(&self, id: CursorId) -> bool {
        self.records[id.index as usize].secret
    }

    fn is_icon(&self, id: CursorId) -> bool {
        self.records[id.index as usize].is_icon
    }

    /// How many locks `id` holds (the tests read this).
    fn locks(&self, id: CursorId) -> u32 {
        self.records[id.index as usize].locks
    }
}

// --- The class pool
// -----------------------------------------------------------------------------------------

/// How many window classes can exist at once.
pub const CLASSES: usize = 128;
/// The class-extra bytes a record holds (registrations asking more are refused: the record is
/// fixed-size, where a pool allocation of any size would do).
pub const MAX_CLASS_EXTRA: usize = 512;
/// The longest ANSI class name, in bytes.
pub const MAX_ANSI_NAME: usize = 256;
/// The longest menu name, in UTF-16 units.
pub const MAX_MENU_NAME: usize = 128;
/// How many owners hold class lists: every process, and the window manager itself.
const MAX_OWNERS: usize = crate::process::MAX_PROCESSES + 1;
/// The window manager itself as an owner: the desktop's own windows and their thread are its, not
/// any process's (an index no process's pool index takes).
pub const SYSTEM_OWNER: Owner = crate::process::MAX_PROCESSES as Owner;

/// A window class's id: its record in the pool and the record's generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClassId {
    index: u16,
    generation: u16,
}

/// One class record's header.
#[derive(Clone, Copy)]
struct Header {
    live: bool,
    generation: u16,
}

impl Header {
    const fn dead() -> Self {
        Header {
            live: false,
            generation: 0,
        }
    }
}

/// The flags a class record carries.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
struct Flags {
    /// Registered by the window manager itself (a server-side wndproc).
    server_side_proc: bool,
    /// A system class: linked into the system list.
    system_class: bool,
    /// Registered with a server class id.
    server_class: bool,
    /// The small icon is the synthesized copy of the icon (destroyed and hidden as such).
    cached_sm_icon: bool,
    /// A 16-bit class awaiting destroy: skipped by every lookup pass.
    wow_defer_destroy: bool,
}

/// A class's menu name: none, an integer id, or a copied string (the string sits in a fixed-size
/// buffer, as the kernel has no heap).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum MenuName {
    None,
    Id(u16),
    Text {
        len: u16,
        units: [u16; MAX_MENU_NAME],
    },
}

impl MenuName {
    /// The raw form the caller passes: 0 for none, the id for an integer id. A string's raw form
    /// is a pointer, which has no single value here, so it answers 0; the service answers the old
    /// name through its own out argument.
    fn raw(self) -> u32 {
        match self {
            MenuName::None => 0,
            MenuName::Id(id) => id as u32,
            MenuName::Text { .. } => 0,
        }
    }
}

/// A window class: the record the class pool holds.
#[derive(Clone, Copy)]
pub struct Class {
    /// The class-name atom (a string atom, or the integer atom given).
    atom: Atom,
    /// Whether the atom came from the table (only table atoms are deleted at teardown).
    atom_added: bool,
    style: u32,
    wnd_proc: u32,
    cb_cls_extra: i32,
    cb_wnd_extra: i32,
    /// The module (hInstance) the class was registered under, as a value.
    module: u32,
    icon: Option<CursorId>,
    cursor: Option<CursorId>,
    icon_sm: Option<CursorId>,
    /// The background brush, as a value (a system color or a GDI handle; never validated here).
    background: u32,
    menu_name: MenuName,
    /// The ANSI copy of the class name, NUL-terminated.
    ansi_name: [u8; MAX_ANSI_NAME],
    ansi_len: u16,
    /// How many windows of the class exist.
    window_count: i32,
    flags: Flags,
    /// The class DC, when the class has one (CS_CLASSDC); the GDI seam.
    class_dc: Option<u32>,
    /// The desktop the class belongs to.
    desktop: u32,
    /// The list link.
    next: Option<ClassId>,
    /// The base record (the record itself for a base class; the base for a clone).
    base: ClassId,
    /// The head of the clone list (base classes only).
    clones: Option<ClassId>,
    /// The class-extra area, zeroed at registration, written by the positive class-data indexes.
    extra: [u8; MAX_CLASS_EXTRA],
}

impl Class {
    /// A record holding no class (a pool's fresh record).
    fn empty() -> Self {
        Class {
            atom: 0,
            atom_added: false,
            style: 0,
            wnd_proc: 0,
            cb_cls_extra: 0,
            cb_wnd_extra: 0,
            module: 0,
            icon: None,
            cursor: None,
            icon_sm: None,
            background: 0,
            menu_name: MenuName::None,
            ansi_name: [0; MAX_ANSI_NAME],
            ansi_len: 0,
            window_count: 0,
            flags: Flags::default(),
            class_dc: None,
            desktop: 0,
            next: None,
            base: ClassId {
                index: 0,
                generation: 0,
            },
            clones: None,
            extra: [0; MAX_CLASS_EXTRA],
        }
    }
}

/// The class pool: records behind headers, ids with generations.
struct ClassPool {
    headers: [Header; CLASSES],
    records: [Class; CLASSES],
}

impl ClassPool {
    /// Take the lowest free record for a new class (zeroed); none when the pool is exhausted.
    fn allocate(&mut self) -> Option<ClassId> {
        let index = self.headers.iter().position(|h| !h.live)?;
        self.headers[index].live = true;
        self.records[index] = Class::empty();
        Some(ClassId {
            index: index as u16,
            generation: self.headers[index].generation,
        })
    }

    /// Free `id`'s record: dead, its generation moved on so the id resolves to nothing.
    fn free(&mut self, id: ClassId) {
        let header = &mut self.headers[id.index as usize];
        debug_assert!(
            header.live && header.generation == id.generation,
            "a live class id"
        );
        header.live = false;
        header.generation = header.generation.wrapping_add(1);
    }

    /// The live record `id` names.
    fn at(&self, id: ClassId) -> &Class {
        let header = &self.headers[id.index as usize];
        debug_assert!(
            header.live && header.generation == id.generation,
            "a live class id"
        );
        &self.records[id.index as usize]
    }

    /// The live record `id` names, mutable.
    fn at_mut(&mut self, id: ClassId) -> &mut Class {
        let header = &mut self.headers[id.index as usize];
        debug_assert!(
            header.live && header.generation == id.generation,
            "a live class id"
        );
        &mut self.records[id.index as usize]
    }

    fn is_live(&self, id: ClassId) -> bool {
        self.headers
            .get(id.index as usize)
            .is_some_and(|h| h.live && h.generation == id.generation)
    }
}

// --- The class-data field table
// -------------------------------------------------------------------------------

/// The width of a class field a negative index names, on the 32-bit platform.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Width {
    Word,
    DWord,
    Pointer,
}

impl Width {
    const fn size(self) -> usize {
        match self {
            Width::Word => 2,
            Width::DWord | Width::Pointer => 4,
        }
    }
}

/// The class field a GCL_*/GCLP_* index names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClassField {
    IconSm,
    Atom,
    Style,
    WndProc,
    CbClsExtra,
    CbWndExtra,
    Module,
    Icon,
    Cursor,
    Background,
    MenuName,
}

/// One index's field and width.
#[derive(Clone, Copy)]
struct FieldEntry {
    field: ClassField,
    width: Width,
}

/// The negative-index table: entry i is the index (i + GCLP_HICONSM) = (i - 34). The indexes the
/// class-change hub intercepts (the wndproc, the icon/cursor, the menu name, cbClsExtra) keep
/// their entries, as the table they stand in for does.
const FIELDS: [Option<FieldEntry>; 27] = [
    Some(FieldEntry {
        field: ClassField::IconSm,
        width: Width::Pointer,
    }), // -34 GCLP_HICONSM
    None, // -33
    Some(FieldEntry {
        field: ClassField::Atom,
        width: Width::Word,
    }), // -32 GCW_ATOM
    None, // -31
    None, // -30
    None, // -29
    None, // -28
    None, // -27
    Some(FieldEntry {
        field: ClassField::Style,
        width: Width::DWord,
    }), // -26 GCL_STYLE
    None, // -25
    Some(FieldEntry {
        field: ClassField::WndProc,
        width: Width::Pointer,
    }), // -24 GCL_WNDPROC
    None, // -23
    None, // -22
    None, // -21
    Some(FieldEntry {
        field: ClassField::CbClsExtra,
        width: Width::DWord,
    }), // -20 GCL_CBCLSEXTRA
    None, // -19
    Some(FieldEntry {
        field: ClassField::CbWndExtra,
        width: Width::DWord,
    }), // -18 GCL_CBWNDEXTRA
    None, // -17
    Some(FieldEntry {
        field: ClassField::Module,
        width: Width::DWord,
    }), // -16 GCL_HMODULE
    None, // -15
    Some(FieldEntry {
        field: ClassField::Icon,
        width: Width::Pointer,
    }), // -14 GCL_HICON
    None, // -13
    Some(FieldEntry {
        field: ClassField::Cursor,
        width: Width::Pointer,
    }), // -12 GCL_HCURSOR
    None, // -11
    Some(FieldEntry {
        field: ClassField::Background,
        width: Width::DWord,
    }), // -10 GCL_HBRBACKGROUND
    None, // -9
    Some(FieldEntry {
        field: ClassField::MenuName,
        width: Width::Pointer,
    }), // -8 GCLP_MENUNAME
];

// --- Windows, as the class logic sees them
// -------------------------------------------------------------------

/// A window as the class-change services see it: the seam where the window records land (the
/// window-creation slice). The services read the window's class, owning process and desktop from
/// it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    pub class: ClassId,
    pub owner: Owner,
    pub desktop: u32,
}

/// A window as the icon-change notification sees it: the same seam, for the windows the
/// notification visits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowView {
    pub class: ClassId,
    /// The window asks to be queried for its drag icon: its small icon is destroyed.
    pub query_drag_icon: bool,
    /// The window has a small-icon property of its own: its title is not redrawn.
    pub has_own_icon_sm: bool,
}

/// What the icon-change notification does to one window of the changed class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowNotice {
    pub destroy_sm_icon: bool,
    pub redraw_title: bool,
}

/// The notification for `window` when `class`'s icon changed: only windows of the class are
/// told, and each is told to destroy its small icon when it asked for drag-icon queries, and to
/// redraw its title when it has no small-icon property of its own.
fn notice_for(window: &WindowView, class: ClassId) -> Option<WindowNotice> {
    (window.class == class).then_some(WindowNotice {
        destroy_sm_icon: window.query_drag_icon,
        redraw_title: !window.has_own_icon_sm,
    })
}

// --- The registry
// ---------------------------------------------------------------------------------------------

/// Which list a class sits in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum List {
    System,
    Private(Owner),
    Public(Owner),
}

/// A process's two class lists.
#[derive(Clone, Copy, Default)]
struct OwnerLists {
    private: Option<ClassId>,
    public: Option<ClassId>,
}

/// The flags a registration carries.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RegisterFlags {
    pub win40_compat: bool,
    pub server_side_proc: bool,
    pub system_class: bool,
    pub server_class: bool,
}

impl RegisterFlags {
    /// The service's flags word.
    pub fn from_bits(bits: u32) -> Self {
        RegisterFlags {
            win40_compat: bits & REGISTER_WIN40_COMPAT != 0,
            server_side_proc: bits & REGISTER_SERVER_SIDE_PROC != 0,
            system_class: bits & REGISTER_SYSTEM_CLASS != 0,
            server_class: bits & REGISTER_SERVER_CLASS != 0,
        }
    }

    /// A user-mode registration's flags word: the caller may ask for the 4.0 compatibility and a
    /// server class, never for a system class or a server-side procedure — only the window
    /// manager registers those, on its own boot path
    /// ([`super::window::WindowManager::boot_desktop`]). ERROR_INVALID_PARAMETER for either.
    pub fn from_user_bits(bits: u32) -> Result<Self, Failure> {
        if bits & (REGISTER_SYSTEM_CLASS | REGISTER_SERVER_SIDE_PROC) != 0 {
            return Err(Failure::InvalidParameter);
        }
        Ok(Self::from_bits(bits))
    }
}

/// A class's fields as GetClassInfo answers them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClassInfo {
    pub atom: Atom,
    pub style: u32,
    pub cb_cls_extra: i32,
    pub cb_wnd_extra: i32,
    pub instance: u32,
    pub icon: u32,
    pub cursor: u32,
    pub icon_sm: u32,
    pub background: u32,
    pub menu_name: MenuName,
    pub wnd_proc: u32,
}

/// The window-class registry: the atom table, the cursor/icon handle table, the class pool with
/// the system list and every process's private and public lists.
pub struct Registry {
    atoms: Atoms,
    cursors: CursorTable,
    classes: ClassPool,
    system: Option<ClassId>,
    owners: [OwnerLists; MAX_OWNERS],
}

impl Registry {
    /// Write an empty registry at `registry`, field by field (by value it would pass through the
    /// stack, which is smaller than it).
    ///
    /// # Safety
    ///
    /// `registry` is valid for writes, aligned, and the records' final address; its previous
    /// contents are overwritten, not dropped.
    pub unsafe fn write_empty(registry: *mut Registry) {
        use core::ptr::addr_of_mut;
        // SAFETY: the caller's contract; every field is written.
        unsafe {
            Atoms::write_empty(addr_of_mut!((*registry).atoms));
            CursorTable::write_empty(addr_of_mut!((*registry).cursors));
            addr_of_mut!((*registry).system).write(None);
            let headers = addr_of_mut!((*registry).classes.headers) as *mut Header;
            let records = addr_of_mut!((*registry).classes.records) as *mut Class;
            for index in 0..CLASSES {
                headers.add(index).write(Header::dead());
                records.add(index).write(Class::empty());
            }
            let owners = addr_of_mut!((*registry).owners) as *mut OwnerLists;
            for index in 0..MAX_OWNERS {
                owners.add(index).write(OwnerLists::default());
            }
        }
    }

    // --- The lists
    // -------------------------------------------------------------------------------------------

    fn list_head(&self, list: List) -> Option<ClassId> {
        match list {
            List::System => self.system,
            List::Private(owner) => self.owners[owner as usize].private,
            List::Public(owner) => self.owners[owner as usize].public,
        }
    }

    fn set_list_head(&mut self, list: List, head: Option<ClassId>) {
        match list {
            List::System => self.system = head,
            List::Private(owner) => self.owners[owner as usize].private = head,
            List::Public(owner) => self.owners[owner as usize].public = head,
        }
    }

    /// Unlink `id` from `list`.
    fn unlink(&mut self, list: List, id: ClassId) {
        let mut previous = None;
        let mut cursor = self.list_head(list);
        while let Some(current) = cursor {
            if current == id {
                let next = self.classes.at(current).next;
                match previous {
                    None => self.set_list_head(list, next),
                    Some(previous) => self.classes.at_mut(previous).next = next,
                }
                return;
            }
            previous = Some(current);
            cursor = self.classes.at(current).next;
        }
    }

    /// One lookup pass over `list`: the class of `atom` whose module matches `module` (any module
    /// for none; only the high word of the handle is compared), skipping classes awaiting a 16-bit
    /// destroy. None for atom 0 or no match.
    fn inner(&self, atom: Atom, list: List, module: Option<u32>) -> Option<ClassId> {
        if atom == 0 {
            return None;
        }
        let mut cursor = self.list_head(list);
        while let Some(id) = cursor {
            let class = self.classes.at(id);
            if class.atom == atom
                && module.is_none_or(|m| hi_word(class.module) == hi_word(m))
                && !class.flags.wow_defer_destroy
            {
                return Some(id);
            }
            cursor = class.next;
        }
        None
    }

    /// The class of `atom` for the process `owner` looking it up as `module`, in the five passes:
    /// the private list under the caller's module, the public list under any, both again under
    /// the user32 module, then the system list. First hit wins.
    pub fn class_ptr(&self, atom: Atom, owner: Owner, module: u32) -> Option<ClassId> {
        self.inner(atom, List::Private(owner), Some(module))
            .or_else(|| self.inner(atom, List::Public(owner), None))
            .or_else(|| self.inner(atom, List::Private(owner), Some(CLIENT_MODULE)))
            .or_else(|| self.inner(atom, List::Public(owner), Some(CLIENT_MODULE)))
            .or_else(|| self.inner(atom, List::System, None))
    }

    /// The atom a class name resolves to, as every lookup resolves it: a string's global atom (0
    /// when the table has none, which names no class), or the integer atom itself. The window
    /// side's creation names its class through this.
    pub fn atom_of(&self, name: Name) -> Atom {
        name.atom(&self.atoms)
    }

    /// The name of the class `id` into `out` (no terminator), GetClassName's text: the string the
    /// atom names in the atom table, '#' and the decimal digits for an integer atom. The answer is
    /// the units written, the name cut at `out`'s length.
    pub fn class_name(&self, id: ClassId, out: &mut [u16]) -> usize {
        let class = self.classes.at(id);
        if self.atoms.contains(class.atom) {
            return self.atoms.name(class.atom, out);
        }
        // The ANSI copy holds the integer form already: '#' and ASCII digits.
        let ansi = &class.ansi_name[..class.ansi_len as usize];
        let written = ansi.len().min(out.len());
        for (unit, &byte) in out.iter_mut().zip(&ansi[..written]) {
            *unit = u16::from(byte);
        }
        written
    }

    // --- Registration
    // ----------------------------------------------------------------------------------------

    /// Register the class `wc` describes, named `class_name` with the menu name `menu`, for the
    /// process `owner` on the desktop `desktop`: the record is made, its fields copied, the
    /// icon/cursor handles validated and locked, the strings copied, and the record linked at
    /// the head of its list. The class-name atom is the answer.
    pub fn register_class(
        &mut self,
        wc: &WndClassExW,
        class_name: Name,
        menu: MenuArg,
        owner: Owner,
        flags: RegisterFlags,
        desktop: u32,
    ) -> Result<Atom, Failure> {
        // An application may not register a class under the window manager's own module handle;
        // system registrations are exempt, and so are pre-4.0-compatible callers.
        if !flags.system_class
            && !flags.server_side_proc
            && wc.instance == WINDOW_MANAGER_MODULE
            && flags.win40_compat
        {
            return Err(Failure::InvalidParameter);
        }

        // The duplicate checks run before any allocation: a private class of the same name and
        // module, and a public class of the same name when CS_GLOBALCLASS is asked. A
        // server-side registration skips both.
        let lookup = class_name.atom(&self.atoms);
        if lookup != 0 && !flags.server_side_proc {
            if self
                .inner(lookup, List::Private(owner), Some(wc.instance))
                .is_some()
            {
                return Err(Failure::ClassAlreadyExists);
            }
            if wc.style & CS_GLOBALCLASS != 0
                && self.inner(lookup, List::Public(owner), None).is_some()
            {
                return Err(Failure::ClassAlreadyExists);
            }
        }

        // The record, zeroed: the class-extra area is never copied from the caller.
        if wc.cb_cls_extra < 0 || wc.cb_cls_extra as usize > MAX_CLASS_EXTRA {
            return Err(Failure::OutOfMemory);
        }
        let id = self.classes.allocate().ok_or(Failure::OutOfMemory)?;
        {
            let class = self.classes.at_mut(id);
            class.style = wc.style;
            class.wnd_proc = wc.wnd_proc;
            class.cb_cls_extra = wc.cb_cls_extra;
            class.cb_wnd_extra = wc.cb_wnd_extra;
            class.module = wc.instance;
            class.background = wc.background;
            class.desktop = desktop;
            class.base = id;
            class.flags = Flags {
                server_side_proc: flags.server_side_proc,
                system_class: flags.system_class,
                server_class: flags.server_class,
                ..Flags::default()
            };
        }

        // The icon and cursor handles, validated and locked in this order: cursor, icon, small
        // icon. A handle naming no cursor fails a 4.0-compatible caller; an older one has the
        // field silently set to none. A null handle is always fine.
        for (which, raw) in [
            (Which::Cursor, wc.cursor),
            (Which::Icon, wc.icon),
            (Which::IconSm, wc.icon_sm),
        ] {
            if let Err(failure) = self.validate_and_lock_cursor(id, which, raw, flags.win40_compat)
            {
                self.release_unlinked(id);
                return Err(failure);
            }
        }

        // The class-name atom: a string goes through the table (unpinned, so it can be deleted
        // at teardown); an integer atom is the name itself, no table entry.
        let (atom, added) = match class_name {
            Name::Text(units) => (self.atoms.add(units, false), true),
            Name::Atom(atom) => (atom, false),
        };
        if atom == 0 {
            // The table is full: no atom to delete, just the cursor locks and the record.
            self.release_unlinked(id);
            return Err(Failure::OutOfMemory);
        }
        {
            let class = self.classes.at_mut(id);
            class.atom = atom;
            class.atom_added = added;
        }

        // The ANSI copy of the class name: the string converted, or '#' plus the atom's decimal
        // digits for an integer atom.
        match class_name {
            Name::Text(units) => {
                if units.len() >= MAX_ANSI_NAME {
                    self.release_unlinked(id);
                    return Err(Failure::OutOfMemory);
                }
                let class = self.classes.at_mut(id);
                for (at, &unit) in units.iter().enumerate() {
                    class.ansi_name[at] = rtl::cp1252::wc_to_mb(unit);
                }
                class.ansi_name[units.len()] = 0;
                class.ansi_len = units.len() as u16;
            }
            Name::Atom(atom) => {
                let class = self.classes.at_mut(id);
                let mut at = 0;
                class.ansi_name[at] = b'#';
                at += 1;
                let mut digits = [0u8; 5];
                let mut value = atom as u32;
                let mut count = 0;
                loop {
                    digits[count] = b'0' + (value % 10) as u8;
                    value /= 10;
                    count += 1;
                    if value == 0 {
                        break;
                    }
                }
                for &digit in digits[..count].iter().rev() {
                    class.ansi_name[at] = digit;
                    at += 1;
                }
                class.ansi_name[at] = 0;
                class.ansi_len = at as u16;
            }
        }

        // The menu name: copied into the record's own buffer when a non-empty string, none when
        // an empty string or null, the raw id when an integer id.
        let menu_name = match menu {
            MenuArg::None => MenuName::None,
            MenuArg::Id(id) => MenuName::Id(id),
            MenuArg::Text(units) => {
                if units.is_empty() {
                    MenuName::None
                } else if units.len() > MAX_MENU_NAME {
                    self.release_unlinked(id);
                    return Err(Failure::OutOfMemory);
                } else {
                    let mut stored = [0u16; MAX_MENU_NAME];
                    stored[..units.len()].copy_from_slice(units);
                    MenuName::Text {
                        len: units.len() as u16,
                        units: stored,
                    }
                }
            }
        };
        self.classes.at_mut(id).menu_name = menu_name;

        // Link at the head of the right list: the system list for a system class, the process's
        // public list for a server-side or CS_GLOBALCLASS class, its private list otherwise.
        let list = if flags.server_side_proc || wc.style & CS_GLOBALCLASS != 0 {
            if flags.system_class {
                List::System
            } else {
                List::Public(owner)
            }
        } else {
            List::Private(owner)
        };
        let next = self.list_head(list);
        self.classes.at_mut(id).next = next;
        self.set_list_head(list, Some(id));

        Ok(atom)
    }

    /// Validate the handle `raw` and lock it into the class `id`'s slot `which`.
    fn validate_and_lock_cursor(
        &mut self,
        id: ClassId,
        which: Which,
        raw: u32,
        compat40: bool,
    ) -> Result<(), Failure> {
        if raw == 0 {
            self.set_cursor_slot(id, which, None);
            return Ok(());
        }
        match self.cursors.validate(raw) {
            Some(cursor) => {
                self.cursors.lock(cursor);
                self.set_cursor_slot(id, which, Some(cursor));
            }
            None => {
                if compat40 {
                    return Err(Failure::InvalidParameter);
                }
                // A pre-4.0 caller: the field is silently set to none and registration continues.
                self.set_cursor_slot(id, which, None);
            }
        }
        Ok(())
    }

    fn cursor_slot(pool: &mut ClassPool, id: ClassId, which: Which) -> &mut Option<CursorId> {
        let class = pool.at_mut(id);
        match which {
            Which::Cursor => &mut class.cursor,
            Which::Icon => &mut class.icon,
            Which::IconSm => &mut class.icon_sm,
        }
    }

    fn set_cursor_slot(&mut self, id: ClassId, which: Which, value: Option<CursorId>) {
        *Self::cursor_slot(&mut self.classes, id, which) = value;
    }

    /// Release a record that was never linked, on a registration failure: the class-name atom if
    /// it was added, then the cursor locks in the reverse of the order they were taken, then the
    /// record. The string copies are the record's own buffers, so they need no freeing.
    fn release_unlinked(&mut self, id: ClassId) {
        let (atom, added) = {
            let class = self.classes.at(id);
            (class.atom, class.atom_added)
        };
        if added && atom != 0 {
            self.atoms.delete(atom);
        }
        for which in [Which::IconSm, Which::Icon, Which::Cursor] {
            let slot = Self::cursor_slot(&mut self.classes, id, which);
            self.cursors.unlock_slot(slot);
        }
        self.classes.free(id);
    }

    // --- Unregister and teardown
    // ------------------------------------------------------------------------------

    /// Unregister the class `name` for the process `owner` registered under `module`: the
    /// private list is tried first, then the public list. Refused while the class has windows.
    pub fn unregister_class(
        &mut self,
        name: Name,
        owner: Owner,
        module: u32,
    ) -> Result<(), Failure> {
        let atom = name.atom(&self.atoms);
        let found = self
            .inner(atom, List::Private(owner), Some(module))
            .map(|id| (id, List::Private(owner)))
            .or_else(|| {
                self.inner(atom, List::Public(owner), None)
                    .map(|id| (id, List::Public(owner)))
            });
        let Some((id, list)) = found else {
            return Err(Failure::ClassDoesNotExist);
        };
        if self.classes.at(id).window_count != 0 {
            return Err(Failure::ClassHasWindows);
        }
        self.destroy_class(id, list, owner);
        Ok(())
    }

    /// A process's end: its classes go, the private list first, then the public one.
    pub fn destroy_owner_classes(&mut self, owner: Owner) {
        for list in [List::Private(owner), List::Public(owner)] {
            while let Some(id) = self.list_head(list) {
                self.destroy_class(id, list, owner);
            }
        }
    }

    /// Destroy the class `id` linked in `list`: the teardown in order — the clones, the atom, the
    /// class DC and the brush (a base class), then the small icon, the icon/cursor unlocks, the
    /// unlink and the record.
    fn destroy_class(&mut self, id: ClassId, list: List, owner: Owner) {
        debug_assert_eq!(self.classes.at(id).window_count, 0, "a class with windows");
        if self.classes.at(id).base == id {
            while let Some(clone) = self.classes.at(id).clones {
                self.destroy_clone(clone, id);
            }
            let (atom, added) = {
                let class = self.classes.at(id);
                (class.atom, class.atom_added)
            };
            if added {
                // A pinned atom survives the delete (and answers 0).
                self.atoms.delete(atom);
            }
            if let Some(dc) = self.classes.at(id).class_dc {
                destroy_class_dc(dc);
            }
            if self.destroy_class_brush(id, owner) {
                delete_gdi_brush(self.classes.at(id).background);
            }
        }
        self.destroy_class_sm_icon(id);
        // The icon, small icon and cursor unlocks, in that order.
        let icon = self.classes.at(id).icon;
        let icon_sm = self.classes.at(id).icon_sm;
        let cursor = self.classes.at(id).cursor;
        if icon.is_some() {
            self.cursors.unlock_slot(&mut self.classes.at_mut(id).icon);
        }
        if icon_sm.is_some() {
            self.cursors
                .unlock_slot(&mut self.classes.at_mut(id).icon_sm);
        }
        if cursor.is_some() {
            self.cursors
                .unlock_slot(&mut self.classes.at_mut(id).cursor);
        }
        self.unlink(list, id);
        self.classes.free(id);
    }

    /// Destroy a clone of the base class `base`: the shared teardown without the base-only parts
    /// (the atom, the menu name, the class DC, the brush), unlinked from the base's clone list.
    fn destroy_clone(&mut self, clone: ClassId, base: ClassId) {
        self.destroy_class_sm_icon(clone);
        let icon = self.classes.at(clone).icon;
        let icon_sm = self.classes.at(clone).icon_sm;
        let cursor = self.classes.at(clone).cursor;
        if icon.is_some() {
            self.cursors
                .unlock_slot(&mut self.classes.at_mut(clone).icon);
        }
        if icon_sm.is_some() {
            self.cursors
                .unlock_slot(&mut self.classes.at_mut(clone).icon_sm);
        }
        if cursor.is_some() {
            self.cursors
                .unlock_slot(&mut self.classes.at_mut(clone).cursor);
        }
        // Unlink from the base's clone list.
        let mut previous = None;
        let mut cursor_id = self.classes.at(base).clones;
        while let Some(current) = cursor_id {
            if current == clone {
                let next = self.classes.at(current).next;
                match previous {
                    None => self.classes.at_mut(base).clones = next,
                    Some(previous) => self.classes.at_mut(previous).next = next,
                };
                break;
            }
            previous = Some(current);
            cursor_id = self.classes.at(current).next;
        }
        self.classes.free(clone);
    }

    /// The class brush's fate: a system color is never a GDI object, and a brush shared with
    /// another class in any of the three lists is left alone (the walks run over the public,
    /// then the private, then the system list). Whether the GDI object itself is deleted.
    fn destroy_class_brush(&mut self, id: ClassId, owner: Owner) -> bool {
        let background = self.classes.at(id).background;
        if background <= MAX_SYSTEM_COLOR_HANDLE {
            return false;
        }
        for list in [List::Public(owner), List::Private(owner), List::System] {
            let mut cursor = self.list_head(list);
            while let Some(other) = cursor {
                let class = self.classes.at(other);
                if other != id && class.background == background {
                    return false;
                }
                cursor = class.next;
            }
        }
        true
    }

    /// Destroy the cached small icon, when the class has one: the cursor destroyed and unlocked,
    /// the flag cleared. Whether there was one.
    fn destroy_class_sm_icon(&mut self, id: ClassId) -> bool {
        if !self.classes.at(id).flags.cached_sm_icon {
            return false;
        }
        if let Some(cursor) = self.classes.at(id).icon_sm {
            self.cursors.destroy(cursor);
            self.cursors
                .unlock_slot(&mut self.classes.at_mut(id).icon_sm);
        }
        self.classes.at_mut(id).flags.cached_sm_icon = false;
        true
    }

    /// Synthesize the small icon from the icon, when the class has an icon but no small icon:
    /// the copy is locked in, and the cached flag is set only when the lock landed.
    fn create_class_sm_icon(&mut self, id: ClassId) {
        debug_assert!(self.classes.at(id).window_count > 0);
        let Some(icon) = self.classes.at(id).icon else {
            return;
        };
        let is_icon = self.cursors.is_icon(icon);
        let copy = self.cursors.copy_image(icon, is_icon);
        self.cursors
            .lock_slot(&mut self.classes.at_mut(id).icon_sm, copy);
        if self.classes.at(id).icon_sm.is_some() {
            self.classes.at_mut(id).flags.cached_sm_icon = true;
        }
    }

    // --- Class info
    // -------------------------------------------------------------------------------------------

    /// GetClassInfo: the class `name` resolves to for the process `owner` looking it up as
    /// `module` (the user32 module when none given). The style is masked to the public bits (and
    /// CS_GLOBALCLASS is masked out of a server-registered class for a 4.0-compatible caller);
    /// the instance maps as the platform's rules say; a system-created small icon is hidden as
    /// null.
    pub fn get_class_info(
        &self,
        name: Name,
        module: Option<u32>,
        owner: Owner,
        compat40: bool,
    ) -> Result<ClassInfo, Failure> {
        let module = module.unwrap_or(CLIENT_MODULE);
        let atom = name.atom(&self.atoms);
        let Some(id) = self.class_ptr(atom, owner, module) else {
            return Err(Failure::ClassDoesNotExist);
        };
        let class = self.classes.at(id);
        let mut style = class.style & CS_PUBLIC;
        if class.flags.server_class && compat40 {
            style &= !CS_GLOBALCLASS;
        }
        let instance = if compat40 {
            if module == CLIENT_MODULE {
                0
            } else {
                module
            }
        } else if class.module == WINDOW_MANAGER_MODULE || class.module == CLIENT_MODULE {
            CLIENT_MODULE
        } else {
            class.module
        };
        let icon_sm = match class.icon_sm {
            Some(cursor) if self.cursors.secret(cursor) => 0,
            other => self.cursors.handle_of(other),
        };
        Ok(ClassInfo {
            atom: class.atom,
            style,
            cb_cls_extra: class.cb_cls_extra,
            cb_wnd_extra: class.cb_wnd_extra,
            instance,
            icon: self.cursors.handle_of(class.icon),
            cursor: self.cursors.handle_of(class.cursor),
            icon_sm,
            background: class.background,
            menu_name: class.menu_name,
            wnd_proc: class.wnd_proc,
        })
    }

    // --- The class-data changes
    // ---------------------------------------------------------------------------------

    /// SetClassWord: the word at `index` in the class-extra area. Another process's window is
    /// refused, a negative index outright, an index past the extra area too.
    pub fn set_class_word(
        &mut self,
        window: &Window,
        caller: Owner,
        index: i32,
        value: u16,
    ) -> Result<u16, Failure> {
        if window.owner != caller {
            return Err(Failure::AccessDenied);
        }
        let base = self.classes.at(window.class).base;
        let extra = self.classes.at(base).cb_cls_extra;
        if index < 0 || index + 2 > extra {
            return Err(Failure::InvalidIndex);
        }
        let old = self.read_extra_word(base, index as usize);
        self.write_extra_word(base, index as usize, value);
        self.propagate_extra_word(base, index as usize, value);
        Ok(old)
    }

    /// SetClassLong: the dword at `index` in the extra area (a negative index goes to the
    /// class-data hub, refused there when the field it names is wider than a dword — none is, on
    /// the 32-bit platform).
    #[allow(clippy::too_many_arguments)]
    pub fn set_class_long(
        &mut self,
        window: &Window,
        caller: Owner,
        index: i32,
        value: u32,
        menu: MenuArg,
        view: Option<&WindowView>,
        windows: &[WindowView],
        notify: &mut dyn FnMut(&WindowView, WindowNotice),
    ) -> Result<u32, Failure> {
        if window.owner != caller {
            return Err(Failure::AccessDenied);
        }
        if index < 0 {
            let entry = index - GCLP_HICONSM;
            if entry < 0
                || FIELDS
                    .get(entry as usize)
                    .and_then(|f| *f)
                    .is_none_or(|f| f.width.size() > 4)
            {
                return Err(Failure::InvalidIndex);
            }
            return self.set_class_data(window, index, value, menu, view, windows, notify);
        }
        let base = self.classes.at(window.class).base;
        let extra = self.classes.at(base).cb_cls_extra;
        if index + 4 > extra {
            return Err(Failure::InvalidIndex);
        }
        let old = self.read_extra_dword(base, index as usize);
        self.write_extra_dword(base, index as usize, value);
        self.propagate_extra_dword(base, index as usize, value);
        Ok(old)
    }

    /// SetClassLongPtr: the same, without the 32-bit entry's width check on negative indexes.
    #[allow(clippy::too_many_arguments)]
    pub fn set_class_long_ptr(
        &mut self,
        window: &Window,
        caller: Owner,
        index: i32,
        value: u32,
        menu: MenuArg,
        view: Option<&WindowView>,
        windows: &[WindowView],
        notify: &mut dyn FnMut(&WindowView, WindowNotice),
    ) -> Result<u32, Failure> {
        if window.owner != caller {
            return Err(Failure::AccessDenied);
        }
        if index < 0 {
            return self.set_class_data(window, index, value, menu, view, windows, notify);
        }
        let base = self.classes.at(window.class).base;
        let extra = self.classes.at(base).cb_cls_extra;
        if index + 4 > extra {
            return Err(Failure::InvalidIndex);
        }
        let old = self.read_extra_dword(base, index as usize);
        self.write_extra_dword(base, index as usize, value);
        self.propagate_extra_dword(base, index as usize, value);
        Ok(old)
    }

    /// The class-change hub for a negative `index`: the wndproc, the icon/cursor, the menu name,
    /// cbClsExtra, and the table-driven default. The old value is the answer.
    #[allow(clippy::too_many_arguments)]
    pub fn set_class_data(
        &mut self,
        window: &Window,
        index: i32,
        value: u32,
        menu: MenuArg,
        view: Option<&WindowView>,
        windows: &[WindowView],
        notify: &mut dyn FnMut(&WindowView, WindowNotice),
    ) -> Result<u32, Failure> {
        match index {
            GCLP_WNDPROC => {
                let old =
                    core::mem::replace(&mut self.classes.at_mut(window.class).wnd_proc, value);
                Ok(old)
            }
            GCLP_HICON | GCLP_HICONSM | GCLP_HCURSOR => {
                let set = self.set_class_cursor(window.class, index, value, view, windows, notify);
                if let Some(failure) = set.failure {
                    return Err(failure);
                }
                Ok(set.old)
            }
            GCLP_MENUNAME => {
                let class = window.class;
                let old = self.classes.at(class).menu_name;
                let new = match menu {
                    MenuArg::None => MenuName::None,
                    MenuArg::Id(id) => MenuName::Id(id),
                    MenuArg::Text(units) => {
                        if units.is_empty() {
                            MenuName::None
                        } else if units.len() > MAX_MENU_NAME {
                            // A name that does not fit leaves the class unchanged.
                            return Err(Failure::OutOfMemory);
                        } else {
                            let mut stored = [0u16; MAX_MENU_NAME];
                            stored[..units.len()].copy_from_slice(units);
                            MenuName::Text {
                                len: units.len() as u16,
                                units: stored,
                            }
                        }
                    }
                };
                self.classes.at_mut(class).menu_name = new;
                Ok(old.raw())
            }
            GCL_CBCLSEXTRA => {
                // cbClsExtra is changeable only on a 16-bit class; F2K registers none, so the
                // change is always refused.
                Err(Failure::InvalidParameter)
            }
            _ => {
                let entry = index - GCLP_HICONSM;
                if entry < 0 {
                    return Err(Failure::InvalidIndex);
                }
                let Some(field) = FIELDS.get(entry as usize).copied().flatten() else {
                    return Err(Failure::InvalidIndex);
                };
                let base = self.classes.at(window.class).base;
                let old = self.field_value(base, field.field);
                self.set_field_value(base, field.field, value);
                // The same write propagates to every clone.
                let mut clone = self.classes.at(base).clones;
                while let Some(c) = clone {
                    self.set_field_value(c, field.field, value);
                    clone = self.classes.at(c).next;
                }
                Ok(old)
            }
        }
    }

    /// The cursor/icon class change: the handle validated (an invalid one records its failure and
    /// the field is set to none), then the icon-change decision on the base class and the same
    /// change on every clone. The old handle, revalidated, is the answer.
    #[allow(clippy::too_many_arguments)]
    fn set_class_cursor(
        &mut self,
        class: ClassId,
        index: i32,
        data: u32,
        view: Option<&WindowView>,
        windows: &[WindowView],
        notify: &mut dyn FnMut(&WindowView, WindowNotice),
    ) -> CursorSet {
        let mut failure = None;
        let mut new = None;
        if data != 0 {
            match self.cursors.validate(data) {
                Some(cursor) => new = Some(cursor),
                None => {
                    failure = Some(if index == GCLP_HICON || index == GCLP_HICONSM {
                        Failure::InvalidIconHandle
                    } else {
                        Failure::InvalidCursorHandle
                    });
                }
            }
        }
        let base = self.classes.at(class).base;
        let old = match index {
            GCLP_HICON | GCLP_HICONSM => {
                self.set_class_icon(base, new, index == GCLP_HICONSM, view, windows, notify)
            }
            GCLP_HCURSOR => self
                .cursors
                .lock_slot(&mut self.classes.at_mut(base).cursor, new),
            _ => None,
        };
        // The same for each clone.
        let mut clone = self.classes.at(base).clones;
        while let Some(c) = clone {
            match index {
                GCLP_HICON | GCLP_HICONSM => {
                    self.set_class_icon(c, new, index == GCLP_HICONSM, view, windows, notify);
                }
                GCLP_HCURSOR => {
                    self.cursors
                        .lock_slot(&mut self.classes.at_mut(c).cursor, new);
                }
                _ => {}
            }
            clone = self.classes.at(c).next;
        }
        CursorSet {
            old: self.cursors.handle_of(old),
            failure,
        }
    }

    /// The icon-change decision for one class: the old icon is saved, the cached small icon is
    /// destroyed first when the big icon changes, the new icon is locked in, a small icon is
    /// synthesized when there is an icon but no small one, and the class's windows are notified —
    /// all of them when the class has more than one window, just the calling one otherwise. The
    /// old cursor, revalidated, is returned (none when the old handle no longer names one).
    #[allow(clippy::too_many_arguments)]
    fn set_class_icon(
        &mut self,
        class: ClassId,
        new: Option<CursorId>,
        small: bool,
        view: Option<&WindowView>,
        windows: &[WindowView],
        notify: &mut dyn FnMut(&WindowView, WindowNotice),
    ) -> Option<CursorId> {
        let old = if small {
            self.classes.at(class).icon_sm
        } else {
            self.classes.at(class).icon
        };
        if old == new {
            return old;
        }
        let mut redraw = true;
        let mut old_handle = self.cursors.handle_of(old);
        if !small {
            // Setting the icon destroys the cached small icon first; if that fails, no redraw.
            if self.classes.at(class).icon_sm.is_some() && !self.destroy_class_sm_icon(class) {
                redraw = false;
            }
            self.cursors
                .lock_slot(&mut self.classes.at_mut(class).icon, new);
        } else {
            // A system-created small icon is never answered to the caller.
            if self.classes.at(class).flags.cached_sm_icon {
                self.destroy_class_sm_icon(class);
                old_handle = 0;
            }
            self.cursors
                .lock_slot(&mut self.classes.at_mut(class).icon_sm, new);
        }
        if self.classes.at(class).icon.is_some() && self.classes.at(class).icon_sm.is_none() {
            self.create_class_sm_icon(class);
        }
        if redraw {
            if self.classes.at(class).window_count > 1 {
                for window in windows {
                    if let Some(notice) = notice_for(window, class) {
                        notify(window, notice);
                    }
                }
            } else if let Some(window) = view {
                if let Some(notice) = notice_for(window, class) {
                    notify(window, notice);
                }
            }
        }
        // The old handle is revalidated before it is answered.
        if old_handle == 0 {
            None
        } else {
            self.cursors.revalidate(old_handle)
        }
    }

    // --- Reference counting
    // -------------------------------------------------------------------------------------

    /// A window of the class `class` is created: same desktop, just the count up; another
    /// desktop, a clone of the class is made (or reused) for it and both counts go up, with the
    /// window pointing at the clone.
    pub fn reference_class(&mut self, class: ClassId, window: &mut Window) -> bool {
        if self.classes.at(class).desktop == window.desktop {
            self.classes.at_mut(class).window_count += 1;
            return true;
        }
        // Find a clone on the window's desktop.
        let mut clone = self.classes.at(class).clones;
        let mut found = None;
        while let Some(c) = clone {
            if self.classes.at(c).desktop == window.desktop {
                found = Some(c);
                break;
            }
            clone = self.classes.at(c).next;
        }
        let clone = match found {
            Some(c) => c,
            None => match self.make_clone(class, window.desktop) {
                Some(c) => c,
                None => return false,
            },
        };
        self.classes.at_mut(class).window_count += 1;
        self.classes.at_mut(clone).window_count += 1;
        window.class = clone;
        true
    }

    /// Make a clone of the base class `class` for the desktop `desktop`: a copy of the record with
    /// its own cursor locks and a zero count, linked into the base's clone list.
    fn make_clone(&mut self, class: ClassId, desktop: u32) -> Option<ClassId> {
        let id = self.classes.allocate()?;
        let mut record = *self.classes.at(class);
        record.desktop = desktop;
        record.base = class;
        record.clones = None;
        record.next = self.classes.at(class).clones;
        record.window_count = 0;
        record.class_dc = None;
        // The cursors are locked into the clone afresh.
        record.icon = record.icon.inspect(|&c| self.cursors.lock(c));
        record.icon_sm = record.icon_sm.inspect(|&c| self.cursors.lock(c));
        record.cursor = record.cursor.inspect(|&c| self.cursors.lock(c));
        self.classes.records[id.index as usize] = record;
        self.classes.at_mut(class).clones = Some(id);
        Some(id)
    }

    /// A window of the class is destroyed: the count down, and a clone whose count reaches zero
    /// is destroyed with it (the base's count goes down too).
    pub fn dereference_class(&mut self, window: &mut Window) {
        let class = window.class;
        debug_assert!(self.classes.at(class).window_count >= 1);
        self.classes.at_mut(class).window_count -= 1;
        if class != self.classes.at(class).base {
            let base = self.classes.at(class).base;
            debug_assert!(self.classes.at(base).window_count >= 1);
            self.classes.at_mut(base).window_count -= 1;
            if self.classes.at(class).window_count == 0 {
                self.destroy_clone(class, base);
            }
        }
    }

    // --- The extra area and the field table
    // ---------------------------------------------------------------------

    fn read_extra_word(&self, id: ClassId, at: usize) -> u16 {
        let extra = &self.classes.at(id).extra;
        u16::from_le_bytes([extra[at], extra[at + 1]])
    }

    fn write_extra_word(&mut self, id: ClassId, at: usize, value: u16) {
        let extra = &mut self.classes.at_mut(id).extra;
        extra[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn read_extra_dword(&self, id: ClassId, at: usize) -> u32 {
        let extra = &self.classes.at(id).extra;
        u32::from_le_bytes([extra[at], extra[at + 1], extra[at + 2], extra[at + 3]])
    }

    fn write_extra_dword(&mut self, id: ClassId, at: usize, value: u32) {
        let extra = &mut self.classes.at_mut(id).extra;
        extra[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn propagate_extra_word(&mut self, base: ClassId, at: usize, value: u16) {
        let mut clone = self.classes.at(base).clones;
        while let Some(c) = clone {
            self.write_extra_word(c, at, value);
            clone = self.classes.at(c).next;
        }
    }

    fn propagate_extra_dword(&mut self, base: ClassId, at: usize, value: u32) {
        let mut clone = self.classes.at(base).clones;
        while let Some(c) = clone {
            self.write_extra_dword(c, at, value);
            clone = self.classes.at(c).next;
        }
    }

    /// The value of the class field `field` of the class `id`, as the table reads it.
    fn field_value(&self, id: ClassId, field: ClassField) -> u32 {
        let class = self.classes.at(id);
        match field {
            ClassField::IconSm => self.cursors.handle_of(class.icon_sm),
            ClassField::Icon => self.cursors.handle_of(class.icon),
            ClassField::Cursor => self.cursors.handle_of(class.cursor),
            ClassField::Atom => class.atom as u32,
            ClassField::Style => class.style,
            ClassField::WndProc => class.wnd_proc,
            ClassField::CbClsExtra => class.cb_cls_extra as u32,
            ClassField::CbWndExtra => class.cb_wnd_extra as u32,
            ClassField::Module => class.module,
            ClassField::Background => class.background,
            ClassField::MenuName => class.menu_name.raw(),
        }
    }

    /// Set the class field `field` of the class `id` to `value`.
    fn set_field_value(&mut self, id: ClassId, field: ClassField, value: u32) {
        let class = self.classes.at_mut(id);
        match field {
            // The cursor slots are reached through the hub's special cases; this path keeps the
            // value's meaning for the table-driven default.
            ClassField::IconSm => {
                class.icon_sm = if value == 0 {
                    None
                } else {
                    self.cursors.validate(value)
                }
            }
            ClassField::Icon => {
                class.icon = if value == 0 {
                    None
                } else {
                    self.cursors.validate(value)
                }
            }
            ClassField::Cursor => {
                class.cursor = if value == 0 {
                    None
                } else {
                    self.cursors.validate(value)
                }
            }
            ClassField::Atom => class.atom = value as u16,
            ClassField::Style => class.style = value,
            ClassField::WndProc => class.wnd_proc = value,
            ClassField::CbClsExtra => class.cb_cls_extra = value as i32,
            ClassField::CbWndExtra => class.cb_wnd_extra = value as i32,
            ClassField::Module => class.module = value,
            ClassField::Background => class.background = value,
            ClassField::MenuName => {
                class.menu_name = if value == 0 {
                    MenuName::None
                } else {
                    MenuName::Id(value as u16)
                }
            }
        }
    }
}

/// Which cursor slot of a class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Which {
    Cursor,
    Icon,
    IconSm,
}

/// The result of a cursor/icon class change: the old handle, and the failure an invalid handle
/// recorded (the field is set to none either way).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CursorSet {
    pub old: u32,
    pub failure: Option<Failure>,
}

/// The high word of a handle-sized value: the part module handles are compared by.
fn hi_word(value: u32) -> u16 {
    (value >> 16) as u16
}

// The GDI seams: the class DC's and the brush's deletion land with the GDI slice.

/// Destroy a class's DC (the GDI slice's seam: no class DCs exist yet).
fn destroy_class_dc(_dc: u32) {}

/// Delete a GDI brush object (the GDI slice's seam: no GDI brush objects exist yet).
fn delete_gdi_brush(_brush: u32) {}

// --- The services
// ----------------------------------------------------------------------------------

// The registry sits in the window manager, behind its one lock with the window registry
// ([`super::window::WindowManager`]): a class change reaches windows, and a window's creation
// reaches classes.

/// Read a NUL-terminated UTF-16 name from the caller at `raw` into `units` (an integer atom when
/// the raw value's high word is zero). A name longer than the buffer is refused.
#[cfg(target_arch = "x86")]
pub(super) fn read_name(raw: u32, units: &mut [u16]) -> Result<Name<'_>, NtStatus> {
    if raw & !0xFFFF == 0 {
        return Ok(Name::Atom(raw as u16));
    }
    let at = UserAddr(raw);
    let mut len = 0;
    loop {
        if len >= units.len() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let unit = at.offset(2 * len as u32).cast::<u16>().read()?;
        if unit == 0 {
            break;
        }
        units[len] = unit;
        len += 1;
    }
    Ok(Name::Text(&units[..len]))
}

/// The menu name argument from its raw value (WNDCLASSEXW's, or SetClassLong's for
/// GCLP_MENUNAME): none, an integer id, or a string.
#[cfg(target_arch = "x86")]
fn read_menu(raw: u32, units: &mut [u16]) -> Result<MenuArg<'_>, NtStatus> {
    if raw == 0 {
        return Ok(MenuArg::None);
    }
    if raw & !0xFFFF == 0 {
        return Ok(MenuArg::Id(raw as u16));
    }
    match read_name(raw, units)? {
        Name::Text(text) => Ok(MenuArg::Text(text)),
        Name::Atom(id) => Ok(MenuArg::Id(id)),
    }
}

/// The window a handle names, as the class-change services see it: the window registry's own
/// record, through its class view.
#[cfg(target_arch = "x86")]
fn window_of(windows: &super::window::Windows, window: Handle) -> Option<Window> {
    windows.class_window(window.raw())
}

/// NtUserRegisterClassExWOW(WndClass, ClassName, Flags, Atom, Wow): register the class the
/// caller's WNDCLASSEXW describes; its class-name atom into `atom` (the caller answers 0 on
/// failure). The `wow` out word is zero: F2K has no 16-bit classes.
#[cfg(target_arch = "x86")]
pub fn register_class_ex_wow(
    call: &mut NtCall,
    wc: UserAddr,
    class_name: u32,
    flags: u32,
    atom: UserPtr<u32>,
    wow: UserPtr<u32>,
) -> NtResult {
    let flags = RegisterFlags::from_user_bits(flags).map_err(Failure::status)?;
    let wc = wc.cast::<WndClassExW>().read()?;
    let mut name_units = [0u16; MAX_ATOM_NAME];
    let name = read_name(class_name, &mut name_units)?;
    let mut menu_units = [0u16; MAX_MENU_NAME];
    let menu = read_menu(wc.menu_name, &mut menu_units)?;
    let caller = super::winsta::gui_thread(call)?;
    let registered = super::window::lock(call.passive()).classes.register_class(
        &wc,
        name,
        menu,
        caller.owner,
        flags,
        caller.desktop,
    );
    let value = registered.map_err(Failure::status)?;
    atom.write(value as u32)?;
    wow.write(0)?;
    Ok(STATUS_SUCCESS)
}

/// NtUserUnregisterClass(ClassName, Instance): unregister the class; refused while it still has
/// windows.
#[cfg(target_arch = "x86")]
pub fn unregister_class(call: &mut NtCall, class_name: u32, instance: u32) -> NtResult {
    let mut units = [0u16; MAX_ATOM_NAME];
    let name = read_name(class_name, &mut units)?;
    let owner = super::winsta::gui_thread(call)?.owner;
    super::window::lock(call.passive())
        .classes
        .unregister_class(name, owner, instance)
        .map_err(Failure::status)?;
    Ok(STATUS_SUCCESS)
}

/// NtUserGetClassInfo(Instance, ClassName, WndClass): the class's fields into the caller's
/// WNDCLASSEXW (its name fields zeroed first, so a failure copies nothing back).
#[cfg(target_arch = "x86")]
pub fn get_class_info(
    call: &mut NtCall,
    instance: Handle,
    class_name: u32,
    out: UserAddr,
) -> NtResult {
    let out = out.cast::<WndClassExW>();
    let mut units = [0u16; MAX_ATOM_NAME];
    let name = read_name(class_name, &mut units)?;
    let owner = super::winsta::gui_thread(call)?.owner;
    let module = (instance.raw() != 0).then_some(instance.raw());
    let mut wc = out.read()?;
    wc.menu_name = 0;
    wc.class_name = 0;
    out.write(wc)?;
    let info = super::window::lock(call.passive())
        .classes
        .get_class_info(name, module, owner, true)
        .map_err(Failure::status)?;
    out.write(WndClassExW {
        cb_size: core::mem::size_of::<WndClassExW>() as u32,
        style: info.style,
        wnd_proc: info.wnd_proc,
        cb_cls_extra: info.cb_cls_extra,
        cb_wnd_extra: info.cb_wnd_extra,
        instance: info.instance,
        icon: info.icon,
        cursor: info.cursor,
        background: info.background,
        menu_name: info.menu_name.raw(),
        class_name: 0,
        icon_sm: info.icon_sm,
    })?;
    Ok(STATUS_SUCCESS)
}

/// NtUserGetClassName(Window, ClassName, MaxCount, Copied): the name of the window's class
/// (GetClassNameW's), any process's window: at most `max_count` units into the caller's buffer,
/// its terminator included, the name cut to `max_count - 1` units when it does not fit; the units
/// copied, the terminator not counted, into `copied`. A `max_count` of 0 copies nothing.
#[cfg(target_arch = "x86")]
pub fn get_class_name(
    call: &mut NtCall,
    window: Handle,
    buffer: UserAddr,
    max_count: u32,
    copied: UserPtr<u32>,
) -> NtResult {
    // A class name is an atom's name or '#' and five digits: MAX_ATOM_NAME units at most.
    let mut units = [0u16; MAX_ATOM_NAME + 1];
    let length = {
        let manager = super::window::lock(call.passive());
        let window = window_of(&manager.windows, window).ok_or(STATUS_INVALID_HANDLE)?;
        manager.classes.class_name(window.class, &mut units)
    };
    let count = length.min((max_count as usize).saturating_sub(1));
    if max_count != 0 {
        units[count] = 0;
        buffer.write(&units.as_bytes()[..2 * (count + 1)])?;
    }
    copied.write(count as u32)?;
    Ok(STATUS_SUCCESS)
}

/// NtUserSetClassLong(Window, Index, Value, Previous): the class-data change; the old value into
/// `previous`. For GCLP_MENUNAME the value is the new menu name, a string pointer or an integer
/// id; an icon change notifies the class's windows.
#[cfg(target_arch = "x86")]
pub fn set_class_long(
    call: &mut NtCall,
    window: Handle,
    index: i32,
    value: u32,
    previous: UserPtr<u32>,
) -> NtResult {
    let mut units = [0u16; MAX_MENU_NAME];
    let menu = if index == GCLP_MENUNAME {
        read_menu(value, &mut units)?
    } else {
        MenuArg::None
    };
    let caller = super::winsta::gui_thread(call)?.owner;
    let old = {
        let mut manager = super::window::lock(call.passive());
        let super::window::WindowManager {
            windows,
            classes,
            views,
        } = &mut *manager;
        let target = window_of(windows, window).ok_or(STATUS_INVALID_HANDLE)?;
        let view = windows.class_view(window.raw());
        let count = windows.class_views(views);
        // The notice has nothing to change yet: the window records cache no small icon and draw
        // no caption until the painting lands.
        classes
            .set_class_long(
                &target,
                caller,
                index,
                value,
                menu,
                view.as_ref(),
                &views[..count],
                &mut |_, _| {},
            )
            .map_err(Failure::status)?
    };
    previous.write(old)?;
    Ok(STATUS_SUCCESS)
}

/// NtUserSetClassWord(Window, Index, Value, Previous): the word class-data change.
#[cfg(target_arch = "x86")]
pub fn set_class_word(
    call: &mut NtCall,
    window: Handle,
    index: i32,
    value: u32,
    previous: UserPtr<u32>,
) -> NtResult {
    let caller = super::winsta::gui_thread(call)?.owner;
    let old = {
        let mut manager = super::window::lock(call.passive());
        let super::window::WindowManager {
            windows, classes, ..
        } = &mut *manager;
        let target = window_of(windows, window).ok_or(STATUS_INVALID_HANDLE)?;
        classes
            .set_class_word(&target, caller, index, value as u16)
            .map_err(Failure::status)?
    };
    previous.write(old as u32)?;
    Ok(STATUS_SUCCESS)
}

// The host builds have no processes and no user memory: the services answer nothing (the host
// tests drive the registry itself).

#[cfg(not(target_arch = "x86"))]
pub fn register_class_ex_wow(
    _: &mut NtCall,
    _: UserAddr,
    _: u32,
    _: u32,
    _: UserPtr<u32>,
    _: UserPtr<u32>,
) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

#[cfg(not(target_arch = "x86"))]
pub fn unregister_class(_: &mut NtCall, _: u32, _: u32) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

#[cfg(not(target_arch = "x86"))]
pub fn get_class_info(_: &mut NtCall, _: Handle, _: u32, _: UserAddr) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

#[cfg(not(target_arch = "x86"))]
pub fn get_class_name(_: &mut NtCall, _: Handle, _: UserAddr, _: u32, _: UserPtr<u32>) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

#[cfg(not(target_arch = "x86"))]
pub fn set_class_long(_: &mut NtCall, _: Handle, _: i32, _: u32, _: UserPtr<u32>) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

#[cfg(not(target_arch = "x86"))]
pub fn set_class_word(_: &mut NtCall, _: Handle, _: i32, _: u32, _: UserPtr<u32>) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

#[cfg(test)]
mod tests {
    //! The class decision logic's host tests, over a registry of each test's own.

    use super::*;

    /// A fresh registry, leaked at its final address (the pool's records stay put, as on target).
    fn registry() -> &'static mut Registry {
        let mut registry = Box::<Registry>::new_uninit();
        // SAFETY: the box is valid, aligned and the records' final address once leaked.
        unsafe { Registry::write_empty(registry.as_mut_ptr()) };
        // SAFETY: written whole just above.
        Box::leak(unsafe { registry.assume_init() })
    }

    /// A text as UTF-16 units.
    fn units(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    /// The test's process and module handles: module handles match by high word.
    const OWNER: Owner = 0;
    const OTHER_OWNER: Owner = 1;
    const MODULE: u32 = 0x0040_0000;
    const SAME_HIGH_WORD: u32 = 0x0040_9ABC;
    const OTHER_HIGH_WORD: u32 = 0x0050_0000;
    /// The one desktop.
    const DESKTOP: u32 = 1;

    /// A WNDCLASSEXW as an application fills it.
    fn wnd_class() -> WndClassExW {
        WndClassExW {
            cb_size: 48,
            style: CS_HREDRAW | CS_VREDRAW,
            wnd_proc: 0x0040_1000,
            cb_cls_extra: 0,
            cb_wnd_extra: 0,
            instance: MODULE,
            icon: 0,
            cursor: 0,
            background: 6, // COLOR_WINDOW + 1, a system color
            menu_name: 0,
            class_name: 0,
            icon_sm: 0,
        }
    }

    /// The 4.0-compatible registration flags.
    fn compat40() -> RegisterFlags {
        RegisterFlags {
            win40_compat: true,
            ..RegisterFlags::default()
        }
    }

    /// A user-mode registration may ask for the 4.0 compatibility and a server class; a system
    /// class or a server-side procedure is refused with ERROR_INVALID_PARAMETER (87).
    #[test]
    fn user_mode_registers_no_system_class() {
        assert_eq!(
            RegisterFlags::from_user_bits(REGISTER_WIN40_COMPAT | REGISTER_SERVER_CLASS),
            Ok(RegisterFlags {
                win40_compat: true,
                server_class: true,
                ..RegisterFlags::default()
            })
        );
        assert_eq!(
            RegisterFlags::from_user_bits(0),
            Ok(RegisterFlags::default())
        );
        for bits in [
            REGISTER_SYSTEM_CLASS,
            REGISTER_SERVER_SIDE_PROC,
            REGISTER_WIN40_COMPAT | REGISTER_SYSTEM_CLASS | REGISTER_SERVER_SIDE_PROC,
        ] {
            let refused = RegisterFlags::from_user_bits(bits).unwrap_err();
            assert_eq!(refused, Failure::InvalidParameter);
            assert_eq!(refused.code(), 87);
            assert_eq!(refused.status(), STATUS_INVALID_PARAMETER);
        }
    }

    /// Register `name` for the test's process and module.
    fn register(
        registry: &mut Registry,
        name: Name,
        wc: &WndClassExW,
        flags: RegisterFlags,
    ) -> Result<Atom, Failure> {
        registry.register_class(wc, name, MenuArg::None, OWNER, flags, DESKTOP)
    }

    /// A cursor record with its handle, as the GDI side would make one.
    fn make_cursor(registry: &mut Registry) -> (CursorId, u32) {
        registry.cursors.make(false, false).unwrap()
    }

    /// A notification sink that ignores everything.
    fn noop(_: &WindowView, _: WindowNotice) {}

    /// A window of `class` on the test's desktop, owned by the test's process.
    fn window(class: ClassId) -> Window {
        Window {
            class,
            owner: OWNER,
            desktop: DESKTOP,
        }
    }

    /// The atom table's return conventions: add and find answer 0 on failure, delete answers 0 on
    /// success and the atom itself on failure, and pinned-range atoms are never deleted. The
    /// name query answers the units written, 0 for an atom with no name.
    #[test]
    fn the_atom_wrappers_follow_their_return_conventions() {
        let registry = registry();
        let foo = units("Foo");
        let atom = registry.atoms.add(&foo, false);
        assert!(atom >= 0xC000, "a global string atom");
        assert_eq!(registry.atoms.find(&foo), atom);
        assert!(!registry.atoms.is_pinned(atom), "added unpinned");
        let mut out = [0u16; 8];
        assert_eq!(registry.atoms.name(atom, &mut out), 3);
        assert_eq!(&out[..3], &foo[..]);
        assert_eq!(registry.atoms.name(0x1234, &mut out), 0, "no such atom");
        // Delete: 0 on success, the atom itself on failure.
        assert_eq!(registry.atoms.delete(atom), 0);
        assert_eq!(registry.atoms.find(&foo), 0);
        assert_eq!(
            registry.atoms.delete(atom),
            atom,
            "inverted return on failure"
        );
        // Pin on add, and the pinned range's guard.
        let bar = units("Bar");
        let pinned = registry.atoms.add(&bar, true);
        assert!(registry.atoms.is_pinned(pinned));
        registry.atoms.set_pinned_range(pinned, pinned);
        assert_eq!(registry.atoms.delete(pinned), 0, "pinned: answered 0...");
        assert!(registry.atoms.contains(pinned), "...but not deleted");
        registry.atoms.set_pinned_range(1, 0);
        assert_eq!(registry.atoms.delete(pinned), 0);
        assert!(!registry.atoms.contains(pinned));
        // A name too long for the table answers 0.
        let long = vec![b'a' as u16; MAX_ATOM_NAME + 1];
        assert_eq!(registry.atoms.add(&long, false), 0);
    }

    /// A 4.0-compatible application may not register a class under the window manager's own
    /// module handle (ERROR_INVALID_PARAMETER, 87); a pre-4.0 caller and a system registration
    /// may.
    #[test]
    fn the_window_managers_own_module_is_rejected_for_4_0_apps() {
        let registry = registry();
        let mut wc = wnd_class();
        wc.instance = WINDOW_MANAGER_MODULE;
        let name = Name::Text(&units("Foo"));
        let err = register(registry, name, &wc, compat40()).unwrap_err();
        assert_eq!(err, Failure::InvalidParameter);
        assert_eq!(err.code(), 87);
        // Pre-4.0: accepted.
        let flags = RegisterFlags::default();
        assert!(register(registry, name, &wc, flags).is_ok());
        // Server-side registration: accepted even 4.0-compatible.
        let flags = RegisterFlags {
            win40_compat: true,
            server_side_proc: true,
            ..RegisterFlags::default()
        };
        assert!(register(registry, name, &wc, flags).is_ok());
    }

    /// The byte-align styles are accepted and stored (they are no longer honored, but no error).
    #[test]
    fn the_byte_align_styles_are_stored() {
        let registry = registry();
        let mut wc = wnd_class();
        wc.style = CS_BYTEALIGNCLIENT | CS_BYTEALIGNWINDOW;
        let atom = register(registry, Name::Text(&units("Foo")), &wc, compat40()).unwrap();
        let id = registry.class_ptr(atom, OWNER, MODULE).unwrap();
        assert_eq!(
            registry.classes.at(id).style,
            CS_BYTEALIGNCLIENT | CS_BYTEALIGNWINDOW
        );
    }

    /// An icon/cursor handle that names no cursor: for a 4.0-compatible caller the registration
    /// fails with ERROR_INVALID_PARAMETER (87) and leaves nothing behind; for an older caller
    /// the field is silently set to none and registration continues. A null handle is always
    /// fine.
    #[test]
    fn invalid_cursor_handles_fail_only_for_4_0_compat() {
        let registry = registry();
        let (cursor, handle) = make_cursor(registry);
        let mut wc = wnd_class();
        wc.cursor = 0xDEAD; // names no cursor
        let name = Name::Text(&units("Foo"));
        let err = register(registry, name, &wc, compat40()).unwrap_err();
        assert_eq!(err, Failure::InvalidParameter);
        assert_eq!(err.code(), 87);
        assert_eq!(
            registry.class_ptr(registry.atoms.find(&units("Foo")), OWNER, MODULE),
            None
        );
        // Pre-4.0: the field is NULLed, registration continues.
        let atom = register(registry, name, &wc, RegisterFlags::default()).unwrap();
        let id = registry.class_ptr(atom, OWNER, MODULE).unwrap();
        assert_eq!(registry.classes.at(id).cursor, None);
        // A valid handle is locked into the record.
        wc.cursor = handle;
        let atom = register(registry, Name::Text(&units("Bar")), &wc, compat40()).unwrap();
        let id = registry.class_ptr(atom, OWNER, MODULE).unwrap();
        assert_eq!(registry.classes.at(id).cursor, Some(cursor));
        assert_eq!(registry.cursors.locks(cursor), 1);
        // Null is fine.
        wc.cursor = 0;
        assert!(register(registry, Name::Text(&units("Baz")), &wc, compat40()).is_ok());
    }

    /// The background brush is not validated at registration: any value is stored as-is.
    #[test]
    fn the_background_is_stored_unvalidated() {
        let registry = registry();
        let mut wc = wnd_class();
        wc.background = 0xBEEF;
        let atom = register(registry, Name::Text(&units("Foo")), &wc, compat40()).unwrap();
        let id = registry.class_ptr(atom, OWNER, MODULE).unwrap();
        assert_eq!(registry.classes.at(id).background, 0xBEEF);
    }

    /// A late failure after the record was made cleans up in order: the atom is deleted, the
    /// cursor locks go back down, the record's slot is freed — and an atom-table failure deletes
    /// no atom (there is none) but still releases everything else.
    #[test]
    fn a_late_failure_cleans_up() {
        let registry = registry();
        let (cursor, handle) = make_cursor(registry);
        let mut wc = wnd_class();
        wc.cursor = handle;
        let name_units = units("Foo");
        // A menu name that does not fit fails after the atom was added and the cursor locked.
        let long_menu = vec![b'm' as u16; MAX_MENU_NAME + 1];
        let err = registry
            .register_class(
                &wc,
                Name::Text(&name_units),
                MenuArg::Text(&long_menu),
                OWNER,
                compat40(),
                DESKTOP,
            )
            .unwrap_err();
        assert_eq!(err, Failure::OutOfMemory);
        assert_eq!(registry.atoms.find(&name_units), 0, "the atom was deleted");
        assert_eq!(
            registry.cursors.locks(cursor),
            0,
            "the cursor lock was released"
        );
        assert_eq!(
            registry.list_head(List::Private(OWNER)),
            None,
            "nothing was linked"
        );
        // The slot was freed: registering again succeeds, and unregistering it releases the
        // cursor lock again.
        let atom = register(registry, Name::Text(&name_units), &wc, compat40()).unwrap();
        assert!(atom >= 0xC000);
        registry
            .unregister_class(Name::Text(&name_units), OWNER, MODULE)
            .unwrap();
        assert_eq!(registry.cursors.locks(cursor), 0);
        // Atom-table exhaustion: no atom to delete, the rest still released.
        registry.atoms.next = 0;
        let other = units("Bar");
        let err = register(registry, Name::Text(&other), &wc, compat40()).unwrap_err();
        assert_eq!(err, Failure::OutOfMemory);
        assert_eq!(registry.atoms.find(&other), 0);
        assert_eq!(registry.cursors.locks(cursor), 0);
        // A pool exhaustion: no record, no atom, no link.
        registry.atoms.next = 0xD000; // the table's numbering back in range
        for i in 0..CLASSES {
            let name = Name::Text(&units(&format!("Class{i}")));
            register(registry, name, &wc, compat40()).unwrap();
        }
        let err = register(registry, Name::Text(&units("Last")), &wc, compat40()).unwrap_err();
        assert_eq!(err, Failure::OutOfMemory);
        assert_eq!(registry.atoms.find(&units("Last")), 0, "no atom was added");
        // The 128 live classes hold the cursor's 128 locks; the failed one added none.
        assert_eq!(registry.cursors.locks(cursor), CLASSES as u32);
    }

    /// A string class name goes through the atom table: the duplicate check uses the lookup
    /// atom, the record's atom is the added one, and it is unpinned so teardown can delete it.
    #[test]
    fn string_names_go_through_the_atom_table() {
        let registry = registry();
        let name_units = units("Foo");
        let wc = wnd_class();
        let atom = register(registry, Name::Text(&name_units), &wc, compat40()).unwrap();
        assert!((0xC000..=0xFFFF).contains(&atom));
        let id = registry.class_ptr(atom, OWNER, MODULE).unwrap();
        let class = registry.classes.at(id);
        assert_eq!(class.atom, atom);
        assert!(class.atom_added);
        assert!(!registry.atoms.is_pinned(atom));
        // Re-registering the same name from the same module: ERROR_CLASS_ALREADY_EXISTS (1410).
        let err = register(registry, Name::Text(&name_units), &wc, compat40()).unwrap_err();
        assert_eq!(err, Failure::ClassAlreadyExists);
        assert_eq!(err.code(), 1410);
    }

    /// An integer-atom class name bypasses the table: the atom is stored as given, no table
    /// entry is made, the duplicate check still applies, and the atom is the answer even though
    /// it is below the string atoms' range.
    #[test]
    fn integer_atom_names_bypass_the_table() {
        let registry = registry();
        let wc = wnd_class();
        let atom = register(registry, Name::Atom(0x8002), &wc, compat40()).unwrap();
        assert_eq!(atom, 0x8002);
        assert!(!registry.atoms.contains(0x8002));
        let id = registry.class_ptr(0x8002, OWNER, MODULE).unwrap();
        assert_eq!(registry.classes.at(id).atom, 0x8002);
        assert!(!registry.classes.at(id).atom_added);
        let err = register(registry, Name::Atom(0x8002), &wc, compat40()).unwrap_err();
        assert_eq!(err, Failure::ClassAlreadyExists);
    }

    /// The ANSI class-name copy: the string converted, or '#' plus the atom's decimal digits for
    /// an integer atom.
    #[test]
    fn the_ansi_name_is_a_copy() {
        let registry = registry();
        let wc = wnd_class();
        let atom = register(registry, Name::Text(&units("Foo")), &wc, compat40()).unwrap();
        let id = registry.class_ptr(atom, OWNER, MODULE).unwrap();
        let class = registry.classes.at(id);
        assert_eq!(&class.ansi_name[..4], b"Foo\0");
        assert_eq!(class.ansi_len, 3);
        let atom = register(registry, Name::Atom(0x8002), &wc, compat40()).unwrap();
        let id = registry.class_ptr(atom, OWNER, MODULE).unwrap();
        let class = registry.classes.at(id);
        assert_eq!(&class.ansi_name[..7], b"#32770\0");
        assert_eq!(class.ansi_len, 6);
    }

    /// The public name-to-atom lookup resolves a name as every lookup does: a registered string
    /// to its atom, an unknown string to 0, an integer atom to itself.
    #[test]
    fn names_resolve_to_atoms_as_lookups_do() {
        let registry = registry();
        let atom = register(
            registry,
            Name::Text(&units("Foo")),
            &wnd_class(),
            compat40(),
        )
        .unwrap();
        assert_eq!(registry.atom_of(Name::Text(&units("Foo"))), atom);
        assert_eq!(registry.atom_of(Name::Text(&units("Nope"))), 0);
        assert_eq!(registry.atom_of(Name::Atom(0x8002)), 0x8002);
        assert_eq!(registry.atom_of(Name::Atom(0)), 0);
    }

    /// GetClassName's text: a string class's name from the atom table, an integer atom's '#' and
    /// digits, an integer atom that names a string atom its string; cut at the buffer's length.
    #[test]
    fn the_class_name_is_the_atoms_name_or_its_number() {
        let registry = registry();
        let wc = wnd_class();
        let foo = register(registry, Name::Text(&units("Foo")), &wc, compat40()).unwrap();
        let dialog = register(registry, Name::Atom(0x8002), &wc, compat40()).unwrap();
        let name = |registry: &Registry, atom, len| {
            let id = registry.class_ptr(atom, OWNER, MODULE).unwrap();
            let mut out = vec![0u16; len];
            let written = registry.class_name(id, &mut out);
            String::from_utf16(&out[..written]).unwrap()
        };
        assert_eq!(name(registry, foo, 16), "Foo");
        assert_eq!(name(registry, foo, 2), "Fo");
        assert_eq!(name(registry, dialog, 16), "#32770");
        assert_eq!(name(registry, dialog, 3), "#32");
        let mut other = wnd_class();
        other.instance = OTHER_HIGH_WORD;
        let again = register(registry, Name::Atom(foo), &other, compat40()).unwrap();
        let id = registry.class_ptr(again, OWNER, OTHER_HIGH_WORD).unwrap();
        let mut out = [0u16; 8];
        assert_eq!(
            registry.class_name(id, &mut out),
            3,
            "the string atom's own name"
        );
    }

    /// A private class may shadow a public or system class of the same name (the public-list
    /// duplicate check runs only when CS_GLOBALCLASS is asked); a duplicate CS_GLOBALCLASS
    /// fails with 1410; the same name under a different module's high word is no duplicate.
    #[test]
    fn the_duplicate_rules() {
        let registry = registry();
        let mut wc = wnd_class();
        wc.style = CS_GLOBALCLASS;
        let bar = units("Bar");
        // A public class, then the same name as CS_GLOBALCLASS again: 1410.
        let atom = register(registry, Name::Text(&bar), &wc, compat40()).unwrap();
        assert_eq!(
            registry.list_head(List::Public(OWNER)),
            Some(registry.class_ptr(atom, OWNER, MODULE).unwrap())
        );
        let err = register(registry, Name::Text(&bar), &wc, compat40()).unwrap_err();
        assert_eq!(err, Failure::ClassAlreadyExists);
        // The same name privately (no CS_GLOBALCLASS): allowed, and it shadows the public one.
        wc.style = CS_HREDRAW;
        let private = register(registry, Name::Text(&bar), &wc, compat40()).unwrap();
        assert_eq!(private, atom);
        let found = registry.class_ptr(atom, OWNER, MODULE).unwrap();
        assert_ne!(found, registry.list_head(List::Public(OWNER)).unwrap());
        assert_eq!(registry.list_head(List::Private(OWNER)), Some(found));
        // The same name under another module's high word: two private classes coexist, the
        // newer at the head of the private list.
        wc.instance = OTHER_HIGH_WORD;
        let other = register(registry, Name::Text(&bar), &wc, compat40()).unwrap();
        assert_eq!(other, atom);
        let head = registry.list_head(List::Private(OWNER)).unwrap();
        assert_eq!(registry.class_ptr(atom, OWNER, OTHER_HIGH_WORD), Some(head));
        assert_eq!(registry.class_ptr(atom, OWNER, MODULE), Some(found));
        // The other process cannot see the private class.
        assert_eq!(registry.class_ptr(atom, OTHER_OWNER, MODULE), None);
    }

    /// A server-side registration skips the duplicate checks entirely and links into the public
    /// list (or the system list when it is a system class).
    #[test]
    fn server_side_registration_skips_the_duplicate_check() {
        let registry = registry();
        let wc = wnd_class();
        let name = Name::Text(&units("Sys"));
        let flags = RegisterFlags {
            server_side_proc: true,
            ..RegisterFlags::default()
        };
        let first = register(registry, name, &wc, flags).unwrap();
        let second = register(registry, name, &wc, flags).unwrap();
        assert_eq!(first, second);
        // Both are in the public list, the newer at the head.
        let head = registry.list_head(List::Public(OWNER)).unwrap();
        let next = registry.classes.at(head).next.unwrap();
        assert_eq!(registry.class_ptr(first, OWNER, MODULE), Some(head));
        assert_eq!(registry.classes.at(next).atom, first);
        // A system class links into the system list.
        let flags = RegisterFlags {
            server_side_proc: true,
            system_class: true,
            ..RegisterFlags::default()
        };
        let atom = register(registry, Name::Text(&units("Sys2")), &wc, flags).unwrap();
        assert_eq!(
            registry.list_head(List::System),
            Some(registry.class_ptr(atom, OWNER, MODULE).unwrap())
        );
    }

    /// Module handles match by high word only: a class registered under 0x0040_0000 is found
    /// from 0x0040_9ABC.
    #[test]
    fn lookups_match_the_module_by_high_word() {
        let registry = registry();
        let wc = wnd_class();
        let atom = register(registry, Name::Text(&units("Foo")), &wc, compat40()).unwrap();
        assert!(registry.class_ptr(atom, OWNER, SAME_HIGH_WORD).is_some());
        assert!(registry.class_ptr(atom, OWNER, OTHER_HIGH_WORD).is_none());
        assert!(
            registry.class_ptr(0, OWNER, MODULE).is_none(),
            "atom 0 names nothing"
        );
    }

    /// The five lookup passes: the caller's private list, its public list, both again under the
    /// user32 module, then the system list — first hit wins, and a class awaiting a 16-bit
    /// destroy is skipped in every pass.
    #[test]
    fn the_lookup_runs_five_passes() {
        let registry = registry();
        let wc = wnd_class();
        // A private class under the caller's module.
        let private_atom = register(registry, Name::Text(&units("Mine")), &wc, compat40()).unwrap();
        // A private class under the user32 module.
        let mut wc_client = wnd_class();
        wc_client.instance = CLIENT_MODULE;
        let client_private = register(
            registry,
            Name::Text(&units("ClientPrivate")),
            &wc_client,
            compat40(),
        )
        .unwrap();
        // A public class.
        let mut wc_public = wnd_class();
        wc_public.style = CS_GLOBALCLASS;
        let public = register(
            registry,
            Name::Text(&units("Shared")),
            &wc_public,
            compat40(),
        )
        .unwrap();
        // A system class.
        let flags = RegisterFlags {
            server_side_proc: true,
            system_class: true,
            ..RegisterFlags::default()
        };
        let system = register(registry, Name::Text(&units("System")), &wc, flags).unwrap();
        // A public class under the user32 module.
        let mut wc_cp = wnd_class();
        wc_cp.instance = CLIENT_MODULE;
        wc_cp.style = CS_GLOBALCLASS;
        let client_public = register(
            registry,
            Name::Text(&units("ClientPublic")),
            &wc_cp,
            compat40(),
        )
        .unwrap();

        // Distinct names resolve through their own list's pass.
        assert!(registry.class_ptr(private_atom, OWNER, MODULE).is_some());
        assert_eq!(
            registry
                .class_ptr(client_private, OWNER, MODULE)
                .map(|id| registry.classes.at(id).module),
            Some(CLIENT_MODULE)
        );
        assert_eq!(
            registry.class_ptr(public, OWNER, MODULE).map(|id| registry
                .classes
                .at(id)
                .flags
                .system_class),
            Some(false)
        );
        assert_eq!(
            registry.class_ptr(system, OWNER, MODULE).map(|id| registry
                .classes
                .at(id)
                .flags
                .system_class),
            Some(true)
        );
        assert_eq!(
            registry
                .class_ptr(client_public, OWNER, MODULE)
                .map(|id| registry.classes.at(id).module),
            Some(CLIENT_MODULE)
        );
        // One name in several lists: the caller's private wins over the public, the public over
        // the user32-module private, that over the user32 public, that over the system.
        let name = units("Everywhere");
        let a = register(registry, Name::Text(&name), &wc, compat40()).unwrap();
        let a_id = registry.class_ptr(a, OWNER, MODULE).unwrap();
        let mut wc_p = wnd_class();
        wc_p.style = CS_GLOBALCLASS;
        wc_p.instance = OTHER_HIGH_WORD;
        let p = register(registry, Name::Text(&name), &wc_p, compat40()).unwrap();
        let p_id = registry.list_head(List::Public(OWNER)).unwrap();
        let mut wc_c = wnd_class();
        wc_c.instance = CLIENT_MODULE;
        let c = register(registry, Name::Text(&name), &wc_c, compat40()).unwrap();
        let c_id = registry.list_head(List::Private(OWNER)).unwrap();
        let flags = RegisterFlags {
            server_side_proc: true,
            system_class: true,
            ..RegisterFlags::default()
        };
        let s = register(registry, Name::Text(&name), &wc, flags).unwrap();
        assert_eq!(a, p);
        assert_eq!(p, c);
        assert_eq!(c, s);
        let found = registry.class_ptr(a, OWNER, MODULE).unwrap();
        assert_eq!(found, a_id, "the caller's private class wins");
        // Skipping the private pass (a module with another high word): the public one wins.
        let found = registry.class_ptr(a, OWNER, OTHER_HIGH_WORD).unwrap();
        assert_eq!(found, p_id);
        // Looked up as the user32 module: its private class under that module is found.
        let found = registry.class_ptr(a, OWNER, CLIENT_MODULE).unwrap();
        assert_eq!(found, c_id);
        // A class awaiting a 16-bit destroy is skipped: the public one is found instead.
        registry.classes.at_mut(a_id).flags.wow_defer_destroy = true;
        let found = registry.class_ptr(a, OWNER, MODULE).unwrap();
        assert_eq!(found, p_id);
    }

    /// Unregister: the happy path removes the class and deletes its atom, releases the cursor
    /// locks and frees the record; a class with windows is refused with
    /// ERROR_CLASS_HAS_WINDOWS (1412); an unknown name or wrong owner with
    /// ERROR_CLASS_DOES_NOT_EXIST (1411); an integer-atom name unregisters too.
    #[test]
    fn unregister_class_rules() {
        let registry = registry();
        let (cursor, handle) = make_cursor(registry);
        let mut wc = wnd_class();
        wc.cursor = handle;
        let name = units("Foo");
        let atom = register(registry, Name::Text(&name), &wc, compat40()).unwrap();
        let id = registry.class_ptr(atom, OWNER, MODULE).unwrap();
        // With a window: 1412, the class stays.
        let mut wnd = window(id);
        assert!(registry.reference_class(id, &mut wnd));
        let err = registry
            .unregister_class(Name::Text(&name), OWNER, MODULE)
            .unwrap_err();
        assert_eq!(err, Failure::ClassHasWindows);
        assert_eq!(err.code(), 1412);
        assert!(registry.classes.is_live(id));
        registry.dereference_class(&mut wnd);
        // Happy path.
        registry
            .unregister_class(Name::Text(&name), OWNER, MODULE)
            .unwrap();
        assert_eq!(registry.atoms.find(&name), 0, "the atom was deleted");
        assert!(!registry.classes.is_live(id), "the record was freed");
        assert_eq!(registry.cursors.locks(cursor), 0, "the cursor was unlocked");
        assert_eq!(registry.list_head(List::Private(OWNER)), None);
        // Unknown name, or the right name under the wrong module: 1411.
        let err = registry
            .unregister_class(Name::Text(&name), OWNER, MODULE)
            .unwrap_err();
        assert_eq!(err, Failure::ClassDoesNotExist);
        assert_eq!(err.code(), 1411);
        register(registry, Name::Text(&name), &wc, compat40()).unwrap();
        let err = registry
            .unregister_class(Name::Text(&name), OWNER, OTHER_HIGH_WORD)
            .unwrap_err();
        assert_eq!(err, Failure::ClassDoesNotExist);
        // An integer-atom name unregisters too, and its record is freed.
        register(registry, Name::Atom(0x8002), &wc, compat40()).unwrap();
        let id = registry.class_ptr(0x8002, OWNER, MODULE).unwrap();
        registry
            .unregister_class(Name::Atom(0x8002), OWNER, MODULE)
            .unwrap();
        assert!(!registry.classes.is_live(id));
    }

    /// The fields a registration copies into the record: the WNDCLASSEXW's tail by value, the
    /// window count zero, the class-extra area zeroed (never copied), the strings copied into
    /// the record's own buffers.
    #[test]
    fn registration_copies_the_fields() {
        let registry = registry();
        let (cursor, handle) = make_cursor(registry);
        let mut wc = wnd_class();
        wc.style = CS_HREDRAW | CS_OWNDC;
        wc.wnd_proc = 0x0040_2000;
        wc.cb_cls_extra = 8;
        wc.cb_wnd_extra = 4;
        wc.instance = MODULE;
        wc.cursor = handle;
        wc.background = 6;
        let menu = units("File");
        let atom = registry
            .register_class(
                &wc,
                Name::Text(&units("Foo")),
                MenuArg::Text(&menu),
                OWNER,
                compat40(),
                DESKTOP,
            )
            .unwrap();
        let id = registry.class_ptr(atom, OWNER, MODULE).unwrap();
        let class = registry.classes.at(id);
        assert_eq!(class.style, wc.style);
        assert_eq!(class.wnd_proc, wc.wnd_proc);
        assert_eq!(class.cb_cls_extra, 8);
        assert_eq!(class.cb_wnd_extra, 4);
        assert_eq!(class.module, MODULE);
        assert_eq!(class.cursor, Some(cursor));
        assert_eq!(class.background, 6);
        assert_eq!(class.window_count, 0);
        assert_eq!(class.base, id);
        assert!(
            class.extra[..8].iter().all(|&b| b == 0),
            "the extra area is zeroed"
        );
        assert_eq!(
            class.menu_name,
            MenuName::Text {
                len: 4,
                units: {
                    let mut u = [0u16; MAX_MENU_NAME];
                    u[..4].copy_from_slice(&menu);
                    u
                }
            }
        );
        // An empty menu-name string becomes none; an integer id is kept as a value.
        let atom = registry
            .register_class(
                &wc,
                Name::Text(&units("Empty")),
                MenuArg::Text(&[]),
                OWNER,
                compat40(),
                DESKTOP,
            )
            .unwrap();
        let id = registry.class_ptr(atom, OWNER, MODULE).unwrap();
        assert_eq!(registry.classes.at(id).menu_name, MenuName::None);
        let atom = registry
            .register_class(
                &wc,
                Name::Text(&units("Id")),
                MenuArg::Id(7),
                OWNER,
                compat40(),
                DESKTOP,
            )
            .unwrap();
        let id = registry.class_ptr(atom, OWNER, MODULE).unwrap();
        assert_eq!(registry.classes.at(id).menu_name, MenuName::Id(7));
    }

    /// SetClassLong on a negative index: the table-driven fields are read and written with their
    /// width, bogus or unmapped indexes fail with ERROR_INVALID_INDEX (1413), and the write
    /// propagates to every clone. GCL_CBCLSEXTRA is refused with ERROR_INVALID_PARAMETER (87)
    /// (it is changeable only on a 16-bit class).
    #[test]
    fn the_table_driven_class_data() {
        let registry = registry();
        let wc = wnd_class();
        let atom = register(registry, Name::Text(&units("Foo")), &wc, compat40()).unwrap();
        let id = registry.class_ptr(atom, OWNER, MODULE).unwrap();
        let wnd = window(id);
        let noop = &mut noop as &mut dyn FnMut(&WindowView, WindowNotice);
        // GCL_STYLE (-26, a dword): the old style is answered.
        let old = registry
            .set_class_long(&wnd, OWNER, GCL_STYLE, 0x55, MenuArg::None, None, &[], noop)
            .unwrap();
        assert_eq!(old, CS_HREDRAW | CS_VREDRAW);
        assert_eq!(registry.classes.at(id).style, 0x55);
        // GCW_ATOM (-32, a word).
        let old = registry
            .set_class_long(
                &wnd,
                OWNER,
                GCW_ATOM,
                0x1234,
                MenuArg::None,
                None,
                &[],
                noop,
            )
            .unwrap();
        assert_eq!(old, atom as u32);
        assert_eq!(registry.classes.at(id).atom, 0x1234);
        // GCL_HBRBACKGROUND (-10) and GCL_HMODULE (-16).
        let old = registry
            .set_class_long(
                &wnd,
                OWNER,
                GCL_HBRBACKGROUND,
                0x99,
                MenuArg::None,
                None,
                &[],
                noop,
            )
            .unwrap();
        assert_eq!(old, 6);
        assert_eq!(registry.classes.at(id).background, 0x99);
        // Bogus and unmapped indexes: 1413.
        for index in [-33, -35, -21, -1] {
            let err = registry
                .set_class_long(&wnd, OWNER, index, 0, MenuArg::None, None, &[], noop)
                .unwrap_err();
            assert_eq!(err, Failure::InvalidIndex, "index {index}");
            assert_eq!(err.code(), 1413);
        }
        // GCL_CBCLSEXTRA: 87.
        let err = registry
            .set_class_long(
                &wnd,
                OWNER,
                GCL_CBCLSEXTRA,
                4,
                MenuArg::None,
                None,
                &[],
                noop,
            )
            .unwrap_err();
        assert_eq!(err, Failure::InvalidParameter);
        assert_eq!(err.code(), 87);
        // GCLP_WNDPROC (-24): the old wndproc is answered.
        let old = registry
            .set_class_long(
                &wnd,
                OWNER,
                GCLP_WNDPROC,
                0x777,
                MenuArg::None,
                None,
                &[],
                noop,
            )
            .unwrap();
        assert_eq!(old, 0x0040_1000);
        assert_eq!(registry.classes.at(id).wnd_proc, 0x777);
        // The same write propagates to a clone.
        let mut other = Window {
            class: id,
            owner: OWNER,
            desktop: DESKTOP + 1,
        };
        assert!(registry.reference_class(id, &mut other));
        let clone = other.class;
        assert_ne!(clone, id);
        registry
            .set_class_long(&wnd, OWNER, GCL_STYLE, 0xAA, MenuArg::None, None, &[], noop)
            .unwrap();
        assert_eq!(
            registry.classes.at(clone).style,
            0xAA,
            "the clone got the write too"
        );
    }

    /// SetClassWord/SetClassLong on a positive index write the class-extra area: another
    /// process's window is refused with ERROR_ACCESS_DENIED (5), a negative index for the word
    /// entry or an index past the extra area with ERROR_INVALID_INDEX (1413), and the old value
    /// is answered.
    #[test]
    fn the_extra_area_writes() {
        let registry = registry();
        let mut wc = wnd_class();
        wc.cb_cls_extra = 8;
        let atom = register(registry, Name::Text(&units("Foo")), &wc, compat40()).unwrap();
        let id = registry.class_ptr(atom, OWNER, MODULE).unwrap();
        let wnd = window(id);
        // Another process's window: 5.
        let foreign = Window {
            class: id,
            owner: OTHER_OWNER,
            desktop: DESKTOP,
        };
        let err = registry
            .set_class_long(
                &foreign,
                OWNER,
                0,
                1,
                MenuArg::None,
                None,
                &[],
                &mut |_, _| {},
            )
            .unwrap_err();
        assert_eq!(err, Failure::AccessDenied);
        assert_eq!(err.code(), 5);
        let err = registry.set_class_word(&foreign, OWNER, 0, 1).unwrap_err();
        assert_eq!(err, Failure::AccessDenied);
        // The dword at 0, then the old value back.
        let old = registry
            .set_class_long(
                &wnd,
                OWNER,
                0,
                0xAABBCCDD,
                MenuArg::None,
                None,
                &[],
                &mut |_, _| {},
            )
            .unwrap();
        assert_eq!(old, 0);
        assert_eq!(registry.read_extra_dword(id, 0), 0xAABBCCDD);
        let old = registry
            .set_class_long(
                &wnd,
                OWNER,
                0,
                0x11223344,
                MenuArg::None,
                None,
                &[],
                &mut |_, _| {},
            )
            .unwrap();
        assert_eq!(old, 0xAABBCCDD);
        // The word at 6 fits (6 + 2 <= 8), at 8 does not; a negative word index is refused
        // outright.
        assert_eq!(registry.set_class_word(&wnd, OWNER, 6, 0xBEEF).unwrap(), 0);
        assert_eq!(registry.read_extra_word(id, 6), 0xBEEF);
        let err = registry.set_class_word(&wnd, OWNER, 8, 0).unwrap_err();
        assert_eq!(err, Failure::InvalidIndex);
        let err = registry.set_class_word(&wnd, OWNER, -1, 0).unwrap_err();
        assert_eq!(err, Failure::InvalidIndex);
        let err = registry
            .set_class_long(&wnd, OWNER, 6, 0, MenuArg::None, None, &[], &mut |_, _| {})
            .unwrap_err();
        assert_eq!(err, Failure::InvalidIndex, "6 + 4 > 8");
    }

    /// The menu-name change copies the new name into the record (a string is copied, an empty
    /// string becomes none, an integer id is kept as a value), frees the old string copy, and
    /// answers the old value; a name that does not fit leaves the class unchanged.
    #[test]
    fn the_menu_name_change_copies() {
        let registry = registry();
        let wc = wnd_class();
        let atom = register(registry, Name::Text(&units("Foo")), &wc, compat40()).unwrap();
        let id = registry.class_ptr(atom, OWNER, MODULE).unwrap();
        let wnd = window(id);
        let noop = &mut noop as &mut dyn FnMut(&WindowView, WindowNotice);
        let old = registry
            .set_class_long(
                &wnd,
                OWNER,
                GCLP_MENUNAME,
                0,
                MenuArg::Text(&units("File")),
                None,
                &[],
                noop,
            )
            .unwrap();
        assert_eq!(old, 0, "the old value was none");
        match registry.classes.at(id).menu_name {
            MenuName::Text { len, units: stored } => {
                assert_eq!(len, 4);
                assert_eq!(&stored[..4], &units("File")[..]);
            }
            other => panic!("{other:?}"),
        }
        // An empty string clears it, an id is stored as a value.
        let old = registry
            .set_class_long(
                &wnd,
                OWNER,
                GCLP_MENUNAME,
                0,
                MenuArg::Text(&[]),
                None,
                &[],
                noop,
            )
            .unwrap();
        assert_eq!(old, 0);
        assert_eq!(registry.classes.at(id).menu_name, MenuName::None);
        let old = registry
            .set_class_long(
                &wnd,
                OWNER,
                GCLP_MENUNAME,
                0,
                MenuArg::Id(7),
                None,
                &[],
                noop,
            )
            .unwrap();
        assert_eq!(old, 0);
        assert_eq!(registry.classes.at(id).menu_name, MenuName::Id(7));
        let old = registry
            .set_class_long(
                &wnd,
                OWNER,
                GCLP_MENUNAME,
                0,
                MenuArg::None,
                None,
                &[],
                noop,
            )
            .unwrap();
        assert_eq!(old, 7, "the old id");
        assert_eq!(registry.classes.at(id).menu_name, MenuName::None);
        // A name that does not fit: the class is unchanged.
        let long = vec![b'x' as u16; MAX_MENU_NAME + 1];
        let err = registry
            .set_class_long(
                &wnd,
                OWNER,
                GCLP_MENUNAME,
                0,
                MenuArg::Text(&long),
                None,
                &[],
                noop,
            )
            .unwrap_err();
        assert_eq!(err, Failure::OutOfMemory);
        assert_eq!(registry.classes.at(id).menu_name, MenuName::None);
    }

    /// The icon change notifies exactly the class's windows: with more than one window of the
    /// class, every window of the class on the desktop is visited (and only those); with one,
    /// just the calling window. Each is told to destroy its small icon when it asked for
    /// drag-icon queries and to redraw its title when it has no small-icon property of its own.
    /// The cached small icon is destroyed first, a small icon is synthesized from the icon, and
    /// the old handle is revalidated before it is answered.
    #[test]
    fn the_icon_change_notifies_the_class_windows() {
        let registry = registry();
        let (_old_icon, old_handle) = make_cursor(registry);
        let (new_icon, new_handle) = make_cursor(registry);
        registry.cursors.make(true, false); // a spare record so the synthesis has room
        let mut wc = wnd_class();
        wc.icon = old_handle;
        let atom = register(registry, Name::Text(&units("Foo")), &wc, compat40()).unwrap();
        let id = registry.class_ptr(atom, OWNER, MODULE).unwrap();
        // Two windows of the class.
        let mut w1 = window(id);
        let mut w2 = window(id);
        assert!(registry.reference_class(id, &mut w1));
        assert!(registry.reference_class(id, &mut w2));
        assert_eq!(registry.classes.at(id).window_count, 2);
        let wnd = window(id);
        // The windows on the desktop: two of the class (one asking for drag icons, one with its
        // own small icon), one of another class.
        let other_atom = register(
            registry,
            Name::Text(&units("Other")),
            &wnd_class(),
            compat40(),
        )
        .unwrap();
        let other = registry.class_ptr(other_atom, OWNER, MODULE).unwrap();
        let views = [
            WindowView {
                class: id,
                query_drag_icon: true,
                has_own_icon_sm: false,
            },
            WindowView {
                class: id,
                query_drag_icon: false,
                has_own_icon_sm: true,
            },
            WindowView {
                class: other,
                query_drag_icon: true,
                has_own_icon_sm: false,
            },
        ];
        let mut notices: Vec<(ClassId, WindowNotice)> = Vec::new();
        let old = registry
            .set_class_long(
                &wnd,
                OWNER,
                GCLP_HICON,
                new_handle,
                MenuArg::None,
                None,
                &views,
                &mut |w, n| notices.push((w.class, n)),
            )
            .unwrap();
        assert_eq!(old, old_handle, "the old handle, revalidated");
        assert_eq!(registry.classes.at(id).icon, Some(new_icon));
        // The small icon was synthesized from the icon and marked cached.
        let sm = registry
            .classes
            .at(id)
            .icon_sm
            .expect("a synthesized small icon");
        assert!(registry.classes.at(id).flags.cached_sm_icon);
        assert!(registry.cursors.secret(sm));
        assert_eq!(registry.cursors.locks(sm), 1);
        // Only the class's two windows were notified, each with its own notice.
        assert_eq!(notices.len(), 2);
        assert!(notices.iter().all(|(c, _)| *c == id));
        assert_eq!(
            notices[0].1,
            WindowNotice {
                destroy_sm_icon: true,
                redraw_title: true
            }
        );
        assert_eq!(
            notices[1].1,
            WindowNotice {
                destroy_sm_icon: false,
                redraw_title: false
            }
        );
        // With a single window of the class, only the calling window is notified.
        let mut single = Window {
            class: id,
            owner: OWNER,
            desktop: DESKTOP + 5,
        };
        assert!(registry.reference_class(id, &mut single));
        // (window_count is now 3; drop the two earlier ones)
        registry.dereference_class(&mut w1);
        registry.dereference_class(&mut w2);
        assert_eq!(registry.classes.at(id).window_count, 1);
        let view = WindowView {
            class: id,
            query_drag_icon: false,
            has_own_icon_sm: false,
        };
        let mut got: Vec<WindowNotice> = Vec::new();
        let (_, third_handle) = make_cursor(registry);
        registry
            .set_class_long(
                &wnd,
                OWNER,
                GCLP_HICON,
                third_handle,
                MenuArg::None,
                Some(&view),
                &views,
                &mut |_, n| got.push(n),
            )
            .unwrap();
        assert_eq!(got.len(), 1, "just the calling window");
        assert_eq!(
            got[0],
            WindowNotice {
                destroy_sm_icon: false,
                redraw_title: true
            }
        );
        // Setting the same icon is a no-op: no notification, no synthesis, the old icon back.
        let mut got: Vec<WindowNotice> = Vec::new();
        let old = registry
            .set_class_long(
                &wnd,
                OWNER,
                GCLP_HICON,
                third_handle,
                MenuArg::None,
                Some(&view),
                &views,
                &mut |_, n| got.push(n),
            )
            .unwrap();
        assert_eq!(old, third_handle);
        assert!(got.is_empty(), "the same icon changes nothing");
    }

    /// The small-icon change with a system-created cached icon: the cached one is destroyed and
    /// the old value is answered as null (apps never see it); the new icon is locked in.
    #[test]
    fn the_small_icon_change_hides_the_cached_one() {
        let registry = registry();
        let (_icon, icon_handle) = make_cursor(registry);
        let mut wc = wnd_class();
        wc.icon = icon_handle;
        let atom = register(registry, Name::Text(&units("Foo")), &wc, compat40()).unwrap();
        let id = registry.class_ptr(atom, OWNER, MODULE).unwrap();
        let mut wnd = window(id);
        assert!(registry.reference_class(id, &mut wnd));
        let wnd = window(id);
        // Set another icon: a small icon is synthesized from it and cached.
        let (_, other_handle) = make_cursor(registry);
        registry
            .set_class_long(
                &wnd,
                OWNER,
                GCLP_HICON,
                other_handle,
                MenuArg::None,
                None,
                &[],
                &mut |_, _| {},
            )
            .unwrap();
        let cached = registry.classes.at(id).icon_sm.unwrap();
        let cached_handle = registry.cursors.handle_of(Some(cached));
        assert!(registry.classes.at(id).flags.cached_sm_icon);
        // Change the small icon: the cached one is destroyed, the answer is null.
        let (sm, sm_handle) = make_cursor(registry);
        let old = registry
            .set_class_long(
                &wnd,
                OWNER,
                GCLP_HICONSM,
                sm_handle,
                MenuArg::None,
                None,
                &[],
                &mut |_, _| {},
            )
            .unwrap();
        assert_eq!(old, 0, "the system-created small icon is never answered");
        assert!(!registry.classes.at(id).flags.cached_sm_icon);
        assert_eq!(
            registry.cursors.validate(cached_handle),
            None,
            "the cached icon was destroyed"
        );
        assert_eq!(registry.classes.at(id).icon_sm, Some(sm));
        assert_eq!(registry.cursors.locks(sm), 1);
    }

    /// A cursor change through GCLP_HCURSOR locks the new cursor and answers the old handle; an
    /// invalid handle fails with ERROR_INVALID_CURSOR_HANDLE (1402) / the icon indexes with
    /// ERROR_INVALID_ICON_HANDLE (1414), and the field is set to none either way.
    #[test]
    fn the_cursor_change_validates_the_handle() {
        let registry = registry();
        let (old_cursor, old_handle) = make_cursor(registry);
        let (new_cursor, new_handle) = make_cursor(registry);
        let mut wc = wnd_class();
        wc.cursor = old_handle;
        let atom = register(registry, Name::Text(&units("Foo")), &wc, compat40()).unwrap();
        let id = registry.class_ptr(atom, OWNER, MODULE).unwrap();
        let wnd = window(id);
        let noop = &mut noop as &mut dyn FnMut(&WindowView, WindowNotice);
        let old = registry
            .set_class_long(
                &wnd,
                OWNER,
                GCLP_HCURSOR,
                new_handle,
                MenuArg::None,
                None,
                &[],
                noop,
            )
            .unwrap();
        assert_eq!(old, old_handle);
        assert_eq!(registry.classes.at(id).cursor, Some(new_cursor));
        assert_eq!(registry.cursors.locks(old_cursor), 0);
        assert_eq!(registry.cursors.locks(new_cursor), 1);
        // An invalid cursor handle: 1402, the field set to none.
        let err = registry
            .set_class_long(
                &wnd,
                OWNER,
                GCLP_HCURSOR,
                0xDEAD,
                MenuArg::None,
                None,
                &[],
                noop,
            )
            .unwrap_err();
        assert_eq!(err, Failure::InvalidCursorHandle);
        assert_eq!(err.code(), 1402);
        assert_eq!(registry.classes.at(id).cursor, None);
        // An invalid icon handle: 1414.
        let err = registry
            .set_class_long(
                &wnd,
                OWNER,
                GCLP_HICON,
                0xDEAD,
                MenuArg::None,
                None,
                &[],
                noop,
            )
            .unwrap_err();
        assert_eq!(err, Failure::InvalidIconHandle);
        assert_eq!(err.code(), 1414);
    }

    /// Reference and dereference: on the class's own desktop just the count goes up and down; on
    /// another desktop a clone is made (or reused), both counts go up, the window points at the
    /// clone, and the clone is destroyed when its count reaches zero.
    #[test]
    fn reference_and_dereference_class() {
        let registry = registry();
        let (cursor, handle) = make_cursor(registry);
        let mut wc = wnd_class();
        wc.cursor = handle;
        let atom = register(registry, Name::Text(&units("Foo")), &wc, compat40()).unwrap();
        let id = registry.class_ptr(atom, OWNER, MODULE).unwrap();
        // Same desktop: the count up and down.
        let mut wnd = window(id);
        assert!(registry.reference_class(id, &mut wnd));
        assert_eq!(registry.classes.at(id).window_count, 1);
        assert_eq!(wnd.class, id);
        registry.dereference_class(&mut wnd);
        assert_eq!(registry.classes.at(id).window_count, 0);
        // Another desktop: a clone is made, both counts up, the window points at the clone.
        let mut other = Window {
            class: id,
            owner: OWNER,
            desktop: DESKTOP + 1,
        };
        assert!(registry.reference_class(id, &mut other));
        let clone = other.class;
        assert_ne!(clone, id);
        assert_eq!(registry.classes.at(clone).desktop, DESKTOP + 1);
        assert_eq!(registry.classes.at(clone).base, id);
        assert_eq!(registry.classes.at(id).window_count, 1);
        assert_eq!(registry.classes.at(clone).window_count, 1);
        assert_eq!(
            registry.classes.at(clone).cursor,
            Some(cursor),
            "the clone holds its own lock"
        );
        assert_eq!(registry.cursors.locks(cursor), 2);
        // The same desktop again reuses the clone.
        let mut again = Window {
            class: id,
            owner: OWNER,
            desktop: DESKTOP + 1,
        };
        assert!(registry.reference_class(id, &mut again));
        assert_eq!(again.class, clone);
        assert_eq!(registry.classes.at(clone).window_count, 2);
        // Dereference down to zero destroys the clone.
        registry.dereference_class(&mut again);
        assert!(registry.classes.is_live(clone));
        registry.dereference_class(&mut other);
        assert!(
            !registry.classes.is_live(clone),
            "the clone at zero was destroyed"
        );
        assert_eq!(registry.classes.at(id).window_count, 0);
        assert_eq!(
            registry.cursors.locks(cursor),
            1,
            "the clone's lock went with it"
        );
    }

    /// Teardown: the class's atom is deleted (a pinned one survives), the clones go first, the
    /// cached small icon is destroyed, the cursor locks are released, the record is unlinked and
    /// freed.
    #[test]
    fn the_teardown_order() {
        let registry = registry();
        let (cursor, handle) = make_cursor(registry);
        let (icon, icon_handle) = make_cursor(registry);
        let mut wc = wnd_class();
        wc.cursor = handle;
        wc.icon = icon_handle;
        wc.background = 0x1000; // a real brush handle, above the system colors
        let name = units("Foo");
        let atom = register(registry, Name::Text(&name), &wc, compat40()).unwrap();
        let id = registry.class_ptr(atom, OWNER, MODULE).unwrap();
        // A clone, a window, a cached small icon.
        let mut other = Window {
            class: id,
            owner: OWNER,
            desktop: DESKTOP + 1,
        };
        assert!(registry.reference_class(id, &mut other));
        let clone = other.class;
        let mut wnd = window(id);
        assert!(registry.reference_class(id, &mut wnd));
        // Change the icon to another one: a small icon is synthesized from it and cached.
        let (_, other_handle) = make_cursor(registry);
        registry
            .set_class_long(
                &wnd,
                OWNER,
                GCLP_HICON,
                other_handle,
                MenuArg::None,
                None,
                &[],
                &mut |_, _| {},
            )
            .unwrap();
        let sm = registry.classes.at(id).icon_sm.unwrap();
        assert!(registry.classes.at(id).flags.cached_sm_icon);
        registry.dereference_class(&mut wnd);
        registry.dereference_class(&mut other);
        // Unregister: the whole teardown.
        registry
            .unregister_class(Name::Text(&name), OWNER, MODULE)
            .unwrap();
        assert_eq!(registry.atoms.find(&name), 0, "the atom was deleted");
        assert!(!registry.classes.is_live(id));
        assert!(!registry.classes.is_live(clone), "the clone went first");
        assert_eq!(registry.cursors.locks(cursor), 0);
        assert_eq!(
            registry
                .cursors
                .validate(registry.cursors.handle_of(Some(icon))),
            Some(icon),
            "the icon itself survives"
        );
        assert_eq!(
            registry
                .cursors
                .validate(registry.cursors.handle_of(Some(sm))),
            None,
            "the cached small icon was destroyed"
        );
        assert_eq!(registry.list_head(List::Private(OWNER)), None);
        // A pinned class-name atom survives the teardown's delete.
        let atom = register(registry, Name::Text(&units("Pinned")), &wc, compat40()).unwrap();
        registry.atoms.set_pinned_range(atom, atom);
        registry
            .unregister_class(Name::Text(&units("Pinned")), OWNER, MODULE)
            .unwrap();
        assert!(
            registry.atoms.contains(atom),
            "the pinned atom was not deleted"
        );
    }

    /// The class brush's deletion rules: a system color (a handle up to 28) is never a GDI
    /// object; a brush shared with another class in any of the three lists is left alone; a
    /// brush no other class references is deleted.
    #[test]
    fn the_brush_deletion_rules() {
        let registry = registry();
        let mut system = wnd_class();
        system.background = 6;
        let atom = register(
            registry,
            Name::Text(&units("SysColor")),
            &system,
            compat40(),
        )
        .unwrap();
        let id = registry.class_ptr(atom, OWNER, MODULE).unwrap();
        assert!(
            !registry.destroy_class_brush(id, OWNER),
            "COLOR_WINDOW+1 is a system color"
        );
        let mut edge = wnd_class();
        edge.background = 28;
        let atom = register(registry, Name::Text(&units("Edge")), &edge, compat40()).unwrap();
        let id = registry.class_ptr(atom, OWNER, MODULE).unwrap();
        assert!(
            !registry.destroy_class_brush(id, OWNER),
            "28 is still a system color handle"
        );
        // A real brush, alone: deleted.
        let mut real = wnd_class();
        real.background = 0x1000;
        let atom = register(registry, Name::Text(&units("Real")), &real, compat40()).unwrap();
        let id = registry.class_ptr(atom, OWNER, MODULE).unwrap();
        assert!(registry.destroy_class_brush(id, OWNER));
        // Shared with a private class of the same process: not deleted.
        let mut share = wnd_class();
        share.background = 0x1000;
        let atom2 = register(registry, Name::Text(&units("Share")), &share, compat40()).unwrap();
        let id2 = registry.class_ptr(atom2, OWNER, MODULE).unwrap();
        assert!(
            !registry.destroy_class_brush(id, OWNER),
            "shared with a private class"
        );
        // Shared only via the system list: still not deleted.
        let flags = RegisterFlags {
            server_side_proc: true,
            system_class: true,
            ..RegisterFlags::default()
        };
        let mut sys = wnd_class();
        sys.background = 0x1000;
        register(registry, Name::Text(&units("SysShare")), &sys, flags).unwrap();
        assert!(
            !registry.destroy_class_brush(id2, OWNER),
            "shared with a system class"
        );
        // A different brush is unaffected.
        let mut other_brush = wnd_class();
        other_brush.background = 0x2000;
        let atom4 = register(
            registry,
            Name::Text(&units("Other")),
            &other_brush,
            compat40(),
        )
        .unwrap();
        let id4 = registry.class_ptr(atom4, OWNER, MODULE).unwrap();
        assert!(
            registry.destroy_class_brush(id4, OWNER),
            "no other class references it"
        );
    }

    /// GetClassInfo: an unknown class fails with ERROR_CLASS_DOES_NOT_EXIST (1411); a found
    /// class answers its atom, the style masked to the public bits (CS_GLOBALCLASS masked out of
    /// a server-registered class for a 4.0-compatible caller), the mapped instance, the
    /// handles, the background, and the menu name; a system-created small icon is hidden as
    /// null.
    #[test]
    fn get_class_info_maps_the_fields() {
        let registry = registry();
        let (_cursor, cursor_handle) = make_cursor(registry);
        let (_icon, icon_handle) = make_cursor(registry);
        let mut wc = wnd_class();
        wc.style = CS_HREDRAW | 0x8000_0000; // an internal bit, masked out of the answer
        wc.cursor = cursor_handle;
        wc.icon = icon_handle;
        let name = units("Foo");
        let atom = register(registry, Name::Text(&name), &wc, compat40()).unwrap();
        let err = registry
            .get_class_info(Name::Text(&units("Nope")), None, OWNER, true)
            .unwrap_err();
        assert_eq!(err, Failure::ClassDoesNotExist);
        assert_eq!(err.code(), 1411);
        let info = registry
            .get_class_info(Name::Text(&name), Some(MODULE), OWNER, true)
            .unwrap();
        assert_eq!(info.atom, atom);
        assert_eq!(info.style, CS_HREDRAW, "only the public bits");
        assert_eq!(info.cursor, cursor_handle);
        assert_eq!(info.icon, icon_handle);
        assert_eq!(info.background, 6);
        assert_eq!(info.instance, MODULE);
        assert_eq!(info.menu_name, MenuName::None);
        // A class registered under the user32 module, looked up with a null module: the
        // instance answers null for a 4.0 caller.
        let mut wc_client = wnd_class();
        wc_client.instance = CLIENT_MODULE;
        let client_name = units("ClientFoo");
        register(registry, Name::Text(&client_name), &wc_client, compat40()).unwrap();
        let info = registry
            .get_class_info(Name::Text(&client_name), None, OWNER, true)
            .unwrap();
        assert_eq!(
            info.instance, 0,
            "the user32 module's classes answer a null instance"
        );
        // Pre-4.0: a class of the window manager's module answers the user32 module.
        let mut wc_sys = wnd_class();
        wc_sys.instance = WINDOW_MANAGER_MODULE;
        wc_sys.style = CS_GLOBALCLASS;
        let flags = RegisterFlags::default(); // pre-4.0
        register(registry, Name::Text(&units("Sys")), &wc_sys, flags).unwrap();
        let info = registry
            .get_class_info(Name::Text(&units("Sys")), None, OWNER, false)
            .unwrap();
        assert_eq!(info.instance, CLIENT_MODULE);
        // A server-registered CS_GLOBALCLASS class: the bit is masked out for a 4.0 caller.
        let mut wc_srv = wnd_class();
        wc_srv.style = CS_GLOBALCLASS | CS_HREDRAW;
        let flags = RegisterFlags {
            server_side_proc: true,
            server_class: true,
            win40_compat: true,
            ..RegisterFlags::default()
        };
        let atom = register(registry, Name::Text(&units("Srv")), &wc_srv, flags).unwrap();
        let info = registry
            .get_class_info(Name::Text(&units("Srv")), Some(MODULE), OWNER, true)
            .unwrap();
        assert_eq!(info.style & CS_GLOBALCLASS, 0);
        let info = registry
            .get_class_info(Name::Text(&units("Srv")), Some(MODULE), OWNER, false)
            .unwrap();
        assert_eq!(
            info.style & CS_GLOBALCLASS,
            CS_GLOBALCLASS,
            "pre-4.0 keeps it"
        );
        // A synthesized small icon is hidden as null.
        let mut wnd = window(registry.class_ptr(atom, OWNER, MODULE).unwrap());
        assert!(
            registry.reference_class(registry.class_ptr(atom, OWNER, MODULE).unwrap(), &mut wnd)
        );
        let srv = registry.class_ptr(atom, OWNER, MODULE).unwrap();
        let wnd = window(srv);
        let (_, other_handle) = make_cursor(registry);
        registry
            .set_class_long(
                &wnd,
                OWNER,
                GCLP_HICON,
                other_handle,
                MenuArg::None,
                None,
                &[],
                &mut |_, _| {},
            )
            .unwrap();
        let info = registry
            .get_class_info(Name::Text(&units("Srv")), Some(MODULE), OWNER, true)
            .unwrap();
        assert_eq!(info.icon_sm, 0, "the synthesized small icon is secret");
    }

    /// A process's end destroys its classes: the private list first, then the public one, and
    /// another process's classes are untouched.
    #[test]
    fn the_process_end_destroys_its_classes() {
        let registry = registry();
        let wc = wnd_class();
        register(registry, Name::Text(&units("A")), &wc, compat40()).unwrap();
        let mut wc_p = wnd_class();
        wc_p.style = CS_GLOBALCLASS;
        register(registry, Name::Text(&units("B")), &wc_p, compat40()).unwrap();
        let mut wc_other = wnd_class();
        wc_other.instance = OTHER_HIGH_WORD;
        let c = registry
            .register_class(
                &wc_other,
                Name::Text(&units("C")),
                MenuArg::None,
                OTHER_OWNER,
                compat40(),
                DESKTOP,
            )
            .unwrap();
        registry.destroy_owner_classes(OWNER);
        assert_eq!(registry.list_head(List::Private(OWNER)), None);
        assert_eq!(registry.list_head(List::Public(OWNER)), None);
        assert_eq!(registry.atoms.find(&units("A")), 0);
        assert_eq!(registry.atoms.find(&units("B")), 0);
        assert!(registry
            .classes
            .is_live(registry.class_ptr(c, OTHER_OWNER, OTHER_HIGH_WORD).unwrap()));
    }
}
