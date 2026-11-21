//! The I/O manager for the drivers NtLoadDriver loads: their DRIVER_OBJECTs, the DEVICE_OBJECTs
//! they make, the names both go by, the file objects a program's opens of a device make, and the
//! IRPs that carry each request to a driver's dispatch routines, in Windows 2000's layouts
//! ([`super::ntddk`]).
//!
//! # The names
//!
//! The object manager's part a legacy driver lives on is three directories: `\Driver`, where the
//! I/O manager names each driver after its service key (`\Driver\F2Kdrvload`), `\Device`, where a
//! driver names its devices (IoCreateDevice), and `\??`, the DOS devices, where it links a Win32
//! name to one (IoCreateSymbolicLink; `\DosDevices` is Windows 2000's link to `\??`, folded here
//! into it). [`Namespace`] keeps them: a name binds one object, compares without regard to case
//! (the I/O manager's names are OBJ_CASE_INSENSITIVE), and goes with it. A name in a directory that
//! does not exist is STATUS_OBJECT_PATH_NOT_FOUND, a name taken STATUS_OBJECT_NAME_COLLISION, as
//! `drvload`'s `names` capture shows. A program's open (`\\.\F2Kdrvload`, which ntdll makes
//! `\??\F2Kdrvload`) is resolved here first ([`Namespace::resolve`]): its links followed to a
//! device, what follows the device's name the open's file name; a name none of the three
//! directories holds is the file systems' (the boot volume's, the named pipes', the null
//! device's).
//!
//! # The objects
//!
//! A driver's structures are blocks of the I/O manager's arena (a [`KernelHeap`] over a static
//! pool, kernel memory every address space maps): its DRIVER_OBJECT with its DRIVER_EXTENSION, its
//! module record (DriverSection) and its strings in one block; each DEVICE_OBJECT with its
//! extension, its DEVOBJ_EXTENSION and, for a volume's type, its VPB in another; a FILE_OBJECT per
//! open; an IRP per request. The pointers a driver holds are their addresses. A device is
//! referenced by each open of it (DEVICE_OBJECT.ReferenceCount, counted before IRP_MJ_CREATE goes
//! down, as Windows 2000's IopParseDevice counts it); a device deleted while opened waits for its
//! last close (DOE_DELETE_PENDING).
//!
//! # The requests
//!
//! Every request is synchronous, in the caller's thread, at the passive level: the IRP is built
//! with one stack location per the device's StackSize, sent down (IoCallDriver's move to the next
//! location, the location's DeviceObject set, the driver's MajorFunction entry called), and
//! completed by the driver (IofCompleteRequest, which walks the locations back up, running their
//! completion routines: [`complete_request`]). The IRP's fields are Windows 2000's for each
//! request: the create's (IRP_CREATE_OPERATION, its security context, the options and the
//! disposition, the requestor's mode), the device control's (METHOD_BUFFERED's system buffer,
//! IRP_BUFFERED_IO, IRP_DEALLOCATE_BUFFER and IRP_INPUT_OPERATION), the cleanup's and the close's
//! (the kernel's own, IRP_CLOSE_OPERATION), the read's and the write's (IRP_READ_OPERATION,
//! IRP_WRITE_OPERATION, a DO_BUFFERED_IO device's system buffer, the caller's buffer as UserBuffer
//! for a device that asks for neither buffering), the flush's.
//!
//! A driver may leave a request pending (IoMarkIrpPending, STATUS_PENDING) and complete it later,
//! from another request's dispatch routine (the inverted call) or its cleanup; a completion
//! routine may keep an IRP (STATUS_MORE_PROCESSING_REQUIRED) and complete it again later. The IRP
//! is completed only once its walk passes the top ([`Progress`]); until then it and everything it
//! points to stay alive. Its sender waits for it, as Windows 2000's I/O manager waits for a
//! synchronous request, off the drivers' stacks: a create, a cleanup and a close in kernel mode (as
//! IopParseDevice and IopCloseFile wait), a read, a write, a device control and a flush in user
//! mode, which a termination interrupts. The IRP owns its system buffer until its sender takes it
//! back; a sender terminated while it waits leaves the IRP to its driver, and its completion
//! retires it, its buffer with it, while the open's close waits for it (the IRP holds its file
//! object). A request's status is then the IRP's, as a synchronous request's final status is.
//!
//! # The stacks and the locks
//!
//! The drivers' code runs on stacks of its own ([`on_driver_stack`]): a kernel stack leaves a
//! driver too little room once a system service's frames are on it. There are [`DRIVER_STACKS`]
//! of them, each one thread's from its entry to its return ([`Stacks`]); a driver's call back
//! into the I/O manager (an open of a device name, a close a completion leads to) runs on the
//! stack it is on, and a thread finding every stack taken waits for one. No lock is held across
//! a driver's call: the I/O manager's tables (the names, the drivers, the opens, a device's
//! references and its driver's device list) change in short steps at the high level, so a
//! dispatch routine that opens a device or waits for another thread's request does not stop the
//! machine's file opens, and other threads' requests run meanwhile. The load lock serializes the
//! loads and unloads alone, as Windows 2000's worker runs them one at a time.
//!
//! # The loads
//!
//! NtLoadDriver's work ([`load_driver`]): the service key opened, `\Driver\<key>` checked free
//! (STATUS_IMAGE_ALREADY_LOADED), the ImagePath's file read and mapped ([`super::loader`]), the
//! DRIVER_OBJECT made (every MajorFunction entry the I/O manager's own refusal,
//! STATUS_INVALID_DEVICE_REQUEST) and DriverEntry called with the RegistryPath, the key's name as
//! Windows 2000's object manager gives it. NtUnloadDriver's ([`unload_driver`]): DriverUnload
//! called, the driver's name and image gone. Windows 2000 runs both in a system worker thread,
//! in the System process: F2K runs them in the caller's thread, standing in for that worker while
//! they run (the System process is the current one, the previous mode the kernel's).
//!
//! An unload while a device of the driver is open is deferred, as Windows 2000 defers it: the
//! unload marks every device of the driver DOE_UNLOAD_PENDING and succeeds ([`check_unload`]);
//! from then on an open of one is STATUS_NO_SUCH_DEVICE ([`open_refusal`]) while the opens made
//! before go on being served; the last of the devices' references dropped (the last open's close)
//! runs DriverUnload ([`unload_due`]), in the closing thread standing in for the System process's
//! worker, and the driver's name goes with it, as the `drvload` capture's `unloadopen` block shows.
//! A device deleted while open stays on its driver's list until its last close
//! ([`delete_device`]): its reference holds the unload, and its driver object and image stay
//! while it does. A deferred unload runs under the load lock, once, and only for a driver still
//! loaded.
//!
//! # What a driver sees of threads and processes
//!
//! F2K's threads and processes are not KTHREADs and EPROCESSes: a driver is handed a stand-in for
//! each (KeGetCurrentThread, IoGetCurrentProcess, PsInitialSystemProcess), a zeroed block of the
//! structure's size, one per thread record and per process record, and one for the System
//! process. They compare as the real ones do (the thread an IRP came in is the current thread,
//! the process the caller's); their fields read zero.
//!
//! Recorded seams: every request is waited for, an overlapped file object's too (Windows 2000
//! returns STATUS_PENDING to an asynchronous one, and completes it through an APC to its thread);
//! no IRP is cancelled (IoCancelIrp, a terminated thread's IoCancelThreadIo); a request a driver
//! sends from inside another driver call (a nested close, say) and leaves pending is waited for on
//! the stack it is on (the thread's other calls wait for it); only METHOD_BUFFERED device controls
//! are served, and no DO_DIRECT_IO read or write (no MDL); a driver whose DriverEntry fails or
//! whose unload leaves devices behind keeps its image mapped.

use core::mem::size_of;

use super::ntddk::{
    IoStackLocation,
    Irp,
    DOE_DELETE_PENDING,
    DOE_UNLOAD_PENDING,
    DO_DEVICE_INITIALIZING,
    DO_EXCLUSIVE,
    DRVO_UNLOAD_INVOKED,
    SL_INVOKE_ON_CANCEL,
    SL_INVOKE_ON_ERROR,
    SL_INVOKE_ON_SUCCESS,
    SL_PENDING_RETURNED,
};
use crate::cm::same_name;
use crate::status::*;

// --- The names ---------------------------------------------------------------------------------

/// The longest object name the I/O manager keeps, in units.
pub const MAX_NAME: usize = 128;

/// How many names the I/O manager's directories hold at once (drivers, devices, links).
pub const NAMES: usize = 64;

/// How many links a name is followed through before the open gives up.
const MAX_HOPS: usize = 8;

const SEPARATOR: u16 = b'\\' as u16;

/// An object's full name, `\`-rooted, at most [`MAX_NAME`] units.
#[derive(Clone, Copy)]
pub struct ObName {
    units: [u16; MAX_NAME],
    length: u16,
}

impl ObName {
    /// The empty name.
    pub const EMPTY: ObName = ObName {
        units: [0; MAX_NAME],
        length: 0,
    };

    /// A name of these units; none past [`MAX_NAME`].
    pub fn of(units: &[u16]) -> Option<ObName> {
        let mut name = ObName::EMPTY;
        name.units.get_mut(..units.len())?.copy_from_slice(units);
        name.length = units.len() as u16;
        Some(name)
    }

    /// Its units.
    pub fn units(&self) -> &[u16] {
        &self.units[..usize::from(self.length)]
    }

    /// `parts` joined, none past [`MAX_NAME`].
    fn joined(parts: &[&[u16]]) -> Option<ObName> {
        let mut name = ObName::EMPTY;
        for part in parts {
            let at = usize::from(name.length);
            name.units
                .get_mut(at..at + part.len())?
                .copy_from_slice(part);
            name.length += part.len() as u16;
        }
        Some(name)
    }
}

/// What a name binds: a device (its DEVICE_OBJECT's address), a driver (its slot), or a link (its
/// target, as given).
// Kept in the namespace's slots by value: a link's target is the large one.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy)]
pub enum Entry {
    Device(u32),
    Driver(u16),
    Link(ObName),
}

/// Whether `units` begin with `prefix` (ASCII, case-insensitively).
fn starts_with(units: &[u16], prefix: &str) -> bool {
    units.len() >= prefix.len()
        && units
            .iter()
            .zip(prefix.bytes())
            .all(|(&unit, byte)| unit < 0x80 && (unit as u8).eq_ignore_ascii_case(&byte))
}

/// The ASCII text as units, into `out`: its length.
fn ascii(text: &str, out: &mut [u16]) -> usize {
    for (slot, byte) in out.iter_mut().zip(text.bytes()) {
        *slot = u16::from(byte);
    }
    text.len()
}

/// The directories the I/O manager's names live in: the root's, `\Device`, `\Driver`, `\??` and
/// `\FileSystem`.
const DIRECTORIES: [&str; 5] = ["", "\\Device", "\\Driver", "\\??", "\\FileSystem"];

/// Whether `units` name one of the [`DIRECTORIES`].
fn is_directory(units: &[u16]) -> bool {
    DIRECTORIES
        .iter()
        .any(|directory| units.len() == directory.len() && starts_with(units, directory))
}

/// A name as the I/O manager keeps it: `\`-rooted (STATUS_OBJECT_PATH_SYNTAX_BAD otherwise),
/// `\DosDevices` folded into `\??`, no empty component (STATUS_OBJECT_NAME_INVALID), at most
/// [`MAX_NAME`] units (STATUS_OBJECT_NAME_INVALID).
pub fn normalize(units: &[u16]) -> Result<ObName, NtStatus> {
    if units.first() != Some(&SEPARATOR) {
        return Err(STATUS_OBJECT_PATH_SYNTAX_BAD);
    }
    const DOS_DEVICES: &str = "\\DosDevices";
    let folded = if starts_with(units, DOS_DEVICES)
        && matches!(units.get(DOS_DEVICES.len()), None | Some(&SEPARATOR))
    {
        let mut prefix = [0u16; 3];
        ascii("\\??", &mut prefix);
        ObName::joined(&[&prefix, &units[DOS_DEVICES.len()..]])
    } else {
        ObName::of(units)
    }
    .ok_or(STATUS_OBJECT_NAME_INVALID)?;
    if folded.units()[1..]
        .split(|&unit| unit == SEPARATOR)
        .any(<[u16]>::is_empty)
        && folded.length > 1
    {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    Ok(folded)
}

/// A name split at its last separator: its directory and its own name.
fn split(name: &[u16]) -> (&[u16], &[u16]) {
    let at = name
        .iter()
        .rposition(|&unit| unit == SEPARATOR)
        .unwrap_or(0);
    (&name[..at], &name[at + 1..])
}

/// What an open's name resolves to: the device, and the rest of the name after the device's (the
/// file object's FileName; empty for the device itself).
#[derive(Clone, Copy)]
pub struct Resolved {
    pub device: u32,
    pub rest: ObName,
}

/// The I/O manager's directories: every name a driver, a device or a link goes by.
pub struct Namespace {
    slots: [Option<(ObName, Entry)>; NAMES],
}

impl Namespace {
    pub const fn new() -> Self {
        Namespace {
            slots: [None; NAMES],
        }
    }

    /// The slot holding `name`, exactly (without regard to case).
    fn find(&self, name: &[u16]) -> Option<usize> {
        self.slots.iter().position(|slot| {
            slot.as_ref()
                .is_some_and(|(held, _)| same_name(held.units(), name))
        })
    }

    /// What `name` binds.
    pub fn get(&self, name: &ObName) -> Option<Entry> {
        self.find(name.units())
            .and_then(|slot| self.slots[slot].map(|(_, entry)| entry))
    }

    /// Bind `name` to `entry`: its directory must be one of the I/O manager's
    /// (STATUS_OBJECT_PATH_NOT_FOUND), the name free (STATUS_OBJECT_NAME_COLLISION; a directory's
    /// own name is taken), a slot free (STATUS_INSUFFICIENT_RESOURCES).
    pub fn insert(&mut self, name: &ObName, entry: Entry) -> Result<(), NtStatus> {
        let (directory, own) = split(name.units());
        if !is_directory(directory) {
            return Err(STATUS_OBJECT_PATH_NOT_FOUND);
        }
        if own.is_empty() {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        if self.find(name.units()).is_some() || is_directory(name.units()) {
            return Err(STATUS_OBJECT_NAME_COLLISION);
        }
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        *slot = Some((*name, entry));
        Ok(())
    }

    /// How many names are bound.
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_some()).count()
    }

    /// Unbind `name`: what it bound, none when it bound nothing.
    pub fn remove(&mut self, name: &ObName) -> Option<Entry> {
        let slot = self.find(name.units())?;
        self.slots[slot].take().map(|(_, entry)| entry)
    }

    /// Unbind the device at `device`, whatever its name.
    pub fn remove_device(&mut self, device: u32) {
        for slot in &mut self.slots {
            if matches!(slot, Some((_, Entry::Device(held))) if *held == device) {
                *slot = None;
            }
        }
    }

    /// The name holding the longest leading part of `name` that ends at a separator or the end,
    /// with what it binds and the rest of `name` after it.
    fn longest(&self, name: &[u16]) -> Option<(Entry, usize)> {
        self.slots
            .iter()
            .flatten()
            .filter(|(held, _)| {
                let held = held.units();
                held.len() <= name.len()
                    && same_name(held, &name[..held.len()])
                    && matches!(name.get(held.len()), None | Some(&SEPARATOR))
            })
            .max_by_key(|(held, _)| held.length)
            .map(|(held, entry)| (*entry, usize::from(held.length)))
    }

    /// What an open of `units` reaches: none when no name of the I/O manager's leads it anywhere
    /// (the file systems' names); else the device, its links followed (at most [`MAX_HOPS`]), and
    /// the rest of the name after the device's. A link to a name nothing holds is
    /// STATUS_OBJECT_NAME_NOT_FOUND (STATUS_OBJECT_PATH_NOT_FOUND when more follows a missing
    /// directory), a driver's name STATUS_OBJECT_TYPE_MISMATCH.
    pub fn resolve(&self, units: &[u16]) -> Option<Result<Resolved, NtStatus>> {
        let mut name = normalize(units).ok()?;
        for hop in 0..MAX_HOPS {
            let Some((entry, length)) = self.longest(name.units()) else {
                if hop == 0 {
                    return None;
                }
                let (directory, _) = split(name.units());
                return Some(Err(if is_directory(directory) {
                    STATUS_OBJECT_NAME_NOT_FOUND
                } else {
                    STATUS_OBJECT_PATH_NOT_FOUND
                }));
            };
            let rest = &name.units()[length..];
            match entry {
                Entry::Device(device) => {
                    return Some(Ok(Resolved {
                        device,
                        rest: ObName::of(rest).expect("a part of a name"),
                    }))
                }
                Entry::Driver(_) => return Some(Err(STATUS_OBJECT_TYPE_MISMATCH)),
                Entry::Link(target) => {
                    let joined = ObName::joined(&[target.units(), rest]);
                    name = match joined.map(|joined| normalize(joined.units())) {
                        Some(Ok(next)) => next,
                        _ => return Some(Err(STATUS_OBJECT_NAME_INVALID)),
                    };
                }
            }
        }
        Some(Err(STATUS_OBJECT_NAME_NOT_FOUND))
    }
}

impl Default for Namespace {
    fn default() -> Self {
        Self::new()
    }
}

// --- The file objects' handles ------------------------------------------------------------------

/// An open of a device, as the file object's context names it ([`crate::fs::file::Context`]): the
/// I/O manager's record of its FILE_OBJECT, and the record's generation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DeviceFile {
    index: u16,
    generation: u16,
}

/// NT_ERROR: a status of the error severity.
pub fn nt_error(status: NtStatus) -> bool {
    status.0 >> 30 == 3
}

/// A request's text for _vsnprintf: `text` into `out`, as the C runtime places it: all of it and
/// a NUL when that fits (its length), all of it without the NUL when it fills `out` exactly (its
/// length), as much as fits when it does not (-1).
pub fn place(out: &mut [u8], text: &[u8]) -> i32 {
    let n = text.len().min(out.len());
    out[..n].copy_from_slice(&text[..n]);
    if text.len() < out.len() {
        out[text.len()] = 0;
        text.len() as i32
    } else if text.len() == out.len() {
        text.len() as i32
    } else {
        -1
    }
}

/// The name Windows 2000's object manager gives a service key the caller named, its components
/// as `stored` spells each (the registry keeps its keys' spellings), the hive roots upper-case
/// (`\REGISTRY\MACHINE\SYSTEM`), and the current control set as the set it links to
/// (`ControlSet001`): F2K's registry has the one, CurrentControlSet, with no link. None when `out`
/// has no room: no component is cut short. (The I/O manager builds the name a component at a time,
/// [`push_object_component`]; this whole-name form is the tests'.)
#[cfg_attr(not(test), allow(dead_code))]
pub fn registry_object_name(stored: &[&[u16]], out: &mut [u16]) -> Option<usize> {
    let mut length = 0;
    for (index, component) in stored.iter().enumerate() {
        push_object_component(index, component, out, &mut length)?;
    }
    Some(length)
}

/// The component at `index` of a service key's object name (see [`registry_object_name`]),
/// after a separator, onto `out` at `*length`, which moves past it. None when `out` has no room.
pub fn push_object_component(
    index: usize,
    component: &[u16],
    out: &mut [u16],
    length: &mut usize,
) -> Option<()> {
    let mut push = |units: &[u16]| -> Option<core::ops::Range<usize>> {
        let at = *length;
        out.get_mut(at..at + units.len())?.copy_from_slice(units);
        *length += units.len();
        Some(at..*length)
    };
    push(&[SEPARATOR])?;
    if index == 3 && same_name(component, &CURRENT_CONTROL_SET.map(u16::from)) {
        push(&CONTROL_SET_001.map(u16::from))?;
        return Some(());
    }
    let pushed = push(component)?;
    if index < 3 {
        for unit in &mut out[pushed] {
            *unit = rtl::path::upcase(*unit);
        }
    }
    Some(())
}

/// The current control set's key name.
const CURRENT_CONTROL_SET: [u8; 17] = *b"CurrentControlSet";

/// The control set Windows 2000's CurrentControlSet links to, as a RegistryPath names it.
const CONTROL_SET_001: [u8; 13] = *b"ControlSet001";

/// A registry path below `\Registry` as F2K's registry holds it: the control set's linked name,
/// `MACHINE\SYSTEM\ControlSet001`, read as the one F2K has, CurrentControlSet (the inverse of
/// [`registry_object_name`]). Into `out`: its length.
pub fn registry_path_below_root(units: &[u16], out: &mut [u16]) -> Option<usize> {
    let mut length = 0;
    for (index, component) in units.split(|&unit| unit == SEPARATOR).enumerate() {
        if index > 0 {
            *out.get_mut(length)? = SEPARATOR;
            length += 1;
        }
        let control_set = CURRENT_CONTROL_SET.map(u16::from);
        let shown: &[u16] = if index == 2 && same_name(component, &CONTROL_SET_001.map(u16::from)) {
            &control_set
        } else {
            component
        };
        out.get_mut(length..length + shown.len())?
            .copy_from_slice(shown);
        length += shown.len();
    }
    Some(length)
}

/// A synchronous device file's CurrentByteOffset after a transfer at `offset` that moved
/// `information` bytes: a LARGE_INTEGER sum, as the platform's, which wraps (the offset may be a
/// write's FILE_WRITE_TO_END_OF_FILE, or whatever the driver left in the object) and never
/// overflows.
pub fn position_after(offset: u64, information: u32) -> u64 {
    offset.wrapping_add(u64::from(information))
}

// --- The unload's states -----------------------------------------------------------------------

/// A device as an unload weighs it: its ReferenceCount (the opens holding it), whether a device is
/// attached above it, and its DEVOBJ_EXTENSION's ExtensionFlags.
pub struct UnloadWeight<'a> {
    pub references: i32,
    pub attached: bool,
    pub extension_flags: &'a mut u32,
}

/// NtUnloadDriver's check (Windows 2000's IopCheckUnloadDriver), over a driver's flags and its
/// devices: STATUS_INVALID_DEVICE_REQUEST for a driver without an unload routine, or whose unload
/// already ran; else every device marked DOE_UNLOAD_PENDING (the opens it refuses from now on, see
/// [`open_refusal`]), and whether the unload runs now: no device referenced or attached to, the
/// driver marked DRVO_UNLOAD_INVOKED. When it does not, the last of the devices' references runs
/// it ([`unload_due`]); NtUnloadDriver succeeds either way.
pub fn check_unload<'a>(
    driver_flags: &mut u32,
    has_unload: bool,
    devices: impl IntoIterator<Item = UnloadWeight<'a>>,
) -> Result<bool, NtStatus> {
    if !has_unload || *driver_flags & DRVO_UNLOAD_INVOKED != 0 {
        return Err(STATUS_INVALID_DEVICE_REQUEST);
    }
    let mut now = true;
    for device in devices {
        *device.extension_flags |= DOE_UNLOAD_PENDING;
        if device.references != 0 || device.attached {
            now = false;
        }
    }
    if now {
        *driver_flags |= DRVO_UNLOAD_INVOKED;
    }
    Ok(now)
}

/// Whether a device's last reference gone runs its driver's pending unload (Windows 2000's
/// IopCompleteUnloadOrDelete): every device of the driver unreferenced, attached to by none, and
/// marked DOE_UNLOAD_PENDING, and the unload not run yet; the driver then marked
/// DRVO_UNLOAD_INVOKED, so that it runs once.
pub fn unload_due<'a>(
    driver_flags: &mut u32,
    devices: impl IntoIterator<Item = UnloadWeight<'a>>,
) -> bool {
    if *driver_flags & DRVO_UNLOAD_INVOKED != 0 {
        return false;
    }
    let due = devices.into_iter().all(|device| {
        device.references == 0
            && !device.attached
            && *device.extension_flags & DOE_UNLOAD_PENDING != 0
    });
    if due {
        *driver_flags |= DRVO_UNLOAD_INVOKED;
    }
    due
}

/// An open's refusal by the device's state (Windows 2000's IopParseDevice): a device still
/// initializing, or whose driver's unload or whose own delete is pending, is
/// STATUS_NO_SUCH_DEVICE (ERROR_FILE_NOT_FOUND, as the `drvload` capture's `unloadopen` block
/// shows); an exclusive device already open STATUS_ACCESS_DENIED.
pub fn open_refusal(device_flags: u32, references: i32, extension_flags: u32) -> Option<NtStatus> {
    if device_flags & DO_DEVICE_INITIALIZING != 0
        || extension_flags & (DOE_UNLOAD_PENDING | DOE_DELETE_PENDING) != 0
    {
        return Some(STATUS_NO_SUCH_DEVICE);
    }
    if device_flags & DO_EXCLUSIVE != 0 && references > 0 {
        return Some(STATUS_ACCESS_DENIED);
    }
    None
}

// --- The drivers' stacks -----------------------------------------------------------------------

/// How many stacks the drivers' code runs on: as many threads at once in the I/O manager's
/// requests, a load or an unload among them.
pub const DRIVER_STACKS: usize = 4;

/// What a thread's claim on the drivers' stacks got.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Claim {
    /// The thread runs on this stack already: a driver's call back into the I/O manager (an
    /// open of a device name, a close) goes on where it is.
    Running(usize),
    /// This stack, free, is the thread's now.
    Took(usize),
    /// Every stack is another thread's: the thread waits for one to be given up.
    Busy,
}

/// Which thread runs on each of the drivers' stacks: its record's index plus one, 0 for a free
/// stack. A thread holds one stack at most, from its first entry into the I/O manager's calls to
/// its return from it; its nested calls run on it.
pub struct Stacks {
    owners: [u32; DRIVER_STACKS],
}

impl Stacks {
    pub const fn new() -> Self {
        Stacks {
            owners: [0; DRIVER_STACKS],
        }
    }

    /// `thread`'s claim (see [`Claim`]).
    pub fn claim(&mut self, thread: u32) -> Claim {
        if let Some(index) = self.owners.iter().position(|&owner| owner == thread) {
            return Claim::Running(index);
        }
        match self.owners.iter().position(|&owner| owner == 0) {
            Some(index) => {
                self.owners[index] = thread;
                Claim::Took(index)
            }
            None => Claim::Busy,
        }
    }

    /// Whether `thread` runs on one of the stacks.
    pub fn runs(&self, thread: u32) -> bool {
        self.owners.contains(&thread)
    }

    /// The stack at `index` given up by the thread that took it.
    pub fn give_up(&mut self, index: usize) {
        self.owners[index] = 0;
    }
}

impl Default for Stacks {
    fn default() -> Self {
        Self::new()
    }
}

// --- The requests' lives -----------------------------------------------------------------------

/// Where a request's IRP is in its life, as the I/O manager keeps it beside the IRP (Windows 2000
/// reads the same from the IRP's PendingReturned, its Tail.Overlay.Thread and the file object's
/// event).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Progress {
    /// Sent down, not completed yet: in its dispatch routine, or held pending by its driver.
    Sent,
    /// Its sender waits for its completion: the dispatch routine left it pending.
    Awaited,
    /// Its sender is gone (a termination ended the wait): its completion retires it, its buffers
    /// with it, as Windows 2000's completion of an IRP its thread left behind does.
    Orphaned,
    /// Completed: its locations walked back up, no completion routine keeping it. Its sender takes
    /// the outcome and gives it back.
    Completed,
}

/// What a request came back with: the status its sender reports (the dispatch routine's, or the
/// IRP's once its sender waited for it), and the IRP's I/O status.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Outcome {
    pub returned: NtStatus,
    pub status: NtStatus,
    pub information: u32,
}

/// What a dispatch routine left: its status, and whether the IRP came back completed (else its
/// driver holds it, pending, or a completion routine kept it).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Dispatched {
    pub returned: NtStatus,
    pub completed: bool,
}

/// What the requests' lives reach through: the IRPs' memory, the drivers' routines, and their
/// senders' waits (the kernel's own on target; a test's fakes on the host).
pub trait Packets {
    /// The IRP at `irp`.
    fn irp(&mut self, irp: u32) -> &mut Irp;
    /// Its stack location `number` (1 to its StackCount; the IRP's CurrentLocation names one).
    fn location(&mut self, irp: u32, number: i8) -> &mut IoStackLocation;
    /// Its progress changed by `change` at once, no completion between the read and the write:
    /// the progress it had.
    fn transition(&mut self, irp: u32, change: fn(Progress) -> Progress) -> Progress;
    /// The dispatch routine at `entry` called: DriverDispatch(DeviceObject, Irp).
    fn dispatch(&mut self, entry: u32, device: u32, irp: u32) -> NtStatus;
    /// The completion routine at `routine` called: IoCompletion(DeviceObject, Irp, Context).
    fn completion(&mut self, routine: u32, device: u32, irp: u32, context: u32) -> NtStatus;
    /// Its waiting sender woken: the IRP completed.
    fn wake(&mut self, irp: u32);
    /// An orphaned IRP's end: its block and what it holds given back.
    fn retire(&mut self, irp: u32);
}

/// IoCallDriver: the IRP moved down to its next stack location, which names `device`, and handed
/// to the dispatch routine at `entry`. The IRP came back completed when its progress says so,
/// whatever the routine returned: a driver that left it pending, or a completion routine that kept
/// it (STATUS_MORE_PROCESSING_REQUIRED), holds it until it completes it.
pub fn call<P: Packets>(packets: &mut P, irp: u32, device: u32, entry: u32) -> Dispatched {
    let packet = packets.irp(irp);
    packet.current_location -= 1;
    packet.current_stack_location = packet
        .current_stack_location
        .wrapping_sub(size_of::<IoStackLocation>() as u32);
    let number = packet.current_location;
    packets.location(irp, number).device_object = device;
    let returned = packets.dispatch(entry, device, irp);
    let completed = packets.transition(irp, |progress| progress) == Progress::Completed;
    Dispatched {
        returned,
        completed,
    }
}

/// IofCompleteRequest's work (Windows 2000's IopfCompleteRequest): the IRP's locations walked back
/// up from the current one, each one's PendingReturned carried up, its completion routine run when
/// its Control asks for it (on success, on an error or a warning, on a cancel); a routine's
/// STATUS_MORE_PROCESSING_REQUIRED stops the walk, the IRP the routine's to complete again. Past
/// the top, the IRP is completed: its waiting sender woken, an orphan retired.
pub fn complete_request<P: Packets>(packets: &mut P, irp: u32) {
    loop {
        let packet = packets.irp(irp);
        let (number, stack_count) = (packet.current_location, packet.stack_count);
        if number > stack_count {
            break;
        }
        let location = *packets.location(irp, number);
        let packet = packets.irp(irp);
        packet.current_location += 1;
        packet.current_stack_location = packet
            .current_stack_location
            .wrapping_add(size_of::<IoStackLocation>() as u32);
        let pending = location.control & SL_PENDING_RETURNED != 0;
        packet.pending_returned = u8::from(pending);
        let success = NtStatus(packet.io_status_status as u32).is_success();
        let wanted = if success {
            SL_INVOKE_ON_SUCCESS
        } else {
            SL_INVOKE_ON_ERROR
        } | if packet.cancel != 0 {
            SL_INVOKE_ON_CANCEL
        } else {
            0
        };
        let above = number + 1;
        if location.completion_routine != 0 && location.control & wanted != 0 {
            let upper = if above <= stack_count {
                packets.location(irp, above).device_object
            } else {
                0
            };
            let status =
                packets.completion(location.completion_routine, upper, irp, location.context);
            if status == STATUS_MORE_PROCESSING_REQUIRED {
                return;
            }
        } else if pending && above <= stack_count {
            // IoMarkIrpPending for the location above, which has no routine to do it.
            packets.location(irp, above).control |= SL_PENDING_RETURNED;
        }
    }
    let before = packets.transition(irp, |progress| match progress {
        Progress::Sent | Progress::Awaited => Progress::Completed,
        other => other,
    });
    match before {
        Progress::Awaited => packets.wake(irp),
        Progress::Orphaned => packets.retire(irp),
        // Completed inside its dispatch (its sender reads it on the dispatch's return), or by a
        // routine that kept it and completes it again past the top.
        Progress::Sent | Progress::Completed => {}
    }
}

/// The sender's wait begins: true when the IRP completed already (no wait), else it is marked
/// awaited, and its completion wakes the sender.
pub fn await_completion<P: Packets>(packets: &mut P, irp: u32) -> bool {
    let before = packets.transition(irp, |progress| match progress {
        Progress::Sent => Progress::Awaited,
        other => other,
    });
    before == Progress::Completed
}

/// The sender's wait ended without the completion (a termination): true when the IRP is left to
/// its completion, orphaned; false when it completed meanwhile, the sender's to take back.
pub fn abandon<P: Packets>(packets: &mut P, irp: u32) -> bool {
    let before = packets.transition(irp, |progress| match progress {
        Progress::Awaited => Progress::Orphaned,
        other => other,
    });
    before != Progress::Completed
}

/// A completed IRP's outcome, as its sender reports it: the dispatch routine's status when the
/// routine returned the IRP completed; the IRP's own when it was left pending and its sender
/// waited (a synchronous request's status is then its final one, as Windows 2000's
/// IopSynchronousServiceTail reads it from the file object).
pub fn outcome<P: Packets>(packets: &mut P, irp: u32, dispatched: Dispatched) -> Outcome {
    let packet = packets.irp(irp);
    let status = NtStatus(packet.io_status_status as u32);
    Outcome {
        returned: if dispatched.completed && dispatched.returned != STATUS_PENDING {
            dispatched.returned
        } else {
            status
        },
        status,
        information: packet.io_status_information,
    }
}

// --- On target: the I/O manager's state, its objects, its requests ------------------------------

#[cfg(target_arch = "x86")]
pub use target::*;

#[cfg(target_arch = "x86")]
mod target {
    use core::alloc::Layout;
    use core::cell::UnsafeCell;
    use core::mem::size_of;
    use core::ptr::NonNull;
    use core::sync::atomic::{AtomicU32, Ordering};

    use super::super::loader::{self, LoadError, MappedImage};
    use super::super::ntddk::*;
    use super::*;
    use crate::block::lock::DeviceLock;
    use crate::cm::{with_registry, Key};
    use crate::level::{self, High, LevelCell};
    use crate::mem::heap::KernelHeap;
    use crate::mem::pool::Block;
    use crate::sched::event::{Event, EventKind, EVENT_WAKE_INCREMENT};
    use crate::sched::wait::{WaitMode, WaitReason, WaitableId};
    use crate::sync::StaticBuf;

    /// The arena's size: every driver's, device's, file object's and IRP's block.
    const ARENA: usize = 256 * 1024;
    /// How many drivers can be loaded at once.
    const DRIVERS: usize = 16;
    /// How many device opens can exist at once.
    const FILES: usize = 64;

    /// A loaded driver: its block (the DRIVER_OBJECT at its start), its image, and its name.
    #[derive(Clone, Copy)]
    struct DriverSlot {
        object: u32,
        image: MappedImage,
        name: ObName,
    }

    /// An open of a device: its FILE_OBJECT and the device, how many of its requests are in
    /// their driver's hands, and whether its close waits for them.
    #[derive(Clone, Copy)]
    struct FileSlot {
        live: bool,
        generation: u16,
        file_object: u32,
        device: u32,
        in_flight: u16,
        closing: bool,
    }

    struct IoManager {
        heap: Option<KernelHeap>,
        names: Namespace,
        drivers: [Option<DriverSlot>; DRIVERS],
        files: [FileSlot; FILES],
        stacks: Stacks,
    }

    /// The I/O manager's state, at the high level as the registry's is: each use is a short
    /// table operation, never a driver's call.
    static IO: LevelCell<High, IoManager> = LevelCell::new(IoManager {
        heap: None,
        names: Namespace::new(),
        drivers: [None; DRIVERS],
        files: [FileSlot {
            live: false,
            generation: 0,
            file_object: 0,
            device: 0,
            in_flight: 0,
            closing: false,
        }; FILES],
        stacks: Stacks::new(),
    });

    fn with_io<R>(step: impl FnOnce(&mut IoManager) -> R) -> R {
        level::raised::<High, _>(|high| {
            let io = IO.get(high);
            let result = step(io);
            NAMED.store(io.names.len() as u32, Ordering::Release);
            result
        })
    }

    /// How many names the I/O manager's directories bind, as its last use left them: read with no
    /// lock by every file open, which asks the I/O manager only when a driver named something.
    static NAMED: AtomicU32 = AtomicU32::new(0);

    #[repr(C, align(8))]
    struct ArenaPool([u8; ARENA]);
    static ARENA_POOL: StaticBuf<ArenaPool> = StaticBuf::new(ArenaPool([0; ARENA]));

    /// The load lock: one load or unload at a time (its DriverEntry or its DriverUnload run as the
    /// System process's worker), as Windows 2000 runs them in its worker. Neither a request nor an
    /// open takes it; a driver's code holds no other lock of the I/O manager's.
    static LOAD_LOCK: DeviceLock<()> = DeviceLock::new(());

    /// The thread holding the load lock: its thread record's index plus one, 0 for none.
    static LOADER: AtomicU32 = AtomicU32::new(0);

    /// Run `body` holding the load lock (inside a critical region); at once when the running
    /// thread holds it already (an unload a load's own call would lead to).
    fn serialized<R>(body: impl FnOnce() -> R) -> R {
        let me = u32::from(crate::sched::current_thread().index()) + 1;
        if LOADER.load(Ordering::Acquire) == me {
            return body();
        }
        crate::process::threads::critical_region(|| {
            LOAD_LOCK.with(|_| {
                LOADER.store(me, Ordering::Release);
                let result = body();
                LOADER.store(0, Ordering::Release);
                result
            })
        })
    }

    /// A stack the I/O manager runs its requests and the drivers' code on: a kernel stack is
    /// 32 KiB, and a system service's own frames (the kernel is built unoptimized) leave a driver
    /// too little of it, where Windows 2000 gives one 12 KiB of its own. 64 KiB, kernel memory.
    const DRIVER_STACK: usize = 64 * 1024;

    #[repr(C, align(16))]
    struct DriverStack([u8; DRIVER_STACK]);

    // The drivers' stacks: each reached only by the thread [`Stacks`] gives it to.
    static mut STACKS: [DriverStack; DRIVER_STACKS] =
        [const { DriverStack([0; DRIVER_STACK]) }; DRIVER_STACKS];

    /// The event a thread waiting for a free stack waits on, set as each is given up.
    // An event embedded in a static: named by its header's address (`WaitableId::Embedded`), and
    // reached only through the dispatcher once named.
    struct StackFreed(UnsafeCell<Event>);

    // SAFETY: one processor. The event is touched directly once, by `init` at boot, before any
    // driver's call; from then on only the dispatcher reaches its header, by its address,
    // serialized at the dispatch level.
    unsafe impl Sync for StackFreed {}

    static FREED: StackFreed = StackFreed(UnsafeCell::new(Event::new(
        EventKind::Synchronization,
        false,
    )));

    impl StackFreed {
        /// The event's name: its header's address. No reference to the event is formed.
        fn id(&self) -> WaitableId {
            // SAFETY: a projection inside the static's own cell: it computes the header's address
            // and reads nothing.
            let header = unsafe { core::ptr::addr_of_mut!((*self.0.get()).waitable) };
            WaitableId::Embedded(NonNull::new(header).expect("a static is not null"))
        }
    }

    /// Run `body` on a drivers' stack of the running thread's own (inside a critical region: a
    /// termination waits for the call to finish), waiting while every stack is another thread's;
    /// at once when the running thread is on one already (a driver's call back into the I/O
    /// manager). No lock is held across the call: other threads' requests and opens run on the
    /// other stacks meanwhile, and a request a driver holds pending is waited for off the stack.
    pub fn on_driver_stack<R>(body: impl FnOnce() -> R) -> R {
        let me = u32::from(crate::sched::current_thread().index()) + 1;
        if with_io(|io| io.stacks.runs(me)) {
            return body();
        }
        crate::process::threads::critical_region(|| {
            let index = loop {
                match with_io(|io| io.stacks.claim(me)) {
                    Claim::Took(index) | Claim::Running(index) => break index,
                    Claim::Busy => {
                        crate::sched::wait::wait_current_for(
                            FREED.id(),
                            WaitReason::Executive,
                            None,
                        );
                    }
                }
            };
            let mut result = None;
            let mut call = Some(|| result = Some(body()));
            // SAFETY: the stacks' addresses, computed without a reference.
            let top = unsafe { (&raw const STACKS[index]) as u32 } + DRIVER_STACK as u32;
            // SAFETY: the stack is this thread's alone until it gives it up; the trampoline runs
            // `call` there and returns to this one.
            unsafe { switch_and_call(top, trampoline_of(&call), (&raw mut call).cast()) };
            with_io(|io| io.stacks.give_up(index));
            level::raised::<crate::level::Dispatch, _>(|dispatch| {
                crate::sched::DISPATCHER
                    .get(dispatch)
                    .set_event(FREED.id(), 0)
            });
            result.expect("the body ran")
        })
    }

    /// The trampoline for a closure of type `F`: `context` is its `Option<F>`, taken and called.
    fn trampoline_of<F: FnOnce()>(_: &Option<F>) -> extern "C" fn(*mut u8) {
        extern "C" fn trampoline<F: FnOnce()>(context: *mut u8) {
            // SAFETY: `on_driver_stack`'s Option<F>, alive across the call.
            let call = unsafe { &mut *context.cast::<Option<F>>() };
            (call.take().expect("called once"))();
        }
        trampoline::<F>
    }

    /// Call `function(context)` with the stack pointer at `top` (16-byte aligned at the call),
    /// and come back to the caller's stack.
    ///
    /// # Safety
    ///
    /// `top` is the top of a stack no one else uses meanwhile, large enough for the call.
    unsafe fn switch_and_call(top: u32, function: extern "C" fn(*mut u8), context: *mut u8) {
        // SAFETY: the caller's contract; the old stack pointer is kept on the new stack and
        // restored once the call returns, every caller-saved register given up to the call.
        unsafe {
            core::arch::asm!(
                "mov edx, esp",
                "mov esp, edi",
                "sub esp, 8",
                "push edx",
                "push ecx",
                "call eax",
                "add esp, 4",
                "pop esp",
                in("edi") top,
                in("eax") function,
                in("ecx") context,
                clobber_abi("C"),
            );
        }
    }

    /// The thread standing in for Windows 2000's system worker while a load or an unload runs a
    /// driver's code: its thread record's index plus one, 0 for none.
    static WORKER: AtomicU32 = AtomicU32::new(0);

    /// Start the I/O manager: its arena, its load lock and its stacks' event. Once, at boot.
    pub fn init() {
        let pool = &mut ARENA_POOL.take().0;
        with_io(|io| io.heap = Some(KernelHeap::new(pool)));
        LOAD_LOCK.init();
        {
            let _masked = crate::pcr::pcr().mask_guard();
            // SAFETY: the one direct reach into the event (see the `Sync` impl): nothing waits on
            // it or sets it yet, and interrupts are masked for the reference's life.
            unsafe { (*FREED.0.get()).init() };
        }
    }

    // --- Memory ---------------------------------------------------------------------------------

    /// A zeroed block of the arena: its address.
    fn allocate(bytes: usize) -> Option<u32> {
        let layout = Layout::from_size_align(bytes.max(8), 8).ok()?;
        let at = with_io(|io| {
            io.heap
                .as_mut()
                .expect("the I/O manager is started")
                .alloc(layout)
        })?;
        // SAFETY: the block is the arena's, `bytes` long, and no one else holds it yet.
        unsafe { core::ptr::write_bytes(at.as_ptr(), 0, bytes) };
        Some(at.as_ptr() as u32)
    }

    /// A block of the arena given back.
    fn release(address: u32) {
        let at = NonNull::new(address as usize as *mut u8).expect("a block's address");
        with_io(|io| {
            io.heap
                .as_mut()
                .expect("the I/O manager is started")
                .dealloc(at)
        });
    }

    /// The structure at `address`: one of the I/O manager's blocks, or memory a driver handed it.
    ///
    /// # Safety
    ///
    /// `address` holds a `T` the caller may change: a block of the arena or a driver's own memory,
    /// kernel memory every address space maps, which no program's pointer reaches.
    unsafe fn at<T>(address: u32) -> &'static mut T {
        // SAFETY: the caller's contract.
        unsafe { &mut *(address as usize as *mut T) }
    }

    /// The units at `address`, `count` of them: a driver's string or one of the I/O manager's.
    fn units_at(address: u32, count: usize) -> &'static [u16] {
        if address == 0 || count == 0 {
            return &[];
        }
        // SAFETY: kernel memory a driver or the arena holds (see `at`), `count` units long.
        unsafe { core::slice::from_raw_parts(address as usize as *const u16, count) }
    }

    /// A driver's UNICODE_STRING at `address`: its units.
    pub fn counted(address: u32) -> &'static [u16] {
        if address == 0 {
            return &[];
        }
        // SAFETY: a driver's UNICODE_STRING (see `at`).
        let string = unsafe { *at::<UnicodeString>(address) };
        units_at(string.buffer, usize::from(string.length) / 2)
    }

    /// A driver's NUL-terminated wide string at `address` (a PCWSTR): its units, at most 32767.
    pub fn terminated(address: u32) -> &'static [u16] {
        if address == 0 {
            return &[];
        }
        let mut count = 0;
        // SAFETY: a driver's string (see `at`), read up to its NUL.
        while count < 0x7FFF && unsafe { *(address as usize as *const u16).add(count) } != 0 {
            count += 1;
        }
        units_at(address, count)
    }

    /// A driver's NUL-terminated byte string at `address`: its bytes, at most 4095.
    pub fn bytes_terminated(address: u32) -> &'static [u8] {
        if address == 0 {
            return &[];
        }
        let mut count = 0;
        // SAFETY: a driver's string (see `at`), read up to its NUL.
        while count < 0xFFF && unsafe { *(address as usize as *const u8).add(count) } != 0 {
            count += 1;
        }
        // SAFETY: the bytes just read.
        unsafe { core::slice::from_raw_parts(address as usize as *const u8, count) }
    }

    /// Copy `units` to `address`, and make the UNICODE_STRING at `string` count them (`room`
    /// bytes of room).
    fn place_string(string: u32, address: u32, units: &[u16], room: usize) {
        // SAFETY: both are the caller's block (see `at`), the units' room inside it.
        unsafe {
            core::ptr::copy_nonoverlapping(
                units.as_ptr(),
                address as usize as *mut u16,
                units.len(),
            );
            *at::<UnicodeString>(string) = UnicodeString {
                length: (units.len() * 2) as u16,
                maximum_length: room as u16,
                buffer: address,
            };
        }
    }

    // --- The threads' and processes' stand-ins --------------------------------------------------

    /// A stand-in's size: an EPROCESS's (0x290), larger than an ETHREAD's (0x240).
    const STAND_IN: usize = 0x290;
    const THREAD_STAND_INS: usize = crate::sched::database::THREAD_RECORDS;
    const PROCESS_STAND_INS: usize = crate::process::MAX_PROCESSES + 1;

    #[repr(C, align(16))]
    struct StandIns<const N: usize>([[u8; STAND_IN]; N]);

    // The stand-ins: zeroed kernel memory a driver may read (and write: its own business).
    static mut THREADS: StandIns<THREAD_STAND_INS> = StandIns([[0; STAND_IN]; THREAD_STAND_INS]);
    static mut PROCESSES: StandIns<PROCESS_STAND_INS> =
        StandIns([[0; STAND_IN]; PROCESS_STAND_INS]);

    /// The System process's stand-in: PsInitialSystemProcess.
    pub fn system_process() -> u32 {
        (&raw const PROCESSES) as u32 + (PROCESS_STAND_INS - 1) as u32 * STAND_IN as u32
    }

    /// Whether the running thread stands in for the system worker (a load or an unload).
    fn in_worker() -> bool {
        crate::sched::try_current_thread()
            .is_some_and(|thread| WORKER.load(Ordering::Acquire) == u32::from(thread.index()) + 1)
    }

    /// The running thread's stand-in: KeGetCurrentThread.
    pub fn current_thread() -> u32 {
        let index = crate::sched::try_current_thread().map_or(0, |thread| thread.index());
        (&raw const THREADS) as u32 + u32::from(index) * STAND_IN as u32
    }

    /// The current process's stand-in: IoGetCurrentProcess. The System process's while the
    /// thread stands in for the worker, or runs for no process.
    pub fn current_process() -> u32 {
        match crate::pcr::pcr().threads.process() {
            Some(index) if !in_worker() => {
                (&raw const PROCESSES) as u32 + u32::from(index) * STAND_IN as u32
            }
            _ => system_process(),
        }
    }

    /// The System process's client id, as the process listing shows it.
    const SYSTEM_PROCESS_ID: u32 = 8;

    /// The current process's client id: PsGetCurrentProcessId.
    pub fn current_process_id() -> u32 {
        match crate::pcr::pcr().threads.process() {
            Some(index) if !in_worker() => crate::process::pool::record(index).id(),
            _ => SYSTEM_PROCESS_ID,
        }
    }

    /// The running thread's client id: PsGetCurrentThreadId.
    pub fn current_thread_id() -> u32 {
        let Some(thread) = crate::sched::try_current_thread() else {
            return 0;
        };
        level::raised::<crate::level::Dispatch, _>(|dispatch| {
            crate::sched::DISPATCHER
                .get(dispatch)
                .thread(thread)
                .thread_id()
        })
    }

    /// The previous mode: ExGetPreviousMode. The kernel's for the worker and the kernel's own
    /// threads; a program's thread came into the kernel from user mode (every request a driver
    /// sees comes through a system service).
    pub fn previous_mode() -> u8 {
        if in_worker() || current_thread_id() == 0 {
            KERNEL_MODE
        } else {
            USER_MODE
        }
    }

    /// Run `body` as the system worker (see the module notes).
    fn as_worker<R>(body: impl FnOnce() -> R) -> R {
        let index = crate::sched::current_thread().index();
        let before = WORKER.swap(u32::from(index) + 1, Ordering::AcqRel);
        let result = body();
        WORKER.store(before, Ordering::Release);
        result
    }

    // --- The dispatch ---------------------------------------------------------------------------

    type DispatchRoutine = extern "stdcall" fn(u32, u32) -> i32;
    type CompletionRoutine = extern "stdcall" fn(u32, u32, u32) -> i32;
    type DriverEntryRoutine = extern "stdcall" fn(u32, u32) -> i32;
    type UnloadRoutine = extern "stdcall" fn(u32);

    /// A routine of a driver's, by its address.
    ///
    /// # Safety
    ///
    /// `address` is a routine of the driver's image (or the kernel's) of type `F`.
    unsafe fn routine<F: Copy>(address: u32) -> F {
        assert_eq!(size_of::<F>(), size_of::<usize>());
        // SAFETY: the caller's contract: a function of this signature lies at `address`.
        unsafe { core::mem::transmute_copy(&(address as usize)) }
    }

    /// The I/O manager's answer for a major function the driver did not set
    /// (IopInvalidDeviceRequest): STATUS_INVALID_DEVICE_REQUEST, completed.
    extern "stdcall" fn invalid_device_request(_device: u32, irp: u32) -> i32 {
        // SAFETY: the IRP the I/O manager sent (see `at`).
        let packet = unsafe { at::<Irp>(irp) };
        packet.io_status_status = STATUS_INVALID_DEVICE_REQUEST.0 as i32;
        packet.io_status_information = 0;
        complete_irp(irp);
        STATUS_INVALID_DEVICE_REQUEST.0 as i32
    }

    /// The I/O manager's record of a request, in the IRP's block before the IRP: its progress, the
    /// event its sender waits on, the open it counts on (whose close waits for it), and the system
    /// buffer the IRP owns until its sender takes it back, or its retirement gives it back.
    struct Tail {
        progress: Progress,
        event: Event,
        file: Option<DeviceFile>,
        system: Option<Block>,
    }

    /// The record's room before the IRP.
    const TAIL: u32 = size_of::<Tail>().next_multiple_of(8) as u32;

    /// The record of the request whose IRP is at `irp`.
    fn tail(irp: u32) -> *mut Tail {
        (irp - TAIL) as usize as *mut Tail
    }

    /// The event the sender of the IRP at `irp` waits on.
    fn completion_event(irp: u32) -> WaitableId {
        // SAFETY: the record's event, named at its block's making and alive with the IRP.
        unsafe { (*tail(irp)).event.id() }
    }

    /// The requests' lives over the kernel's memory and the drivers' routines.
    struct Kernel;

    impl Packets for Kernel {
        fn irp(&mut self, irp: u32) -> &mut Irp {
            // SAFETY: an IRP of the I/O manager's, alive while its request is (see `at`).
            unsafe { at::<Irp>(irp) }
        }

        fn location(&mut self, irp: u32, number: i8) -> &mut IoStackLocation {
            // Wrapping: a driver's own CurrentLocation names the location, valid or not.
            let index = (i32::from(number) - 1) as u32;
            let address = (irp + size_of::<Irp>() as u32)
                .wrapping_add(index.wrapping_mul(size_of::<IoStackLocation>() as u32));
            // SAFETY: a location of the IRP's, inside its block (see `at`).
            unsafe { at::<IoStackLocation>(address) }
        }

        fn transition(&mut self, irp: u32, change: fn(Progress) -> Progress) -> Progress {
            with_io(|_| {
                // SAFETY: the IRP's record (see `tail`); the I/O manager's level holds every other
                // transition off.
                let progress = unsafe { &mut (*tail(irp)).progress };
                let before = *progress;
                *progress = change(before);
                before
            })
        }

        fn dispatch(&mut self, entry: u32, device: u32, irp: u32) -> NtStatus {
            // SAFETY: the driver's MajorFunction entry: the driver's routine, or the I/O manager's.
            let dispatch = unsafe { routine::<DispatchRoutine>(entry) };
            NtStatus(dispatch(device, irp) as u32)
        }

        fn completion(&mut self, address: u32, device: u32, irp: u32, context: u32) -> NtStatus {
            // SAFETY: a completion routine the driver set on its location.
            let completion = unsafe { routine::<CompletionRoutine>(address) };
            NtStatus(completion(device, irp, context) as u32)
        }

        fn wake(&mut self, irp: u32) {
            level::raised::<crate::level::Dispatch, _>(|dispatch| {
                crate::sched::DISPATCHER
                    .get(dispatch)
                    .set_event(completion_event(irp), EVENT_WAKE_INCREMENT)
            });
        }

        fn retire(&mut self, irp: u32) {
            drop(give_back(irp));
        }
    }

    /// IofCompleteRequest (see [`complete_request`]).
    pub fn complete_irp(irp: u32) {
        complete_request(&mut Kernel, irp);
    }

    /// A request for a device: the IRP's fields its builder sets.
    pub struct Request {
        pub major: u8,
        pub flags: u32,
        pub requestor_mode: u8,
        pub user_buffer: u32,
        pub file_object: u32,
        pub parameters: [u32; 4],
    }

    /// A request sent: its IRP, and what its dispatch routine left.
    struct Sent {
        irp: u32,
        dispatched: Dispatched,
    }

    /// The IRP for `request` built and sent down to `device` (IoCallDriver), on the drivers'
    /// stack: what its dispatch routine left. `file` is the open the request counts on (a read's,
    /// a write's, a device control's, a flush's: the open's close waits for the IRP), `system`
    /// the system buffer the IRP takes (its SystemBuffer), owned by the IRP until its sender takes
    /// it back ([`finish`]).
    fn send(
        device: u32,
        request: &Request,
        file: Option<DeviceFile>,
        system: Option<Block>,
    ) -> Result<Sent, NtStatus> {
        // SAFETY: a device of a loaded driver, referenced by the caller (see `at`).
        let (stack_count, driver) = unsafe {
            let device = at::<DeviceObject>(device);
            // StackSize is a CCHAR: a driver's larger one cannot be counted in the IRP.
            (
                device.stack_size.clamp(1, i8::MAX as u8 - 1),
                device.driver_object,
            )
        };
        let size = irp_size(stack_count);
        let block = allocate(TAIL as usize + size).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        let irp = block + TAIL;
        let system_buffer = system.as_ref().map_or(0, Block::virtual_address);
        // SAFETY: the record's room in the block just made; its event is named at its place.
        unsafe {
            tail(irp).write(Tail {
                progress: Progress::Sent,
                event: Event::new(EventKind::Notification, false),
                file,
                system,
            });
            (*tail(irp)).event.init();
        }
        if let Some(file) = file {
            with_io(|io| {
                if let Some(slot) = io.files.get_mut(usize::from(file.index)) {
                    slot.in_flight += 1;
                }
            });
        }
        let first_location = irp + size_of::<Irp>() as u32;
        {
            // SAFETY: the IRP's block, just made (see `at`).
            let packet = unsafe { at::<Irp>(irp) };
            packet.kind = IO_TYPE_IRP;
            packet.size = size as u16;
            packet.flags = request.flags;
            packet.system_buffer = system_buffer;
            packet.requestor_mode = request.requestor_mode;
            packet.stack_count = stack_count as i8;
            packet.current_location = stack_count as i8 + 1;
            packet.current_stack_location =
                first_location + u32::from(stack_count) * size_of::<IoStackLocation>() as u32;
            packet.user_buffer = request.user_buffer;
            packet.thread = current_thread();
            packet.original_file_object = request.file_object;
            // The location the driver is sent: the last.
            let mut kernel = Kernel;
            let location = kernel.location(irp, stack_count as i8);
            location.major_function = request.major;
            location.parameters = request.parameters;
            location.file_object = request.file_object;
        }
        // SAFETY: the driver's object (see `at`).
        let entry =
            unsafe { at::<DriverObject>(driver) }.major_function[usize::from(request.major)];
        let entry = if entry == 0 {
            invalid_device_request as *const () as u32
        } else {
            entry
        };
        let dispatched = call(&mut Kernel, irp, device, entry);
        Ok(Sent { irp, dispatched })
    }

    /// A sent request's end, where its sender is (off the drivers' stack for a request sent from
    /// outside it): a request its dispatch routine left pending waited for in `mode`, as Windows
    /// 2000 waits for a synchronous request; its outcome taken, and its IRP given back with its
    /// system buffer, which the sender takes back. A user-mode wait a termination interrupts
    /// leaves the IRP to its completion, which retires it and what it holds, and the request ends
    /// with the wait's status (STATUS_USER_APC).
    fn finish(sent: Sent, mode: WaitMode) -> Result<(Outcome, Option<Block>), NtStatus> {
        let irp = sent.irp;
        if !sent.dispatched.completed && !await_completion(&mut Kernel, irp) {
            let event = completion_event(irp);
            let status = crate::sched::wait::wait_current_with(|dispatcher, thread, stamp, _| {
                dispatcher.wait_for(
                    thread,
                    event,
                    WaitReason::Executive,
                    mode,
                    false,
                    None,
                    stamp,
                )
            });
            if status != STATUS_SUCCESS && abandon(&mut Kernel, irp) {
                return Err(status);
            }
        }
        let outcome = outcome(&mut Kernel, irp, sent.dispatched);
        Ok((outcome, give_back(irp)))
    }

    /// A request's IRP given back with its record: its system buffer, and its count on its open,
    /// whose close, put off for the request, runs once the open's last request goes.
    fn give_back(irp: u32) -> Option<Block> {
        // SAFETY: the IRP's record (see `tail`), read out once: nothing reaches it any more.
        let (file, system) = unsafe {
            let record = &mut *tail(irp);
            (record.file.take(), record.system.take())
        };
        release(irp - TAIL);
        if let Some(file) = file {
            let close = with_io(|io| {
                let slot = io.files.get_mut(usize::from(file.index))?;
                slot.in_flight -= 1;
                Some(slot.in_flight == 0 && slot.closing)
            });
            if close == Some(true) {
                close_now(file);
            }
        }
        system
    }

    // --- Devices and links -------------------------------------------------------------------

    /// What IoCreateDevice is asked.
    pub struct DeviceRequest<'a> {
        pub driver: u32,
        pub extension: u32,
        pub name: Option<&'a [u16]>,
        pub device_type: u32,
        pub characteristics: u32,
        pub exclusive: bool,
    }

    /// Whether a device of this type carries a volume (IopCreateVpb's types).
    fn has_volume(device_type: u32) -> bool {
        matches!(
            device_type,
            FILE_DEVICE_DISK | FILE_DEVICE_CD_ROM | FILE_DEVICE_TAPE | FILE_DEVICE_VIRTUAL_DISK
        )
    }

    /// IoCreateDevice: the DEVICE_OBJECT made (its extension after it, zeroed; its
    /// DEVOBJ_EXTENSION; a VPB for a volume's type), named (a name's errors before anything is
    /// made), and put first on its driver's list, DO_DEVICE_INITIALIZING set.
    pub fn create_device(request: &DeviceRequest) -> Result<u32, NtStatus> {
        let name = request.name.map(normalize).transpose()?;
        if let Some(name) = &name {
            // The name's refusals first: the same checks the insert below makes.
            with_io(|io| {
                let (directory, _) = split(name.units());
                if !is_directory(directory) {
                    return Err(STATUS_OBJECT_PATH_NOT_FOUND);
                }
                match io.names.get(name) {
                    Some(_) => Err(STATUS_OBJECT_NAME_COLLISION),
                    None => Ok(()),
                }
            })?;
        }
        let extension = (request.extension as usize).next_multiple_of(8);
        let volume = has_volume(request.device_type);
        let device_size = size_of::<DeviceObject>();
        let dope_at = device_size + extension;
        let vpb_at = dope_at + size_of::<DevObjExtension>();
        let total = vpb_at + if volume { size_of::<Vpb>() } else { 0 };
        let block = allocate(total).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        // SAFETY: the block just made, a DEVICE_OBJECT at its start (see `at`).
        let device = unsafe { at::<DeviceObject>(block) };
        device.kind = IO_TYPE_DEVICE;
        device.size = (device_size + request.extension as usize) as u16;
        device.driver_object = request.driver;
        device.flags = DO_DEVICE_INITIALIZING
            | if name.is_some() {
                DO_DEVICE_HAS_NAME
            } else {
                0
            }
            | if request.exclusive { DO_EXCLUSIVE } else { 0 };
        device.characteristics = request.characteristics;
        device.device_extension = if request.extension > 0 {
            block + device_size as u32
        } else {
            0
        };
        device.device_type = request.device_type;
        device.stack_size = 1;
        device.alignment_requirement = 0;
        device.sector_size = match request.device_type {
            FILE_DEVICE_DISK | FILE_DEVICE_VIRTUAL_DISK => 512,
            FILE_DEVICE_CD_ROM => 2048,
            _ => 0,
        };
        device.device_object_extension = block + dope_at as u32;
        // SAFETY: the DEVOBJ_EXTENSION inside the block.
        let dope = unsafe { at::<DevObjExtension>(block + dope_at as u32) };
        dope.kind = IO_TYPE_DEVICE_OBJECT_EXTENSION;
        dope.size = size_of::<DevObjExtension>() as u16;
        dope.device_object = block;
        if volume {
            device.vpb = block + vpb_at as u32;
            // SAFETY: the VPB inside the block.
            let vpb = unsafe { at::<Vpb>(device.vpb) };
            vpb.kind = IO_TYPE_VPB;
            vpb.size = size_of::<Vpb>() as u16;
            vpb.real_device = block;
        }
        if let Some(name) = &name {
            if let Err(status) = with_io(|io| io.names.insert(name, Entry::Device(block))) {
                release(block);
                return Err(status);
            }
        }
        with_io(|_| {
            // SAFETY: the driver's object (see `at`).
            let driver = unsafe { at::<DriverObject>(request.driver) };
            device.next_device = driver.device_object;
            driver.device_object = block;
        });
        Ok(block)
    }

    /// The device off its driver's list, and its block given back, its VPB with it.
    fn free_device(device: u32) {
        with_io(|_| {
            // SAFETY: a device of the driver's (see `at`), and its driver's object, which its
            // devices keep (see `forget_driver`).
            let object = unsafe { at::<DeviceObject>(device) };
            let driver = unsafe { at::<DriverObject>(object.driver_object) };
            let mut link = &mut driver.device_object;
            let mut hops = 0;
            while *link != 0 && hops < 1024 {
                if *link == device {
                    *link = object.next_device;
                    break;
                }
                // SAFETY: a device on the driver's list.
                link = unsafe { &mut at::<DeviceObject>(*link).next_device };
                hops += 1;
            }
        });
        release(device);
    }

    /// IoDeleteDevice: the device's name gone, and the device off its driver's list and its block
    /// given back, or, while an open holds it, once its last close comes (DOE_DELETE_PENDING): it
    /// stays on its driver's list meanwhile, so its references hold an unload of the driver, and
    /// the driver object and image it runs on stay, as Windows 2000's IopCompleteUnloadOrDelete
    /// keeps a referenced device on its driver's list. The check and the mark are one step with a
    /// close's dropping of the reference ([`dereference_device`]).
    pub fn delete_device(device: u32) {
        let now = with_io(|io| {
            io.names.remove_device(device);
            // SAFETY: a device of the driver's (see `at`), and its DEVOBJ_EXTENSION.
            let object = unsafe { at::<DeviceObject>(device) };
            if object.reference_count > 0 {
                unsafe { at::<DevObjExtension>(object.device_object_extension) }.extension_flags |=
                    DOE_DELETE_PENDING;
                return false;
            }
            true
        });
        if now {
            free_device(device);
        }
    }

    /// IoCreateSymbolicLink: `link` names `target` (not looked at until an open follows it).
    pub fn create_link(link: &[u16], target: &[u16]) -> Result<(), NtStatus> {
        let link = normalize(link)?;
        let target = ObName::of(target).ok_or(STATUS_OBJECT_NAME_INVALID)?;
        with_io(|io| io.names.insert(&link, Entry::Link(target)))
    }

    /// IoDeleteSymbolicLink: STATUS_OBJECT_NAME_NOT_FOUND for a name that is no link.
    pub fn delete_link(link: &[u16]) -> Result<(), NtStatus> {
        let link = normalize(link)?;
        with_io(|io| match io.names.get(&link) {
            Some(Entry::Link(_)) => {
                io.names.remove(&link);
                Ok(())
            }
            Some(_) => Err(STATUS_OBJECT_TYPE_MISMATCH),
            None => Err(STATUS_OBJECT_NAME_NOT_FOUND),
        })
    }

    // --- The opens -----------------------------------------------------------------------------

    /// A device an open holds a reference on: dropped, the reference goes
    /// ([`dereference_device`]); a create takes it over ([`create`]).
    pub struct Referenced(Resolved);

    impl Drop for Referenced {
        fn drop(&mut self) {
            dereference_device(self.0.device);
        }
    }

    /// An open of `units` resolved to a device and the device referenced for it (its
    /// ReferenceCount, as IopParseDevice counts it before IRP_MJ_CREATE): none when the name is
    /// no name of the I/O manager's. A device still initializing, being deleted or whose driver's
    /// unload is pending is STATUS_NO_SUCH_DEVICE, an exclusive one already open
    /// STATUS_ACCESS_DENIED ([`open_refusal`]).
    pub fn reference_device(units: &[u16]) -> Option<Result<Referenced, NtStatus>> {
        on_driver_stack(|| reference(units))
    }

    fn reference(units: &[u16]) -> Option<Result<Referenced, NtStatus>> {
        with_io(|io| {
            let resolved = match io.names.resolve(units)? {
                Ok(resolved) => resolved,
                Err(status) => return Some(Err(status)),
            };
            // SAFETY: a named device (see `at`): a name goes before its device's block does.
            let device = unsafe { at::<DeviceObject>(resolved.device) };
            // SAFETY: its DEVOBJ_EXTENSION.
            let dope = unsafe { at::<DevObjExtension>(device.device_object_extension) };
            if let Some(status) =
                open_refusal(device.flags, device.reference_count, dope.extension_flags)
            {
                return Some(Err(status));
            }
            device.reference_count += 1;
            Some(Ok(Referenced(resolved)))
        })
    }

    /// Whether an open of `units` is the I/O manager's to resolve (see [`Namespace::resolve`]).
    pub fn is_device_name(units: &[u16]) -> bool {
        // Every open asks: the system service's own frames leave little stack, so the answer is
        // had at once while no driver named anything, and on the drivers' stack otherwise.
        NAMED.load(Ordering::Acquire) != 0
            && on_driver_stack(|| with_io(|io| io.names.resolve(units).is_some()))
    }

    /// The FILE_DEVICE_* type of the device an open is of.
    pub fn device_type(file: DeviceFile) -> u32 {
        open_of(file).map_or(0, |(_, device)| {
            // SAFETY: an open's device (see `at`): the open references it.
            unsafe { at::<DeviceObject>(device) }.device_type
        })
    }

    /// An open's reference on `device` dropped (IopDecrementDeviceObjectRef): with the last, a
    /// device deleted meanwhile goes, and a pending unload of its driver runs once none of the
    /// driver's devices is referenced any more ([`unload_due`]; on the drivers' stack, as the
    /// System process's worker, as Windows 2000 runs it from the last close).
    pub fn dereference_device(device: u32) {
        let (driver, last, flags) = with_io(|_| {
            // SAFETY: a referenced device (see `at`).
            let object = unsafe { at::<DeviceObject>(device) };
            object.reference_count -= 1;
            // SAFETY: its DEVOBJ_EXTENSION.
            let dope = unsafe { at::<DevObjExtension>(object.device_object_extension) };
            (
                object.driver_object,
                object.reference_count == 0,
                dope.extension_flags,
            )
        });
        if !last {
            return;
        }
        if flags & DOE_DELETE_PENDING != 0 {
            free_device(device);
        }
        if flags & DOE_UNLOAD_PENDING != 0 {
            serialized(|| {
                on_driver_stack(|| {
                    let due = with_io(|io| {
                        // Another thread's unload may have run since the reference went: the
                        // driver is weighed only while it is still loaded.
                        let loaded = io
                            .drivers
                            .iter()
                            .flatten()
                            .any(|slot| slot.object == driver);
                        // SAFETY: the driver's object, loaded (see `at`).
                        loaded
                            && unload_due(
                                &mut unsafe { at::<DriverObject>(driver) }.flags,
                                weights(unsafe { at::<DriverObject>(driver) }.device_object),
                            )
                    });
                    if due {
                        run_unload(driver);
                    }
                })
            });
        }
    }

    /// The devices on a driver's list from `first` (NextDevice), as an unload weighs each.
    fn weights(first: u32) -> impl Iterator<Item = UnloadWeight<'static>> {
        let mut device = first;
        let mut hops = 0;
        core::iter::from_fn(move || {
            if device == 0 || hops >= 1024 {
                return None;
            }
            hops += 1;
            // SAFETY: a device on its driver's list (see `at`), and its DEVOBJ_EXTENSION.
            let object = unsafe { at::<DeviceObject>(device) };
            let dope = unsafe { at::<DevObjExtension>(object.device_object_extension) };
            device = object.next_device;
            Some(UnloadWeight {
                references: object.reference_count,
                attached: object.attached_device != 0,
                extension_flags: &mut dope.extension_flags,
            })
        })
    }

    /// What an open asks of the device (IRP_MJ_CREATE's parameters).
    pub struct OpenRequest {
        /// The access asked for, the generic rights mapped (the security context's DesiredAccess).
        pub desired_access: u32,
        pub disposition: u32,
        pub options: u32,
        pub file_attributes: u16,
        pub share_access: u16,
        pub synchronous: bool,
    }

    /// The create: a FILE_OBJECT made for the device `referenced` holds ([`reference_device`]),
    /// IRP_MJ_CREATE sent down, and the open recorded: its handle's context and the I/O status's
    /// Information. A refusal drops the reference and the object. A create its driver leaves
    /// pending is waited for in kernel mode, as Windows 2000's IopParseDevice waits for it: its
    /// file object and its security context live until it completes.
    pub fn create(
        referenced: Referenced,
        request: &OpenRequest,
    ) -> Result<(DeviceFile, u32), NtStatus> {
        let resolved = core::mem::ManuallyDrop::new(referenced).0;
        let device = resolved.device;
        let Some((file, context)) = open_file_object(&resolved, request) else {
            dereference_device(device);
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        };
        let create = Request {
            major: crate::dev::irp::IRP_MJ_CREATE,
            flags: IRP_CREATE_OPERATION | IRP_SYNCHRONOUS_API | IRP_DEFER_IO_COMPLETION,
            requestor_mode: USER_MODE,
            user_buffer: 0,
            file_object: file,
            parameters: [
                context,
                request.disposition << 24 | request.options & 0x00FF_FFFF,
                u32::from(request.file_attributes) | u32::from(request.share_access) << 16,
                0,
            ],
        };
        let outcome = on_driver_stack(|| send(device, &create, None, None))
            .and_then(|sent| finish(sent, WaitMode::Kernel));
        release(context);
        let information = match outcome {
            Ok((outcome, _)) if !nt_error(outcome.status) => outcome.information,
            Ok((outcome, _)) => return Err(refuse_open(file, device, outcome.status)),
            Err(status) => return Err(refuse_open(file, device, status)),
        };
        let recorded = with_io(|io| {
            let (index, slot) = io
                .files
                .iter_mut()
                .enumerate()
                .find(|(_, slot)| !slot.live)?;
            *slot = FileSlot {
                live: true,
                generation: slot.generation.wrapping_add(1),
                file_object: file,
                device,
                in_flight: 0,
                closing: false,
            };
            Some(DeviceFile {
                index: index as u16,
                generation: slot.generation,
            })
        });
        match recorded {
            Some(handle) => Ok((handle, information)),
            None => {
                send_close(device, file, crate::dev::irp::IRP_MJ_CLEANUP);
                send_close(device, file, crate::dev::irp::IRP_MJ_CLOSE);
                Err(refuse_open(file, device, STATUS_TOO_MANY_OPENED_FILES))
            }
        }
    }

    /// An open refused with `status`: its file object and its reference on the device gone.
    fn refuse_open(file: u32, device: u32, status: NtStatus) -> NtStatus {
        free_file_object(file);
        dereference_device(device);
        status
    }

    /// A FILE_OBJECT for an open of `resolved` (its FileName the rest of the name after the
    /// device's), and the IO_SECURITY_CONTEXT its create names: their addresses.
    fn open_file_object(resolved: &Resolved, request: &OpenRequest) -> Option<(u32, u32)> {
        let rest = resolved.rest.units();
        let file = allocate(size_of::<FileObject>() + rest.len() * 2)?;
        let Some(context) = allocate(size_of::<IoSecurityContext>()) else {
            release(file);
            return None;
        };
        // SAFETY: the blocks just made (see `at`).
        let object = unsafe { at::<FileObject>(file) };
        object.kind = IO_TYPE_FILE;
        object.size = size_of::<FileObject>() as u16;
        object.device_object = resolved.device;
        object.flags = if request.synchronous {
            FO_SYNCHRONOUS_IO
        } else {
            0
        };
        if !rest.is_empty() {
            let names = file + size_of::<FileObject>() as u32;
            place_string(
                file + core::mem::offset_of!(FileObject, file_name) as u32,
                names,
                rest,
                rest.len() * 2,
            );
        }
        // SAFETY: the security context's block.
        let security = unsafe { at::<IoSecurityContext>(context) };
        security.desired_access = request.desired_access;
        security.full_create_options = request.disposition << 24 | request.options;
        Some((file, context))
    }

    fn free_file_object(file: u32) {
        release(file);
    }

    /// The open `file` names: its FILE_OBJECT and its device; none for a record gone.
    fn open_of(file: DeviceFile) -> Option<(u32, u32)> {
        with_io(|io| {
            let slot = io.files.get(usize::from(file.index))?;
            (slot.live && slot.generation == file.generation)
                .then_some((slot.file_object, slot.device))
        })
    }

    /// IRP_MJ_CLEANUP or IRP_MJ_CLOSE for `file`, the kernel's own request (whatever the driver
    /// answers: a cleanup or a close cannot fail), waited for in kernel mode when the driver
    /// leaves it pending, as Windows 2000's IopCloseFile and IopDeleteFile wait.
    fn send_close(device: u32, file: u32, major: u8) {
        let close = Request {
            major,
            flags: IRP_CLOSE_OPERATION | IRP_SYNCHRONOUS_API,
            requestor_mode: KERNEL_MODE,
            user_buffer: 0,
            file_object: file,
            parameters: [0; 4],
        };
        if let Ok(sent) = on_driver_stack(|| send(device, &close, None, None)) {
            let _ = finish(sent, WaitMode::Kernel);
        }
    }

    /// An open's cleanup, its last handle closed: IRP_MJ_CLEANUP (where a driver completes, or
    /// cancels, the requests it holds pending for the open).
    pub fn cleanup(file: DeviceFile) {
        if let Some((object, device)) = open_of(file) {
            send_close(device, object, crate::dev::irp::IRP_MJ_CLEANUP);
        }
    }

    /// An open's close, its last reference gone: IRP_MJ_CLOSE, then its FILE_OBJECT and its
    /// reference on the device go. While a request on the open is still in its driver's hands
    /// (its sender was terminated while it waited), the close waits for that request's
    /// completion, as Windows 2000's IRP holds its file object.
    pub fn close(file: DeviceFile) {
        let now = with_io(|io| {
            let Some(slot) = io.files.get_mut(usize::from(file.index)) else {
                return false;
            };
            if !slot.live || slot.generation != file.generation {
                return false;
            }
            slot.closing = slot.in_flight > 0;
            !slot.closing
        });
        if now {
            close_now(file);
        }
    }

    /// The close itself (see [`close`]).
    fn close_now(file: DeviceFile) {
        let Some((object, device)) = open_of(file) else {
            return;
        };
        send_close(device, object, crate::dev::irp::IRP_MJ_CLOSE);
        with_io(|io| io.files[usize::from(file.index)].live = false);
        free_file_object(object);
        dereference_device(device);
    }

    /// IRP_MJ_DEVICE_CONTROL for `file`, METHOD_BUFFERED: the system buffer (`system`, holding the
    /// input; none with no buffers), which the IRP owns until it is handed back with the outcome,
    /// and the lengths, the caller's output buffer the IRP's UserBuffer. A request the driver
    /// leaves pending is waited for (see [`finish`]).
    pub fn device_control(
        file: DeviceFile,
        code: u32,
        system: Option<Block>,
        input_length: u32,
        output_length: u32,
        user_output: u32,
    ) -> Result<(Outcome, Option<Block>), NtStatus> {
        let (object, device) = open_of(file).ok_or(STATUS_INVALID_HANDLE)?;
        let flags = if input_length != 0 || output_length != 0 {
            IRP_BUFFERED_IO
                | IRP_DEALLOCATE_BUFFER
                | if user_output != 0 {
                    IRP_INPUT_OPERATION
                } else {
                    0
                }
        } else {
            0
        };
        let control = Request {
            major: crate::dev::irp::IRP_MJ_DEVICE_CONTROL,
            flags,
            requestor_mode: USER_MODE,
            user_buffer: if flags == 0 { 0 } else { user_output },
            file_object: object,
            parameters: [output_length, input_length, code, 0],
        };
        let sent = on_driver_stack(|| send(device, &control, Some(file), system))?;
        finish(sent, WaitMode::User)
    }

    /// The DO_* flags of the device an open is of (its buffering: DO_BUFFERED_IO, DO_DIRECT_IO,
    /// or neither).
    pub fn device_flags(file: DeviceFile) -> u32 {
        open_of(file).map_or(0, |(_, device)| {
            // SAFETY: an open's device (see `at`): the open references it.
            unsafe { at::<DeviceObject>(device) }.flags
        })
    }

    /// What a read or a write moves: the system buffer (none but for a DO_BUFFERED_IO device's
    /// transfer, a block holding a write's bytes, the IRP's until it is handed back), the
    /// caller's buffer, the length, and the offset (none for the file object's
    /// CurrentByteOffset).
    pub struct Transfer {
        pub system: Option<Block>,
        pub user_buffer: u32,
        pub length: u32,
        pub offset: Option<u64>,
    }

    /// IRP_MJ_READ or IRP_MJ_WRITE (`major`) for `file`: Parameters.Read (the length, the key,
    /// the offset), IRP_READ_OPERATION or IRP_WRITE_OPERATION with IRP_DEFER_IO_COMPLETION, and
    /// for a system buffer IRP_BUFFERED_IO and IRP_DEALLOCATE_BUFFER (a read's
    /// IRP_INPUT_OPERATION too). A synchronous file object's CurrentByteOffset moves past what the
    /// driver moved. A request the driver leaves pending is waited for (see [`finish`]).
    pub fn read_write(
        file: DeviceFile,
        major: u8,
        transfer: Transfer,
    ) -> Result<(Outcome, Option<Block>), NtStatus> {
        let (object, device) = open_of(file).ok_or(STATUS_INVALID_HANDLE)?;
        // SAFETY: the open's FILE_OBJECT (see `at`).
        let file_object = unsafe { at::<FileObject>(object) };
        let offset = transfer.offset.unwrap_or(file_object.current_byte_offset);
        let read = major == crate::dev::irp::IRP_MJ_READ;
        let buffered = if transfer.system.is_none() {
            0
        } else {
            IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | if read { IRP_INPUT_OPERATION } else { 0 }
        };
        let operation = if read {
            IRP_READ_OPERATION
        } else {
            IRP_WRITE_OPERATION
        };
        let request = Request {
            major,
            flags: operation | IRP_DEFER_IO_COMPLETION | buffered,
            requestor_mode: USER_MODE,
            user_buffer: transfer.user_buffer,
            file_object: object,
            parameters: [transfer.length, 0, offset as u32, (offset >> 32) as u32],
        };
        let sent = on_driver_stack(|| send(device, &request, Some(file), transfer.system))?;
        let (outcome, system) = finish(sent, WaitMode::User)?;
        if file_object.flags & FO_SYNCHRONOUS_IO != 0 && !nt_error(outcome.status) {
            file_object.current_byte_offset = position_after(offset, outcome.information);
        }
        Ok((outcome, system))
    }

    /// IRP_MJ_FLUSH_BUFFERS for `file`, waited for when the driver leaves it pending.
    pub fn flush(file: DeviceFile) -> Result<Outcome, NtStatus> {
        let (object, device) = open_of(file).ok_or(STATUS_INVALID_HANDLE)?;
        let request = Request {
            major: crate::dev::irp::IRP_MJ_FLUSH_BUFFERS,
            flags: IRP_SYNCHRONOUS_API,
            requestor_mode: USER_MODE,
            user_buffer: 0,
            file_object: object,
            parameters: [0; 4],
        };
        let sent = on_driver_stack(|| send(device, &request, Some(file), None))?;
        finish(sent, WaitMode::User).map(|(outcome, _)| outcome)
    }

    // --- Loads and unloads -------------------------------------------------------------------

    /// `\Registry\`, which a service key's name starts with.
    const REGISTRY: &str = "\\Registry\\";

    /// The longest registry path a load reads, in units.
    const MAX_PATH: usize = 260;

    /// The service key the caller names (`\Registry\Machine\System\CurrentControlSet\Services\X`):
    /// the key, and its own name (the driver's). STATUS_OBJECT_NAME_NOT_FOUND when it does not
    /// exist.
    fn service_key(units: &[u16]) -> Result<(Key, ObName), NtStatus> {
        if !starts_with(units, REGISTRY) {
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        }
        let below = &units[REGISTRY.len()..];
        let mut path = [0u16; MAX_PATH];
        let length =
            registry_path_below_root(below, &mut path).ok_or(STATUS_OBJECT_NAME_INVALID)?;
        let key = with_registry(|registry| registry.open(registry.root(), &path[..length]))?;
        let (_, own) = split(units);
        let own = ObName::of(own).ok_or(STATUS_OBJECT_NAME_INVALID)?;
        Ok((key, own))
    }

    /// The registry's own spelling of each component of `below` (a path below `\Registry`), into
    /// `out` as the object manager names the key: its length.
    fn registry_path(below: &[u16], out: &mut [u16]) -> Option<usize> {
        /// The longest key name the registry's spelling is read for, in units (a key name's
        /// limit on Windows 2000 is 255).
        const UNITS: usize = 256;
        let mut path = [0u16; MAX_PATH];
        let length = registry_path_below_root(below, &mut path)?;
        let path = &path[..length];
        let mut written = 0;
        let mut root = [0u16; 8];
        let n = ascii("REGISTRY", &mut root);
        push_object_component(0, &root[..n], out, &mut written)?;
        let mut so_far = 0;
        for (index, component) in path.split(|&unit| unit == SEPARATOR).enumerate() {
            so_far += component.len() + usize::from(index > 0);
            let mut spelled = [0u16; UNITS];
            let n = with_registry(|registry| {
                let key = registry.open(registry.root(), &path[..so_far]).ok()?;
                let name = registry.info(key).ok()?.name.as_chunks::<2>().0;
                for (slot, pair) in spelled.get_mut(..name.len())?.iter_mut().zip(name) {
                    *slot = u16::from_le_bytes(*pair);
                }
                Some(name.len())
            })?;
            push_object_component(index + 1, &spelled[..n], out, &mut written)?;
        }
        Some(written)
    }

    /// A value of `key` as units (REG_SZ or REG_EXPAND_SZ, its NUL dropped), into `out`: its
    /// length; none when the key has no such string.
    fn string_value(key: Key, name: &str, out: &mut [u16]) -> Option<usize> {
        let mut units = [0u16; 32];
        let n = ascii(name, &mut units);
        with_registry(|registry| {
            let value = registry.query_value(key, &units[..n]).ok()?;
            if !matches!(value.kind, 1 | 2) {
                return None;
            }
            let mut length = 0;
            for pair in value.data.as_chunks::<2>().0 {
                let unit = u16::from_le_bytes([pair[0], pair[1]]);
                if unit == 0 {
                    break;
                }
                *out.get_mut(length)? = unit;
                length += 1;
            }
            Some(length)
        })
    }

    /// The loaded driver named `name`: its slot.
    fn driver_named(name: &ObName) -> Option<u16> {
        with_io(|io| match io.names.get(name) {
            Some(Entry::Driver(slot)) => Some(slot),
            _ => None,
        })
    }

    /// The image's status as NtLoadDriver reports it.
    fn load_status(error: LoadError) -> NtStatus {
        match error {
            LoadError::NotAnImage(_) | LoadError::Malformed | LoadError::NoRelocations => {
                STATUS_INVALID_IMAGE_FORMAT
            }
            LoadError::UnsupportedRelocation(_) => STATUS_INVALID_IMAGE_FORMAT,
            LoadError::Unresolved => STATUS_DRIVER_ENTRYPOINT_NOT_FOUND,
            LoadError::OutOfRegion | LoadError::OutOfFrames => STATUS_INSUFFICIENT_RESOURCES,
        }
    }

    /// NtLoadDriver's work, for the service key `units` names (see the module notes).
    pub fn load_driver(units: &[u16]) -> Result<(), NtStatus> {
        serialized(|| on_driver_stack(|| load(units)))
    }

    /// The `\Driver\<name>` name.
    fn driver_name(own: &ObName) -> Option<ObName> {
        let mut prefix = [0u16; 8];
        let n = ascii("\\Driver\\", &mut prefix);
        ObName::joined(&[&prefix[..n], own.units()])
    }

    fn load(units: &[u16]) -> Result<(), NtStatus> {
        let (key, own) = service_key(units)?;
        let name = driver_name(&own).ok_or(STATUS_OBJECT_NAME_INVALID)?;
        if driver_named(&name).is_some() {
            return Err(STATUS_IMAGE_ALREADY_LOADED);
        }
        let mut image_path = [0u16; MAX_PATH];
        let Some(length) = string_value(key, "ImagePath", &mut image_path) else {
            crate::dbgprint::unhandled(
                "ntoskrnl",
                "NtLoadDriver",
                format_args!("DriverServiceName={}", Units(units)),
                format_args!("a service key without an ImagePath is not yet implemented"),
            );
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        };
        let image_path = &image_path[..length];
        // The RegistryPath before the image is mapped: its refusal leaves nothing mapped.
        let mut registry = [0u16; MAX_PATH];
        let registry_length = registry_path(&units[REGISTRY.len()..], &mut registry)
            .ok_or(STATUS_OBJECT_NAME_INVALID)?;
        let file = crate::nt::file::read_whole_file(image_path)?;
        let image = loader::map_driver_image(file.as_ref()).map_err(load_status)?;
        drop(file);
        let driver = match make_driver_object(
            &image,
            &name,
            &own,
            image_path,
            &registry[..registry_length],
        ) {
            Some(driver) => driver,
            None => {
                loader::unmap_driver_image(&image);
                return Err(STATUS_INSUFFICIENT_RESOURCES);
            }
        };
        let slot = with_io(|io| {
            let slot = io.drivers.iter().position(Option::is_none)?;
            io.names.insert(&name, Entry::Driver(slot as u16)).ok()?;
            io.drivers[slot] = Some(DriverSlot {
                object: driver,
                image,
                name,
            });
            Some(slot)
        });
        let Some(slot) = slot else {
            release(driver);
            loader::unmap_driver_image(&image);
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        };
        // SAFETY: the image's entry point, DriverEntry(DriverObject, RegistryPath).
        let entry = unsafe { routine::<DriverEntryRoutine>(image.entry_va) };
        let registry_string = driver + REGISTRY_PATH_AT;
        let status = NtStatus(as_worker(|| entry(driver, registry_string)) as u32);
        if nt_error(status) {
            forget_driver(slot as u16);
            return Err(status);
        }
        // IopReadyDeviceObjects: the driver's devices are ready once DriverEntry returns.
        with_io(|_| {
            // SAFETY: the driver's object and its devices (see `at`).
            let mut device = unsafe { at::<DriverObject>(driver) }.device_object;
            let mut hops = 0;
            while device != 0 && hops < 1024 {
                // SAFETY: a device on the driver's list.
                let object = unsafe { at::<DeviceObject>(device) };
                object.flags &= !DO_DEVICE_INITIALIZING;
                device = object.next_device;
                hops += 1;
            }
        });
        Ok(())
    }

    /// Where the driver's block keeps its parts.
    const EXTENSION_AT: u32 = 0xA8;
    const MODULE_AT: u32 = 0xC0;
    const HARDWARE_AT: u32 = 0xF8;
    const REGISTRY_PATH_AT: u32 = 0x100;
    const STRINGS_AT: u32 = 0x108;

    /// The hardware database's key, as every DRIVER_OBJECT names it.
    const HARDWARE_DATABASE: &str = "\\REGISTRY\\MACHINE\\HARDWARE\\DESCRIPTION\\SYSTEM";

    /// The driver's block: its DRIVER_OBJECT (every MajorFunction entry the I/O manager's
    /// refusal), its DRIVER_EXTENSION (ServiceKeyName), its module record, and the strings they
    /// name: the driver's name, the service key's, the RegistryPath, the hardware database's.
    fn make_driver_object(
        image: &MappedImage,
        name: &ObName,
        service: &ObName,
        image_path: &[u16],
        registry: &[u16],
    ) -> Option<u32> {
        let mut hardware = [0u16; 48];
        let hardware_length = ascii(HARDWARE_DATABASE, &mut hardware);
        let hardware = &hardware[..hardware_length];
        let base_name = image_path
            .rsplit(|&unit| unit == SEPARATOR)
            .next()
            .unwrap_or(image_path);
        let strings = [
            name.units(),
            service.units(),
            registry,
            hardware,
            image_path,
            base_name,
        ];
        let room: usize = strings.iter().map(|units| units.len() * 2 + 2).sum();
        let block = allocate(STRINGS_AT as usize + room)?;
        let mut at_string = block + STRINGS_AT;
        let mut place = |string: u32, units: &[u16], room: usize| {
            place_string(string, at_string, units, room);
            at_string += (units.len() * 2 + 2) as u32;
        };
        // SAFETY: the block just made (see `at`): the DRIVER_OBJECT at its start, its parts at
        // their offsets.
        let driver = unsafe { at::<DriverObject>(block) };
        driver.kind = IO_TYPE_DRIVER;
        driver.size = size_of::<DriverObject>() as u16;
        driver.flags = DRVO_LEGACY_DRIVER;
        driver.driver_start = image.base;
        driver.driver_size = image.size;
        driver.driver_section = block + MODULE_AT;
        driver.driver_extension = block + EXTENSION_AT;
        driver.hardware_database = block + HARDWARE_AT;
        driver.driver_init = image.entry_va;
        driver.major_function = [invalid_device_request as *const () as u32; MAJOR_FUNCTIONS];
        let names = core::mem::offset_of!(DriverObject, driver_name) as u32;
        place(block + names, name.units(), name.units().len() * 2);
        // SAFETY: the extension inside the block.
        let extension = unsafe { at::<DriverExtension>(block + EXTENSION_AT) };
        extension.driver_object = block;
        let service_name =
            block + EXTENSION_AT + core::mem::offset_of!(DriverExtension, service_key_name) as u32;
        place(service_name, service.units(), service.units().len() * 2 + 2);
        place(block + REGISTRY_PATH_AT, registry, registry.len() * 2);
        place(block + HARDWARE_AT, hardware, hardware.len() * 2 + 2);
        // SAFETY: the module record inside the block.
        let module = unsafe { at::<ModuleEntry>(block + MODULE_AT) };
        module.dll_base = image.base;
        module.entry_point = image.entry_va;
        module.size_of_image = image.size;
        let full = block + MODULE_AT + core::mem::offset_of!(ModuleEntry, full_dll_name) as u32;
        let base = block + MODULE_AT + core::mem::offset_of!(ModuleEntry, base_dll_name) as u32;
        place(full, image_path, image_path.len() * 2 + 2);
        place(base, base_name, base_name.len() * 2 + 2);
        Some(block)
    }

    /// A driver's slot and name gone; its block and image too, unless devices of its remain
    /// (they name it: kept, as Windows 2000 keeps a driver object its devices reference).
    fn forget_driver(slot: u16) {
        let Some(driver) = with_io(|io| {
            let driver = io.drivers[usize::from(slot)].take()?;
            io.names.remove(&driver.name);
            Some(driver)
        }) else {
            return;
        };
        // SAFETY: the driver's object (see `at`): a device deleted while open stays on its list
        // until its last close, so the block and image stay for it.
        if with_io(|_| unsafe { at::<DriverObject>(driver.object) }.device_object) != 0 {
            crate::dbgprint::unhandled(
                "ntoskrnl",
                "IopDeleteDriver",
                format_args!("DriverName={}", Units(driver.name.units())),
                format_args!(
                    "a driver whose devices outlive it keeps its image: their deletion with the \
                     driver is not yet implemented"
                ),
            );
            return;
        }
        release(driver.object);
        loader::unmap_driver_image(&driver.image);
    }

    /// NtUnloadDriver's work, for the service key `units` names (see the module notes).
    pub fn unload_driver(units: &[u16]) -> Result<(), NtStatus> {
        serialized(|| on_driver_stack(|| unload(units)))
    }

    fn unload(units: &[u16]) -> Result<(), NtStatus> {
        let (_, own) = service_key(units)?;
        let name = driver_name(&own).ok_or(STATUS_OBJECT_NAME_INVALID)?;
        let slot = driver_named(&name).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        let object = with_io(|io| io.drivers[usize::from(slot)].map(|driver| driver.object))
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        let now = with_io(|_| {
            // SAFETY: the driver's object (see `at`).
            let driver = unsafe { at::<DriverObject>(object) };
            check_unload(
                &mut driver.flags,
                driver.driver_unload != 0,
                weights(driver.device_object),
            )
        })?;
        if now {
            run_unload(object);
        }
        Ok(())
    }

    /// The unload itself, DRVO_UNLOAD_INVOKED set (by [`check_unload`] or [`unload_due`]):
    /// DriverUnload run as the System process's worker, then the driver's name gone (a second
    /// NtUnloadDriver's STATUS_OBJECT_NAME_NOT_FOUND) and its block and image with it.
    fn run_unload(object: u32) {
        // SAFETY: the driver's object (see `at`) and its DriverUnload(DriverObject), which
        // `check_unload` found set.
        let unload = unsafe { routine::<UnloadRoutine>(at::<DriverObject>(object).driver_unload) };
        as_worker(|| unload(object));
        let slot = with_io(|io| {
            io.drivers
                .iter()
                .position(|slot| slot.is_some_and(|driver| driver.object == object))
        });
        if let Some(slot) = slot {
            forget_driver(slot as u16);
        }
    }

    /// RtlWriteRegistryValue's work, RTL_REGISTRY_ABSOLUTE: `value` of `key` (an absolute path,
    /// which must exist) set to `data` of type `kind`.
    pub fn write_registry_value(
        path: &[u16],
        value: &[u16],
        kind: u32,
        data: &[u8],
    ) -> Result<(), NtStatus> {
        if !starts_with(path, REGISTRY) {
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        }
        let mut below = [0u16; MAX_PATH];
        let length = registry_path_below_root(&path[REGISTRY.len()..], &mut below)
            .ok_or(STATUS_OBJECT_NAME_INVALID)?;
        let now = crate::time::system_filetime();
        crate::cm::storing(|registry| {
            let key = registry.open(registry.root(), &below[..length])?;
            registry.set_bytes(key, value, kind, data, now)
        })
    }

    /// Units shown as text, for a stub's line.
    struct Units<'a>(&'a [u16]);

    impl core::fmt::Display for Units<'_> {
        fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            out.write_str("\"")?;
            for unit in char::decode_utf16(self.0.iter().copied()) {
                core::fmt::Write::write_char(out, unit.unwrap_or('?'))?;
            }
            out.write_str("\"")
        }
    }
}

#[cfg(test)]
mod tests {
    use rtl::testing::wide;

    use super::*;

    fn named(text: &str) -> ObName {
        normalize(&wide(text)).unwrap()
    }

    fn text(name: &ObName) -> std::string::String {
        std::string::String::from_utf16(name.units()).unwrap()
    }

    /// `\DosDevices` is `\??`; a name is `\`-rooted and has no empty component.
    #[test]
    fn names_are_normalized() {
        assert_eq!(text(&named("\\DosDevices\\F2Kdrvload")), "\\??\\F2Kdrvload");
        assert_eq!(text(&named("\\dosdevices\\X")), "\\??\\X");
        assert_eq!(text(&named("\\DosDevicesX\\Y")), "\\DosDevicesX\\Y");
        assert_eq!(text(&named("\\Device\\F2Kdrvload")), "\\Device\\F2Kdrvload");
        assert_eq!(
            normalize(&wide("Device\\X")).err(),
            Some(STATUS_OBJECT_PATH_SYNTAX_BAD)
        );
        assert_eq!(
            normalize(&wide("\\Device\\\\X")).err(),
            Some(STATUS_OBJECT_NAME_INVALID)
        );
        assert_eq!(
            normalize(&wide(&"\\x".repeat(MAX_NAME))).err(),
            Some(STATUS_OBJECT_NAME_INVALID)
        );
    }

    /// The `names` capture's refusals: a name taken, a directory that does not exist, a link
    /// deleted twice; a link to a device that does not exist is made all the same.
    #[test]
    fn the_directories_refuse_as_windows_2000_s_do() {
        let mut names = Namespace::new();
        let device = named("\\Device\\F2Kdrvload");
        names.insert(&device, Entry::Device(0x1000)).unwrap();
        assert_eq!(
            names.insert(&named("\\device\\f2kdrvload"), Entry::Device(0x2000)),
            Err(STATUS_OBJECT_NAME_COLLISION)
        );
        assert_eq!(
            names.insert(
                &named("\\F2KNoSuchDirectory\\F2Kdrvload"),
                Entry::Device(0x2000)
            ),
            Err(STATUS_OBJECT_PATH_NOT_FOUND)
        );
        let link = named("\\DosDevices\\F2Kdrvload");
        names.insert(&link, Entry::Link(device)).unwrap();
        assert_eq!(
            names.insert(&link, Entry::Link(device)),
            Err(STATUS_OBJECT_NAME_COLLISION)
        );
        assert_eq!(
            names.insert(&named("\\Device"), Entry::Device(1)),
            Err(STATUS_OBJECT_NAME_COLLISION)
        );
        let other = named("\\DosDevices\\F2KdrvloadY");
        names
            .insert(&other, Entry::Link(named("\\Device\\F2KdrvloadNone")))
            .unwrap();
        assert!(names.remove(&other).is_some());
        assert!(names.remove(&other).is_none());
    }

    /// An open follows the DOS device's link to the device; the rest of the name is the file's;
    /// a name the I/O manager does not hold is the file systems'.
    #[test]
    fn opens_follow_links_to_devices() {
        let mut names = Namespace::new();
        let device = named("\\Device\\F2Kdrvload");
        names.insert(&device, Entry::Device(0x1000)).unwrap();
        names
            .insert(&named("\\??\\F2Kdrvload"), Entry::Link(device))
            .unwrap();
        names
            .insert(
                &named("\\??\\Dangling"),
                Entry::Link(named("\\Device\\None")),
            )
            .unwrap();
        names
            .insert(&named("\\Driver\\F2Kdrvload"), Entry::Driver(0))
            .unwrap();
        let open = |text: &str| {
            names
                .resolve(&wide(text))
                .map(|resolved| resolved.map(|r| (r.device, super::tests::text(&r.rest))))
        };
        assert_eq!(open("\\??\\F2Kdrvload"), Some(Ok((0x1000, "".into()))));
        assert_eq!(open("\\??\\f2kdrvload"), Some(Ok((0x1000, "".into()))));
        assert_eq!(open("\\Device\\F2Kdrvload"), Some(Ok((0x1000, "".into()))));
        assert_eq!(
            open("\\??\\F2Kdrvload\\sub"),
            Some(Ok((0x1000, "\\sub".into())))
        );
        assert_eq!(open("\\??\\F2KdrvloadX"), None);
        assert_eq!(open("\\??\\C:\\CORPUS\\X.TXT"), None);
        assert_eq!(
            open("\\??\\Dangling"),
            Some(Err(STATUS_OBJECT_NAME_NOT_FOUND))
        );
        assert_eq!(
            open("\\Driver\\F2Kdrvload"),
            Some(Err(STATUS_OBJECT_TYPE_MISMATCH))
        );
    }

    /// A device as the unload tests weigh it: its references, and its extension flags.
    struct Device {
        references: i32,
        attached: bool,
        flags: u32,
    }

    impl Device {
        fn open(references: i32) -> Device {
            Device {
                references,
                attached: false,
                flags: 0,
            }
        }
    }

    fn weights(devices: &mut [Device]) -> impl Iterator<Item = UnloadWeight<'_>> {
        devices.iter_mut().map(|device| UnloadWeight {
            references: device.references,
            attached: device.attached,
            extension_flags: &mut device.flags,
        })
    }

    /// The `unload` capture: with no device open, NtUnloadDriver unloads at once, the driver
    /// marked DRVO_UNLOAD_INVOKED; a driver without DriverUnload, or whose unload ran, refuses.
    #[test]
    fn an_unload_with_nothing_open_runs_at_once() {
        let mut driver = super::super::ntddk::DRVO_LEGACY_DRIVER;
        let mut devices = [Device::open(0), Device::open(0)];
        assert_eq!(
            check_unload(&mut driver, true, weights(&mut devices)),
            Ok(true)
        );
        assert_ne!(driver & DRVO_UNLOAD_INVOKED, 0);
        assert!(devices.iter().all(|d| d.flags & DOE_UNLOAD_PENDING != 0));
        assert_eq!(
            check_unload(&mut driver, true, weights(&mut devices)),
            Err(STATUS_INVALID_DEVICE_REQUEST)
        );
        assert!(!unload_due(&mut driver, weights(&mut devices)));
        let mut driver = 0;
        assert_eq!(
            check_unload(&mut driver, false, weights(&mut [Device::open(0)])),
            Err(STATUS_INVALID_DEVICE_REQUEST)
        );
        // A driver with no device left unloads at once too.
        assert_eq!(check_unload(&mut driver, true, weights(&mut [])), Ok(true));
    }

    /// The `unloadopen` capture: with a handle open the unload is left pending (NtUnloadDriver
    /// succeeds all the same), a new open of the device is refused, a second unload request
    /// leaves it pending, and the last close runs it, once.
    #[test]
    fn an_unload_with_a_handle_open_waits_for_its_last_close() {
        let mut driver = 0;
        // Two handles open on the first device.
        let mut devices = [Device::open(2), Device::open(0)];
        assert_eq!(
            check_unload(&mut driver, true, weights(&mut devices)),
            Ok(false)
        );
        assert_eq!(driver & DRVO_UNLOAD_INVOKED, 0);
        assert_eq!(
            open_refusal(0, devices[0].references, devices[0].flags),
            Some(STATUS_NO_SUCH_DEVICE)
        );
        assert_eq!(
            open_refusal(0, devices[1].references, devices[1].flags),
            Some(STATUS_NO_SUCH_DEVICE)
        );
        assert_eq!(
            check_unload(&mut driver, true, weights(&mut devices)),
            Ok(false)
        );
        // The first close: the second handle still holds the device.
        devices[0].references -= 1;
        assert!(!unload_due(&mut driver, weights(&mut devices)));
        devices[0].references -= 1;
        assert!(unload_due(&mut driver, weights(&mut devices)));
        assert_ne!(driver & DRVO_UNLOAD_INVOKED, 0);
        assert!(!unload_due(&mut driver, weights(&mut devices)));
    }

    /// A device attached to holds the unload as an open does; a device the unload never marked
    /// (made after it) keeps the driver loaded.
    #[test]
    fn an_attached_or_unmarked_device_holds_the_unload() {
        let mut driver = 0;
        let mut devices = [Device {
            references: 0,
            attached: true,
            flags: 0,
        }];
        assert_eq!(
            check_unload(&mut driver, true, weights(&mut devices)),
            Ok(false)
        );
        devices[0].attached = false;
        assert!(unload_due(&mut driver, weights(&mut devices)));
        let mut driver = 0;
        assert!(!unload_due(&mut driver, weights(&mut [Device::open(0)])));
    }

    /// The opens a device refuses: initializing, its driver's unload or its own delete pending
    /// (STATUS_NO_SUCH_DEVICE), exclusive and open (STATUS_ACCESS_DENIED).
    #[test]
    fn opens_are_refused_by_the_device_s_state() {
        use super::super::ntddk::DO_DEVICE_HAS_NAME;
        assert_eq!(open_refusal(DO_DEVICE_HAS_NAME, 0, 0), None);
        assert_eq!(open_refusal(DO_DEVICE_HAS_NAME, 3, 0), None);
        assert_eq!(
            open_refusal(DO_DEVICE_INITIALIZING, 0, 0),
            Some(STATUS_NO_SUCH_DEVICE)
        );
        assert_eq!(
            open_refusal(0, 0, DOE_DELETE_PENDING),
            Some(STATUS_NO_SUCH_DEVICE)
        );
        assert_eq!(
            open_refusal(DO_EXCLUSIVE, 1, DOE_UNLOAD_PENDING),
            Some(STATUS_NO_SUCH_DEVICE)
        );
        assert_eq!(open_refusal(DO_EXCLUSIVE, 1, 0), Some(STATUS_ACCESS_DENIED));
        assert_eq!(open_refusal(DO_EXCLUSIVE, 0, 0), None);
    }

    /// _vsnprintf's placement: the NUL when it fits, none when the text fills the buffer, -1
    /// when it does not fit.
    #[test]
    fn vsnprintf_places_as_the_c_runtime_does() {
        let mut out = [0xFFu8; 4];
        assert_eq!(place(&mut out, b"ab"), 2);
        assert_eq!(out, [b'a', b'b', 0, 0xFF]);
        let mut out = [0xFFu8; 4];
        assert_eq!(place(&mut out, b"abcd"), 4);
        assert_eq!(out, *b"abcd");
        let mut out = [0xFFu8; 4];
        assert_eq!(place(&mut out, b"abcdef"), -1);
        assert_eq!(out, *b"abcd");
    }

    /// The RegistryPath DriverEntry is handed: the hive roots upper-case, the current control set
    /// as ControlSet001 (the capture's Length 116), and its way back to F2K's key.
    #[test]
    fn the_registry_path_is_the_object_manager_s() {
        let parts = [
            wide("REGISTRY"),
            wide("MACHINE"),
            wide("SYSTEM"),
            wide("CurrentControlSet"),
            wide("Services"),
            wide("F2Kdrvload"),
        ];
        let parts: std::vec::Vec<&[u16]> = parts.iter().map(|part| part.as_slice()).collect();
        let mut out = [0u16; 128];
        let length = registry_object_name(&parts, &mut out).unwrap();
        let path = std::string::String::from_utf16(&out[..length]).unwrap();
        assert_eq!(
            path,
            "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\F2Kdrvload"
        );
        assert_eq!(length * 2, 116);
        let mut back = [0u16; 128];
        let below = &out[10..length];
        let n = registry_path_below_root(below, &mut back).unwrap();
        assert_eq!(
            std::string::String::from_utf16(&back[..n]).unwrap(),
            "MACHINE\\SYSTEM\\CurrentControlSet\\Services\\F2Kdrvload"
        );
        let n = registry_path_below_root(&wide("Machine\\System\\CurrentControlSet\\X"), &mut back)
            .unwrap();
        assert_eq!(
            std::string::String::from_utf16(&back[..n]).unwrap(),
            "Machine\\System\\CurrentControlSet\\X"
        );
    }

    // --- The requests' lives, over fake drivers ---------------------------------------------

    use super::super::ntddk::{IoStackLocation, Irp};

    /// A fake driver's routine: a dispatch routine (device, IRP) or a completion routine
    /// (device, IRP, context), by its index plus one as its address.
    type Routine = fn(&mut Fake, u32, u32, u32) -> NtStatus;

    /// IRPs in a table (an IRP's address its index), the fake drivers' routines, and what the
    /// I/O manager did: the senders it woke, the orphans it retired, the IRPs the drivers hold.
    struct Fake {
        irps: std::vec::Vec<(Irp, [IoStackLocation; 4], Progress)>,
        routines: std::vec::Vec<Routine>,
        held: std::vec::Vec<u32>,
        woken: std::vec::Vec<u32>,
        retired: std::vec::Vec<u32>,
        completions: std::vec::Vec<(u32, u32)>,
        /// The drivers' stacks, the thread running, the names, and what its opens reached.
        stacks: Stacks,
        thread: u32,
        names: Namespace,
        opened: std::vec::Vec<(Claim, u32)>,
    }

    impl Fake {
        fn new(routines: &[Routine]) -> Fake {
            Fake {
                irps: std::vec::Vec::new(),
                routines: routines.to_vec(),
                held: std::vec::Vec::new(),
                woken: std::vec::Vec::new(),
                retired: std::vec::Vec::new(),
                completions: std::vec::Vec::new(),
                stacks: Stacks::new(),
                thread: 1,
                names: Namespace::new(),
                opened: std::vec::Vec::new(),
            }
        }

        /// A fresh IRP of `stack_count` locations, before IoCallDriver.
        fn make(&mut self, stack_count: i8) -> u32 {
            // SAFETY: the IRP is plain integers, all zero a valid one.
            let mut packet: Irp = unsafe { core::mem::zeroed() };
            packet.stack_count = stack_count;
            packet.current_location = stack_count + 1;
            self.irps
                .push((packet, [IoStackLocation::default(); 4], Progress::Sent));
            (self.irps.len() - 1) as u32
        }

        /// The progress of the IRP at `irp`.
        fn progress(&self, irp: u32) -> Progress {
            self.irps[irp as usize].2
        }

        /// The IRP's I/O status set, and the IRP completed (IoCompleteRequest).
        fn finish(&mut self, irp: u32, status: NtStatus, information: u32) {
            let packet = self.irp(irp);
            packet.io_status_status = status.0 as i32;
            packet.io_status_information = information;
            complete_request(self, irp);
        }

        /// The IRP's current location marked pending (IoMarkIrpPending).
        fn mark_pending(&mut self, irp: u32) {
            let number = self.irp(irp).current_location;
            self.location(irp, number).control |= SL_PENDING_RETURNED;
        }
    }

    impl Packets for Fake {
        fn irp(&mut self, irp: u32) -> &mut Irp {
            &mut self.irps[irp as usize].0
        }

        fn location(&mut self, irp: u32, number: i8) -> &mut IoStackLocation {
            &mut self.irps[irp as usize].1[number as usize - 1]
        }

        fn transition(&mut self, irp: u32, change: fn(Progress) -> Progress) -> Progress {
            let progress = &mut self.irps[irp as usize].2;
            let before = *progress;
            *progress = change(before);
            before
        }

        fn dispatch(&mut self, entry: u32, device: u32, irp: u32) -> NtStatus {
            (self.routines[entry as usize - 1])(self, device, irp, 0)
        }

        fn completion(&mut self, routine: u32, device: u32, irp: u32, context: u32) -> NtStatus {
            self.completions.push((routine, device));
            (self.routines[routine as usize - 1])(self, device, irp, context)
        }

        fn wake(&mut self, irp: u32) {
            self.woken.push(irp);
        }

        fn retire(&mut self, irp: u32) {
            self.retired.push(irp);
        }
    }

    /// Completes its IRP at once, 4 bytes moved.
    fn completes(fake: &mut Fake, _: u32, irp: u32, _: u32) -> NtStatus {
        fake.finish(irp, STATUS_SUCCESS, 4);
        STATUS_SUCCESS
    }

    /// Marks its IRP pending and holds it.
    fn pends(fake: &mut Fake, _: u32, irp: u32, _: u32) -> NtStatus {
        fake.mark_pending(irp);
        fake.held.push(irp);
        STATUS_PENDING
    }

    /// The inverted call's second request: completes the IRP the driver held (its answer, 8
    /// bytes), then its own.
    fn answers_the_held(fake: &mut Fake, _: u32, irp: u32, _: u32) -> NtStatus {
        let held = fake.held.pop().expect("a request held");
        fake.finish(held, STATUS_SUCCESS, 8);
        fake.finish(irp, STATUS_SUCCESS, 0);
        STATUS_SUCCESS
    }

    /// A completion routine that keeps its IRP (to complete it again later).
    fn keeps(fake: &mut Fake, _: u32, irp: u32, _: u32) -> NtStatus {
        fake.held.push(irp);
        STATUS_MORE_PROCESSING_REQUIRED
    }

    /// A completion routine that lets its IRP go on up.
    fn lets_go(_: &mut Fake, _: u32, _: u32, _: u32) -> NtStatus {
        STATUS_SUCCESS
    }

    /// STATUS_CANCELLED, a cancelled request's status (an error).
    const CANCELLED: NtStatus = NtStatus(0xC000_0120);

    /// A dispatch routine that opens a device by its name (as a driver's ZwCreateFile does): the
    /// open's claim on the stacks and the device it reaches; then completes its own request.
    fn opens_a_device(fake: &mut Fake, _: u32, irp: u32, _: u32) -> NtStatus {
        let claim = fake.stacks.claim(fake.thread);
        let units: std::vec::Vec<u16> = "\\??\\Other".encode_utf16().collect();
        let device = match fake.names.resolve(&units) {
            Some(Ok(resolved)) => resolved.device,
            _ => 0,
        };
        fake.opened.push((claim, device));
        fake.finish(irp, STATUS_SUCCESS, 0);
        STATUS_SUCCESS
    }

    const COMPLETES: u32 = 1;
    const PENDS: u32 = 2;
    const ANSWERS: u32 = 3;
    const KEEPS: u32 = 4;
    const LETS_GO: u32 = 5;
    const OPENS: u32 = 6;
    const DEVICE: u32 = 0xD0;

    fn fake() -> Fake {
        Fake::new(&[
            completes,
            pends,
            answers_the_held,
            keeps,
            lets_go,
            opens_a_device,
        ])
    }

    /// A request its driver completes in its dispatch routine comes back completed, with the
    /// routine's status: its sender neither waits nor is woken.
    #[test]
    fn a_request_completed_in_its_dispatch_comes_back_completed() {
        let mut fake = fake();
        let irp = fake.make(1);
        let dispatched = call(&mut fake, irp, DEVICE, COMPLETES);
        assert_eq!(
            dispatched,
            Dispatched {
                returned: STATUS_SUCCESS,
                completed: true
            }
        );
        assert_eq!(fake.location(irp, 1).device_object, DEVICE);
        assert_eq!(
            outcome(&mut fake, irp, dispatched),
            Outcome {
                returned: STATUS_SUCCESS,
                status: STATUS_SUCCESS,
                information: 4
            }
        );
        assert!(fake.woken.is_empty() && fake.retired.is_empty());
    }

    /// A request its driver leaves pending stays its driver's: not completed, so its sender
    /// waits, keeping what the IRP points to; the completion, from another request, wakes it, and
    /// its status is the IRP's, not STATUS_PENDING.
    #[test]
    fn a_pending_request_is_waited_for_until_another_completes_it() {
        let mut fake = fake();
        let first = fake.make(1);
        let dispatched = call(&mut fake, first, DEVICE, PENDS);
        assert_eq!(
            dispatched,
            Dispatched {
                returned: STATUS_PENDING,
                completed: false
            }
        );
        assert!(!await_completion(&mut fake, first));
        assert_eq!(fake.progress(first), Progress::Awaited);
        // The inverted call: the second request's dispatch completes the first.
        let second = fake.make(1);
        assert!(call(&mut fake, second, DEVICE, ANSWERS).completed);
        assert_eq!(fake.woken, [first]);
        assert!(fake.retired.is_empty());
        assert_eq!(fake.progress(first), Progress::Completed);
        assert_eq!(fake.irp(first).pending_returned, 1);
        assert_eq!(
            outcome(&mut fake, first, dispatched),
            Outcome {
                returned: STATUS_SUCCESS,
                status: STATUS_SUCCESS,
                information: 8
            }
        );
    }

    /// A pending request completed before its sender begins waiting is not waited for, and
    /// wakes no one.
    #[test]
    fn a_request_completed_before_the_wait_is_not_waited_for() {
        let mut fake = fake();
        let irp = fake.make(1);
        assert!(!call(&mut fake, irp, DEVICE, PENDS).completed);
        fake.finish(irp, STATUS_SUCCESS, 0);
        assert!(await_completion(&mut fake, irp));
        assert!(fake.woken.is_empty());
    }

    /// A sender whose wait a termination ends leaves its IRP to the driver: the completion
    /// retires it (and what it owns) instead of waking anyone. Once completed, it is the
    /// sender's again.
    #[test]
    fn an_abandoned_request_is_retired_by_its_completion() {
        let mut fake = fake();
        let irp = fake.make(1);
        assert!(!call(&mut fake, irp, DEVICE, PENDS).completed);
        assert!(!await_completion(&mut fake, irp));
        assert!(abandon(&mut fake, irp));
        assert_eq!(fake.progress(irp), Progress::Orphaned);
        assert!(fake.retired.is_empty());
        fake.finish(irp, CANCELLED, 0);
        assert_eq!(fake.retired, [irp]);
        assert!(fake.woken.is_empty());

        let late = fake.make(1);
        assert!(!call(&mut fake, late, DEVICE, PENDS).completed);
        assert!(!await_completion(&mut fake, late));
        fake.finish(late, STATUS_SUCCESS, 0);
        assert!(!abandon(&mut fake, late));
        assert_eq!(fake.progress(late), Progress::Completed);
    }

    /// A completion routine at the top location that keeps its IRP
    /// (STATUS_MORE_PROCESSING_REQUIRED): every location is walked, but the IRP is not
    /// completed, so its sender waits; the routine's own completion later ends it.
    #[test]
    fn a_routine_keeping_the_irp_at_the_top_leaves_it_uncompleted() {
        let mut fake = fake();
        let irp = fake.make(1);
        {
            let top = fake.location(irp, 1);
            top.completion_routine = KEEPS;
            top.control = SL_INVOKE_ON_SUCCESS;
        }
        let dispatched = call(&mut fake, irp, DEVICE, COMPLETES);
        assert_eq!(fake.held, [irp]);
        assert!(fake.irp(irp).current_location > fake.irp(irp).stack_count);
        assert!(!dispatched.completed);
        assert!(!await_completion(&mut fake, irp));
        // The routine's owner completes it again: past the top already, so it is completed.
        complete_request(&mut fake, irp);
        assert_eq!(fake.woken, [irp]);
        assert_eq!(
            outcome(&mut fake, irp, dispatched),
            Outcome {
                returned: STATUS_SUCCESS,
                status: STATUS_SUCCESS,
                information: 4
            }
        );
    }

    /// The walk runs a routine as its Control asks: on success, on an error or a warning (not
    /// NT_SUCCESS), on a cancel whatever the status; it hands the routine the device above (none
    /// past the top), and carries a pending mark up past a location without a routine.
    #[test]
    fn completion_routines_run_as_their_control_asks() {
        let run = |status: NtStatus, cancel: bool, control: u8| {
            let mut fake = fake();
            let irp = fake.make(2);
            fake.location(irp, 2).device_object = 0xA2;
            fake.irp(irp).current_location = 1;
            fake.irp(irp).cancel = u8::from(cancel);
            {
                let lower = fake.location(irp, 1);
                lower.completion_routine = LETS_GO;
                lower.control = control;
            }
            fake.finish(irp, status, 0);
            fake.completions
        };
        assert_eq!(
            run(STATUS_SUCCESS, false, SL_INVOKE_ON_SUCCESS),
            [(LETS_GO, 0xA2)]
        );
        assert!(run(STATUS_SUCCESS, false, SL_INVOKE_ON_ERROR).is_empty());
        assert_eq!(
            run(STATUS_BUFFER_OVERFLOW, false, SL_INVOKE_ON_ERROR),
            [(LETS_GO, 0xA2)]
        );
        assert_eq!(
            run(STATUS_SUCCESS, true, SL_INVOKE_ON_CANCEL),
            [(LETS_GO, 0xA2)]
        );
        assert_eq!(run(CANCELLED, true, SL_INVOKE_ON_ERROR), [(LETS_GO, 0xA2)]);
        assert!(run(CANCELLED, false, SL_INVOKE_ON_CANCEL).is_empty());

        // The top location's routine, run on an error: no device above it, and past it the IRP
        // is completed.
        let mut alone = fake();
        let irp = alone.make(1);
        alone.irp(irp).current_location = 1;
        {
            let top = alone.location(irp, 1);
            top.completion_routine = LETS_GO;
            top.control = SL_INVOKE_ON_ERROR;
        }
        alone.finish(irp, CANCELLED, 0);
        assert_eq!(alone.completions, [(LETS_GO, 0)]);
        assert_eq!(alone.progress(irp), Progress::Completed);

        // The lower location marked pending, no routine: the mark goes up to the upper one.
        let mut fake = fake();
        let irp = fake.make(2);
        fake.irp(irp).current_location = 1;
        fake.location(irp, 1).control = SL_PENDING_RETURNED;
        fake.finish(irp, STATUS_SUCCESS, 0);
        assert_ne!(fake.location(irp, 2).control & SL_PENDING_RETURNED, 0);
        assert_eq!(fake.irp(irp).pending_returned, 1);
        assert_eq!(fake.progress(irp), Progress::Completed);
    }

    /// A thread runs on one of the drivers' stacks from its first entry to its return: a call
    /// back into the I/O manager runs where it is (no second claim, no wait on itself), while
    /// other threads take the other stacks; with every stack taken a thread waits, until one is
    /// given up.
    #[test]
    fn each_thread_runs_on_a_stack_of_its_own() {
        let mut stacks = Stacks::new();
        assert_eq!(stacks.claim(1), Claim::Took(0));
        assert_eq!(stacks.claim(1), Claim::Running(0));
        assert!(stacks.runs(1) && !stacks.runs(2));
        assert_eq!(stacks.claim(2), Claim::Took(1));
        for thread in 3..=DRIVER_STACKS as u32 {
            assert!(matches!(stacks.claim(thread), Claim::Took(_)));
        }
        assert_eq!(stacks.claim(99), Claim::Busy);
        stacks.give_up(1);
        assert_eq!(stacks.claim(99), Claim::Took(1));
        assert_eq!(stacks.claim(1), Claim::Running(0));
    }

    /// A dispatch routine that re-enters the I/O manager, opening a device by its name, runs the
    /// open on its own stack (where the one shared lock across the dispatch waited for itself);
    /// another thread's open meanwhile takes another stack.
    #[test]
    fn a_dispatch_reentering_the_io_manager_runs_on_its_own_stack() {
        let mut fake = fake();
        let other = named("\\Device\\Other");
        fake.names.insert(&other, Entry::Device(0x2000)).unwrap();
        fake.names
            .insert(&named("\\??\\Other"), Entry::Link(other))
            .unwrap();
        assert_eq!(fake.stacks.claim(fake.thread), Claim::Took(0));
        let irp = fake.make(1);
        assert!(call(&mut fake, irp, DEVICE, OPENS).completed);
        assert_eq!(fake.opened, [(Claim::Running(0), 0x2000)]);
        assert_eq!(fake.stacks.claim(2), Claim::Took(1));
        fake.stacks.give_up(0);
        assert!(!fake.stacks.runs(1));
    }

    /// A device deleted while open stays on its driver's list, so its reference holds the
    /// driver's unload as an open device's does; its last close frees it, and the unload is due.
    #[test]
    fn a_device_deleted_while_open_holds_the_unload() {
        let mut driver = 0;
        let mut devices = [
            Device {
                references: 1,
                attached: false,
                flags: DOE_DELETE_PENDING,
            },
            Device::open(0),
        ];
        assert_eq!(
            check_unload(&mut driver, true, weights(&mut devices)),
            Ok(false)
        );
        // The last close frees the deleted device: off the list, the rest weighed.
        assert!(unload_due(&mut driver, weights(&mut devices[1..])));
    }

    /// The RegistryPath's components are never cut short: a long service name is kept whole
    /// (the registry's spelling read component by component), and a name past the room is
    /// refused rather than truncated.
    #[test]
    fn the_registry_path_keeps_long_components_whole() {
        let long = "S".repeat(100);
        let parts = [
            wide("REGISTRY"),
            wide("Machine"),
            wide("System"),
            wide("CurrentControlSet"),
            wide("Services"),
            wide(&long),
        ];
        let parts: std::vec::Vec<&[u16]> = parts.iter().map(|part| part.as_slice()).collect();
        let mut out = [0u16; 260];
        let length = registry_object_name(&parts, &mut out).unwrap();
        assert_eq!(
            std::string::String::from_utf16(&out[..length]).unwrap(),
            format!("\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\{long}")
        );
        let mut small = [0u16; 100];
        assert_eq!(registry_object_name(&parts, &mut small), None);
        // A hive root longer than the old 32-unit buffer is upper-cased whole.
        let root = "x".repeat(40);
        let mut length = 0;
        push_object_component(1, &wide(&root), &mut out, &mut length).unwrap();
        assert_eq!(
            std::string::String::from_utf16(&out[..length]).unwrap(),
            format!("\\{}", "X".repeat(40))
        );
    }

    /// A synchronous device file's position after a transfer wraps as a LARGE_INTEGER sum: a
    /// write at FILE_WRITE_TO_END_OF_FILE, or a driver's position near 2^64, does not overflow.
    #[test]
    fn the_position_after_a_transfer_wraps() {
        assert_eq!(position_after(0x1000, 0x200), 0x1200);
        assert_eq!(position_after(u64::MAX, 2), 1);
        assert_eq!(position_after(u64::MAX - 1, 0), u64::MAX - 1);
    }
}
