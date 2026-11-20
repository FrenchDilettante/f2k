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
//! completion routines). A driver that leaves its IRP pending is the stub path: F2K has no
//! asynchronous completion yet. The IRP's fields are Windows 2000's for each request: the create's
//! (IRP_CREATE_OPERATION, its security context, the options and the disposition, the requestor's
//! mode), the device control's (METHOD_BUFFERED's system buffer, IRP_BUFFERED_IO,
//! IRP_DEALLOCATE_BUFFER and IRP_INPUT_OPERATION), the cleanup's and the close's (the kernel's
//! own, IRP_CLOSE_OPERATION).
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
//! # What a driver sees of threads and processes
//!
//! F2K's threads and processes are not KTHREADs and EPROCESSes: a driver is handed a stand-in for
//! each (KeGetCurrentThread, IoGetCurrentProcess, PsInitialSystemProcess), a zeroed block of the
//! structure's size, one per thread record and per process record, and one for the System
//! process. They compare as the real ones do (the thread an IRP came in is the current thread,
//! the process the caller's); their fields read zero.
//!
//! Recorded seams: requests are synchronous (no pending IRP, no cancel, no completion APC); only
//! METHOD_BUFFERED device controls are served; an unload while a device of the driver is open,
//! which Windows 2000 defers to the last close, is the stub path; a driver whose DriverEntry fails
//! or whose unload leaves devices behind keeps its image mapped.

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

    /// Whether it has none.
    pub fn is_empty(&self) -> bool {
        self.length == 0
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

    /// Whether no name is bound.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
/// (`ControlSet001`): F2K's registry has the one, CurrentControlSet, with no link.
pub fn registry_object_name(stored: &[&[u16]], out: &mut [u16]) -> Option<usize> {
    let mut length = 0;
    let mut push = |units: &[u16], length: &mut usize| -> Option<()> {
        out.get_mut(*length..*length + units.len())?
            .copy_from_slice(units);
        *length += units.len();
        Some(())
    };
    for (index, component) in stored.iter().enumerate() {
        push(&[SEPARATOR], &mut length)?;
        let mut buffer = [0u16; 32];
        let shown: &[u16] = if index < 3 {
            let mut upper = [0u16; 32];
            let n = component.len().min(32);
            for (slot, &unit) in upper.iter_mut().zip(&component[..n]) {
                *slot = rtl::path::upcase(unit);
            }
            buffer[..n].copy_from_slice(&upper[..n]);
            &buffer[..n]
        } else if index == 3 && same_name(component, &CURRENT_CONTROL_SET.map(u16::from)) {
            let n = ascii("ControlSet001", &mut buffer);
            &buffer[..n]
        } else {
            component
        };
        push(shown, &mut length)?;
    }
    Some(length)
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

// --- On target: the I/O manager's state, its objects, its requests ------------------------------

#[cfg(target_arch = "x86")]
pub use target::*;

#[cfg(target_arch = "x86")]
mod target {
    use core::alloc::Layout;
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

    /// An open of a device: its FILE_OBJECT and the device.
    #[derive(Clone, Copy)]
    struct FileSlot {
        live: bool,
        generation: u16,
        file_object: u32,
        device: u32,
    }

    struct IoManager {
        heap: Option<KernelHeap>,
        names: Namespace,
        drivers: [Option<DriverSlot>; DRIVERS],
        files: [FileSlot; FILES],
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
        }; FILES],
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

    /// The drivers' lock: one thread at a time runs in the I/O manager's requests, on the drivers'
    /// stack ([`on_driver_stack`]); a load or an unload among them, as Windows 2000 serializes
    /// those in its worker.
    static DRIVER_LOCK: DeviceLock<()> = DeviceLock::new(());

    /// The stack the I/O manager runs its requests and the drivers' code on: a kernel stack is
    /// 32 KiB, and a system service's own frames (the kernel is built unoptimized) leave a driver
    /// too little of it, where Windows 2000 gives one 12 KiB of its own. 64 KiB, kernel memory.
    const DRIVER_STACK: usize = 64 * 1024;

    #[repr(C, align(16))]
    struct DriverStack([u8; DRIVER_STACK]);

    // The drivers' stack: reached only by the thread holding DRIVER_LOCK.
    static mut STACK: DriverStack = DriverStack([0; DRIVER_STACK]);

    /// The thread running on the drivers' stack: its thread record's index plus one, 0 for none.
    static ON_STACK: AtomicU32 = AtomicU32::new(0);

    /// Run `body` on the drivers' stack, holding the drivers' lock (inside a critical region: a
    /// termination waits for the request to finish); at once when the running thread is on it
    /// already (a driver's call back into the I/O manager).
    pub fn on_driver_stack<R>(body: impl FnOnce() -> R) -> R {
        let me = u32::from(crate::sched::current_thread().index()) + 1;
        if ON_STACK.load(Ordering::Acquire) == me {
            return body();
        }
        crate::process::threads::critical_region(|| {
            DRIVER_LOCK.with(|_| {
                ON_STACK.store(me, Ordering::Release);
                let mut result = None;
                let mut call = Some(|| result = Some(body()));
                let top = (&raw const STACK) as u32 + DRIVER_STACK as u32;
                // SAFETY: the stack is this thread's alone while it holds the lock; the trampoline
                // runs `call` there and returns to this one.
                unsafe { switch_and_call(top, trampoline_of(&call), (&raw mut call).cast()) };
                ON_STACK.store(0, Ordering::Release);
                result.expect("the body ran")
            })
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

    /// Start the I/O manager: its arena and its load lock. Once, at boot.
    pub fn init() {
        let pool = &mut ARENA_POOL.take().0;
        with_io(|io| io.heap = Some(KernelHeap::new(pool)));
        DRIVER_LOCK.init();
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
        WORKER.store(u32::from(index) + 1, Ordering::Release);
        let result = body();
        WORKER.store(0, Ordering::Release);
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
        complete_request(irp);
        STATUS_INVALID_DEVICE_REQUEST.0 as i32
    }

    /// IofCompleteRequest's work: the IRP's locations walked back up from the current one, each
    /// one's completion routine run when its Control asks for it (STATUS_MORE_PROCESSING_REQUIRED
    /// stops the walk: the routine keeps the IRP).
    pub fn complete_request(irp: u32) {
        // SAFETY: the IRP a driver completes (see `at`).
        let packet = unsafe { at::<Irp>(irp) };
        while packet.current_location <= packet.stack_count {
            // SAFETY: the current location lies inside the IRP's block while the location is.
            let location = unsafe { *at::<IoStackLocation>(packet.current_stack_location) };
            packet.current_location += 1;
            packet.current_stack_location += size_of::<IoStackLocation>() as u32;
            if location.control & SL_PENDING_RETURNED != 0 {
                packet.pending_returned = 1;
            }
            let status = NtStatus(packet.io_status_status as u32);
            let wanted = if packet.cancel != 0 {
                SL_INVOKE_ON_CANCEL
            } else if nt_error(status) {
                SL_INVOKE_ON_ERROR
            } else {
                SL_INVOKE_ON_SUCCESS
            };
            if location.completion_routine != 0 && location.control & wanted != 0 {
                let upper = if packet.current_location <= packet.stack_count {
                    // SAFETY: as above: the upper location is the IRP's.
                    unsafe { at::<IoStackLocation>(packet.current_stack_location).device_object }
                } else {
                    0
                };
                // SAFETY: a completion routine the driver set on its location.
                let routine = unsafe { routine::<CompletionRoutine>(location.completion_routine) };
                if routine(upper, irp, location.context) == STATUS_MORE_PROCESSING_REQUIRED.0 as i32
                {
                    return;
                }
            }
        }
    }

    /// A request for a device: the IRP's fields its builder sets.
    pub struct Request {
        pub major: u8,
        pub flags: u32,
        pub requestor_mode: u8,
        pub system_buffer: u32,
        pub user_buffer: u32,
        pub file_object: u32,
        pub parameters: [u32; 4],
    }

    /// What a request came back with: the dispatch routine's status, and the IRP's I/O status.
    #[derive(Clone, Copy)]
    pub struct Outcome {
        pub returned: NtStatus,
        pub status: NtStatus,
        pub information: u32,
    }

    /// Build the IRP for `request`, send it down to `device` (IoCallDriver) and take it back
    /// completed. A driver that leaves it pending is the stub path (STATUS_NOT_IMPLEMENTED; the
    /// IRP stays the driver's).
    pub fn call_driver(device: u32, request: &Request) -> Result<Outcome, NtStatus> {
        // SAFETY: a device of a loaded driver, referenced by the caller (see `at`).
        let (stack_count, driver) = unsafe {
            let device = at::<DeviceObject>(device);
            (device.stack_size.max(1), device.driver_object)
        };
        let size = irp_size(stack_count);
        let irp = allocate(size).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        let first_location = irp + size_of::<Irp>() as u32;
        let next =
            first_location + u32::from(stack_count - 1) * size_of::<IoStackLocation>() as u32;
        {
            // SAFETY: the IRP's block, just made (see `at`).
            let packet = unsafe { at::<Irp>(irp) };
            packet.kind = IO_TYPE_IRP;
            packet.size = size as u16;
            packet.flags = request.flags;
            packet.system_buffer = request.system_buffer;
            packet.requestor_mode = request.requestor_mode;
            packet.stack_count = stack_count as i8;
            packet.current_location = stack_count as i8 + 1;
            packet.current_stack_location = next + size_of::<IoStackLocation>() as u32;
            packet.user_buffer = request.user_buffer;
            packet.thread = current_thread();
            packet.original_file_object = request.file_object;
            // SAFETY: the next location lies inside the block.
            let location = unsafe { at::<IoStackLocation>(next) };
            location.major_function = request.major;
            location.parameters = request.parameters;
            location.file_object = request.file_object;
            // IoCallDriver: down to the next location, which names the device.
            packet.current_location -= 1;
            packet.current_stack_location = next;
            location.device_object = device;
        }
        // SAFETY: the driver's object (see `at`).
        let entry =
            unsafe { at::<DriverObject>(driver) }.major_function[usize::from(request.major)];
        let entry = if entry == 0 {
            invalid_device_request as *const () as u32
        } else {
            entry
        };
        // SAFETY: the driver's MajorFunction entry: the driver's routine, or the I/O manager's.
        let dispatch = unsafe { routine::<DispatchRoutine>(entry) };
        let returned = NtStatus(dispatch(device, irp) as u32);
        // SAFETY: the IRP's block, back from the driver.
        let packet = unsafe { *at::<Irp>(irp) };
        if packet.current_location <= packet.stack_count {
            crate::dbgprint::unhandled(
                "ntoskrnl",
                "IoCallDriver",
                format_args!("MajorFunction={}", request.major),
                format_args!(
                    "the driver did not complete the IRP (returned {:#010x}): pending IRPs are \
                     not yet implemented",
                    returned.0
                ),
            );
            return Err(STATUS_NOT_IMPLEMENTED);
        }
        release(irp);
        Ok(Outcome {
            returned,
            status: NtStatus(packet.io_status_status as u32),
            information: packet.io_status_information,
        })
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
        // SAFETY: the driver's object (see `at`).
        let driver = unsafe { at::<DriverObject>(request.driver) };
        device.next_device = driver.device_object;
        driver.device_object = block;
        Ok(block)
    }

    /// The device's block given back, its VPB with it.
    fn free_device(device: u32) {
        release(device);
    }

    /// IoDeleteDevice: the device's name gone, the device off its driver's list, and its block
    /// given back, or, while an open holds it, once its last close comes (DOE_DELETE_PENDING).
    pub fn delete_device(device: u32) {
        with_io(|io| io.names.remove_device(device));
        // SAFETY: a device of the driver's (see `at`).
        let object = unsafe { at::<DeviceObject>(device) };
        // SAFETY: its driver's object.
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
        if object.reference_count > 0 {
            // SAFETY: its DEVOBJ_EXTENSION.
            unsafe { at::<DevObjExtension>(object.device_object_extension) }.extension_flags |=
                DOE_DELETE_PENDING;
            return;
        }
        free_device(device);
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
    /// no name of the I/O manager's. A device still initializing or being deleted is
    /// STATUS_NO_SUCH_DEVICE, an exclusive one already open STATUS_ACCESS_DENIED.
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
            if device.flags & DO_DEVICE_INITIALIZING != 0 {
                return Some(Err(STATUS_NO_SUCH_DEVICE));
            }
            if device.flags & DO_EXCLUSIVE != 0 && device.reference_count > 0 {
                return Some(Err(STATUS_ACCESS_DENIED));
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

    /// An open's reference on `device` dropped: a device deleted meanwhile goes with the last.
    pub fn dereference_device(device: u32) {
        let gone = with_io(|_| {
            // SAFETY: a referenced device (see `at`).
            let object = unsafe { at::<DeviceObject>(device) };
            object.reference_count -= 1;
            // SAFETY: its DEVOBJ_EXTENSION.
            let dope = unsafe { at::<DevObjExtension>(object.device_object_extension) };
            object.reference_count == 0 && dope.extension_flags & DOE_DELETE_PENDING != 0
        });
        if gone {
            free_device(device);
        }
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
    /// Information. A refusal drops the reference and the object.
    pub fn create(
        referenced: Referenced,
        request: &OpenRequest,
    ) -> Result<(DeviceFile, u32), NtStatus> {
        on_driver_stack(|| create_on_stack(referenced, request))
    }

    fn create_on_stack(
        referenced: Referenced,
        request: &OpenRequest,
    ) -> Result<(DeviceFile, u32), NtStatus> {
        let resolved = core::mem::ManuallyDrop::new(referenced).0;
        let device = resolved.device;
        let made = open_file_object(&resolved, request);
        let (file, context) = match made {
            Some(made) => made,
            None => {
                dereference_device(device);
                return Err(STATUS_INSUFFICIENT_RESOURCES);
            }
        };
        let outcome = call_driver(
            device,
            &Request {
                major: crate::dev::irp::IRP_MJ_CREATE,
                flags: IRP_CREATE_OPERATION | IRP_SYNCHRONOUS_API | IRP_DEFER_IO_COMPLETION,
                requestor_mode: USER_MODE,
                system_buffer: 0,
                user_buffer: 0,
                file_object: file,
                parameters: [
                    context,
                    request.disposition << 24 | request.options & 0x00FF_FFFF,
                    u32::from(request.file_attributes) | u32::from(request.share_access) << 16,
                    0,
                ],
            },
        );
        release(context);
        let refused = match outcome {
            Ok(outcome) if !nt_error(outcome.status) => None,
            Ok(outcome) => Some(outcome.status),
            Err(status) => Some(status),
        };
        if let Some(status) = refused {
            free_file_object(file);
            dereference_device(device);
            return Err(status);
        }
        let information = outcome.map_or(0, |outcome| outcome.information);
        let recorded = with_io(|io| {
            let (index, slot) = io
                .files
                .iter_mut()
                .enumerate()
                .find(|(_, slot)| !slot.live)?;
            slot.live = true;
            slot.generation = slot.generation.wrapping_add(1);
            slot.file_object = file;
            slot.device = device;
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
                free_file_object(file);
                dereference_device(device);
                Err(STATUS_TOO_MANY_OPENED_FILES)
            }
        }
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
    /// answers: a cleanup or a close cannot fail).
    fn send_close(device: u32, file: u32, major: u8) {
        let _ = call_driver(
            device,
            &Request {
                major,
                flags: IRP_CLOSE_OPERATION | IRP_SYNCHRONOUS_API,
                requestor_mode: KERNEL_MODE,
                system_buffer: 0,
                user_buffer: 0,
                file_object: file,
                parameters: [0; 4],
            },
        );
    }

    /// An open's cleanup, its last handle closed: IRP_MJ_CLEANUP.
    pub fn cleanup(file: DeviceFile) {
        on_driver_stack(|| cleanup_on_stack(file));
    }

    fn cleanup_on_stack(file: DeviceFile) {
        if let Some((object, device)) = open_of(file) {
            send_close(device, object, crate::dev::irp::IRP_MJ_CLEANUP);
        }
    }

    /// An open's close, its last reference gone: IRP_MJ_CLOSE, then its FILE_OBJECT and its
    /// reference on the device go.
    pub fn close(file: DeviceFile) {
        on_driver_stack(|| close_on_stack(file));
    }

    fn close_on_stack(file: DeviceFile) {
        let Some((object, device)) = open_of(file) else {
            return;
        };
        send_close(device, object, crate::dev::irp::IRP_MJ_CLOSE);
        with_io(|io| io.files[usize::from(file.index)].live = false);
        free_file_object(object);
        dereference_device(device);
    }

    /// IRP_MJ_DEVICE_CONTROL for `file`, METHOD_BUFFERED: the system buffer (the caller's block,
    /// `system`, holding the input; 0 with no buffers) and the lengths, the caller's output
    /// buffer the IRP's UserBuffer.
    pub fn device_control(
        file: DeviceFile,
        code: u32,
        system: u32,
        input_length: u32,
        output_length: u32,
        user_output: u32,
    ) -> Result<Outcome, NtStatus> {
        on_driver_stack(|| {
            control_on_stack(file, code, system, input_length, output_length, user_output)
        })
    }

    fn control_on_stack(
        file: DeviceFile,
        code: u32,
        system: u32,
        input_length: u32,
        output_length: u32,
        user_output: u32,
    ) -> Result<Outcome, NtStatus> {
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
        call_driver(
            device,
            &Request {
                major: crate::dev::irp::IRP_MJ_DEVICE_CONTROL,
                flags,
                requestor_mode: USER_MODE,
                system_buffer: system,
                user_buffer: if flags == 0 { 0 } else { user_output },
                file_object: object,
                parameters: [output_length, input_length, code, 0],
            },
        )
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
        const DEPTH: usize = 12;
        const UNITS: usize = 64;
        let mut path = [0u16; MAX_PATH];
        let length = registry_path_below_root(below, &mut path)?;
        let path = &path[..length];
        let mut stored = [[0u16; UNITS]; DEPTH];
        let mut lengths = [0usize; DEPTH];
        lengths[0] = ascii("REGISTRY", &mut stored[0]);
        let mut count = 1;
        let mut so_far = 0;
        for component in path.split(|&unit| unit == SEPARATOR) {
            so_far += component.len() + usize::from(count > 1);
            let spelled = stored.get_mut(count)?;
            let n = with_registry(|registry| {
                let key = registry.open(registry.root(), &path[..so_far]).ok()?;
                let info = registry.info(key).ok()?;
                let mut n = 0;
                for (slot, pair) in spelled.iter_mut().zip(info.name.as_chunks::<2>().0) {
                    *slot = u16::from_le_bytes([pair[0], pair[1]]);
                    n += 1;
                }
                Some(n)
            })?;
            lengths[count] = n;
            count += 1;
        }
        let mut parts: [&[u16]; DEPTH] = [&[]; DEPTH];
        for (index, part) in parts.iter_mut().enumerate().take(count) {
            *part = &stored[index][..lengths[index]];
        }
        registry_object_name(&parts[..count], out)
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
        on_driver_stack(|| load(units))
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
        let file = crate::nt::file::read_whole_file(image_path)?;
        let image = loader::map_driver_image(file.as_ref()).map_err(load_status)?;
        drop(file);
        let mut registry = [0u16; MAX_PATH];
        let registry_length = registry_path(&units[REGISTRY.len()..], &mut registry)
            .ok_or(STATUS_OBJECT_NAME_INVALID)?;
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
        // SAFETY: the driver's object (see `at`).
        if unsafe { at::<DriverObject>(driver.object) }.device_object != 0 {
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
        on_driver_stack(|| unload(units))
    }

    fn unload(units: &[u16]) -> Result<(), NtStatus> {
        let (_, own) = service_key(units)?;
        let name = driver_name(&own).ok_or(STATUS_OBJECT_NAME_INVALID)?;
        let slot = driver_named(&name).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        let object = with_io(|io| io.drivers[usize::from(slot)].map(|driver| driver.object))
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        // SAFETY: the driver's object (see `at`).
        let driver = unsafe { at::<DriverObject>(object) };
        if driver.driver_unload == 0 {
            return Err(STATUS_INVALID_DEVICE_REQUEST);
        }
        let mut device = driver.device_object;
        let mut hops = 0;
        while device != 0 && hops < 1024 {
            // SAFETY: a device on the driver's list.
            let object = unsafe { at::<DeviceObject>(device) };
            if object.reference_count > 0 {
                crate::dbgprint::unhandled(
                    "ntdll",
                    "NtUnloadDriver",
                    format_args!("DriverServiceName={}", Units(units)),
                    format_args!(
                        "an unload while a device of the driver is open (deferred to its last \
                         close) is not yet implemented"
                    ),
                );
                return Err(STATUS_NOT_IMPLEMENTED);
            }
            device = object.next_device;
            hops += 1;
        }
        // SAFETY: the driver's DriverUnload(DriverObject).
        let unload = unsafe { routine::<UnloadRoutine>(driver.driver_unload) };
        as_worker(|| unload(object));
        driver.flags |= DRVO_UNLOAD_INVOKED;
        forget_driver(slot);
        Ok(())
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
        with_registry(|registry| {
            let key = registry.open(registry.root(), &below[..length])?;
            let mut scratch = registry.scratch(data.len())?;
            scratch.bytes_mut().copy_from_slice(data);
            registry.set_value(key, value, kind, scratch, now)
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
    use super::*;

    fn wide(text: &str) -> std::vec::Vec<u16> {
        text.encode_utf16().collect()
    }

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
}
