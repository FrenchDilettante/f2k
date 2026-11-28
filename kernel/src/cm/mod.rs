//! The configuration manager: the registry, kept in kernel memory for the kernel's life (nothing is
//! saved to disk yet), which the key services (`nt::key`) open, read and change.
//!
//! The registry is a tree of keys, each holding named values of a type and some bytes. Names are
//! case-insensitive and case-preserving: a lookup folds both sides' units to upper case
//! (`rtl::text::upcase`), while a key or a value keeps the spelling it was made with. A key's
//! subkeys are listed in their folded names' order, as Windows 2000's hives index them; its values
//! in the order they were first set.
//!
//! Keys and values are records in slot pools ([`Slots`]) that grow a chunk at a time, as the
//! object manager's objects are, and a key is named by its record and the record's generation
//! ([`Key`]): a deleted key's record moves on to a new generation, so a key object still naming it
//! ([`KeyBody`]) finds it gone (STATUS_KEY_DELETED) rather than whatever reuses the record. What
//! bounds them is the u16 record index (65,535 keys, 65,535 values) and memory; the storage quota
//! below runs out long before either, since every key and value has a name.
//!
//! Names, classes and value data live in the registry's storage, taken from the nonpaged pool
//! ([`crate::mem::pool`]) as it grows, as Windows 2000 keeps its hives in pool memory: chunks of
//! [`CHUNK`] bytes, each a [`KernelHeap`], for names, classes and data up to [`SMALL_DATA`] bytes,
//! and pages of its own for larger data (a large value's data is a hive cell of its own on Windows
//! 2000 too). They are read through the registry, so no slice of them outlives its borrow. The
//! storage is bounded three ways, so that no one caller takes the registry from every other:
//!
//! - a value's data is at most [`MAX_VALUE_DATA`] bytes, 1 MiB, the documented limit for a value in
//!   Windows 2000's hive format ("1 MB (standard format)"); larger data is
//!   STATUS_INSUFFICIENT_RESOURCES, Windows 2000's answer to a hive cell it cannot allocate;
//! - the storage holds at most [`QUOTA_PAGES`] pages, 4 MiB, as Windows 2000's registry quota
//!   (RegistrySizeLimit) bounds its hives; a store past it is STATUS_INSUFFICIENT_RESOURCES;
//! - large data never takes the quota's last [`RESERVE_PAGES`], which are the chunks' alone: a
//!   registry filled with large values still takes a key, a name, a small value. Windows 2000 has
//!   no such reserve; it shows only in a registry some 4 MiB full.
//!
//! The registry's steps run at the high level, where the pool, high-level state of its own, is out
//! of reach: memory comes and goes between the steps. A store that finds no room in the chunks, or
//! no record left in its pool's chunks, says so ([`Registry::need`]), and its caller ([`storing`])
//! makes what it needs from the pool ([`Need::make`]), hands it in ([`Registry::supply`]) and runs
//! it again. A large value's data comes on the pages the service copied it into from its
//! caller, which become the value's; pages a value lets go wait ([`Registry::take_released`]) for
//! the caller to give them back after the step ([`settle`]). Chunks are kept for the kernel's life.
//! What a service copies in from its caller or out to it (a name, a class, an answer) is staged on
//! pages of its own, outside the storage, so no copy of the caller's memory runs inside the
//! registry, an answer however large cannot starve a store, and a full storage still answers.
//!
//! The registry is made at boot with the keys Windows 2000 has from its boot on, reduced
//! to what F2K needs: the root `\Registry`, the machine's and the users' roots under it (`MACHINE`
//! and `USER`, as Windows 2000 spells them), the current user's hive `\Registry\User\jeb`
//! (Windows names it after the user's SID), and the computer's name,
//! `\Registry\Machine\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`'s
//! `ComputerName`, REG_SZ "QEMU", and the scheduler's priority separation,
//! `\Registry\Machine\SYSTEM\CurrentControlSet\Control\PriorityControl`'s
//! `Win32PrioritySeparation`, REG_DWORD 2 (Windows 2000 Professional's default; see
//! `crate::process::foreground`), and the user's wait at a session's end,
//! `\Registry\User\jeb\Control Panel\Desktop`'s `WaitToKillAppTimeout`, REG_SZ "20000" (Windows
//! 2000's default, a string of digits as Windows keeps it; see `crate::session`, and its kernel
//! option `session-wait`, which a test boot gives to seed another wait). A hive's root
//! (`\Registry`, its two roots, `SYSTEM`, the user's hive) cannot be deleted.

use core::alloc::Layout;
use core::cmp::Ordering;
use core::ptr::NonNull;
#[cfg(target_arch = "x86")]
use core::sync::atomic::{AtomicU32, Ordering as Atomic};

use rtl::cstr::ascii_units;
use rtl::text::{cmp_ignore_case, eq_ignore_case};

#[cfg(target_arch = "x86")]
use crate::level::{self, High, LevelCell};
use crate::mem::heap::KernelHeap;
use crate::mem::paging::PAGE_SIZE;
use crate::mem::pool::pages_for;
use crate::slots::{per_page, Chunk, Codec, Match, Record, Reuse, Slots, KERNEL_PAGES};
use crate::status::*;

/// A chunk of the storage, in bytes: room for the longest name (32 KiB) with the largest small
/// data, so a fresh chunk holds what any one store puts in chunks.
pub const CHUNK: usize = 64 * 1024;
/// The largest data a chunk holds; larger data takes pages of its own.
pub const SMALL_DATA: usize = 16 * 1024;
/// The largest value's data, in bytes: 1 MiB (see the module notes).
pub const MAX_VALUE_DATA: usize = 1024 * 1024;
/// The most pages the storage holds: 4 MiB.
pub const QUOTA_PAGES: usize = 1024;
/// The quota's last pages, which large data never takes: four chunks.
pub const RESERVE_PAGES: usize = 4 * CHUNK_PAGES;
/// A chunk's pages.
const CHUNK_PAGES: usize = CHUNK / PAGE_SIZE as usize;
/// How many chunks the storage can hold: the quota's worth.
const CHUNKS: usize = QUOTA_PAGES / CHUNK_PAGES;
/// How many large values' data the storage can hold: the quota's worth, the smallest large data
/// taking five pages. The quota, not this table, is what runs out.
const LARGE: usize = QUOTA_PAGES / (SMALL_DATA / PAGE_SIZE as usize + 1);
/// The longest key name, in units: the documented limit, 255 characters.
pub const MAX_KEY_NAME: usize = 255;
/// The longest value name, in units: the documented limit, 16383 characters.
pub const MAX_VALUE_NAME: usize = 16383;

/// What separates a path's key names.
pub const SEPARATOR: u16 = b'\\' as u16;

/// REG_SZ: a value's type, a NUL-terminated string.
pub const REG_SZ: u32 = 1;

/// REG_DWORD: a value's type, a 32-bit number, little-endian.
pub const REG_DWORD: u32 = 4;

/// The key of the scheduler's priority separation, below the root.
pub const PRIORITY_CONTROL: &str = "MACHINE\\SYSTEM\\CurrentControlSet\\Control\\PriorityControl";

/// The priority separation's value (see `crate::process::foreground`).
pub const PRIORITY_SEPARATION: &str = "Win32PrioritySeparation";

/// The current user's desktop settings, below the root (HKCU\Control Panel\Desktop).
pub const DESKTOP: &str = "USER\\jeb\\Control Panel\\Desktop";

/// The wait a process has to end once a session's end asks it (see `crate::session`), in
/// milliseconds, written in decimal: a REG_SZ, as Windows 2000 keeps it.
pub const WAIT_TO_KILL_APP_TIMEOUT: &str = "WaitToKillAppTimeout";

/// A key: its record and the record's generation. The generation is 32 bits: a stale key would
/// name its record's new key only after some four billion deletes of that one record, where 16 bits
/// took 65,536.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Key {
    index: u16,
    generation: u32,
}

/// A key object's body: the key its open named (none in a pool's fresh record). The object lives
/// as long as its handles; the key may go first (a delete through another handle), which the
/// services find through [`Registry::check`].
#[derive(Clone, Copy, Debug)]
pub struct KeyBody {
    pub key: Option<Key>,
}

impl KeyBody {
    /// A record naming no key yet (a pool's fresh record).
    pub const fn none() -> Self {
        KeyBody { key: None }
    }

    /// The body of an open of `key`.
    pub const fn of(key: Key) -> Self {
        KeyBody { key: Some(key) }
    }
}

/// Pages of the nonpaged pool: a chunk of the storage, a large value's data, or what a service
/// stages. Dropping them gives them back to the pool, which only code outside the registry's
/// steps may do.
#[cfg(target_arch = "x86")]
pub use crate::mem::pool::Block as Pages;

/// Pages of the nonpaged pool (see the target's): on the host, a buffer of the heap's, 8-aligned
/// as a heap's pool must be.
#[cfg(not(target_arch = "x86"))]
pub struct Pages {
    words: std::boxed::Box<[u64]>,
    len: usize,
}

#[cfg(not(target_arch = "x86"))]
impl AsRef<[u8]> for Pages {
    fn as_ref(&self) -> &[u8] {
        // SAFETY: the words' bytes, `len` of them at most (the words are rounded up to it).
        unsafe { core::slice::from_raw_parts(self.words.as_ptr().cast(), self.len) }
    }
}

#[cfg(not(target_arch = "x86"))]
impl AsMut<[u8]> for Pages {
    fn as_mut(&mut self) -> &mut [u8] {
        // SAFETY: as in `as_ref`; the exclusive borrow makes this the only reference.
        unsafe { core::slice::from_raw_parts_mut(self.words.as_mut_ptr().cast(), self.len) }
    }
}

/// Fresh zeroed pages for `bytes` bytes (at least one): none when the pool has no room.
pub fn allocate(bytes: usize) -> Option<Pages> {
    #[cfg(target_arch = "x86")]
    {
        crate::mem::pool::allocate(bytes)
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let words = std::vec![0u64; bytes.max(1).div_ceil(8)].into_boxed_slice();
        Some(Pages { words, len: bytes })
    }
}

/// `pages`' bytes as UTF-16 units (pages start on a page, so aligned for them): a name a service
/// staged.
pub fn units(pages: &Pages) -> &[u16] {
    let bytes = pages.as_ref();
    // SAFETY: the pages' bytes, aligned for units (a pool block starts on a page, a host one on 8
    // bytes), `len / 2` units of them; the borrow of `pages` keeps them.
    unsafe { core::slice::from_raw_parts(bytes.as_ptr().cast(), bytes.len() / 2) }
}

/// `pages`, kept for the kernel's life: their bytes, which nothing gives back.
fn keep(pages: Pages) -> &'static mut [u8] {
    #[cfg(target_arch = "x86")]
    {
        let len = pages.as_ref().len();
        let at = pages.virtual_address() as *mut u8;
        core::mem::forget(pages);
        // SAFETY: the block's pages, mapped in every address space; forgotten, the block never
        // unmaps them, and nothing else names them.
        unsafe { core::slice::from_raw_parts_mut(at, len) }
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let len = pages.len;
        let words = std::boxed::Box::leak(pages.words);
        // SAFETY: the leaked words' bytes, `len` of them at most.
        unsafe { core::slice::from_raw_parts_mut(words.as_mut_ptr().cast(), len) }
    }
}

/// Where a blob lives: a chunk, or a large value's pages (by their slot).
#[derive(Clone, Copy)]
enum Home {
    Chunk(u8),
    Large(u16),
}

/// A block of the storage (none for an empty one): where a name, a class or a value's data lives.
/// The registry reads a live one's bytes through itself ([`Registry::bytes`]), so they are borrowed
/// for no longer than the registry is. A large value's data is named by its slot alone, its bytes
/// found through the pages the slot holds.
#[derive(Clone, Copy)]
struct Blob {
    /// A chunk's block's first byte; none for an empty blob or a large value's data.
    at: Option<NonNull<u8>>,
    bytes: u32,
    home: Home,
}

impl Blob {
    const EMPTY: Blob = Blob {
        at: None,
        bytes: 0,
        home: Home::Chunk(0),
    };

    /// A chunk's block's first byte; for an empty blob a dangling one, never read (the slices
    /// made of it are empty), aligned as a storage block is.
    fn start(self) -> *mut u8 {
        self.at
            .unwrap_or(NonNull::<u64>::dangling().cast())
            .as_ptr()
    }
}

/// A large value's data: its pages, and whether a value holds them still. Pages no value holds
/// wait for [`Registry::take_released`].
struct Large {
    pages: Option<Pages>,
    held: bool,
}

impl Large {
    const NONE: Large = Large {
        pages: None,
        held: false,
    };
}

/// The registry's records' ids: a slot's index alone, every lookup matching whatever lives there.
/// A key carries its own 32-bit generation ([`Key`]), which its record keeps; a value is found by
/// its key and its name, and no id of one outlives a step.
enum ByIndex {}

impl Codec for ByIndex {
    type Id = u32;

    const LANES: usize = 1;
    /// The u16 record index of [`Key`] and [`Value::key`]: 65,535 records of each kind, far more
    /// than the storage's quota names.
    const MAX_INDEX: u32 = 0xFFFE;
    const MAX_UNIQ: u16 = 0xFFFE;
    const RESERVED_LOW: u32 = 0;
    const REUSE: Reuse = Reuse::Fifo;

    fn encode(index: u32, _: u16) -> u32 {
        index
    }

    fn decode(id: u32) -> Option<(u32, Match)> {
        Some((id, Match::Any))
    }
}

/// One key's record. Its pool's slot says whether it lives; the generation stays across the
/// record's reuses.
#[derive(Clone, Copy)]
struct Node {
    generation: u32,
    /// The parent key's record (the root's is its own).
    parent: u16,
    /// A hive's root: never deleted.
    permanent: bool,
    /// Made with REG_OPTION_VOLATILE: its subkeys must be too.
    volatile: bool,
    name: Blob,
    class: Blob,
    /// When the key, its values or its list of subkeys last changed (a FILETIME).
    last_write: u64,
}

impl Node {
    const FRESH: Node = Node {
        generation: 0,
        parent: 0,
        permanent: false,
        volatile: false,
        name: Blob::EMPTY,
        class: Blob::EMPTY,
        last_write: 0,
    };
}

// SAFETY: `write_fresh` writes a whole record.
unsafe impl Record for Node {
    unsafe fn write_fresh(at: *mut Self, _: u32) {
        // SAFETY: the caller's contract.
        unsafe { at.write(Self::FRESH) };
    }
}

/// One value's record.
#[derive(Clone, Copy)]
struct Value {
    /// Its key's record.
    key: u16,
    /// When it was first set, among every value (the key lists its values in that order).
    order: u32,
    kind: u32,
    name: Blob,
    data: Blob,
}

impl Value {
    const FRESH: Value = Value {
        key: 0,
        order: 0,
        kind: 0,
        name: Blob::EMPTY,
        data: Blob::EMPTY,
    };
}

// SAFETY: `write_fresh` writes a whole record.
unsafe impl Record for Value {
    unsafe fn write_fresh(at: *mut Self, _: u32) {
        // SAFETY: the caller's contract.
        unsafe { at.write(Self::FRESH) };
    }
}

/// Keys to a chunk, and values: one page's worth each.
const NODES_PER_CHUNK: usize = per_page::<Node>();
const VALUES_PER_CHUNK: usize = per_page::<Value>();

type Nodes = Slots<Node, ByIndex, NODES_PER_CHUNK>;
type Values = Slots<Value, ByIndex, VALUES_PER_CHUNK>;

// Measured: 40-byte keys and 36-byte values on target, 85 and 93 to a page (the host's pointer is
// 8 bytes, its counts not pinned).
#[cfg(target_arch = "x86")]
const _: () = assert!(NODES_PER_CHUNK == 85 && VALUES_PER_CHUNK == 93);
const _: () = assert!(Nodes::CHUNK_PAGES == 1 && Values::CHUNK_PAGES == 1);

/// What a step found missing, for its caller to make outside the registry ([`Need::make`]) and
/// hand in ([`Registry::supply`]) before running it again.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Need {
    /// A chunk of the storage ([`CHUNK`] bytes): the quota has room for one.
    Storage,
    /// The key records' next chunk, by its number.
    Keys(u32),
    /// The value records' next chunk, by its number.
    Values(u32),
}

/// What [`Need::make`] made: a chunk of the storage, or a chunk of records with the directory pages
/// its publication takes.
pub struct Made(Supply);

enum Supply {
    Storage(Pages),
    Keys(Chunk<Node, NODES_PER_CHUNK>),
    Values(Chunk<Value, VALUES_PER_CHUNK>),
}

impl Need {
    /// Make what is needed, from the pool: outside the registry's steps. None when the pool has
    /// no room.
    pub fn make(self) -> Option<Made> {
        let supply = match self {
            Need::Storage => Supply::Storage(allocate(CHUNK)?),
            Need::Keys(number) => Supply::Keys(Chunk::make(number, &KERNEL_PAGES)?),
            Need::Values(number) => Supply::Values(Chunk::make(number, &KERNEL_PAGES)?),
        };
        Some(Made(supply))
    }
}

impl Made {
    /// What a registry starts with: its first chunk of the storage, and its first chunks of key
    /// and value records. None when the pool has no room (what was made given back).
    pub fn first() -> Option<[Made; 3]> {
        let storage = Need::Storage.make()?;
        let Some(keys) = Need::Keys(0).make() else {
            storage.give_back();
            return None;
        };
        let Some(values) = Need::Values(0).make() else {
            storage.give_back();
            keys.give_back();
            return None;
        };
        Some([storage, keys, values])
    }

    /// Give back what the registry refused ([`Registry::supply`]): outside the registry's steps.
    pub fn give_back(self) {
        match self.0 {
            Supply::Storage(pages) => drop(pages),
            Supply::Keys(chunk) => chunk.give_back(&KERNEL_PAGES),
            Supply::Values(chunk) => chunk.give_back(&KERNEL_PAGES),
        }
    }
}

/// What a key's information classes report about it (sizes in bytes). The name and the class are
/// their UTF-16 units' bytes, little-endian, as the storage holds them and the information
/// structures carry them.
pub struct KeyInfo<'a> {
    pub last_write: u64,
    pub name: &'a [u8],
    pub class: &'a [u8],
    pub subkeys: u32,
    pub max_subkey_name: u32,
    pub max_subkey_class: u32,
    pub values: u32,
    pub max_value_name: u32,
    pub max_value_data: u32,
}

/// What a value's information classes report about it; the name as [`KeyInfo`]'s.
pub struct ValueInfo<'a> {
    pub kind: u32,
    pub name: &'a [u8],
    pub data: &'a [u8],
}

/// A relative path's key names, checked: one trailing separator is ignored; an empty name
/// elsewhere (a doubled separator, a leading one) or one past [`MAX_KEY_NAME`] is
/// STATUS_OBJECT_NAME_INVALID. The empty path has no names.
pub fn components(path: &[u16]) -> Result<Components<'_>, NtStatus> {
    let path = path.strip_suffix(&[SEPARATOR]).unwrap_or(path);
    if !path.is_empty()
        && path
            .split(|&unit| unit == SEPARATOR)
            .any(|name| name.is_empty() || name.len() > MAX_KEY_NAME)
    {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    Ok(Components { rest: path })
}

/// A checked path's key names, first first (see [`components`]).
pub struct Components<'a> {
    rest: &'a [u16],
}

impl<'a> Iterator for Components<'a> {
    type Item = &'a [u16];

    fn next(&mut self) -> Option<&'a [u16]> {
        if self.rest.is_empty() {
            return None;
        }
        match self.rest.iter().position(|&unit| unit == SEPARATOR) {
            Some(at) => {
                let name = &self.rest[..at];
                self.rest = &self.rest[at + 1..];
                Some(name)
            }
            None => Some(core::mem::take(&mut self.rest)),
        }
    }
}

/// The registry: its keys, its values and their storage.
pub struct Registry {
    nodes: Nodes,
    values: Values,
    /// The storage's chunks, as they were added.
    chunks: [Option<KernelHeap>; CHUNKS],
    /// The large values' data, by slot.
    large: [Large; LARGE],
    /// The pages the storage holds: its chunks', and its large data's, let go or not.
    pages: usize,
    /// What the last step found missing: room in the chunks while the quota has room for
    /// another, or a chunk of records.
    need: Option<Need>,
    /// The next value's place in its key's order.
    next_order: u32,
}

// SAFETY: the registry owns what its blobs point at: the blocks of its own chunks, whose heaps were
// handed the only reference to their pages, and its records' chunks. Moving the registry to
// another thread moves that ownership with it; the pointers are just how the blobs and the pools
// name them.
unsafe impl Send for Registry {}

impl Registry {
    /// A registry with no key and no storage yet: a constant, so the kernel's is built at compile
    /// time, never on a stack ([`Registry::start`] makes it usable).
    pub const fn empty() -> Self {
        Registry {
            nodes: Slots::new(),
            values: Slots::new(),
            chunks: [const { None }; CHUNKS],
            large: [const { Large::NONE }; LARGE],
            pages: 0,
            need: None,
            next_order: 0,
        }
    }

    /// Give the registry its first chunks ([`Made::first`]), and the keys and the values it
    /// starts with (see the module notes).
    ///
    /// # Panics
    ///
    /// It was started already.
    pub fn start(&mut self, first: [Made; 3]) {
        assert!(self.pages == 0, "the registry started twice");
        for made in first {
            if self.supply(made).is_err() {
                unreachable!("an empty registry takes its first chunks");
            }
        }
        self.seed();
    }

    /// Take what a step needed ([`Registry::need`], [`Need::make`]); handed back when it is
    /// needed no more (another step took the room meanwhile, or the storage's quota has none),
    /// for the caller to give back outside the step ([`Made::give_back`]).
    pub fn supply(&mut self, made: Made) -> Result<(), Made> {
        match made.0 {
            Supply::Storage(pages) => self
                .add_chunk(pages)
                .map_err(|pages| Made(Supply::Storage(pages))),
            Supply::Keys(chunk) => self
                .nodes
                .adopt(chunk)
                .map_err(|refused| Made(Supply::Keys(refused.chunk))),
            Supply::Values(chunk) => self
                .values
                .adopt(chunk)
                .map_err(|refused| Made(Supply::Values(refused.chunk))),
        }
    }

    /// Take `chunk`, [`CHUNK`] bytes of fresh pages, into the storage for the kernel's life;
    /// handed back when the quota has no room for it.
    ///
    /// # Panics
    ///
    /// `chunk` is not [`CHUNK`] bytes.
    pub fn add_chunk(&mut self, chunk: Pages) -> Result<(), Pages> {
        assert_eq!(chunk.as_ref().len(), CHUNK, "a chunk's size");
        let slot = self.chunks.iter().position(Option::is_none);
        let Some(slot) = slot.filter(|_| self.pages + CHUNK_PAGES <= QUOTA_PAGES) else {
            return Err(chunk);
        };
        self.chunks[slot] = Some(KernelHeap::new(keep(chunk)));
        self.pages += CHUNK_PAGES;
        Ok(())
    }

    /// What the last step found missing, if anything: room in the storage's chunks while the
    /// quota has room for another ([`Registry::add_chunk`]), or a chunk of records. Asking clears
    /// it.
    pub fn need(&mut self) -> Option<Need> {
        self.need.take()
    }

    /// Whether `pool` has a record to hand out without a chunk made first; noting the chunk it
    /// needs ([`Registry::need`]) when it has not, as `need` names it.
    fn room<T: Record, const PER: usize>(
        pool: &Slots<T, ByIndex, PER>,
        need: &mut Option<Need>,
        wanted: fn(u32) -> Need,
    ) -> Result<(), NtStatus> {
        if pool.needs_chunk(0) {
            *need = Some(wanted(pool.next_chunk()));
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        Ok(())
    }

    /// Pages a large value's data held and let go since (the value deleted, or set anew), for the
    /// caller to give back to the pool outside the step; none when none wait.
    pub fn take_released(&mut self) -> Option<Pages> {
        let slot = self
            .large
            .iter_mut()
            .find(|slot| !slot.held && slot.pages.is_some())?;
        let pages = slot.pages.take()?;
        self.pages -= pages_for(pages.as_ref().len());
        Some(pages)
    }

    /// The pages the storage holds: its chunks', and its large data's (until they are taken back,
    /// [`Registry::take_released`]).
    pub fn pages(&self) -> usize {
        self.pages
    }

    /// The keys and the value the registry starts with.
    fn seed(&mut self) {
        let name = ascii_units::<8>("REGISTRY");
        let blob = self.store_units(&name).expect("the storage holds the seed");
        let (index, node) = self.nodes.allocate(0).expect("a chunk of key records");
        assert_eq!(index, 0, "the root's record");
        *node = Node {
            permanent: true,
            name: blob,
            ..Node::FRESH
        };
        let root = self.root();
        // Each key of the path, made in turn below the root.
        let make = |registry: &mut Registry, path: &str, permanent: bool| {
            let mut key = root;
            for name in path.split('\\') {
                let name = ascii_units::<32>(name);
                let length = name
                    .iter()
                    .position(|&unit| unit == 0)
                    .unwrap_or(name.len());
                key = registry
                    .create(key, &name[..length], &[], false, 0)
                    .expect("the registry holds the seed")
                    .0;
            }
            registry.node_mut(key.index).permanent = permanent;
            key
        };
        make(self, "MACHINE", true);
        make(self, "USER", true);
        make(self, "USER\\jeb", true);
        make(self, "MACHINE\\SYSTEM", true);
        let computer = make(
            self,
            "MACHINE\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName",
            false,
        );
        let name = ascii_units::<12>("ComputerName");
        let mut data = [0; 10];
        put_units(&mut data, &ascii_units::<5>("QEMU"));
        self.set_bytes(computer, &name, REG_SZ, &data, 0)
            .expect("the registry holds the seed");
        let priority = make(self, PRIORITY_CONTROL, false);
        let name = ascii_units::<23>(PRIORITY_SEPARATION);
        let data = crate::process::foreground::DEFAULT_PRIORITY_SEPARATION.to_le_bytes();
        self.set_bytes(priority, &name, REG_DWORD, &data, 0)
            .expect("the registry holds the seed");
        make(self, DESKTOP, false);
        self.set_decimal(
            DESKTOP,
            WAIT_TO_KILL_APP_TIMEOUT,
            crate::session::WAIT_TO_KILL_APP_TIMEOUT_MS,
        )
        .expect("the registry holds the seed");
    }

    /// Set the value `name` of the existing key `path` names below the root (both ASCII) to
    /// `number` written in decimal, a REG_SZ, as Windows 2000 keeps its desktop's numbers.
    pub fn set_decimal(&mut self, path: &str, name: &str, number: u32) -> Result<(), NtStatus> {
        let key = self.open(self.root(), &ascii_units::<128>(path)[..path.len()])?;
        let mut digits = [0u8; 10];
        let mut at = digits.len();
        let mut rest = number;
        loop {
            at -= 1;
            digits[at] = b'0' + (rest % 10) as u8;
            rest /= 10;
            if rest == 0 {
                break;
            }
        }
        // The digits, then the NUL, in UTF-16LE.
        let mut data = [0u8; 22];
        for (pair, &digit) in data.chunks_exact_mut(2).zip(&digits[at..]) {
            pair[0] = digit;
        }
        let length = (digits.len() - at + 1) * 2;
        self.set_bytes(
            key,
            &ascii_units::<64>(name)[..name.len()],
            REG_SZ,
            &data[..length],
            0,
        )
    }

    /// The REG_SZ value `name` of the key `path` names below the root (both ASCII), read as a
    /// decimal number, if it is one: its digits, up to its NUL or its end, nothing else.
    pub fn decimal(&self, path: &str, name: &str) -> Option<u32> {
        let key = self
            .open(self.root(), &ascii_units::<128>(path)[..path.len()])
            .ok()?;
        let value = self
            .query_value(key, &ascii_units::<64>(name)[..name.len()])
            .ok()?;
        if value.kind != REG_SZ {
            return None;
        }
        let units = value
            .data
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .take_while(|&unit| unit != 0);
        let mut number: Option<u32> = None;
        for unit in units {
            let digit = char::from_u32(u32::from(unit))?.to_digit(10)?;
            number = Some(number.unwrap_or(0).checked_mul(10)?.checked_add(digit)?);
        }
        number
    }

    /// The REG_DWORD value `name` of the key `path` names below the root (both ASCII), if it is
    /// one.
    pub fn dword(&self, path: &str, name: &str) -> Option<u32> {
        let key = self
            .open(self.root(), &ascii_units::<128>(path)[..path.len()])
            .ok()?;
        let value = self
            .query_value(key, &ascii_units::<64>(name)[..name.len()])
            .ok()?;
        let data: [u8; 4] = value.data.try_into().ok()?;
        (value.kind == REG_DWORD).then(|| u32::from_le_bytes(data))
    }

    /// `\Registry`, the root key.
    pub fn root(&self) -> Key {
        Key {
            index: 0,
            generation: self.nodes.get(0).map_or(0, |node| node.generation),
        }
    }

    /// The live record `index`.
    ///
    /// # Panics
    ///
    /// No key lives there.
    fn node(&self, index: u16) -> &Node {
        self.nodes.get(index.into()).expect("a live key's record")
    }

    /// [`Registry::node`], to change.
    fn node_mut(&mut self, index: u16) -> &mut Node {
        self.nodes
            .get_mut(index.into())
            .expect("a live key's record")
    }

    fn key(&self, index: u16) -> Key {
        Key {
            index,
            generation: self.node(index).generation,
        }
    }

    /// The record of `key`, while it lives; STATUS_KEY_DELETED once it is gone.
    pub fn check(&self, key: Key) -> Result<u16, NtStatus> {
        match self.nodes.get(key.index.into()) {
            Some(node) if node.generation == key.generation => Ok(key.index),
            _ => Err(STATUS_KEY_DELETED),
        }
    }

    /// The bytes of `blob`, one of this registry's live blocks.
    fn bytes(&self, blob: Blob) -> &[u8] {
        if let Home::Large(slot) = blob.home {
            let pages = self.large[slot as usize].pages.as_ref();
            return &pages.expect("a large value's pages").as_ref()[..blob.bytes as usize];
        }
        // SAFETY: a live block of this registry's chunks, `bytes` bytes long (or an empty slice):
        // the registry owns the storage, and its blocks change only through `&mut self`, so
        // they hold still for the borrow of `self` the slice keeps.
        unsafe { core::slice::from_raw_parts(blob.start(), blob.bytes as usize) }
    }

    /// The units of `blob`, one of this registry's live blocks of a chunk holding a name or a
    /// class.
    fn units(&self, blob: Blob) -> &[u16] {
        // SAFETY: as in `bytes`; a chunk's block is 8-aligned, so aligned for units, and holds
        // `bytes / 2` of them.
        unsafe { core::slice::from_raw_parts(blob.start().cast(), blob.bytes as usize / 2) }
    }

    /// A fresh block of `bytes` bytes in a chunk (none for none): STATUS_INSUFFICIENT_RESOURCES
    /// when no chunk has room, noting whether the quota has room for another
    /// ([`Registry::needs_chunk`]).
    fn reserve(&mut self, bytes: usize) -> Result<Blob, NtStatus> {
        self.need = None;
        if bytes == 0 {
            return Ok(Blob::EMPTY);
        }
        let layout =
            Layout::from_size_align(bytes, 8).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        for (index, chunk) in self.chunks.iter_mut().enumerate() {
            if let Some(at) = chunk.as_mut().and_then(|heap| heap.alloc(layout)) {
                return Ok(Blob {
                    at: Some(at),
                    bytes: bytes as u32,
                    home: Home::Chunk(index as u8),
                });
            }
        }
        if self.chunks.iter().any(Option::is_none) && self.pages + CHUNK_PAGES <= QUOTA_PAGES {
            self.need = Some(Need::Storage);
        }
        Err(STATUS_INSUFFICIENT_RESOURCES)
    }

    /// The bytes of `blob`, a fresh block of a chunk's, to fill.
    fn fill(&mut self, blob: Blob) -> &mut [u8] {
        // SAFETY: a live block of this registry's, `bytes` bytes long (or an empty slice), that no
        // record names yet: the exclusive borrow of `self` makes this the only reference to it.
        unsafe { core::slice::from_raw_parts_mut(blob.start(), blob.bytes as usize) }
    }

    /// `bytes` copied into a fresh block of a chunk's (see [`Registry::reserve`]).
    fn store(&mut self, bytes: &[u8]) -> Result<Blob, NtStatus> {
        let blob = self.reserve(bytes.len())?;
        self.fill(blob).copy_from_slice(bytes);
        Ok(blob)
    }

    /// `units` copied into a fresh block of a chunk's (see [`Registry::reserve`]).
    fn store_units(&mut self, units: &[u16]) -> Result<Blob, NtStatus> {
        let blob = self.reserve(2 * units.len())?;
        put_units(self.fill(blob), units);
        Ok(blob)
    }

    /// Give a block back: to its chunk, or a large value's pages to the ones waiting to go back to
    /// the pool ([`Registry::take_released`]).
    fn free(&mut self, blob: Blob) {
        match (blob.home, blob.at) {
            (Home::Chunk(index), Some(at)) => self.chunks[index as usize]
                .as_mut()
                .expect("a chunk the registry holds")
                .dealloc(at),
            (Home::Chunk(_), None) => {}
            (Home::Large(slot), _) => self.large[slot as usize].held = false,
        }
    }

    /// The live subkeys of record `parent`, in their records' order.
    fn children(&self, parent: u16) -> impl Iterator<Item = u16> + '_ {
        self.nodes
            .iter()
            .filter(move |&(index, node)| index != 0 && node.parent == parent)
            .map(|(index, _)| index as u16)
    }

    /// The name of record `index`.
    fn name(&self, index: u16) -> &[u16] {
        self.units(self.node(index).name)
    }

    /// The live subkey of record `parent` named `name`.
    fn child(&self, parent: u16, name: &[u16]) -> Option<u16> {
        self.children(parent)
            .find(|&index| eq_ignore_case(self.name(index), name))
    }

    /// The key `path` names below `from` ("" names `from` itself): STATUS_OBJECT_NAME_NOT_FOUND
    /// when a key on the way is missing.
    pub fn open(&self, from: Key, path: &[u16]) -> Result<Key, NtStatus> {
        let mut index = self.check(from)?;
        for name in components(path)? {
            index = self
                .child(index, name)
                .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        }
        Ok(self.key(index))
    }

    /// The key `path` names below `from`, made when its last name is missing (with `class`,
    /// `volatile` or not, at `now`), and whether it was: the keys on the way must exist
    /// (STATUS_OBJECT_NAME_NOT_FOUND), and a key made below a volatile one must be volatile
    /// (STATUS_CHILD_MUST_BE_VOLATILE). An existing key is opened whatever its volatility.
    pub fn create(
        &mut self,
        from: Key,
        path: &[u16],
        class: &[u16],
        volatile: bool,
        now: u64,
    ) -> Result<(Key, bool), NtStatus> {
        let mut index = self.check(from)?;
        let mut names = components(path)?.peekable();
        while let Some(name) = names.next() {
            match self.child(index, name) {
                Some(child) => index = child,
                None if names.peek().is_none() => {
                    if self.node(index).volatile && !volatile {
                        return Err(STATUS_CHILD_MUST_BE_VOLATILE);
                    }
                    return self
                        .make_key(index, name, class, volatile, now)
                        .map(|key| (key, true));
                }
                None => return Err(STATUS_OBJECT_NAME_NOT_FOUND),
            }
        }
        Ok((self.key(index), false))
    }

    /// A new key named `name` below record `parent`.
    fn make_key(
        &mut self,
        parent: u16,
        name: &[u16],
        class: &[u16],
        volatile: bool,
        now: u64,
    ) -> Result<Key, NtStatus> {
        Self::room(&self.nodes, &mut self.need, Need::Keys)?;
        let name = self.store_units(name)?;
        let class = match self.store_units(class) {
            Ok(class) => class,
            Err(status) => {
                self.free(name);
                return Err(status);
            }
        };
        // A chunk is made (`room`), so only the records' limit refuses.
        let Ok((index, node)) = self.nodes.allocate(0) else {
            self.free(name);
            self.free(class);
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        };
        *node = Node {
            generation: node.generation,
            parent,
            permanent: false,
            volatile,
            name,
            class,
            last_write: now,
        };
        self.node_mut(parent).last_write = now;
        Ok(self.key(index as u16))
    }

    /// Delete `key` with its values (at `now`): STATUS_CANNOT_DELETE for a key with subkeys or a
    /// hive's root. Its record moves on to a new generation, so its key objects find it gone.
    pub fn delete(&mut self, key: Key, now: u64) -> Result<(), NtStatus> {
        let index = self.check(key)?;
        let node = *self.node(index);
        if node.permanent || self.children(index).next().is_some() {
            return Err(STATUS_CANNOT_DELETE);
        }
        for slot in 0..self.values.high_water() {
            if self
                .values
                .get(slot)
                .is_some_and(|value| value.key == index)
            {
                self.drop_value(slot);
            }
        }
        self.free(node.name);
        self.free(node.class);
        *self.node_mut(index) = Node {
            generation: node.generation.wrapping_add(1),
            ..Node::FRESH
        };
        self.nodes.free(index.into());
        self.node_mut(node.parent).last_write = now;
        Ok(())
    }

    /// Subkey `position` of `key`, in the listing's order (its folded name's); none past the last.
    /// Siblings' names differ once folded, so the subkey at `position` is the one with exactly
    /// `position` siblings named before it.
    pub fn subkey(&self, key: Key, position: u32) -> Result<Option<Key>, NtStatus> {
        let index = self.check(key)?;
        let before = |child: u16| {
            self.children(index)
                .filter(|&other| {
                    cmp_ignore_case(self.name(other), self.name(child)) == Ordering::Less
                })
                .count()
        };
        Ok(self
            .children(index)
            .find(|&child| before(child) == position as usize)
            .map(|child| self.key(child)))
    }

    /// What the information classes report about `key`.
    pub fn info(&self, key: Key) -> Result<KeyInfo<'_>, NtStatus> {
        let index = self.check(key)?;
        let node = self.node(index);
        let mut info = KeyInfo {
            last_write: node.last_write,
            name: self.bytes(node.name),
            class: self.bytes(node.class),
            subkeys: 0,
            max_subkey_name: 0,
            max_subkey_class: 0,
            values: 0,
            max_value_name: 0,
            max_value_data: 0,
        };
        for child in self.children(index) {
            let child = self.node(child);
            info.subkeys += 1;
            info.max_subkey_name = info.max_subkey_name.max(child.name.bytes);
            info.max_subkey_class = info.max_subkey_class.max(child.class.bytes);
        }
        for (_, value) in self.values.iter().filter(|(_, value)| value.key == index) {
            info.values += 1;
            info.max_value_name = info.max_value_name.max(value.name.bytes);
            info.max_value_data = info.max_value_data.max(value.data.bytes);
        }
        Ok(info)
    }

    /// The live value of record `key` named `name`.
    fn find_value(&self, key: u16, name: &[u16]) -> Option<u32> {
        self.values
            .iter()
            .find(|(_, value)| value.key == key && eq_ignore_case(self.units(value.name), name))
            .map(|(slot, _)| slot)
    }

    /// The live value record `slot`.
    fn value(&self, slot: u32) -> &Value {
        self.values.get(slot).expect("a live value's record")
    }

    /// [`Registry::value`], to change.
    fn value_mut(&mut self, slot: u32) -> &mut Value {
        self.values.get_mut(slot).expect("a live value's record")
    }

    fn value_info(&self, slot: u32) -> ValueInfo<'_> {
        let value = self.value(slot);
        ValueInfo {
            kind: value.kind,
            name: self.bytes(value.name),
            data: self.bytes(value.data),
        }
    }

    /// The value of `key` named `name` (the empty name is the key's default value):
    /// STATUS_OBJECT_NAME_NOT_FOUND when it has none.
    pub fn query_value(&self, key: Key, name: &[u16]) -> Result<ValueInfo<'_>, NtStatus> {
        let index = self.check(key)?;
        let slot = self
            .find_value(index, name)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        Ok(self.value_info(slot))
    }

    /// Value `position` of `key`, in the order its values were first set; none past the last.
    pub fn value_at(&self, key: Key, position: u32) -> Result<Option<ValueInfo<'_>>, NtStatus> {
        let index = self.check(key)?;
        let mut after = None;
        let mut slot = None;
        for _ in 0..=position {
            slot = self
                .values
                .iter()
                .filter(|(_, value)| {
                    value.key == index && after.is_none_or(|after| value.order > after)
                })
                .min_by_key(|(_, value)| value.order)
                .map(|(slot, value)| (slot, value.order));
            match slot {
                Some((_, order)) => after = Some(order),
                None => return Ok(None),
            }
        }
        Ok(slot.map(|(slot, _)| self.value_info(slot)))
    }

    /// Set `key`'s value `name` to `data`'s bytes (none: no bytes), of type `kind` (at `now`): an
    /// existing value of the name takes the new type and data, keeping its place and spelling.
    /// Data up to [`SMALL_DATA`] bytes is copied into a chunk, its pages left to the caller; larger
    /// data's pages become the value's own, taken out of `data`. STATUS_INSUFFICIENT_RESOURCES for
    /// data past [`MAX_VALUE_DATA`], and for a store the storage has no room for (large data never
    /// taking the quota's reserve, [`RESERVE_PAGES`]). A value that cannot be set is left as it
    /// was, and `data` with the caller.
    pub fn set_value(
        &mut self,
        key: Key,
        name: &[u16],
        kind: u32,
        data: &mut Option<Pages>,
        now: u64,
    ) -> Result<(), NtStatus> {
        let length = data.as_ref().map_or(0, |pages| pages.as_ref().len());
        if length <= SMALL_DATA {
            let bytes = data.as_ref().map_or(&[][..], |pages| pages.as_ref());
            return self.set_bytes(key, name, kind, bytes, now);
        }
        if length > MAX_VALUE_DATA {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        let pages = pages_for(length);
        let slot = self
            .large
            .iter()
            .position(|slot| slot.pages.is_none())
            .filter(|_| self.pages + pages <= QUOTA_PAGES - RESERVE_PAGES)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        self.place_value(key, name, kind, now, |registry| {
            registry.large[slot] = Large {
                pages: Some(data.take().expect("the large data's pages")),
                held: true,
            };
            registry.pages += pages;
            Ok(Blob {
                at: None,
                bytes: length as u32,
                home: Home::Large(slot as u16),
            })
        })
    }

    /// [`Registry::set_value`] of `data`, at most [`SMALL_DATA`] bytes, copied into a chunk
    /// (STATUS_INSUFFICIENT_RESOURCES for more): what the kernel's own writes take.
    pub fn set_bytes(
        &mut self,
        key: Key,
        name: &[u16],
        kind: u32,
        data: &[u8],
        now: u64,
    ) -> Result<(), NtStatus> {
        if data.len() > SMALL_DATA {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        self.place_value(key, name, kind, now, |registry| registry.store(data))
    }

    /// [`Registry::set_value`]'s work, `data` making the value's data block once everything else
    /// the value needs is taken: nothing changes when either fails.
    fn place_value(
        &mut self,
        key: Key,
        name: &[u16],
        kind: u32,
        now: u64,
        data: impl FnOnce(&mut Self) -> Result<Blob, NtStatus>,
    ) -> Result<(), NtStatus> {
        let index = self.check(key)?;
        // The value's record, and its name if it is new: a new record is live from here on, its
        // data still empty.
        let (slot, fresh) = match self.find_value(index, name) {
            Some(slot) => (slot, None),
            None => {
                Self::room(&self.values, &mut self.need, Need::Values)?;
                let name = self.store_units(name)?;
                // A chunk is made (`room`), so only the records' limit refuses.
                let Ok((slot, value)) = self.values.allocate(0) else {
                    self.free(name);
                    return Err(STATUS_INSUFFICIENT_RESOURCES);
                };
                *value = Value {
                    key: index,
                    order: self.next_order,
                    kind,
                    name,
                    data: Blob::EMPTY,
                };
                (slot, Some(name))
            }
        };
        let data = match data(self) {
            Ok(data) => data,
            Err(status) => {
                if let Some(name) = fresh {
                    self.free(name);
                    self.values.free(slot);
                }
                return Err(status);
            }
        };
        if fresh.is_some() {
            self.next_order = self.next_order.wrapping_add(1);
        }
        let old = self.value(slot).data;
        self.free(old);
        let value = self.value_mut(slot);
        value.kind = kind;
        value.data = data;
        self.node_mut(index).last_write = now;
        Ok(())
    }

    /// Delete `key`'s value `name` (at `now`): STATUS_OBJECT_NAME_NOT_FOUND when it has none.
    pub fn delete_value(&mut self, key: Key, name: &[u16], now: u64) -> Result<(), NtStatus> {
        let index = self.check(key)?;
        let slot = self
            .find_value(index, name)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        self.drop_value(slot);
        self.node_mut(index).last_write = now;
        Ok(())
    }

    fn drop_value(&mut self, slot: u32) {
        let value = *self.value(slot);
        self.free(value.name);
        self.free(value.data);
        self.values.free(slot);
    }
}

/// `units` as their little-endian bytes into `out` (twice their length).
pub fn put_units(out: &mut [u8], units: &[u16]) {
    for (pair, &unit) in out.chunks_exact_mut(2).zip(units) {
        pair.copy_from_slice(&unit.to_le_bytes());
    }
}

// --- The kernel's registry ---------------------------------------------------------------------

/// The kernel's registry: started at boot ([`init`]), then reached by the key services one short
/// step at a time ([`with_registry`]).
///
/// No interrupt and no DPC reaches it: its callers are system services, which run with interrupts
/// masked. A step never waits, never touches its caller's memory (the services copy in before it
/// and out after it, through pages staged outside it) and never reaches other high-level state (the
/// clock's reading included). So it runs at the high level, through the bridge: each step masks
/// interrupts for its own length, as its callers have already, which keeps the interrupt exposure
/// as it was, and a step reaching the registry from inside another's borrow is refused. The pool
/// is such other state: the storage and the records' pools grow, and the storage shrinks, between
/// steps ([`storing`], [`settle`]).
// Note: Windows 2000 guards the registry with a passive-level lock of its own (an ERESOURCE, taken
// for the length of a registry call). That is the faithful protection, to adopt together with the
// object directory's lock.
#[cfg(target_arch = "x86")]
static REGISTRY: LevelCell<High, Registry> = LevelCell::new(Registry::empty());

/// The pages the kernel's registry's storage holds, as [`settle`] last counted them.
#[cfg(target_arch = "x86")]
static HELD: AtomicU32 = AtomicU32::new(0);

/// Start the kernel's registry: its first chunks, and the keys and the values it has from its boot
/// on. Once, at boot.
///
/// # Panics
///
/// The nonpaged pool has no room for the first chunks.
#[cfg(target_arch = "x86")]
pub fn init() {
    let first = Made::first().expect("the nonpaged pool holds the registry's first chunks");
    with_registry(|registry| registry.start(first));
    settle();
    if let Some(wait) = crate::session::option_wait() {
        storing(|registry| registry.set_decimal(DESKTOP, WAIT_TO_KILL_APP_TIMEOUT, wait))
            .expect("the registry holds the seed");
    }
}

/// The current user's WaitToKillAppTimeout (`DESKTOP`'s), read at each session's end as Windows
/// 2000's console server reads it; none when it is missing or no decimal number.
#[cfg(target_arch = "x86")]
pub fn wait_to_kill_app_timeout() -> Option<u32> {
    with_registry(|registry| registry.decimal(DESKTOP, WAIT_TO_KILL_APP_TIMEOUT))
}

/// Run `step`, a change to the kernel's registry, as a step: when it finds something missing (no
/// room in the storage's chunks while the quota has room for another, or no record left in its
/// pool's chunks), that is made from the pool between steps and `step` runs again (a fresh chunk
/// holds what one store puts in chunks). Then [`settle`].
#[cfg(target_arch = "x86")]
pub fn storing<R>(step: impl FnMut(&mut Registry) -> Result<R, NtStatus>) -> Result<R, NtStatus> {
    let result = supplied(&mut Kernel, step);
    settle();
    result
}

/// A way to a registry, one step at a time: the kernel's through the bridge ([`Kernel`]), or a
/// test's own.
#[cfg(any(target_arch = "x86", test))]
trait Reach {
    fn reach<R>(&mut self, step: impl FnOnce(&mut Registry) -> R) -> R;
}

/// The kernel's registry, through [`with_registry`].
#[cfg(target_arch = "x86")]
struct Kernel;

#[cfg(target_arch = "x86")]
impl Reach for Kernel {
    fn reach<R>(&mut self, step: impl FnOnce(&mut Registry) -> R) -> R {
        with_registry(step)
    }
}

/// How many times a step runs again for what it found missing: a step takes at most one record
/// and room in the storage, so it needs at most a chunk of records, then a chunk of the storage.
#[cfg(any(target_arch = "x86", test))]
const SUPPLIES: usize = 2;

/// `step` run on the registry `registry` reaches, and run again (at most [`SUPPLIES`] times) once
/// what it found missing is made outside it and handed in: [`storing`]'s work. What the registry
/// refuses (another step took the room meanwhile, or the quota has none) is given back outside it.
#[cfg(any(target_arch = "x86", test))]
fn supplied<R>(
    registry: &mut impl Reach,
    mut step: impl FnMut(&mut Registry) -> Result<R, NtStatus>,
) -> Result<R, NtStatus> {
    let mut result = registry.reach(&mut step);
    for _ in 0..SUPPLIES {
        if result.is_ok() {
            break;
        }
        let Some(made) = registry.reach(Registry::need).and_then(Need::make) else {
            break;
        };
        if let Err(made) = registry.reach(|registry| registry.supply(made)) {
            made.give_back();
            break;
        }
        result = registry.reach(&mut step);
    }
    result
}

/// Give the pages the kernel's registry let go back to the pool, and count the pages its storage
/// holds ([`held_frames`]): after each step that may let pages go, outside the registry.
#[cfg(target_arch = "x86")]
pub fn settle() {
    while let Some(pages) = with_registry(Registry::take_released) {
        drop(pages);
    }
    HELD.store(
        with_registry(|registry| registry.pages()) as u32,
        Atomic::Relaxed,
    );
}

/// The frames the kernel's registry's storage holds: allocations that outlive the process that
/// made them, which the teardown audits count with the free frames.
#[cfg(target_arch = "x86")]
pub fn held_frames() -> u32 {
    HELD.load(Atomic::Relaxed)
}

/// Run `step` on the kernel's registry (see [`REGISTRY`]), through the bridge to the high level.
///
/// # Panics
///
/// The processor is already at the high level: `step`, or code it calls, reaching the registry
/// again from inside its own borrow, or the caller holding other high-level state.
#[cfg(target_arch = "x86")]
pub fn with_registry<R>(step: impl FnOnce(&mut Registry) -> R) -> R {
    level::raised::<High, _>(|high| step(REGISTRY.get(high)))
}

/// The registry's Win32PrioritySeparation (`PriorityControl`'s), read at boot as Windows 2000's
/// kernel reads it (its control vector, into PsRawPrioritySeparation); the Professional default
/// when it is missing or no REG_DWORD.
#[cfg(target_arch = "x86")]
pub fn priority_separation() -> u32 {
    with_registry(|registry| registry.dword(PRIORITY_CONTROL, PRIORITY_SEPARATION))
        .unwrap_or(crate::process::foreground::DEFAULT_PRIORITY_SEPARATION)
}

/// Flush the hives to their files, the shutdown's step before the file systems are done, as
/// Windows 2000's kernel flushes them when it shuts down. Nothing to write yet: the hives live in
/// kernel memory alone, none of them on disk.
pub fn flush_hives() {}

#[cfg(test)]
mod tests {
    //! The registry's tree over a registry of the tests' own: names, the listing's order, deletes
    //! and their stale keys, values.

    use rtl::testing::wide;

    use super::*;

    fn registry() -> &'static mut Registry {
        let registry = Box::leak(Box::new(Registry::empty()));
        registry.start(Made::first().unwrap());
        registry
    }

    /// `bytes` on fresh pages, as a service stages a value's data (none for none).
    fn data(bytes: &[u8]) -> Option<Pages> {
        (!bytes.is_empty()).then(|| {
            let mut pages = allocate(bytes.len()).unwrap();
            pages.as_mut().copy_from_slice(bytes);
            pages
        })
    }

    /// The tests' registry, reached directly.
    impl Reach for &mut Registry {
        fn reach<R>(&mut self, step: impl FnOnce(&mut Registry) -> R) -> R {
            step(self)
        }
    }

    /// `step` as the kernel's `storing` runs it: again with what it found missing; the pages let
    /// go taken back after.
    fn storing<R>(
        mut r: &mut Registry,
        step: impl FnMut(&mut Registry) -> Result<R, NtStatus>,
    ) -> Result<R, NtStatus> {
        let result = supplied(&mut r, step);
        while r.take_released().is_some() {}
        result
    }

    impl Made {
        fn is_keys(&self) -> bool {
            matches!(self.0, Supply::Keys(_))
        }
    }

    impl Registry {
        /// Whether every chunk's heap holds together.
        fn audit(&self) -> bool {
            self.chunks
                .iter()
                .flatten()
                .all(|heap| heap.audit().is_ok())
        }
    }

    /// A reported name's text, from its little-endian bytes.
    fn text(bytes: &[u8]) -> String {
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        String::from_utf16(&units).unwrap()
    }

    /// A number set in decimal reads back; a value that is no REG_SZ of digits alone reads as none.
    #[test]
    fn decimal_values() {
        let r = registry();
        for number in [0, 200, 20_000, u32::MAX] {
            r.set_decimal(DESKTOP, WAIT_TO_KILL_APP_TIMEOUT, number)
                .unwrap();
            assert_eq!(r.decimal(DESKTOP, WAIT_TO_KILL_APP_TIMEOUT), Some(number));
        }
        let desktop = r
            .open(r.root(), &wide("USER\\jeb\\Control Panel\\Desktop"))
            .unwrap();
        let name = wide("WaitToKillAppTimeout");
        for bad in [
            &b"2\0x\0\0\0"[..],
            b"\0\0",
            b"4\02\09\04\09\06\07\02\09\06\0\0\0",
        ] {
            r.set_bytes(desktop, &name, REG_SZ, bad, 0).unwrap();
            assert_eq!(
                r.decimal(DESKTOP, WAIT_TO_KILL_APP_TIMEOUT),
                None,
                "{bad:?}"
            );
        }
        r.set_bytes(desktop, &name, REG_DWORD, &200u32.to_le_bytes(), 0)
            .unwrap();
        assert_eq!(r.decimal(DESKTOP, WAIT_TO_KILL_APP_TIMEOUT), None);
        assert_eq!(
            r.set_decimal("USER\\jeb\\Missing", WAIT_TO_KILL_APP_TIMEOUT, 1),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
    }

    #[test]
    fn the_seed_is_there() {
        let r = registry();
        let root = r.root();
        assert_eq!(text(r.info(root).unwrap().name), "REGISTRY");
        let user = r.open(root, &wide("user\\JEB")).unwrap();
        assert_eq!(text(r.info(user).unwrap().name), "jeb");
        let name = r
            .open(
                root,
                &wide("Machine\\System\\CurrentControlSet\\Control\\ComputerName\\ComputerName"),
            )
            .unwrap();
        let value = r.query_value(name, &wide("computername")).unwrap();
        assert_eq!(value.kind, REG_SZ);
        assert_eq!(value.data, b"Q\0E\0M\0U\0\0\0");
        let priority = r
            .open(
                root,
                &wide("Machine\\System\\CurrentControlSet\\Control\\PriorityControl"),
            )
            .unwrap();
        let value = r
            .query_value(priority, &wide("Win32PrioritySeparation"))
            .unwrap();
        assert_eq!((value.kind, value.data), (REG_DWORD, &[2, 0, 0, 0][..]));
        assert_eq!(r.dword(PRIORITY_CONTROL, PRIORITY_SEPARATION), Some(2));
        assert_eq!(r.dword(PRIORITY_CONTROL, "Missing"), None);
        let desktop = r
            .open(root, &wide("user\\jeb\\control panel\\desktop"))
            .unwrap();
        let value = r
            .query_value(desktop, &wide("waittokillapptimeout"))
            .unwrap();
        assert_eq!(value.kind, REG_SZ);
        assert_eq!(value.data, b"2\00\00\00\00\0\0\0");
        assert_eq!(r.decimal(DESKTOP, WAIT_TO_KILL_APP_TIMEOUT), Some(20_000));
        assert_eq!(
            r.delete(user, 0),
            Err(STATUS_CANNOT_DELETE),
            "a hive's root stays"
        );
        let machine = r.open(root, &wide("MACHINE")).unwrap();
        assert_eq!(
            r.subkey(machine, 0).unwrap(),
            Some(r.open(machine, &wide("SYSTEM")).unwrap())
        );
        assert_eq!(r.subkey(machine, 1).unwrap(), None);
    }

    #[test]
    fn names_fold_case_and_keep_their_spelling() {
        let r = registry();
        let user = r.open(r.root(), &wide("USER\\jeb")).unwrap();
        let (made, created) = r.create(user, &wide("Software"), &[], false, 1).unwrap();
        assert!(created);
        let (again, created) = r.create(user, &wide("SOFTWARE"), &[], false, 2).unwrap();
        assert_eq!((again, created), (made, false));
        assert_eq!(text(r.info(again).unwrap().name), "Software");
        assert_eq!(
            r.open(user, &wide("software\\")).unwrap(),
            made,
            "a trailing separator"
        );
        assert_eq!(r.open(user, &wide("")).unwrap(), user, "the empty path");
        assert_eq!(
            r.open(user, &wide("\\software")),
            Err(STATUS_OBJECT_NAME_INVALID)
        );
        assert_eq!(
            r.open(user, &wide("a\\\\b")),
            Err(STATUS_OBJECT_NAME_INVALID)
        );
        assert_eq!(
            r.open(user, &wide("Missing\\x")),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(
            r.create(user, &wide("Missing\\x"), &[], false, 0),
            Err(STATUS_OBJECT_NAME_NOT_FOUND),
            "the keys on the way exist"
        );
        let long = vec![b'k' as u16; MAX_KEY_NAME + 1];
        assert_eq!(
            r.create(user, &long, &[], false, 0),
            Err(STATUS_OBJECT_NAME_INVALID)
        );
    }

    /// Beyond Latin-1's block too: ÿ, œ, š and ž fold to Ÿ, Œ, Š and Ž (NT's upcase rule), so a
    /// key named with one is opened by the other case.
    #[test]
    fn names_fold_the_letters_beyond_latin_1() {
        let r = registry();
        let user = r.open(r.root(), &wide("USER\\jeb")).unwrap();
        let (made, created) = r.create(user, &wide("Mašina"), &[], false, 0).unwrap();
        assert!(created);
        assert_eq!(r.open(user, &wide("MAŠINA")).unwrap(), made);
        let (again, created) = r.create(user, &wide("MAŠINA"), &[], false, 0).unwrap();
        assert_eq!((again, created), (made, false));
        assert_eq!(
            r.open(user, &wide("Masina")),
            Err(STATUS_OBJECT_NAME_NOT_FOUND),
            "s is not š"
        );
        let (made, _) = r.create(user, &wide("œÿž"), &[], false, 0).unwrap();
        assert_eq!(r.open(user, &wide("ŒŸŽ")).unwrap(), made);
    }

    #[test]
    fn subkeys_list_in_folded_order() {
        let r = registry();
        let jeb = r.open(r.root(), &wide("USER\\jeb")).unwrap();
        // A key of the test's own: the user's hive holds the seed's keys.
        let (user, _) = r.create(jeb, &wide("List"), &[], false, 0).unwrap();
        for name in ["delta", "Alpha", "charlie", "bravo", "Echo"] {
            r.create(user, &wide(name), &[], false, 0).unwrap();
        }
        let listed: Vec<String> = (0..)
            .map_while(|position| r.subkey(user, position).unwrap())
            .map(|key| text(r.info(key).unwrap().name))
            .collect();
        assert_eq!(listed, ["Alpha", "bravo", "charlie", "delta", "Echo"]);
        let info = r.info(user).unwrap();
        assert_eq!((info.subkeys, info.max_subkey_name), (5, 14));
    }

    #[test]
    fn a_deleted_key_is_gone_for_its_holders() {
        let r = registry();
        let user = r.open(r.root(), &wide("USER\\jeb")).unwrap();
        let (a, _) = r.create(user, &wide("a"), &[], false, 0).unwrap();
        let (b, _) = r.create(a, &wide("b"), &[], false, 0).unwrap();
        assert_eq!(
            r.delete(a, 0),
            Err(STATUS_CANNOT_DELETE),
            "a key with a subkey"
        );
        r.set_value(b, &wide("x"), REG_SZ, &mut data(&[0, 0]), 0)
            .unwrap();
        r.delete(b, 0).unwrap();
        assert_eq!(r.check(b), Err(STATUS_KEY_DELETED));
        assert_eq!(r.query_value(b, &wide("x")).err(), Some(STATUS_KEY_DELETED));
        assert_eq!(
            r.create(b, &wide("c"), &[], false, 0).err(),
            Some(STATUS_KEY_DELETED)
        );
        assert_eq!(r.subkey(b, 0).err(), Some(STATUS_KEY_DELETED));
        assert_eq!(r.delete(b, 0), Err(STATUS_KEY_DELETED));
        // The name made anew is another key, even in the same record.
        let (again, created) = r.create(a, &wide("b"), &[], false, 0).unwrap();
        assert!(created);
        assert_ne!(again, b);
        assert_eq!(r.check(b), Err(STATUS_KEY_DELETED));
        r.delete(again, 0).unwrap();
        r.delete(a, 0).unwrap();
    }

    #[test]
    fn values_set_replace_and_list_in_order() {
        let r = registry();
        let user = r.open(r.root(), &wide("USER\\jeb")).unwrap();
        let set = |r: &mut Registry, name: &str, kind: u32, bytes: &[u8]| {
            r.set_value(user, &wide(name), kind, &mut data(bytes), 5)
                .unwrap()
        };
        set(r, "one", 4, &[1, 0, 0, 0]);
        set(r, "", REG_SZ, b"d\0\0\0");
        set(r, "Two", 3, &[]);
        set(r, "ONE", 3, &[9, 9]);
        let one = r.query_value(user, &wide("one")).unwrap();
        assert_eq!(
            (one.kind, one.data, text(one.name)),
            (3, &[9u8, 9][..], "one".into())
        );
        assert_eq!(r.query_value(user, &wide("")).unwrap().data, b"d\0\0\0");
        assert_eq!(r.query_value(user, &wide("two")).unwrap().data, b"");
        let order: Vec<String> = (0..)
            .map_while(|position| r.value_at(user, position).unwrap())
            .map(|value| text(value.name))
            .collect();
        assert_eq!(order, ["one", "", "Two"]);
        let info = r.info(user).unwrap();
        assert_eq!(
            (info.values, info.max_value_name, info.max_value_data),
            (3, 6, 4)
        );
        r.delete_value(user, &wide("TWO"), 6).unwrap();
        assert_eq!(
            r.query_value(user, &wide("Two")).err(),
            Some(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(
            r.delete_value(user, &wide("Two"), 6),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(r.info(user).unwrap().last_write, 6);
        // A failed set leaves the value as it was, and gives its data back.
        let (gone, _) = r.create(user, &wide("gone"), &[], false, 7).unwrap();
        r.delete(gone, 7).unwrap();
        let mut kept = data(&[1, 2, 3, 4]);
        assert_eq!(
            r.set_value(gone, &wide("one"), 1, &mut kept, 7),
            Err(STATUS_KEY_DELETED)
        );
        assert!(kept.is_some(), "the data stays the caller's");
        assert_eq!(r.query_value(user, &wide("one")).unwrap().data, &[9, 9]);
        assert!(r.audit());
    }

    /// A value's data is 1 MiB at most; past it, nothing changes and the pages stay the caller's.
    #[test]
    fn a_value_holds_a_megabyte_at_most() {
        let r = registry();
        let user = r.open(r.root(), &wide("USER\\jeb")).unwrap();
        let mut over = data(&vec![7; MAX_VALUE_DATA + 1]);
        assert_eq!(
            r.set_value(user, &wide("big"), 3, &mut over, 0),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );
        assert!(over.is_some(), "the pages stay the caller's");
        assert_eq!(
            r.query_value(user, &wide("big")).err(),
            Some(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        let mut most = data(&vec![7; MAX_VALUE_DATA]);
        r.set_value(user, &wide("big"), 3, &mut most, 0).unwrap();
        assert!(most.is_none(), "the value's own pages");
        let value = r.query_value(user, &wide("BIG")).unwrap();
        assert!(value.data.len() == MAX_VALUE_DATA && value.data.iter().all(|&b| b == 7));
        assert_eq!(
            r.set_bytes(user, &wide("b"), 3, &[0; SMALL_DATA + 1], 0),
            Err(STATUS_INSUFFICIENT_RESOURCES),
            "the kernel's own writes are small"
        );
    }

    /// Small data lives in a chunk; larger data on pages of its own, which go back once no value
    /// holds them.
    #[test]
    fn large_data_has_pages_of_its_own_until_let_go() {
        let r = registry();
        let user = r.open(r.root(), &wide("USER\\jeb")).unwrap();
        let before = r.pages();
        r.set_value(user, &wide("small"), 3, &mut data(&[1; SMALL_DATA]), 0)
            .unwrap();
        assert_eq!(r.pages(), before, "in the chunk");
        let large: Vec<u8> = (0..=SMALL_DATA).map(|i| i as u8).collect();
        r.set_value(user, &wide("large"), 3, &mut data(&large), 0)
            .unwrap();
        assert_eq!(r.pages(), before + 5);
        assert_eq!(
            r.query_value(user, &wide("LARGE")).unwrap().data,
            &large[..]
        );
        assert!(r.take_released().is_none());
        // Set anew, small: its pages are let go.
        r.set_value(user, &wide("large"), 3, &mut data(&[1]), 1)
            .unwrap();
        assert_eq!(r.take_released().unwrap().as_ref().len(), large.len());
        assert!(r.take_released().is_none());
        assert_eq!(r.pages(), before);
        // Deleted with its key, and with the value alone.
        let (k, _) = r.create(user, &wide("k"), &[], false, 0).unwrap();
        r.set_value(k, &wide("x"), 3, &mut data(&large), 0).unwrap();
        r.set_value(k, &wide("y"), 3, &mut data(&large), 0).unwrap();
        r.delete_value(k, &wide("y"), 0).unwrap();
        assert!(r.take_released().is_some());
        r.delete(k, 0).unwrap();
        assert!(r.take_released().is_some());
        assert_eq!(r.pages(), before);
        assert!(r.audit());
    }

    /// A store finding no room in the chunks asks for one, and takes it.
    #[test]
    fn a_store_with_no_room_asks_for_a_chunk() {
        let r = registry();
        let user = r.open(r.root(), &wide("USER\\jeb")).unwrap();
        let mut n = 0;
        let refused = loop {
            let name = wide(&n.to_string());
            match r.set_value(user, &name, 3, &mut data(&[0; SMALL_DATA]), 0) {
                Ok(()) => n += 1,
                Err(status) => break status,
            }
        };
        assert_eq!(refused, STATUS_INSUFFICIENT_RESOURCES);
        assert_eq!(r.need(), Some(Need::Storage));
        assert_eq!(r.need(), None, "asking clears it");
        assert!(r.add_chunk(allocate(CHUNK).unwrap()).is_ok());
        r.set_value(
            user,
            &wide(&n.to_string()),
            3,
            &mut data(&[0; SMALL_DATA]),
            0,
        )
        .unwrap();
        assert!(r.audit());
    }

    /// One caller filling the registry with large values leaves the reserve to every other: a
    /// key, small values. The chunks themselves stop at the quota.
    #[test]
    fn one_caller_filling_the_registry_leaves_room_for_another() {
        let r = registry();
        let user = r.open(r.root(), &wide("USER\\jeb")).unwrap();
        let (hog, _) = r.create(user, &wide("hog"), &[], false, 0).unwrap();
        let fill = |r: &mut Registry, size: usize| {
            let mut count = 0;
            loop {
                let name = wide(&format!("{size}-{count}"));
                let mut big = data(&vec![0xAB; size]);
                match storing(r, |r| r.set_value(hog, &name, 3, &mut big, 0)) {
                    Ok(()) => count += 1,
                    Err(status) => {
                        assert_eq!(status, STATUS_INSUFFICIENT_RESOURCES);
                        return count;
                    }
                }
            }
        };
        assert_eq!(fill(r, MAX_VALUE_DATA), 3, "4 MiB less the reserve");
        fill(r, SMALL_DATA + 1);
        assert!(r.pages() > QUOTA_PAGES - RESERVE_PAGES - 5);
        // Another caller: a key and small values, past what the chunk held already.
        let (other, created) =
            storing(r, |r| r.create(user, &wide("other"), &[], false, 0)).unwrap();
        assert!(created);
        let held = r.pages();
        for n in 0..8 {
            let name = wide(&n.to_string());
            storing(r, |r| {
                r.set_value(other, &name, 3, &mut data(&[1; SMALL_DATA]), 0)
            })
            .unwrap();
        }
        assert!(r.pages() > held, "new chunks, from the reserve");
        // Small values fill the rest; the chunks stop at the quota.
        let mut n = 8;
        let refused = loop {
            let name = wide(&n.to_string());
            match storing(r, |r| {
                r.set_value(other, &name, 3, &mut data(&[1; SMALL_DATA]), 0)
            }) {
                Ok(()) => n += 1,
                Err(status) => break status,
            }
        };
        assert_eq!(refused, STATUS_INSUFFICIENT_RESOURCES);
        assert!(r.pages() <= QUOTA_PAGES);
        assert_eq!(r.need(), None, "no room for another chunk");
        assert!(r.audit());
    }

    /// Keys and values have no cap but their u16 index and memory: a step finding no record left
    /// in its pool's chunks names the chunk it needs, changes nothing, and runs again once the
    /// chunk is handed in, past the 512 keys and 1,024 values the fixed pools held.
    #[test]
    fn keys_and_values_grow_a_chunk_at_a_time() {
        let r = registry();
        let jeb = r.open(r.root(), &wide("USER\\jeb")).unwrap();
        let (many, _) = r.create(jeb, &wide("Many"), &[], false, 0).unwrap();
        // Fill the key records' chunks made so far.
        let mut n = 0;
        while !r.nodes.needs_chunk(0) {
            r.create(many, &wide(&format!("k{n}")), &[], false, 0)
                .unwrap();
            n += 1;
        }
        let pages = r.pages();
        let name = wide(&format!("k{n}"));
        assert_eq!(
            r.create(many, &name, &[], false, 0),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );
        assert_eq!(r.need(), Some(Need::Keys(r.nodes.next_chunk())));
        assert_eq!(r.open(many, &name), Err(STATUS_OBJECT_NAME_NOT_FOUND));
        assert_eq!(r.pages(), pages, "no name stored");
        // A chunk not the next one goes back whole.
        let stale = Need::Keys(r.nodes.next_chunk() + 1).make().unwrap();
        let refused = r.supply(stale).unwrap_err();
        assert!(refused.is_keys());
        refused.give_back();
        assert!(
            storing(r, |r| r.create(many, &name, &[], false, 0))
                .unwrap()
                .1
        );
        // The values' pool the same way, a large value's pages staying the caller's while its
        // record waits for a chunk.
        while !r.values.needs_chunk(0) {
            n += 1;
            r.set_value(many, &wide(&format!("v{n}")), 3, &mut data(&[1]), 0)
                .unwrap();
        }
        let mut large = data(&[7; SMALL_DATA + 1]);
        assert_eq!(
            r.set_value(many, &wide("large"), 3, &mut large, 0),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );
        assert!(large.is_some(), "the pages stay the caller's");
        assert_eq!(r.need(), Some(Need::Values(r.values.next_chunk())));
        storing(r, |r| r.set_value(many, &wide("large"), 3, &mut large, 0)).unwrap();
        assert!(large.is_none());
        // Past the old caps, through `storing`.
        for k in 0..600 {
            storing(r, |r| {
                r.create(many, &wide(&format!("x{k}")), &[], false, 0)
            })
            .unwrap();
        }
        for v in 0..1100 {
            let name = wide(&format!("y{v}"));
            storing(r, |r| {
                r.set_value(many, &name, 4, &mut data(&[1, 0, 0, 0]), 0)
            })
            .unwrap();
        }
        assert!(r.nodes.live() > 600 && r.values.live() > 1100);
        let info = r.info(many).unwrap();
        assert!(info.subkeys > 600 && info.values > 1100);
        assert_eq!(
            r.query_value(many, &wide("LARGE")).unwrap().data,
            &[7; SMALL_DATA + 1][..]
        );
        // Deleting the subkeys and the key frees their records for the next.
        let live = r.nodes.live();
        for k in 0..600 {
            let key = r.open(many, &wide(&format!("x{k}"))).unwrap();
            r.delete(key, 0).unwrap();
        }
        assert_eq!(r.nodes.live(), live - 600);
        assert!(r.audit());
    }

    /// A volatile key's subkeys must be volatile; a non-volatile key's may be either, and an
    /// existing key opens whatever the option.
    #[test]
    fn a_volatile_keys_subkeys_are_volatile() {
        let r = registry();
        let user = r.open(r.root(), &wide("USER\\jeb")).unwrap();
        let (volatile, _) = r.create(user, &wide("v"), &[], true, 0).unwrap();
        assert_eq!(
            r.create(volatile, &wide("lasting"), &[], false, 0),
            Err(STATUS_CHILD_MUST_BE_VOLATILE)
        );
        assert_eq!(
            r.open(volatile, &wide("lasting")),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        let (inner, created) = r.create(volatile, &wide("passing"), &[], true, 0).unwrap();
        assert!(created);
        assert_eq!(
            r.create(user, &wide("V"), &[], false, 0),
            Ok((volatile, false)),
            "an existing key opens"
        );
        let (lasting, _) = r.create(user, &wide("lasting"), &[], false, 0).unwrap();
        assert!(r.create(lasting, &wide("passing"), &[], true, 0).unwrap().1);
        r.delete(inner, 0).unwrap();
    }

    /// A record deleted more often than a 16-bit generation counts still finds its first key gone.
    #[test]
    fn a_stale_key_outlives_many_reuses_of_its_record() {
        let r = registry();
        let user = r.open(r.root(), &wide("USER\\jeb")).unwrap();
        let (first, _) = r.create(user, &wide("k"), &[], false, 0).unwrap();
        r.delete(first, 0).unwrap();
        for _ in 0..=u16::MAX as u32 {
            let (again, _) = r.create(user, &wide("k"), &[], false, 0).unwrap();
            r.delete(again, 0).unwrap();
        }
        let (last, _) = r.create(user, &wide("k"), &[], false, 0).unwrap();
        assert_eq!(last.index, first.index, "the same record, reused");
        assert_eq!(r.check(first), Err(STATUS_KEY_DELETED));
    }

    /// The listing's order is the folded names', whatever the records' order; a subkey's position
    /// counts its siblings named before it.
    #[test]
    fn subkeys_select_by_position() {
        let r = registry();
        let jeb = r.open(r.root(), &wide("USER\\jeb")).unwrap();
        // A key of the test's own: the user's hive holds the seed's keys.
        let (user, _) = r.create(jeb, &wide("List"), &[], false, 0).unwrap();
        for name in ["c", "A", "b"] {
            r.create(user, &wide(name), &[], false, 0).unwrap();
        }
        let b = r.open(user, &wide("B")).unwrap();
        r.delete(b, 0).unwrap();
        r.create(user, &wide("aa"), &[], false, 0).unwrap();
        let listed: Vec<String> = (0..)
            .map_while(|position| r.subkey(user, position).unwrap())
            .map(|key| text(r.info(key).unwrap().name))
            .collect();
        assert_eq!(listed, ["A", "aa", "c"]);
    }
}
