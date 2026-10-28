//! The configuration manager: the registry, kept in kernel memory for the kernel's life (nothing is
//! saved to disk yet), which the key services (`nt::key`) open, read and change.
//!
//! The registry is a tree of keys, each holding named values of a type and some bytes. Names are
//! case-insensitive and case-preserving: a lookup folds both sides' units to upper case
//! (`rtl::path::upcase`), while a key or a value keeps the spelling it was made with. A key's
//! subkeys are listed in their folded names' order, as Windows 2000's hives index them; its values
//! in the order they were first set.
//!
//! Keys and values are records in fixed pools, as the object manager's objects are, and a key is
//! named by its record and the record's generation ([`Key`]): a deleted key's record moves on to a
//! new generation, so a key object still naming it ([`KeyBody`]) finds it gone
//! (STATUS_KEY_DELETED) rather than whatever reuses the record. Names, classes and value data live
//! in the registry's own arena, a [`KernelHeap`] over a static pool.
//!
//! The registry is made at its first use with the keys Windows 2000 has from its boot on, reduced
//! to what F2K needs: the root `\Registry`, the machine's and the users' roots under it (`MACHINE`
//! and `USER`, as Windows 2000 spells them), the current user's hive `\Registry\User\jeb`
//! (Windows names it after the user's SID), and the computer's name,
//! `\Registry\Machine\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`'s
//! `ComputerName`, REG_SZ "QEMU". A hive's root (`\Registry`, its two roots, `SYSTEM`, the user's
//! hive) cannot be deleted.

use core::alloc::Layout;
use core::cmp::Ordering;
use core::ptr::NonNull;

use crate::mem::heap::KernelHeap;
use crate::status::*;

/// How many keys can exist at once.
pub const KEYS: usize = 512;
/// How many values can exist at once.
pub const VALUES: usize = 1024;
/// The arena's size: every name, class and value's data.
pub const ARENA: usize = 128 * 1024;
/// The longest key name, in units: the documented limit, 255 characters.
pub const MAX_KEY_NAME: usize = 255;
/// The longest value name, in units: the documented limit, 16383 characters.
pub const MAX_VALUE_NAME: usize = 16383;

/// What separates a path's key names.
pub const SEPARATOR: u16 = b'\\' as u16;

/// REG_SZ: a value's type, a NUL-terminated string.
pub const REG_SZ: u32 = 1;

/// A key: its record and the record's generation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Key {
    index: u16,
    generation: u16,
}

/// A key object's body: the key its open named. The object lives as long as its handles; the key
/// may go first (a delete through another handle), which the services find through
/// [`Registry::check`].
#[derive(Clone, Copy, Debug)]
pub struct KeyBody {
    pub key: Key,
}

impl KeyBody {
    /// A record naming no key yet (a pool's fresh record).
    pub const fn none() -> Self {
        KeyBody {
            key: Key {
                index: 0,
                generation: u16::MAX,
            },
        }
    }
}

/// Some bytes in the arena (none for an empty blob).
#[derive(Clone, Copy)]
struct Blob {
    at: Option<NonNull<u8>>,
    bytes: u32,
}

impl Blob {
    const EMPTY: Blob = Blob { at: None, bytes: 0 };

    /// Its bytes. The lifetime is the caller's to keep within the blob's.
    fn bytes<'a>(self) -> &'a [u8] {
        match self.at {
            // SAFETY: a live arena block of `bytes` bytes, the arena's for the kernel's life.
            Some(at) => unsafe { core::slice::from_raw_parts(at.as_ptr(), self.bytes as usize) },
            None => &[],
        }
    }

    /// Its bytes, writable.
    fn bytes_mut<'a>(self) -> &'a mut [u8] {
        match self.at {
            // SAFETY: as `bytes`; the services run serialized, so nothing else reaches the block.
            Some(at) => unsafe {
                core::slice::from_raw_parts_mut(at.as_ptr(), self.bytes as usize)
            },
            None => &mut [],
        }
    }

    /// Its bytes as UTF-16 units (an arena block is 8-aligned).
    fn units<'a>(self) -> &'a [u16] {
        match self.at {
            // SAFETY: as `bytes`; the block is aligned for units and holds `bytes / 2` of them.
            Some(at) => unsafe {
                core::slice::from_raw_parts(at.as_ptr().cast(), self.bytes as usize / 2)
            },
            None => &[],
        }
    }
}

/// One key's record.
#[derive(Clone, Copy)]
struct Node {
    live: bool,
    generation: u16,
    /// The parent key's record (the root's is its own).
    parent: u16,
    /// A hive's root: never deleted.
    permanent: bool,
    name: Blob,
    class: Blob,
    /// When the key, its values or its list of subkeys last changed (a FILETIME).
    last_write: u64,
}

impl Node {
    const DEAD: Node = Node {
        live: false,
        generation: 0,
        parent: 0,
        permanent: false,
        name: Blob::EMPTY,
        class: Blob::EMPTY,
        last_write: 0,
    };
}

/// One value's record.
#[derive(Clone, Copy)]
struct Value {
    live: bool,
    /// Its key's record.
    key: u16,
    /// When it was first set, among every value (the key lists its values in that order).
    order: u32,
    kind: u32,
    name: Blob,
    data: Blob,
}

impl Value {
    const DEAD: Value = Value {
        live: false,
        key: 0,
        order: 0,
        kind: 0,
        name: Blob::EMPTY,
        data: Blob::EMPTY,
    };
}

/// What a key's information classes report about it (sizes in bytes).
pub struct KeyInfo<'a> {
    pub last_write: u64,
    pub name: &'a [u16],
    pub class: &'a [u16],
    pub subkeys: u32,
    pub max_subkey_name: u32,
    pub max_subkey_class: u32,
    pub values: u32,
    pub max_value_name: u32,
    pub max_value_data: u32,
}

/// What a value's information classes report about it.
pub struct ValueInfo<'a> {
    pub kind: u32,
    pub name: &'a [u16],
    pub data: &'a [u8],
}

/// Two names' order, as the registry compares them: unit by unit, folded to upper case.
pub fn compare(a: &[u16], b: &[u16]) -> Ordering {
    a.iter()
        .map(|&unit| rtl::path::upcase(unit))
        .cmp(b.iter().map(|&unit| rtl::path::upcase(unit)))
}

/// Whether two names are the same name.
pub fn same_name(a: &[u16], b: &[u16]) -> bool {
    a.len() == b.len() && compare(a, b) == Ordering::Equal
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

/// The registry: its keys, its values and their arena.
pub struct Registry {
    nodes: [Node; KEYS],
    values: [Value; VALUES],
    arena: KernelHeap,
    /// The next value's place in its key's order.
    next_order: u32,
}

impl Registry {
    /// Write the registry at `registry`, over `pool` as its arena, made with the keys and the value
    /// it starts with (see the module notes).
    ///
    /// # Safety
    ///
    /// `registry` is valid for writes, aligned, and the registry's final address; its previous
    /// contents are overwritten, not dropped.
    pub unsafe fn write_new(registry: *mut Registry, pool: &'static mut [u8]) {
        use core::ptr::addr_of_mut;
        // SAFETY: the caller's contract; every field is written.
        unsafe {
            let nodes = addr_of_mut!((*registry).nodes) as *mut Node;
            for index in 0..KEYS {
                nodes.add(index).write(Node::DEAD);
            }
            let values = addr_of_mut!((*registry).values) as *mut Value;
            for index in 0..VALUES {
                values.add(index).write(Value::DEAD);
            }
            addr_of_mut!((*registry).arena).write(KernelHeap::new(pool));
            addr_of_mut!((*registry).next_order).write(0);
            (*registry).seed();
        }
    }

    /// The keys and the value the registry starts with.
    fn seed(&mut self) {
        let name = wide::<8>("REGISTRY");
        let node = &mut self.nodes[0];
        *node = Node {
            live: true,
            generation: 0,
            parent: 0,
            permanent: true,
            name: Blob::EMPTY,
            class: Blob::EMPTY,
            last_write: 0,
        };
        let blob = self.store_units(&name).expect("the arena holds the seed");
        self.nodes[0].name = blob;
        let root = self.root();
        // Each key of the path, made in turn below the root.
        let make = |registry: &mut Registry, path: &str, permanent: bool| {
            let mut key = root;
            for name in path.split('\\') {
                let name = wide::<32>(name);
                let length = name
                    .iter()
                    .position(|&unit| unit == 0)
                    .unwrap_or(name.len());
                key = registry
                    .create(key, &name[..length], &[], 0)
                    .expect("the registry holds the seed")
                    .0;
            }
            registry.nodes[key.index as usize].permanent = permanent;
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
        let name = wide::<12>("ComputerName");
        let data = wide::<5>("QEMU");
        self.set_value(computer, &name, REG_SZ, 2 * data.len(), 0, |out| {
            put_units(out, &data);
            Ok(())
        })
        .expect("the registry holds the seed");
    }

    /// `\Registry`, the root key.
    pub fn root(&self) -> Key {
        Key {
            index: 0,
            generation: self.nodes[0].generation,
        }
    }

    fn key(&self, index: u16) -> Key {
        Key {
            index,
            generation: self.nodes[index as usize].generation,
        }
    }

    /// The record of `key`, while it lives; STATUS_KEY_DELETED once it is gone.
    pub fn check(&self, key: Key) -> Result<u16, NtStatus> {
        let node = self
            .nodes
            .get(key.index as usize)
            .ok_or(STATUS_KEY_DELETED)?;
        if node.live && node.generation == key.generation {
            Ok(key.index)
        } else {
            Err(STATUS_KEY_DELETED)
        }
    }

    /// `units` copied into a fresh arena block (none for no units); STATUS_INSUFFICIENT_RESOURCES
    /// when the arena has no room.
    fn store_units(&mut self, units: &[u16]) -> Result<Blob, NtStatus> {
        let blob = self.allocate(2 * units.len())?;
        put_units(blob.bytes_mut(), units);
        Ok(blob)
    }

    /// A fresh arena block of `bytes` bytes (none for none); STATUS_INSUFFICIENT_RESOURCES when the
    /// arena has no room.
    fn allocate(&mut self, bytes: usize) -> Result<Blob, NtStatus> {
        if bytes == 0 {
            return Ok(Blob::EMPTY);
        }
        let layout =
            Layout::from_size_align(bytes, 8).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let at = self
            .arena
            .alloc(layout)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        Ok(Blob {
            at: Some(at),
            bytes: bytes as u32,
        })
    }

    /// Give a block back to the arena.
    fn free(&mut self, blob: Blob) {
        if let Some(at) = blob.at {
            self.arena.dealloc(at);
        }
    }

    /// `units` read into a scratch block by `fill`, handed to `then`, and the block given back: how
    /// a service holds a name it read from its caller (a value name may be 16383 units long).
    pub fn with_scratch<R>(
        &mut self,
        units: usize,
        fill: impl FnOnce(&mut [u8]) -> Result<(), NtStatus>,
        then: impl FnOnce(&mut Registry, &[u16]) -> R,
    ) -> Result<R, NtStatus> {
        let blob = self.allocate(2 * units)?;
        let result = fill(blob.bytes_mut()).map(|()| then(self, blob.units()));
        self.free(blob);
        result
    }

    /// The live subkey of record `parent` named `name`.
    fn child(&self, parent: u16, name: &[u16]) -> Option<u16> {
        (1..KEYS as u16).find(|&index| {
            let node = &self.nodes[index as usize];
            node.live && node.parent == parent && same_name(node.name.units(), name)
        })
    }

    /// The live subkeys of record `parent`, in the listing's order, into `out`: how many.
    fn children(&self, parent: u16, out: &mut [u16; KEYS]) -> usize {
        let mut count = 0;
        for index in 1..KEYS as u16 {
            let node = &self.nodes[index as usize];
            if node.live && node.parent == parent {
                out[count] = index;
                count += 1;
            }
        }
        out[..count].sort_unstable_by(|&a, &b| {
            compare(
                self.nodes[a as usize].name.units(),
                self.nodes[b as usize].name.units(),
            )
        });
        count
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

    /// The key `path` names below `from`, made when its last name is missing (with `class`, at
    /// `now`), and whether it was: the keys on the way must exist (STATUS_OBJECT_NAME_NOT_FOUND).
    pub fn create(
        &mut self,
        from: Key,
        path: &[u16],
        class: &[u16],
        now: u64,
    ) -> Result<(Key, bool), NtStatus> {
        let mut index = self.check(from)?;
        let mut names = components(path)?.peekable();
        while let Some(name) = names.next() {
            match self.child(index, name) {
                Some(child) => index = child,
                None if names.peek().is_none() => {
                    return self
                        .make_key(index, name, class, now)
                        .map(|key| (key, true))
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
        now: u64,
    ) -> Result<Key, NtStatus> {
        let index = (1..KEYS)
            .find(|&index| !self.nodes[index].live)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        let name = self.store_units(name)?;
        let class = match self.store_units(class) {
            Ok(class) => class,
            Err(status) => {
                self.free(name);
                return Err(status);
            }
        };
        let node = &mut self.nodes[index];
        *node = Node {
            live: true,
            generation: node.generation,
            parent,
            permanent: false,
            name,
            class,
            last_write: now,
        };
        self.nodes[parent as usize].last_write = now;
        Ok(self.key(index as u16))
    }

    /// Delete `key` with its values (at `now`): STATUS_CANNOT_DELETE for a key with subkeys or a
    /// hive's root. Its record moves on to a new generation, so its key objects find it gone.
    pub fn delete(&mut self, key: Key, now: u64) -> Result<(), NtStatus> {
        let index = self.check(key)?;
        let node = self.nodes[index as usize];
        if node.permanent
            || self.nodes[1..]
                .iter()
                .any(|child| child.live && child.parent == index)
        {
            return Err(STATUS_CANNOT_DELETE);
        }
        for slot in 0..VALUES {
            if self.values[slot].live && self.values[slot].key == index {
                self.drop_value(slot);
            }
        }
        self.free(node.name);
        self.free(node.class);
        self.nodes[index as usize] = Node {
            generation: node.generation.wrapping_add(1),
            ..Node::DEAD
        };
        self.nodes[node.parent as usize].last_write = now;
        Ok(())
    }

    /// Subkey `position` of `key`, in the listing's order; none past the last.
    pub fn subkey(&self, key: Key, position: u32) -> Result<Option<Key>, NtStatus> {
        let index = self.check(key)?;
        let mut children = [0u16; KEYS];
        let count = self.children(index, &mut children);
        Ok(children[..count]
            .get(position as usize)
            .map(|&child| self.key(child)))
    }

    /// What the information classes report about `key`.
    pub fn info(&self, key: Key) -> Result<KeyInfo<'_>, NtStatus> {
        let index = self.check(key)?;
        let node = &self.nodes[index as usize];
        let mut info = KeyInfo {
            last_write: node.last_write,
            name: node.name.units(),
            class: node.class.units(),
            subkeys: 0,
            max_subkey_name: 0,
            max_subkey_class: 0,
            values: 0,
            max_value_name: 0,
            max_value_data: 0,
        };
        for child in self.nodes[1..]
            .iter()
            .filter(|child| child.live && child.parent == index)
        {
            info.subkeys += 1;
            info.max_subkey_name = info.max_subkey_name.max(child.name.bytes);
            info.max_subkey_class = info.max_subkey_class.max(child.class.bytes);
        }
        for value in self
            .values
            .iter()
            .filter(|value| value.live && value.key == index)
        {
            info.values += 1;
            info.max_value_name = info.max_value_name.max(value.name.bytes);
            info.max_value_data = info.max_value_data.max(value.data.bytes);
        }
        Ok(info)
    }

    /// The live value of record `key` named `name`.
    fn find_value(&self, key: u16, name: &[u16]) -> Option<usize> {
        (0..VALUES).find(|&slot| {
            let value = &self.values[slot];
            value.live && value.key == key && same_name(value.name.units(), name)
        })
    }

    fn value_info(&self, slot: usize) -> ValueInfo<'_> {
        let value = &self.values[slot];
        ValueInfo {
            kind: value.kind,
            name: value.name.units(),
            data: value.data.bytes(),
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
            slot = (0..VALUES)
                .filter(|&slot| {
                    let value = &self.values[slot];
                    value.live
                        && value.key == index
                        && after.is_none_or(|after| value.order > after)
                })
                .min_by_key(|&slot| self.values[slot].order);
            match slot {
                Some(found) => after = Some(self.values[found].order),
                None => return Ok(None),
            }
        }
        Ok(slot.map(|slot| self.value_info(slot)))
    }

    /// Set `key`'s value `name` to `size` bytes of type `kind`, which `fill` writes (at `now`): an
    /// existing value of the name takes the new type and data, keeping its place and spelling.
    pub fn set_value(
        &mut self,
        key: Key,
        name: &[u16],
        kind: u32,
        size: usize,
        now: u64,
        fill: impl FnOnce(&mut [u8]) -> Result<(), NtStatus>,
    ) -> Result<(), NtStatus> {
        let index = self.check(key)?;
        let data = self.allocate(size)?;
        if let Err(status) = fill(data.bytes_mut()) {
            self.free(data);
            return Err(status);
        }
        let slot = match self.find_value(index, name) {
            Some(slot) => {
                let old = self.values[slot].data;
                self.free(old);
                slot
            }
            None => {
                let made = (0..VALUES)
                    .find(|&slot| !self.values[slot].live)
                    .ok_or(STATUS_INSUFFICIENT_RESOURCES)
                    .and_then(|slot| self.store_units(name).map(|name| (slot, name)));
                let (slot, stored) = match made {
                    Ok(made) => made,
                    Err(status) => {
                        self.free(data);
                        return Err(status);
                    }
                };
                self.values[slot] = Value {
                    live: true,
                    key: index,
                    order: self.next_order,
                    kind,
                    name: stored,
                    data: Blob::EMPTY,
                };
                self.next_order = self.next_order.wrapping_add(1);
                slot
            }
        };
        self.values[slot].kind = kind;
        self.values[slot].data = data;
        self.nodes[index as usize].last_write = now;
        Ok(())
    }

    /// Delete `key`'s value `name` (at `now`): STATUS_OBJECT_NAME_NOT_FOUND when it has none.
    pub fn delete_value(&mut self, key: Key, name: &[u16], now: u64) -> Result<(), NtStatus> {
        let index = self.check(key)?;
        let slot = self
            .find_value(index, name)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        self.drop_value(slot);
        self.nodes[index as usize].last_write = now;
        Ok(())
    }

    fn drop_value(&mut self, slot: usize) {
        let value = self.values[slot];
        self.free(value.name);
        self.free(value.data);
        self.values[slot] = Value::DEAD;
    }
}

/// A name's units as their bytes (little-endian, as the information structures carry them).
pub fn unit_bytes(units: &[u16]) -> &[u8] {
    // SAFETY: the units' memory (the registry's, or the kernel's own), read as twice as many
    // bytes; a u16 has no padding, and every target F2K builds for is little-endian.
    unsafe { core::slice::from_raw_parts(units.as_ptr().cast(), 2 * units.len()) }
}

/// `units` as their little-endian bytes into `out` (twice their length).
pub fn put_units(out: &mut [u8], units: &[u16]) {
    for (pair, &unit) in out.chunks_exact_mut(2).zip(units) {
        pair.copy_from_slice(&unit.to_le_bytes());
    }
}

/// `text` (ASCII) as units, NUL-padded to `N`.
fn wide<const N: usize>(text: &str) -> [u16; N] {
    let mut out = [0u16; N];
    for (unit, byte) in out.iter_mut().zip(text.bytes()) {
        *unit = byte as u16;
    }
    out
}

// --- The kernel's registry ---------------------------------------------------------------------

/// The arena's pool (8-aligned, as the heap requires).
#[cfg(target_arch = "x86")]
#[repr(align(8))]
struct ArenaPool([u8; ARENA]);

#[cfg(target_arch = "x86")]
static mut ARENA_POOL: ArenaPool = ArenaPool([0; ARENA]);

/// The kernel's registry, built in place at its first use (by value it would pass the stack).
#[cfg(target_arch = "x86")]
static mut REGISTRY: core::mem::MaybeUninit<Registry> = core::mem::MaybeUninit::uninit();

/// Whether [`REGISTRY`] is built.
#[cfg(target_arch = "x86")]
static mut BUILT: bool = false;

/// The kernel's registry.
#[cfg(target_arch = "x86")]
pub fn registry() -> &'static mut Registry {
    // SAFETY: single CPU, and no interrupt path reaches the registry. Its callers are services,
    // which run with interrupts masked and never wait while they hold the reference, so no other
    // thread forms one meanwhile. Built once, in place, before the first use; the pool is this
    // module's alone, handed to the registry's arena once.
    // Note: `with_scratch` reads user memory inside the borrow. A fault in that copy enters the
    // exception handler with the reference live; it resolves without the registry and without
    // waiting today, but a resolution that waited would let another thread's service take a
    // second reference.
    unsafe {
        let registry = (*core::ptr::addr_of_mut!(REGISTRY)).as_mut_ptr();
        if !BUILT {
            let pool = core::slice::from_raw_parts_mut(
                core::ptr::addr_of_mut!(ARENA_POOL.0).cast::<u8>(),
                ARENA,
            );
            Registry::write_new(registry, pool);
            BUILT = true;
        }
        &mut *registry
    }
}

#[cfg(test)]
mod tests {
    //! The registry's tree over a registry of the tests' own: names, the listing's order, deletes
    //! and their stale keys, values.

    use super::*;

    fn registry() -> &'static mut Registry {
        let pool = Box::leak(vec![0u64; ARENA / 8].into_boxed_slice());
        // SAFETY: a u64 slice is 8-aligned; reinterpreted as its bytes.
        let pool =
            unsafe { core::slice::from_raw_parts_mut(pool.as_mut_ptr().cast::<u8>(), ARENA) };
        let mut registry = Box::<Registry>::new_uninit();
        // SAFETY: the box is valid, aligned and the registry's final address once leaked.
        unsafe { Registry::write_new(registry.as_mut_ptr(), pool) };
        // SAFETY: written whole just above.
        Box::leak(unsafe { registry.assume_init() })
    }

    fn w(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    fn text(units: &[u16]) -> String {
        String::from_utf16(units).unwrap()
    }

    #[test]
    fn the_seed_is_there() {
        let r = registry();
        let root = r.root();
        assert_eq!(text(r.info(root).unwrap().name), "REGISTRY");
        let user = r.open(root, &w("user\\JEB")).unwrap();
        assert_eq!(text(r.info(user).unwrap().name), "jeb");
        let name = r
            .open(
                root,
                &w("Machine\\System\\CurrentControlSet\\Control\\ComputerName\\ComputerName"),
            )
            .unwrap();
        let value = r.query_value(name, &w("computername")).unwrap();
        assert_eq!(value.kind, REG_SZ);
        assert_eq!(value.data, b"Q\0E\0M\0U\0\0\0");
        assert_eq!(
            r.delete(user, 0),
            Err(STATUS_CANNOT_DELETE),
            "a hive's root stays"
        );
        let machine = r.open(root, &w("MACHINE")).unwrap();
        assert_eq!(
            r.subkey(machine, 0).unwrap(),
            Some(r.open(machine, &w("SYSTEM")).unwrap())
        );
        assert_eq!(r.subkey(machine, 1).unwrap(), None);
    }

    #[test]
    fn names_fold_case_and_keep_their_spelling() {
        let r = registry();
        let user = r.open(r.root(), &w("USER\\jeb")).unwrap();
        let (made, created) = r.create(user, &w("Software"), &[], 1).unwrap();
        assert!(created);
        let (again, created) = r.create(user, &w("SOFTWARE"), &[], 2).unwrap();
        assert_eq!((again, created), (made, false));
        assert_eq!(text(r.info(again).unwrap().name), "Software");
        assert_eq!(
            r.open(user, &w("software\\")).unwrap(),
            made,
            "a trailing separator"
        );
        assert_eq!(r.open(user, &w("")).unwrap(), user, "the empty path");
        assert_eq!(
            r.open(user, &w("\\software")),
            Err(STATUS_OBJECT_NAME_INVALID)
        );
        assert_eq!(r.open(user, &w("a\\\\b")), Err(STATUS_OBJECT_NAME_INVALID));
        assert_eq!(
            r.open(user, &w("Missing\\x")),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(
            r.create(user, &w("Missing\\x"), &[], 0),
            Err(STATUS_OBJECT_NAME_NOT_FOUND),
            "the keys on the way exist"
        );
        let long = vec![b'k' as u16; MAX_KEY_NAME + 1];
        assert_eq!(
            r.create(user, &long, &[], 0),
            Err(STATUS_OBJECT_NAME_INVALID)
        );
    }

    #[test]
    fn subkeys_list_in_folded_order() {
        let r = registry();
        let user = r.open(r.root(), &w("USER\\jeb")).unwrap();
        for name in ["delta", "Alpha", "charlie", "bravo", "Echo"] {
            r.create(user, &w(name), &[], 0).unwrap();
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
        let user = r.open(r.root(), &w("USER\\jeb")).unwrap();
        let (a, _) = r.create(user, &w("a"), &[], 0).unwrap();
        let (b, _) = r.create(a, &w("b"), &[], 0).unwrap();
        assert_eq!(
            r.delete(a, 0),
            Err(STATUS_CANNOT_DELETE),
            "a key with a subkey"
        );
        r.set_value(b, &w("x"), REG_SZ, 2, 0, |out| {
            out.copy_from_slice(&[0, 0]);
            Ok(())
        })
        .unwrap();
        r.delete(b, 0).unwrap();
        assert_eq!(r.check(b), Err(STATUS_KEY_DELETED));
        assert_eq!(r.query_value(b, &w("x")).err(), Some(STATUS_KEY_DELETED));
        assert_eq!(r.create(b, &w("c"), &[], 0).err(), Some(STATUS_KEY_DELETED));
        assert_eq!(r.subkey(b, 0).err(), Some(STATUS_KEY_DELETED));
        assert_eq!(r.delete(b, 0), Err(STATUS_KEY_DELETED));
        // The name made anew is another key, even in the same record.
        let (again, created) = r.create(a, &w("b"), &[], 0).unwrap();
        assert!(created);
        assert_ne!(again, b);
        assert_eq!(r.check(b), Err(STATUS_KEY_DELETED));
        r.delete(again, 0).unwrap();
        r.delete(a, 0).unwrap();
    }

    #[test]
    fn values_set_replace_and_list_in_order() {
        let r = registry();
        let user = r.open(r.root(), &w("USER\\jeb")).unwrap();
        let set = |r: &mut Registry, name: &str, kind: u32, data: &[u8]| {
            r.set_value(user, &w(name), kind, data.len(), 5, |out| {
                out.copy_from_slice(data);
                Ok(())
            })
            .unwrap()
        };
        set(r, "one", 4, &[1, 0, 0, 0]);
        set(r, "", REG_SZ, b"d\0\0\0");
        set(r, "Two", 3, &[]);
        set(r, "ONE", 3, &[9, 9]);
        let one = r.query_value(user, &w("one")).unwrap();
        assert_eq!(
            (one.kind, one.data, text(one.name)),
            (3, &[9u8, 9][..], "one".into())
        );
        assert_eq!(r.query_value(user, &w("")).unwrap().data, b"d\0\0\0");
        assert_eq!(r.query_value(user, &w("two")).unwrap().data, b"");
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
        r.delete_value(user, &w("TWO"), 6).unwrap();
        assert_eq!(
            r.query_value(user, &w("Two")).err(),
            Some(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(
            r.delete_value(user, &w("Two"), 6),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(r.info(user).unwrap().last_write, 6);
        // A failed fill leaves the value as it was.
        assert_eq!(
            r.set_value(user, &w("one"), 1, 4, 7, |_| Err(STATUS_ACCESS_VIOLATION)),
            Err(STATUS_ACCESS_VIOLATION)
        );
        assert_eq!(r.query_value(user, &w("one")).unwrap().data, &[9, 9]);
    }

    #[test]
    fn a_scratch_name_goes_back() {
        let r = registry();
        let user = r.open(r.root(), &w("USER\\jeb")).unwrap();
        let found = r
            .with_scratch(
                3,
                |bytes| {
                    bytes.copy_from_slice(b"J\0E\0B\0");
                    Ok(())
                },
                |r, name| r.open(r.root(), &w("USER")).and_then(|u| r.open(u, name)),
            )
            .unwrap();
        assert_eq!(found, Ok(user));
        assert_eq!(r.arena.audit(), Ok(()));
    }
}
