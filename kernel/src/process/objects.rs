//! The process's synchronization-object records beyond events: semaphores, mutexes, the user-APC
//! records QueueUserAPC queues, the named-object table, and the process's own waitable.
//!
//! Every pool hands out a record that is fresh or that nothing can reach any more — no handle names
//! it, no thread waits on it, and (a mutex) no thread owns it — so a record is reused only once it
//! is dead. Names live in a small table beside the pools: a name binds one object for as long as a
//! handle names the object (the platform drops a name with its object's last handle), so a lookup
//! skips an entry whose object no handle names, and a record's reuse forgets whatever name it had.
//! Names compare exactly (Win32 object names are case-sensitive).

use crate::sched::apc::Apc;
use crate::sched::mutex::Mutex;
use crate::sched::object::{HandleTable, Slot};
use crate::sched::semaphore::Semaphore;
use crate::sched::wait::{WaitKind, Waitable};

/// How many semaphores a process can have at once.
pub const SEMAPHORES: usize = 64;
/// How many mutexes a process can have at once.
pub const MUTEXES: usize = 64;
/// How many user APCs can be queued at once, across the process's threads.
pub const USER_APCS: usize = 64;
/// How many named objects a process can have at once.
pub const NAMES: usize = 32;
/// The longest object name: MAX_PATH.
pub const MAX_NAME: usize = 260;

/// One name-table entry: the object a name binds (by its table slot), or free.
#[derive(Clone, Copy)]
pub struct NamedObject {
    /// The named object, as a handle-table slot (its kind and waitable header); none when free.
    slot: Option<Slot>,
    /// The name's length.
    length: u16,
    /// The name's bytes (the ANSI name the program passed).
    bytes: [u8; MAX_NAME],
}

impl NamedObject {
    const fn free() -> Self {
        NamedObject {
            slot: None,
            length: 0,
            bytes: [0; MAX_NAME],
        }
    }

    fn name(&self) -> &[u8] {
        &self.bytes[..self.length as usize]
    }
}

/// A name lookup's outcome for a create.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NameError {
    /// The name is longer than an object name may be.
    TooLong,
    /// The name table is full.
    Full,
}

/// The records themselves.
pub struct SyncObjects {
    semaphores: [Semaphore; SEMAPHORES],
    semaphores_used: usize,
    mutexes: [Mutex; MUTEXES],
    mutexes_used: usize,
    apcs: [Apc; USER_APCS],
    names: [NamedObject; NAMES],
    /// The process object's waitable: signaled at the process's end (which no thread of the
    /// process outlives, so its own threads only ever see it unsignaled).
    process: Waitable,
}

impl SyncObjects {
    /// Fresh records, by value (the tests build processes this way).
    #[cfg(test)]
    pub const fn empty() -> Self {
        SyncObjects {
            semaphores: [const { Semaphore::new(0) }; SEMAPHORES],
            semaphores_used: 0,
            mutexes: [const { Mutex::new() }; MUTEXES],
            mutexes_used: 0,
            apcs: [const { Apc::detached() }; USER_APCS],
            names: [const { NamedObject::free() }; NAMES],
            process: Waitable::new(WaitKind::NotificationEvent, 0),
        }
    }

    /// Write fresh records at `objects`, element by element (by value they would pass through the
    /// caller's stack), and close the process waitable's sentinel there.
    ///
    /// # Safety
    ///
    /// `objects` is valid for writes, aligned, and the records' final address; its previous
    /// contents are overwritten, not dropped.
    pub unsafe fn write_empty(objects: *mut SyncObjects) {
        use core::ptr::addr_of_mut;
        // SAFETY: the caller's contract; every field is written.
        unsafe {
            let semaphores = addr_of_mut!((*objects).semaphores) as *mut Semaphore;
            for index in 0..SEMAPHORES {
                semaphores.add(index).write(Semaphore::new(0));
            }
            addr_of_mut!((*objects).semaphores_used).write(0);
            let mutexes = addr_of_mut!((*objects).mutexes) as *mut Mutex;
            for index in 0..MUTEXES {
                mutexes.add(index).write(Mutex::new());
            }
            addr_of_mut!((*objects).mutexes_used).write(0);
            let apcs = addr_of_mut!((*objects).apcs) as *mut Apc;
            for index in 0..USER_APCS {
                apcs.add(index).write(Apc::detached());
            }
            let names = addr_of_mut!((*objects).names) as *mut NamedObject;
            for index in 0..NAMES {
                names.add(index).write(NamedObject::free());
            }
            addr_of_mut!((*objects).process).write(Waitable::new(WaitKind::NotificationEvent, 0));
            (*objects).process.init();
        }
    }

    /// The process object's waitable header.
    pub fn process_waitable(&mut self) -> *mut Waitable {
        core::ptr::addr_of_mut!(self.process)
    }

    /// A fresh semaphore at `initial` with ceiling `limit`, or none (the records are exhausted).
    pub fn new_semaphore(
        &mut self,
        handles: &HandleTable,
        initial: i32,
        limit: i32,
    ) -> Option<&mut Semaphore> {
        let index = reusable(
            &mut self.semaphores[..],
            &mut self.semaphores_used,
            |semaphore| {
                let waitable = semaphore.waitable();
                // SAFETY: the record's header, at its final address.
                handles.references(waitable) == 0 && unsafe { (*waitable).waiters.is_empty() }
            },
        )?;
        let semaphore = &mut self.semaphores[index];
        forget(&mut self.names, semaphore.waitable());
        *semaphore = Semaphore::new(limit);
        semaphore.init();
        semaphore.waitable.signal_state = initial;
        Some(semaphore)
    }

    /// A fresh, free mutex, or none (the records are exhausted).
    pub fn new_mutex(&mut self, handles: &HandleTable) -> Option<&mut Mutex> {
        let index = reusable(&mut self.mutexes[..], &mut self.mutexes_used, |mutex| {
            let owned = !mutex.owner().is_null();
            let waitable = mutex.waitable();
            // SAFETY: the record's header, at its final address.
            !owned && handles.references(waitable) == 0 && unsafe { (*waitable).waiters.is_empty() }
        })?;
        let mutex = &mut self.mutexes[index];
        forget(&mut self.names, mutex.waitable());
        *mutex = Mutex::new();
        mutex.init();
        Some(mutex)
    }

    /// A user-APC record that is in no queue, or none (every record is queued).
    pub fn free_apc(&mut self) -> Option<&mut Apc> {
        self.apcs.iter_mut().find(|apc| !apc.inserted())
    }

    /// The live object `name` binds: an entry whose object a handle still names.
    pub fn lookup(&self, handles: &HandleTable, name: &[u8]) -> Option<Slot> {
        self.names.iter().find_map(|entry| {
            let slot = entry.slot?;
            let live = slot
                .waitable()
                .is_some_and(|waitable| handles.references(waitable) > 0);
            (live && entry.name() == name).then_some(slot)
        })
    }

    /// Bind `name` to the object `slot` names: a free entry, or one whose object no handle names.
    pub fn bind(&mut self, handles: &HandleTable, name: &[u8], slot: Slot) -> Result<(), NameError> {
        if name.len() > MAX_NAME {
            return Err(NameError::TooLong);
        }
        let entry = self
            .names
            .iter_mut()
            .find(|entry| match entry.slot.and_then(Slot::waitable) {
                Some(waitable) => handles.references(waitable) == 0,
                None => true,
            })
            .ok_or(NameError::Full)?;
        entry.slot = Some(slot);
        entry.length = name.len() as u16;
        entry.bytes[..name.len()].copy_from_slice(name);
        Ok(())
    }

    /// Forget the name bound to `waitable`, if any (its record is being reused).
    pub fn forget_name(&mut self, waitable: *mut Waitable) {
        forget(&mut self.names, waitable);
    }
}

/// Forget the name bound to `waitable`, if any.
fn forget(names: &mut [NamedObject], waitable: *mut Waitable) {
    for entry in names.iter_mut() {
        if entry.slot.and_then(Slot::waitable) == Some(waitable) {
            *entry = NamedObject::free();
        }
    }
}

/// The index of a record to hand out: the first dead one under the pool's high-water mark, else
/// the next never-used one; none when the pool is exhausted.
fn reusable<T>(records: &mut [T], used: &mut usize, dead: impl FnMut(&mut T) -> bool) -> Option<usize> {
    if let Some(index) = records[..*used].iter_mut().position(dead) {
        return Some(index);
    }
    if *used < records.len() {
        *used += 1;
        return Some(*used - 1);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn objects() -> &'static mut SyncObjects {
        Box::leak(Box::new(SyncObjects::empty()))
    }

    /// A name binds its object while a handle names it: found by its exact spelling, gone with its
    /// object's last handle, and forgotten when the record is reused.
    #[test]
    fn a_name_lives_as_long_as_a_handle_names_its_object() {
        let objects = objects();
        let mut handles = HandleTable::empty();
        let semaphore = objects.new_semaphore(&handles, 1, 5).unwrap().waitable();
        let slot = Slot::Semaphore(semaphore);
        let handle = handles.insert(slot);
        objects.bind(&handles, b"F2K.sync.semaphore", slot).unwrap();

        assert_eq!(objects.lookup(&handles, b"F2K.sync.semaphore"), Some(slot));
        assert_eq!(objects.lookup(&handles, b"f2k.sync.semaphore"), None, "case-sensitive");
        assert_eq!(objects.lookup(&handles, b"F2K.sync"), None);

        handles.close(handle);
        assert_eq!(objects.lookup(&handles, b"F2K.sync.semaphore"), None, "the last handle closed");

        // The dead record is the one handed out next, and its old name does not come back with it.
        let again = objects.new_semaphore(&handles, 0, 1).unwrap().waitable();
        assert_eq!(again, semaphore);
        handles.insert(Slot::Semaphore(again));
        assert_eq!(objects.lookup(&handles, b"F2K.sync.semaphore"), None);
    }

    /// The pools reuse only dead records: a mutex someone owns stays out of reach even without a
    /// handle, and the records exhaust at their capacity.
    #[test]
    fn records_are_reused_only_once_dead() {
        let objects = objects();
        let handles = HandleTable::empty();
        let first = objects.new_mutex(&handles).unwrap() as *mut Mutex;
        // SAFETY: the record lives in the leaked pool.
        unsafe { (*first).owner = core::ptr::NonNull::dangling().as_ptr() };
        let second = objects.new_mutex(&handles).unwrap() as *mut Mutex;
        assert_ne!(first, second, "an owned mutex is not reused");
        // SAFETY: as above.
        unsafe { (*first).owner = core::ptr::null_mut() };
        assert_eq!(objects.new_mutex(&handles).unwrap() as *mut Mutex, first);

        let mut handles = HandleTable::empty();
        for _ in 0..SEMAPHORES {
            let s = objects.new_semaphore(&handles, 0, 1).unwrap().waitable();
            handles.insert(Slot::Semaphore(s));
        }
        assert!(objects.new_semaphore(&handles, 0, 1).is_none(), "exhausted");
    }

    /// The name table refuses an over-long name and fills at its capacity.
    #[test]
    fn the_name_table_bounds() {
        let objects = objects();
        let mut handles = HandleTable::empty();
        let long = [b'x'; MAX_NAME + 1];
        let s = objects.new_semaphore(&handles, 0, 1).unwrap().waitable();
        let slot = Slot::Semaphore(s);
        handles.insert(slot);
        assert_eq!(objects.bind(&handles, &long, slot), Err(NameError::TooLong));
        for index in 0..NAMES {
            objects.bind(&handles, format!("n{index}").as_bytes(), slot).unwrap();
        }
        assert_eq!(objects.bind(&handles, b"one more", slot), Err(NameError::Full));
    }
}
