//! The object manager: every kernel object a handle can name, with its lifetime.
//!
//! Objects live in typed pools global to the kernel: every process's objects share them, and a
//! process's end deletes only what its own references held (the leak sweep waits for quiescence,
//! when no process is left to hold one). An object is named by an [`ObjectId`] (its kind, its pool
//! index and that record's generation), never by a raw pointer: the generation moves on at the
//! delete, so an id that outlived its object resolves to nothing, not to the record's next object.
//!
//! The dispatcher objects (events, semaphores, mutexes, waitable timers, threads, and the waitable
//! side of processes) keep only their headers here: their bodies are records of the dispatcher
//! database ([`crate::sched::database`]) at the same index, as Windows 2000 keeps a dispatcher
//! object's DISPATCHER_HEADER apart from its object header. An id names its body by that index
//! ([`ObjectId::waitable`]), reached with the dispatch token; the directory holds no token, so what
//! it does to a body (a create's fresh body, a deletion's cancel) it does raised to dispatch level.
//!
//! Each object carries two counts. The pointer count is every reference: the creator's while it
//! builds the object, each handle's, each wait's (for the wait's whole life, replays after an APC
//! included), a thread's own while it runs, a process's own until its teardown ends. The handle
//! count is the handles alone. The last handle's close drops the object's name (NT's temporary
//! objects); the last reference deletes the object (an owned mutex leaves its owner's list) and
//! frees its record. Nothing scans handle tables to decide whether an object lives.
//! `\BaseNamedObjects` is a directory object, permanent: made at its first open, never deleted.
//!
//! Names live in one namespace for all kinds (the `\BaseNamedObjects` directory): a name binds one
//! live object, compares exactly (Win32 object names are case-sensitive; a caller's
//! OBJ_CASE_INSENSITIVE folds the comparison), and goes with the bound object's last handle. A
//! name is kept as the UTF-16 units its creator's UNICODE_STRING gave, whatever they are.
//!
//! # The directory's lock
//!
//! The kernel's directory is passive-level state behind a short lock (Windows 2000's object
//! manager guards its namespace and object headers with a fast mutex too): [`lock`] takes it with
//! the caller's passive token, which the guard keeps borrowed; [`locked`] is the bridge for code
//! holding no token. The lock is never held across a wait, a user-memory copy or disk I/O, so a
//! deletion does not finish its teardown in place: what lies outside the directory (a section's
//! frames, a file object's cleanup, which may delete the file on disk, and its close) comes back as
//! a [`Followup`], which the caller finishes with [`finish`] once the lock is released, as Windows
//! 2000 runs an object's delete procedure after dropping the object-manager lock. A look-up and
//! what it decides (a name's binding and the create it allows, a handle's object and the reference
//! that keeps it) happen in one hold.
//!
//! A kind plugs in with its row in the pools' table ([`Directory`]), a `create_*`, and, when its
//! deletion needs more than the record going dead (a timer leaving the timer table, an owned mutex
//! its owner's list), an arm in `delete`; a kind whose body the directory holds gets its typed
//! accessor from the bodies' table; what its deletion leaves outside is a [`Followup`] variant.
//!
//! Every kind lives in a slot pool ([`crate::slots`]) that grows a page at a time from the nonpaged
//! pool and keeps its peak, so a record never moves; its only bound is the u16 index, and a create
//! that finds no page fails as out-of-memory would. A dispatcher object's body is made in the
//! dispatcher database at its record's index, from the same pages, before the id is handed out.
//! The processes' pool hands out its lowest free index first, never the System process's
//! ([`ProcessIndex`]); the threads' never the system threads' ([`ThreadIndex`]); only memory caps
//! processes and threads, as on Windows 2000. A slot pool's first generation is 1 and moves on at
//! the delete, so no live object's id carries generation 0.

pub mod access;
mod bodies;
mod counts;
mod create;
mod descriptors;
mod directory;
mod followup;
pub mod grant;
mod names;
mod records;
mod references;
mod rundown;
pub mod sdcache;
pub mod security;
mod segments;
#[cfg(target_arch = "x86")]
mod target;
#[cfg(test)]
mod testkit;
mod typed;
mod types;

/// The documented all-access masks, granted to the creator's handle (an event's the services
/// take from their caller: the tests' entries name it).
#[cfg_attr(not(test), allow(unused_imports))]
pub use rtl::nt::access::EVENT_ALL_ACCESS;
pub use rtl::nt::access::{PROCESS_ALL_ACCESS, SECTION_ALL_ACCESS, THREAD_ALL_ACCESS};

pub use self::bodies::*;
use self::counts::*;
use self::descriptors::*;
pub use self::directory::*;
pub use self::followup::*;
pub use self::names::*;
pub use self::records::*;
#[cfg(target_arch = "x86")]
pub use self::target::*;
pub use self::types::*;
