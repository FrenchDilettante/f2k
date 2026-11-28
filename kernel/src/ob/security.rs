//! The object manager's security wiring: the security descriptor an object carries as a shared
//! cache handle (see [`super::sdcache`]), its capture from a caller's OBJECT_ATTRIBUTES, and the
//! default each kind gets when the create captured none.
//!
//! An object's security descriptor lives in the shared cache ([`super::sdcache`]): the record in
//! the directory (see [`super::Directory`]) holds an [`SdRef`], a reference-counted handle to the
//! one entry the descriptor's bytes are cached in, captured self-relative when the create's
//! OBJECT_ATTRIBUTES named one, or the kind's default — a NULL DACL, which grants every access —
//! when it did not. Objects whose descriptors are equal, the per-type defaults above all, share
//! one entry. The captured descriptor travels from the attributes' read to the object's
//! allocation through a per-thread pending slot ([`set_pending`]/[`take_pending`]): every create
//! or open service reads its OBJECT_ATTRIBUTES on the calling thread and allocates the object in
//! the same call.
//!
//! What a handle's grant does with the descriptor — the access check a user-mode caller's request
//! runs against it — is [`super::grant`].

use super::sdcache::{self, SdRef};
use super::ObjectType;
use crate::nt::capture::CallerMemory;
use crate::sec::{
    SecurityDescriptor,
    SECURITY_DESCRIPTOR_MIN_LENGTH,
    SECURITY_DESCRIPTOR_REVISION,
    SE_DACL_PRESENT,
    SE_SELF_RELATIVE,
};
use crate::status::{
    NtStatus,
    STATUS_BUFFER_TOO_SMALL,
    STATUS_INSUFFICIENT_RESOURCES,
    STATUS_SUCCESS,
};

/// Round a length up to a dword boundary.
const fn align4(len: usize) -> usize {
    (len + 3) & !3
}

/// The most bytes an allow ACE takes: its header, the mask and the longest SID.
const ACE_CAP: usize = 8 + 68;

/// An ACL of revision 2 holding one allow ACE per `(mask, sid)` given, each dword-padded: type 0,
/// flags 0, the ACE's size, the mask, the SID. Its bytes onto `out`, and their count.
fn allow_acl(out: &mut [u8], aces: &[(u32, &crate::se::Sid)]) -> usize {
    let mut len = 0usize;
    let mut put = |len: &mut usize, bytes: &[u8]| {
        out[*len..*len + bytes.len()].copy_from_slice(bytes);
        *len += bytes.len();
    };
    for (mask, sid) in aces {
        let size = align4(8 + sid.size());
        let mut ace = [0u8; 4];
        ace[2..4].copy_from_slice(&(size as u16).to_le_bytes());
        put(&mut len, &ace);
        put(&mut len, &mask.to_le_bytes());
        put(&mut len, crate::se::sid_bytes(sid).as_slice());
        while len % 4 != 0 {
            put(&mut len, &[0]);
        }
    }
    let size = 8 + align4(len);
    // The header goes first: shift the ACEs down past it.
    out.copy_within(..len, 8);
    out[..8].copy_from_slice(&[2, 0, 0, 0, 0, 0, 0, 0]);
    out[2..4].copy_from_slice(&(size as u16).to_le_bytes());
    out[4..6].copy_from_slice(&(aces.len() as u16).to_le_bytes());
    size
}

/// The most bytes the ACLs the defaults pack take: the header plus one allow ACE per SID named.
const ACL_CAP: usize = 8 + 8 * ACE_CAP;

/// Pack a self-relative descriptor from its parts in the order owner, group, DACL into a pool
/// buffer: the header with their dword-aligned offsets (a part not given keeps a zero field), then
/// the parts. None when the pages have no room.
fn pack_sd(
    control: u16,
    owner: Option<&[u8]>,
    group: Option<&[u8]>,
    dacl: Option<&[u8]>,
) -> Option<sdcache::PoolBuf> {
    let mut size = SECURITY_DESCRIPTOR_MIN_LENGTH;
    for part in [owner, group, dacl].into_iter().flatten() {
        size += align4(part.len());
    }
    let mut bytes = sdcache::PoolBuf::take(size)?;
    let mut len = SECURITY_DESCRIPTOR_MIN_LENGTH;
    let mut header = SecurityDescriptor {
        revision: SECURITY_DESCRIPTOR_REVISION,
        sbz1: 0,
        control: control | SE_SELF_RELATIVE,
        owner: 0,
        group: 0,
        sacl: 0,
        dacl: 0,
    };
    for (field, part) in [
        (&mut header.owner, owner),
        (&mut header.group, group),
        (&mut header.dacl, dacl),
    ] {
        if let Some(part) = part {
            *field = len as u32;
            let whole = bytes.as_mut_slice();
            whole[len..len + part.len()].copy_from_slice(part);
            let padded = align4(part.len());
            whole[len + part.len()..len + padded].fill(0);
            len += padded;
        }
    }
    assert!(header.write(&mut bytes.as_mut_slice()[..SECURITY_DESCRIPTOR_MIN_LENGTH]));
    Some(bytes)
}

/// The NULL DACL descriptor — a self-relative header with the DACL present and a zero field, a
/// NULL DACL, which grants every access — as a shared cache handle. None when the pages have no
/// room for the entry.
pub fn null_dacl() -> Option<SdRef> {
    let mut bytes = [0u8; SECURITY_DESCRIPTOR_MIN_LENGTH];
    bytes[0] = SECURITY_DESCRIPTOR_REVISION;
    let control = SE_DACL_PRESENT | SE_SELF_RELATIVE;
    bytes[2..4].copy_from_slice(&control.to_le_bytes());
    sdcache::log(&bytes)
}

/// The access every allow ACE of a default descriptor's DACL grants: every right a process
/// object can grant.
const ALLOW_ALL: u32 = 0x001F_0FFF;

/// The default descriptor an object of `kind` carries when its create captured none, as a shared
/// cache handle; None when the pages have no room for the entry. A file's holds the
/// Administrators owner and the Users group with no DACL (a query of the DACL alone answers the
/// bare 20-byte header); a process's holds the Administrators owner, the logon's primary group
/// and an Administrators-and-SYSTEM allow-all DACL (116 bytes); a key's holds the Administrators
/// owner, the logon's primary group and a DACL allowing every SID of the logon — its user, its
/// groups and SYSTEM — everything (272 bytes); every other kind's is the NULL DACL. Each distinct
/// default is one entry, shared by every object of its kind.
pub fn default_sd(kind: ObjectType) -> Option<SdRef> {
    match kind {
        ObjectType::File => sdcache::log(&pack_sd(
            0,
            Some(crate::se::sid_bytes(&crate::se::ADMINISTRATORS).as_slice()),
            Some(crate::se::sid_bytes(&crate::se::USERS).as_slice()),
            None,
        )?),
        ObjectType::Process => {
            let mut acl = [0u8; ACL_CAP];
            let len = allow_acl(
                &mut acl,
                &[
                    (ALLOW_ALL, &crate::se::ADMINISTRATORS),
                    (ALLOW_ALL, &crate::se::LOCAL_SYSTEM),
                ],
            );
            sdcache::log(&pack_sd(
                SE_DACL_PRESENT,
                Some(crate::se::sid_bytes(&crate::se::ADMINISTRATORS).as_slice()),
                Some(crate::se::sid_bytes(&crate::se::PRIMARY_GROUP).as_slice()),
                Some(&acl[..len]),
            )?)
        }
        ObjectType::Key => {
            // The logon's own SIDs: its user and primary group, the groups it holds, SYSTEM.
            let mut acl = [0u8; ACL_CAP];
            let len = allow_acl(
                &mut acl,
                &[
                    (ALLOW_ALL, &crate::se::USER),
                    (ALLOW_ALL, &crate::se::PRIMARY_GROUP),
                    (ALLOW_ALL, &crate::se::ADMINISTRATORS),
                    (ALLOW_ALL, &crate::se::USERS),
                    (ALLOW_ALL, &crate::se::EVERYONE),
                    (ALLOW_ALL, &crate::se::LOCAL_SYSTEM),
                    (ALLOW_ALL, &crate::se::INTERACTIVE),
                    (ALLOW_ALL, &crate::se::AUTHENTICATED_USERS),
                ],
            );
            sdcache::log(&pack_sd(
                SE_DACL_PRESENT,
                Some(crate::se::sid_bytes(&crate::se::ADMINISTRATORS).as_slice()),
                Some(crate::se::sid_bytes(&crate::se::PRIMARY_GROUP).as_slice()),
                Some(&acl[..len]),
            )?)
        }
        _ => null_dacl(),
    }
}

/// Capture the security descriptor at `input` in the caller's memory into the cache, self-relative,
/// and return a handle to it: every range probed before it is read (a bad range fails the call with
/// the probe's status), each part validated as it is copied from user mode. A null `input`, or a
/// kernel-mode caller, captures nothing — an OBJECT_ATTRIBUTES read does this, on a user-mode
/// caller only.
pub fn capture_sd(input: u32, user_mode: bool) -> Result<Option<SdRef>, NtStatus> {
    capture(input, user_mode, false)
}

/// The same capture, forced: the descriptor at `input` is captured even from a kernel-mode caller
/// (the set security services do this, always reading the caller's descriptor).
pub fn capture_sd_forced(input: u32, user_mode: bool) -> Result<Option<SdRef>, NtStatus> {
    capture(input, user_mode, true)
}

/// The capture itself, in two passes: the first with an empty buffer sizes the descriptor (its
/// parts probed, so a bad range fails there), the second copies it out into a buffer of that size,
/// of whatever length it takes, and logs it into the cache.
fn capture(input: u32, user_mode: bool, force: bool) -> Result<Option<SdRef>, NtStatus> {
    if input == 0 || (!user_mode && !force) {
        return Ok(None);
    }
    let mut needed = 0u32;
    let status =
        crate::sec::sd::capture(&CallerMemory, input, user_mode, force, &mut [], &mut needed);
    if status == STATUS_SUCCESS {
        return Ok(None);
    }
    if status != STATUS_BUFFER_TOO_SMALL {
        return Err(status);
    }
    let mut buf = sdcache::PoolBuf::take(needed as usize).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    let mut len = 0u32;
    let status = crate::sec::sd::capture(
        &CallerMemory,
        input,
        user_mode,
        force,
        buf.as_mut_slice(),
        &mut len,
    );
    if status != STATUS_SUCCESS {
        return Err(status);
    }
    Ok(sdcache::log(&buf.as_slice()[..len as usize]))
}

/// The security descriptor the current create or open captured from its OBJECT_ATTRIBUTES, waiting
/// for the object's allocation to take it.
pub fn set_pending(sd: Option<SdRef>) {
    pending::set(sd);
}

/// Take the pending descriptor, leaving none: the object's allocation takes it, a create or open
/// that made no object drops it.
pub fn take_pending() -> Option<SdRef> {
    pending::take()
}

/// Make the pending slot of the thread at object `index`, with its object (a page for its chunk
/// when the first thread takes it): false when no page is left.
#[cfg(target_arch = "x86")]
pub fn make_pending_slot(index: u16) -> bool {
    pending::make(index)
}

#[cfg(target_arch = "x86")]
mod pending {
    use super::SdRef;
    use crate::slots::{entries_per_page, Record, SideTable, KERNEL_PAGES};

    /// One thread's pending slot: the services read the attributes and allocate the object on the
    /// same thread, so each slot is reached only by its own thread.
    struct Slot(core::cell::UnsafeCell<Option<SdRef>>);

    // SAFETY: slot `i` is reached only through the thread whose record is `i` (the system threads
    // run no user services, but each has its slot anyway), and the boot's only during boot,
    // before the scheduler runs; one thread runs one service at a time. A slot's handle is moved
    // out or replaced only by its own thread, so no handle is shared across threads.
    unsafe impl Sync for Slot {}

    // SAFETY: writes a whole record.
    unsafe impl Record for Slot {
        unsafe fn write_fresh(at: *mut Self, _: u32) {
            // SAFETY: the caller's contract.
            unsafe { at.write(Slot(core::cell::UnsafeCell::new(None))) };
        }
    }

    /// The threads' slots, by thread object index (a system thread's at its own), made with the
    /// thread from the nonpaged pool and kept for the next at its index, as a field of the thread.
    static SLOTS: SideTable<Slot, { entries_per_page::<Slot>() }> = SideTable::new();

    /// The slot for a service reached with no current thread: the boot's object creations.
    static BOOT: Slot = Slot(core::cell::UnsafeCell::new(None));

    pub fn make(index: u16) -> bool {
        SLOTS.ensure(index.into(), &KERNEL_PAGES).is_ok()
    }

    fn slot() -> &'static core::cell::UnsafeCell<Option<SdRef>> {
        let Some(thread) = crate::sched::try_current_thread() else {
            return &BOOT.0;
        };
        if SLOTS.address(thread.index().into()).is_none() {
            // A system thread's, made at its first service (each system thread's chunk is the
            // first's, made once).
            assert!(make(thread.index()), "a page for a system thread's slot");
        }
        &SLOTS
            .get(thread.index().into())
            .expect("a thread's pending slot made with it")
            .0
    }

    pub fn set(sd: Option<SdRef>) {
        // SAFETY: this thread's own slot; the assignment releases whatever was pending.
        unsafe { *slot().get() = sd };
    }

    pub fn take() -> Option<SdRef> {
        // SAFETY: this thread's own slot; the take moves the handle out, releasing nothing.
        unsafe { (*slot().get()).take() }
    }
}

#[cfg(all(not(target_arch = "x86"), test))]
mod pending {
    std::thread_local! {
        static SLOT: core::cell::RefCell<Option<super::SdRef>> =
            const { core::cell::RefCell::new(None) };
    }

    pub fn set(sd: Option<super::SdRef>) {
        SLOT.with(|slot| *slot.borrow_mut() = sd);
    }

    pub fn take() -> Option<super::SdRef> {
        SLOT.with(|slot| slot.borrow_mut().take())
    }
}

#[cfg(all(not(target_arch = "x86"), not(test)))]
mod pending {
    use super::SdRef;

    struct Slot(core::cell::UnsafeCell<Option<SdRef>>);

    // SAFETY: host builds outside the tests do not run services concurrently.
    unsafe impl Sync for Slot {}

    static SLOT: Slot = Slot(core::cell::UnsafeCell::new(None));

    pub fn set(sd: Option<SdRef>) {
        // SAFETY: as the type's contract; the assignment releases whatever was pending.
        unsafe { *SLOT.0.get() = sd };
    }

    pub fn take() -> Option<SdRef> {
        // SAFETY: as the type's contract.
        unsafe { (*SLOT.0.get()).take() }
    }
}

/// The caller's mode, as a system service's request carries it.
#[cfg(target_arch = "x86")]
pub fn caller_mode() -> crate::sec::CallerMode {
    if crate::dev::io::previous_mode() == crate::dev::ntddk::USER_MODE {
        crate::sec::CallerMode::User
    } else {
        crate::sec::CallerMode::Kernel
    }
}

/// The caller's mode: host builds serve no user caller, so the kernel's.
#[cfg(not(target_arch = "x86"))]
pub fn caller_mode() -> crate::sec::CallerMode {
    crate::sec::CallerMode::Kernel
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sec::testkit::{acl, allowed, sd, sd_bytes, sid, user_sid};
    use crate::sec::{SecurityDescriptor, SE_DACL_PRESENT, SE_SELF_RELATIVE};
    use crate::status::STATUS_ACCESS_VIOLATION;
    use crate::user::syscall::host::Page;

    // -- the defaults --------------------------------------------------------------

    /// The NULL DACL default is a 20-byte self-relative header, the DACL present with a zero
    /// field, cached as one entry shared by every handle to it.
    #[test]
    fn the_null_dacl_default_is_a_shared_20_byte_header() {
        let a = null_dacl().unwrap();
        let b = null_dacl().unwrap();
        assert!(a.same(&b), "every NULL DACL is the one entry");
        assert_eq!(sdcache::refs(&a), 2);
        let bytes = sd_bytes(&a);
        assert_eq!(bytes.len(), 20);
        let header = SecurityDescriptor::parse(&bytes).unwrap();
        assert_eq!(header.revision, 1);
        assert!(header.is_self_relative());
        assert!(header.has_control(SE_DACL_PRESENT));
        assert_eq!(header.dacl, 0, "a null DACL");
        assert_eq!(header.owner, 0);
        assert!(crate::sec::is_valid_relative(&bytes, 0));
        drop(a);
        drop(b);
    }

    /// The per-kind defaults: a file's is the Administrators owner and the Users group with no
    /// DACL (52 bytes, control self-relative only, so a DACL query answers the bare header); a
    /// process's is the Administrators owner, the primary group and the Administrators-and-SYSTEM
    /// DACL (116 bytes, DACL present); every other kind's is the NULL DACL. Each kind's default is
    /// one shared entry, and all are valid self-relative descriptors.
    #[test]
    fn the_per_kind_defaults() {
        let file = default_sd(ObjectType::File).unwrap();
        assert_eq!(sd_bytes(&file).len(), 52);
        let h = SecurityDescriptor::parse(&sd_bytes(&file)).unwrap();
        assert_eq!(h.control, SE_SELF_RELATIVE, "no DACL present");
        assert_eq!((h.owner, h.group, h.dacl), (20, 36, 0));
        assert!(crate::sec::sid::equal(
            &sd_bytes(&file)[20..36],
            crate::se::sid_bytes(&crate::se::ADMINISTRATORS).as_slice()
        ));
        assert!(crate::sec::sid::equal(
            &sd_bytes(&file)[36..52],
            crate::se::sid_bytes(&crate::se::USERS).as_slice()
        ));
        assert!(crate::sec::is_valid_relative(&sd_bytes(&file), 0));

        let process = default_sd(ObjectType::Process).unwrap();
        assert_eq!(sd_bytes(&process).len(), 116);
        let h = SecurityDescriptor::parse(&sd_bytes(&process)).unwrap();
        assert_eq!(h.control, SE_SELF_RELATIVE | SE_DACL_PRESENT);
        assert_eq!((h.owner, h.group, h.dacl), (20, 36, 64));
        assert!(crate::sec::sid::equal(
            &sd_bytes(&process)[20..36],
            crate::se::sid_bytes(&crate::se::ADMINISTRATORS).as_slice()
        ));
        assert!(crate::sec::sid::equal(
            &sd_bytes(&process)[36..64],
            crate::se::sid_bytes(&crate::se::PRIMARY_GROUP).as_slice()
        ));
        assert!(crate::sec::is_valid_relative(&sd_bytes(&process), 0));

        // A key's default: the Administrators owner, the logon's primary group and a DACL
        // allowing every SID of the logon everything — 272 bytes, DACL present, no SACL.
        let key = default_sd(ObjectType::Key).unwrap();
        assert_eq!(sd_bytes(&key).len(), 272);
        let h = SecurityDescriptor::parse(&sd_bytes(&key)).unwrap();
        assert_eq!(h.control, SE_SELF_RELATIVE | SE_DACL_PRESENT);
        assert_eq!((h.owner, h.group, h.dacl, h.sacl), (20, 36, 64, 0));
        assert!(crate::sec::sid::equal(
            &sd_bytes(&key)[20..36],
            crate::se::sid_bytes(&crate::se::ADMINISTRATORS).as_slice()
        ));
        assert!(crate::sec::sid::equal(
            &sd_bytes(&key)[36..64],
            crate::se::sid_bytes(&crate::se::PRIMARY_GROUP).as_slice()
        ));
        assert!(crate::sec::is_valid_relative(&sd_bytes(&key), 0));
        // Its DACL: eight allow ACEs, one per SID of the logon.
        let dacl = &sd_bytes(&key)[64..];
        assert_eq!(dacl[0], 2, "ACL revision 2");
        assert_eq!(
            u16::from_le_bytes([dacl[2], dacl[3]]) as usize,
            272 - 64,
            "the ACL's size"
        );
        assert_eq!(u16::from_le_bytes([dacl[4], dacl[5]]), 8, "eight ACEs");

        for kind in [ObjectType::Event, ObjectType::Section, ObjectType::Token] {
            let other = default_sd(kind).unwrap();
            assert!(other.same(&null_dacl().unwrap()), "{kind:?}");
            assert_eq!(sd_bytes(&other).len(), 20);
        }

        // Each distinct default is one entry, shared by every object that gets it.
        let again = default_sd(ObjectType::File).unwrap();
        assert!(again.same(&file));
        assert_eq!(sdcache::refs(&file), 2);
        assert!(!again.same(&process));
        assert!(!default_sd(ObjectType::Key).unwrap().same(&process));
        drop(file);
        drop(process);
        drop(again);
    }

    // -- capture -------------------------------------------------------------------

    /// The caller's memory: a host page through the installed `UserMemory`, the same seam the
    /// syscall arguments' capture uses.
    const BASE: u32 = 0x10000;

    /// An absolute-form SD at BASE+0x100 in a fresh page, its DACL at +0x400 and its owner at
    /// +0x600: a present DACL with one allowed ACE over the user, owned by the user.
    fn absolute_sd_page() -> (Page, u32) {
        let user = user_sid();
        let dacl = acl(&[allowed(0x0002_0001 | 0x0001, &user)]);
        let mut page = vec![0u8; 0x800];
        page[0x400..0x400 + dacl.len()].copy_from_slice(&dacl);
        page[0x600..0x600 + user.len()].copy_from_slice(&user);
        let h = SecurityDescriptor {
            revision: 1,
            sbz1: 0,
            control: SE_DACL_PRESENT,
            owner: BASE + 0x600,
            group: 0,
            sacl: 0,
            dacl: BASE + 0x400,
        };
        let mut header = [0u8; 20];
        assert!(h.write(&mut header));
        page[0x100..0x114].copy_from_slice(&header);
        (Page::read_only(BASE, page), BASE + 0x100)
    }

    /// A user-mode capture of the caller's descriptor lands in the cache, packed self-relative,
    /// every range probed: null input and kernel mode without force capture nothing, a bad range
    /// fails with the probe's status, and the handle reads the packed bytes back.
    #[test]
    fn capture_sd_probes_and_packs_the_callers_descriptor() {
        use std::cell::RefCell;
        use std::rc::Rc;

        use crate::user::syscall::host::install;

        let (page, at) = absolute_sd_page();
        let memory = Rc::new(RefCell::new(page));
        let _installed = install(memory);

        // Null input: nothing.
        assert_eq!(capture_sd(0, true), Ok(None));
        // Kernel mode without force: the input is used as it is, nothing captured.
        assert_eq!(capture_sd(at, false), Ok(None));

        // A user-mode capture: packed self-relative, the DACL first, then the owner, cached.
        let captured = capture_sd(at, true).unwrap().unwrap();
        let bytes = sd_bytes(&captured);
        let header = SecurityDescriptor::parse(&bytes).unwrap();
        let user = user_sid();
        let dacl = acl(&[allowed(0x0002_0001 | 0x0001, &user)]);
        // The user SID is 28 bytes, the ACE 36, the ACL 44: DACL at 20, owner at 64.
        assert!(header.is_self_relative());
        assert!(header.has_control(SE_DACL_PRESENT));
        assert_eq!(header.dacl, 20, "the DACL packed right after the header");
        assert_eq!(header.owner, 20 + 44, "then the owner, dword-aligned");
        assert_eq!(
            &bytes[20..28],
            &dacl[..8],
            "the ACL's header, size rewritten aligned"
        );
        assert_eq!(
            &bytes[28..64],
            &allowed(0x0002_0001 | 0x0001, &user)[..],
            "the ACE"
        );
        assert_eq!(&bytes[64..92], &user[..], "the owner SID");
        assert!(crate::sec::is_valid_relative(&bytes, 0));
        // The same descriptor captures to the same entry.
        let again = capture_sd(at, true).unwrap().unwrap();
        assert!(again.same(&captured));
        drop(again);
        drop(captured);

        // An unreadable header: the probe's status.
        assert_eq!(capture_sd(BASE + 0x7F0, true), Err(STATUS_ACCESS_VIOLATION));
        // A misaligned one.
        assert_eq!(
            capture_sd(at + 2, true),
            Err(crate::sec::STATUS_DATATYPE_MISALIGNMENT)
        );
        // A part pointing outside the caller's memory.
        let mut page = vec![0u8; 0x800];
        let h = SecurityDescriptor {
            revision: 1,
            sbz1: 0,
            control: SE_DACL_PRESENT,
            owner: 0,
            group: 0,
            sacl: 0,
            dacl: BASE + 0x800,
        };
        let mut header = [0u8; 20];
        assert!(h.write(&mut header));
        page[0x100..0x114].copy_from_slice(&header);
        let memory = Rc::new(RefCell::new(Page::read_only(BASE, page)));
        let _installed = install(memory);
        assert_eq!(capture_sd(BASE + 0x100, true), Err(STATUS_ACCESS_VIOLATION));
    }

    /// A capture of a descriptor past the old fixed bound still lands, whole: a DACL of ACEs over
    /// long SIDs, packed self-relative, sized and copied in the two passes.
    #[test]
    fn capture_sd_takes_a_descriptor_of_any_size() {
        use std::cell::RefCell;
        use std::rc::Rc;

        use crate::user::syscall::host::install;

        let user = user_sid();
        // A DACL of four allow ACEs over a 15-sub-authority SID: past 256 bytes packed.
        let long = sid(5, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let dacl = acl(&[
            allowed(0xFFFF_FFFF, &long),
            allowed(0xFFFF_FFFF, &long),
            allowed(0xFFFF_FFFF, &long),
            allowed(0xFFFF_FFFF, &long),
        ]);
        assert!(20 + dacl.len() + user.len() > 256);
        let mut page = vec![0u8; 0x2000];
        page[0x400..0x400 + dacl.len()].copy_from_slice(&dacl);
        page[0x1000..0x1000 + user.len()].copy_from_slice(&user);
        let h = SecurityDescriptor {
            revision: 1,
            sbz1: 0,
            control: SE_DACL_PRESENT,
            owner: BASE + 0x1000,
            group: 0,
            sacl: 0,
            dacl: BASE + 0x400,
        };
        let mut header = [0u8; 20];
        assert!(h.write(&mut header));
        page[0x100..0x114].copy_from_slice(&header);
        let memory = Rc::new(RefCell::new(Page::read_only(BASE, page)));
        let _installed = install(memory);

        let captured = capture_sd(BASE + 0x100, true).unwrap().unwrap();
        let bytes = sd_bytes(&captured);
        assert_eq!(bytes.len(), 20 + dacl.len() + user.len());
        assert!(crate::sec::is_valid_relative(&bytes, 0));
        assert_eq!(&bytes[20..20 + dacl.len()], &dacl[..]);
        drop(captured);
    }

    // -- the pending descriptor ----------------------------------------------------

    /// The pending descriptor is taken once: the object's allocation takes it, a create or open
    /// that made no object drops it.
    #[test]
    fn the_pending_sd_is_taken_once() {
        let handle = sdcache::log(&sd(&user_sid(), &[allowed(0x7, &user_sid())])).unwrap();
        let refs = sdcache::refs(&handle);
        set_pending(Some(handle));
        assert_eq!(sdcache::refs(&take_pending().unwrap()), refs);
        assert_eq!(take_pending(), None, "taken");
        set_pending(None);
        assert_eq!(take_pending(), None);
    }
}
