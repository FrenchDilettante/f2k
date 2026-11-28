//! The page-fault decision table: what a faulting access to a user page resolves to, read off
//! the page-table entry alone.
//!
//! An entry carries its page's whole state. A present entry (bit 0) names its frame in bits
//! 12-31, lets the hardware write when bit 1 is set, is a user page when bit 2 is set, and
//! records its protection in bits 9-11 (0 when the protection was never recorded: the write bit
//! then says read-write, its absence read-only). A non-present entry is one the CPU ignores, so
//! its bits carry the state instead: bit 1 marks the page committed, bit 2 the guard flag, bits
//! 9-11 the protection as above, bits 12-31 the frame, and the free bits 3-8 where the page is
//! ([`TRANSITION`], [`PROTOTYPE`], [`PAGE_FILE`]). The layout is [`super::pte`]'s.
//!
//! [`resolve`] is the table: given the entry and the access's kind — a store (`write`), from user
//! mode (`user`) — it says what the fault path does with the page. It is pure: the region table,
//! the frame database and the thread's stack are the caller's, and every resolution but
//! [`Resolution::Raise`] names the state the entry already records.

use super::phys::PhysAddr;
use super::pte::{
    frame_bits,
    index_bits,
    protection_of_index,
    EntryWord,
    COMMITTED,
    GUARD,
    PAGE_FILE,
    PRESENT,
    PROTOTYPE,
    SOFT_TAGS,
    TRANSITION,
    USER,
    WRITE,
};
use super::vm;

/// What a faulting access resolves to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Resolution {
    /// Committed but never touched: bring in a zeroed frame.
    DemandZero,
    /// The frame is named and on a backing list: make the page present again; no I/O.
    Transition,
    /// A present copy-on-write page written: sever the copy, make the page private and writable.
    CopyOnWrite,
    /// A guard page touched: the stack check grows the running thread's stack by the page when
    /// the fault lies inside its reservation — the stack overflow when no room is left below it —
    /// and raises the guard-page violation for any other guard page.
    Guard,
    /// A section's page: bring it in from the section.
    Section,
    /// A private page's slot in the paging file: read the page back.
    PageFile,
    /// Nothing resolves the access: raise STATUS_ACCESS_VIOLATION.
    Raise,
}

/// The decision for a faulting access to the page whose entry is `entry`: `write` when the access
/// is a store, `user` when it came from user mode.
pub fn resolve(entry: EntryWord, write: bool, user: bool) -> Resolution {
    if entry & PRESENT != 0 {
        // A present page: `vm::decode` resolves its frame and protection (an unrecorded
        // protection reads as read-write when the write bit is set, read-only otherwise).
        let (frame, protect) = vm::decode(entry).unwrap_or((PhysAddr::ZERO, vm::PAGE_NOACCESS));
        if frame == PhysAddr::ZERO || (user && entry & USER == 0) {
            // The null frame is never mapped, and a user-mode access to a supervisor page is the
            // violation.
            return Resolution::Raise;
        }
        if write && entry & WRITE == 0 {
            // The hardware may not write the page: a copy-on-write page is severed, any other is
            // a write to a read-only page.
            return if copy_on_write(protect & 0xFF) {
                Resolution::CopyOnWrite
            } else {
                Resolution::Raise
            };
        }
        // A present page the access may use does not fault; one that faults anyway stands
        // unresolved.
        return Resolution::Raise;
    }

    // A non-present entry: the CPU ignores its bits, so they carry the page's state. A page whose
    // recorded protection allows no access at all — or no write, short of a copy-on-write sever,
    // which the page-in resolves — is the violation whatever its backing state.
    let index = index_bits(entry);
    let protect = protection_of_index(index);
    if index == 0 || (write && !writable(protect) && !copy_on_write(protect)) {
        return Resolution::Raise;
    }
    let frame = frame_bits(entry);
    let backing = entry & SOFT_TAGS;
    if entry & GUARD != 0 {
        // A guard page: committed, its frame named, no backing tag.
        return if entry & COMMITTED != 0 && backing == 0 && frame != 0 {
            Resolution::Guard
        } else {
            Resolution::Raise
        };
    }
    if entry & COMMITTED != 0 {
        // Committed but not present: no frame yet, so the first touch fills it with zeroes.
        return if backing == 0 && frame == 0 {
            Resolution::DemandZero
        } else {
            Resolution::Raise
        };
    }
    // A soft entry: exactly one backing tag, with its payload.
    match backing {
        TRANSITION if frame != 0 => Resolution::Transition,
        PROTOTYPE => Resolution::Section,
        PAGE_FILE if frame != 0 => Resolution::PageFile,
        _ => Resolution::Raise,
    }
}

/// Whether a base protection lets the hardware write.
fn writable(base: u32) -> bool {
    matches!(base, vm::PAGE_READWRITE | vm::PAGE_EXECUTE_READWRITE)
}

/// Whether a base protection is copy-on-write: read-only to the hardware, its first write the
/// sever.
fn copy_on_write(base: u32) -> bool {
    matches!(base, vm::PAGE_WRITECOPY | vm::PAGE_EXECUTE_WRITECOPY)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::pte::{frame_of, INDEX_SHIFT};

    /// A frame the entries below name.
    /// A frame's field in an entry.
    const FRAME: EntryWord = 0x0050_0000;

    /// The protection index of a base protection, in an entry's bits 9-11.
    fn index(base: u32) -> u32 {
        match base {
            vm::PAGE_READONLY => 1,
            vm::PAGE_READWRITE => 2,
            vm::PAGE_WRITECOPY => 3,
            vm::PAGE_EXECUTE => 4,
            vm::PAGE_EXECUTE_READ => 5,
            vm::PAGE_EXECUTE_READWRITE => 6,
            vm::PAGE_EXECUTE_WRITECOPY => 7,
            _ => 0,
        }
    }

    /// A present entry, as `vm::encode` writes it.
    fn present(protect: u32) -> u32 {
        vm::encode(frame_of(FRAME), protect)
    }

    /// A committed, non-present entry with a frame, as `vm::encode` writes it (a no-access or a
    /// guard page).
    fn committed(protect: u32) -> u32 {
        vm::encode(frame_of(FRAME), protect)
    }

    /// A soft entry: a backing tag, its payload in bits 12-31, the protection in bits 9-11.
    fn soft(tag: u32, payload: u32, protect: u32) -> u32 {
        tag | payload | (index(protect) << INDEX_SHIFT)
    }

    /// A committed entry with no frame yet (the first touch has not happened).
    fn demand(protect: u32) -> u32 {
        COMMITTED | (index(protect) << INDEX_SHIFT)
    }

    /// A supervisor page: present and writable, but not a user page.
    fn supervisor() -> u32 {
        FRAME | PRESENT | WRITE | (index(vm::PAGE_READWRITE) << INDEX_SHIFT)
    }

    /// A committed private page, first touch: a read and a write both bring in the zeroed frame,
    /// from user mode and from the kernel.
    #[test]
    fn a_demand_zero_page_fills_on_first_touch() {
        let entry = demand(vm::PAGE_READWRITE);
        assert_eq!(resolve(entry, false, true), Resolution::DemandZero);
        assert_eq!(resolve(entry, true, true), Resolution::DemandZero);
        assert_eq!(resolve(entry, false, false), Resolution::DemandZero);
        assert_eq!(resolve(entry, true, false), Resolution::DemandZero);
        // A committed read-only page fills on a read; a write to it is the violation.
        let entry = demand(vm::PAGE_READONLY);
        assert_eq!(resolve(entry, false, true), Resolution::DemandZero);
        assert_eq!(resolve(entry, true, true), Resolution::Raise);
    }

    /// A page on a backing list: the frame is named, the page comes back with no I/O, on a read
    /// and on a write. A write the recorded protection does not allow is the violation.
    #[test]
    fn a_transition_page_comes_back_from_its_frame() {
        let entry = soft(TRANSITION, FRAME, vm::PAGE_READWRITE);
        assert_eq!(resolve(entry, false, true), Resolution::Transition);
        assert_eq!(resolve(entry, true, true), Resolution::Transition);
        assert_eq!(resolve(entry, true, false), Resolution::Transition);
        let entry = soft(TRANSITION, FRAME, vm::PAGE_READONLY);
        assert_eq!(resolve(entry, false, true), Resolution::Transition);
        assert_eq!(resolve(entry, true, true), Resolution::Raise);
        // A copy-on-write page's write is the sever, resolved with the page-in.
        let entry = soft(TRANSITION, FRAME, vm::PAGE_WRITECOPY);
        assert_eq!(resolve(entry, true, true), Resolution::Transition);
    }

    /// A present copy-on-write page written: the sever, from user mode and from the kernel. A
    /// read of it does not fault.
    #[test]
    fn a_write_to_a_copy_on_write_page_severs_it() {
        let entry = present(vm::PAGE_WRITECOPY);
        assert_eq!(resolve(entry, true, true), Resolution::CopyOnWrite);
        assert_eq!(resolve(entry, true, false), Resolution::CopyOnWrite);
        let entry = present(vm::PAGE_EXECUTE_WRITECOPY);
        assert_eq!(resolve(entry, true, true), Resolution::CopyOnWrite);
    }

    /// A guard page touched, on a read and on a write, from user mode and from the kernel: the
    /// stack check decides growth against overflow against the guard-page violation.
    #[test]
    fn a_guard_page_fires() {
        let entry = committed(vm::PAGE_READWRITE | vm::PAGE_GUARD);
        assert_eq!(resolve(entry, false, true), Resolution::Guard);
        assert_eq!(resolve(entry, true, true), Resolution::Guard);
        assert_eq!(resolve(entry, false, false), Resolution::Guard);
        assert_eq!(resolve(entry, true, false), Resolution::Guard);
    }

    /// A section's page: brought in from the section on a read and on a write; a copy-on-write
    /// section page's write is the sever, resolved with the page-in. A write the recorded
    /// protection refuses is the violation.
    #[test]
    fn a_section_page_comes_in_from_its_section() {
        let entry = soft(PROTOTYPE, 0x10_0000, vm::PAGE_READONLY);
        assert_eq!(resolve(entry, false, true), Resolution::Section);
        assert_eq!(resolve(entry, true, true), Resolution::Raise);
        let entry = soft(PROTOTYPE, 0x10_0000, vm::PAGE_READWRITE);
        assert_eq!(resolve(entry, false, true), Resolution::Section);
        assert_eq!(resolve(entry, true, true), Resolution::Section);
        let entry = soft(PROTOTYPE, 0, vm::PAGE_WRITECOPY);
        assert_eq!(resolve(entry, true, true), Resolution::Section);
        assert_eq!(resolve(entry, false, true), Resolution::Section);
    }

    /// A private page's slot in the paging file: read back on a read and on a write.
    #[test]
    fn a_paging_file_page_is_read_back() {
        let entry = soft(PAGE_FILE, 0x30_0000, vm::PAGE_READWRITE);
        assert_eq!(resolve(entry, false, true), Resolution::PageFile);
        assert_eq!(resolve(entry, true, true), Resolution::PageFile);
        assert_eq!(resolve(entry, true, false), Resolution::PageFile);
        let entry = soft(PAGE_FILE, 0x30_0000, vm::PAGE_READONLY);
        assert_eq!(resolve(entry, false, true), Resolution::PageFile);
        assert_eq!(resolve(entry, true, true), Resolution::Raise);
    }

    /// The violations: an uncommitted page, a committed no-access page, a write to a read-only
    /// present page, a user-mode access to a supervisor page, and a committed page that still
    /// names its frame without being a guard page.
    #[test]
    fn the_access_violations_raise() {
        // No entry at all: the page is not committed (the region table is the caller's).
        assert_eq!(resolve(0, false, true), Resolution::Raise);
        assert_eq!(resolve(0, true, true), Resolution::Raise);
        // A committed page it may not touch.
        let entry = committed(vm::PAGE_NOACCESS);
        assert_eq!(resolve(entry, false, true), Resolution::Raise);
        assert_eq!(resolve(entry, true, true), Resolution::Raise);
        // A write to a present read-only page, from user mode and from the kernel.
        let entry = present(vm::PAGE_READONLY);
        assert_eq!(resolve(entry, true, true), Resolution::Raise);
        assert_eq!(resolve(entry, true, false), Resolution::Raise);
        // A user-mode access to a supervisor page, read or write.
        assert_eq!(resolve(supervisor(), false, true), Resolution::Raise);
        assert_eq!(resolve(supervisor(), true, true), Resolution::Raise);
        // A committed entry with a frame that is not a guard page: not one the manager writes.
        let entry = COMMITTED | FRAME | (index(vm::PAGE_READWRITE) << INDEX_SHIFT);
        assert_eq!(resolve(entry, false, true), Resolution::Raise);
        assert_eq!(resolve(entry, true, true), Resolution::Raise);
    }

    /// A present page the access may use does not fault; a fault on one anyway stands
    /// unresolved.
    #[test]
    fn a_fault_on_a_present_allowed_page_stands() {
        let entry = present(vm::PAGE_READWRITE);
        assert_eq!(resolve(entry, true, true), Resolution::Raise);
        assert_eq!(resolve(entry, false, true), Resolution::Raise);
        assert_eq!(resolve(supervisor(), false, false), Resolution::Raise);
        // A read of a present copy-on-write page does not fault either.
        assert_eq!(
            resolve(present(vm::PAGE_WRITECOPY), false, true),
            Resolution::Raise
        );
    }

    /// Malformed entries: a backing tag without its payload, two backing tags at once, a guard
    /// flag on an entry that is not a committed guard page, the null frame on a present entry,
    /// and a soft entry with no tag at all.
    #[test]
    fn malformed_entries_raise() {
        // A transition entry must name its frame; a paging-file slot is counted from one.
        assert_eq!(
            resolve(soft(TRANSITION, 0, vm::PAGE_READWRITE), false, true),
            Resolution::Raise
        );
        assert_eq!(
            resolve(soft(PAGE_FILE, 0, vm::PAGE_READWRITE), true, true),
            Resolution::Raise
        );
        // Two backing tags at once.
        assert_eq!(
            resolve(
                soft(TRANSITION | PROTOTYPE, FRAME, vm::PAGE_READWRITE),
                false,
                true
            ),
            Resolution::Raise
        );
        assert_eq!(
            resolve(
                soft(PROTOTYPE | PAGE_FILE, FRAME, vm::PAGE_READWRITE),
                true,
                true
            ),
            Resolution::Raise
        );
        // A guard flag without the committed marker, with a backing tag, or without a frame.
        assert_eq!(
            resolve(
                GUARD | FRAME | (index(vm::PAGE_READWRITE) << INDEX_SHIFT),
                true,
                true
            ),
            Resolution::Raise
        );
        assert_eq!(
            resolve(
                soft(TRANSITION, FRAME, vm::PAGE_READWRITE) | GUARD,
                true,
                true
            ),
            Resolution::Raise
        );
        assert_eq!(
            resolve(
                GUARD | COMMITTED | (index(vm::PAGE_READWRITE) << INDEX_SHIFT),
                true,
                true
            ),
            Resolution::Raise
        );
        // A committed entry with a backing tag.
        assert_eq!(
            resolve(
                COMMITTED | soft(PROTOTYPE, 0x10_0000, vm::PAGE_READWRITE),
                true,
                true
            ),
            Resolution::Raise
        );
        // A present entry naming the null frame.
        assert_eq!(
            resolve(
                PRESENT | USER | WRITE | (index(vm::PAGE_READWRITE) << INDEX_SHIFT),
                true,
                true
            ),
            Resolution::Raise
        );
        // A soft entry with no backing tag: only the protection bits set.
        assert_eq!(
            resolve(index(vm::PAGE_READWRITE) << INDEX_SHIFT, false, true),
            Resolution::Raise
        );
        // A no-access soft entry, read or written.
        assert_eq!(
            resolve(soft(TRANSITION, FRAME, vm::PAGE_NOACCESS), false, true),
            Resolution::Raise
        );
        assert_eq!(
            resolve(soft(PROTOTYPE, 0x10_0000, vm::PAGE_NOACCESS), true, true),
            Resolution::Raise
        );
    }
}
