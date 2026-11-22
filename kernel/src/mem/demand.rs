//! Applying a page fault the entry alone can resolve: the demand-paging half of the fault path.
//!
//! [`apply`] reads the faulting page's entry, asks [`fault::resolve`] what the access resolves
//! to, and applies it: a demand-zero page — committed, never touched — gets a zeroed frame
//! mapped present, with the protection the entry records; a transition page — its frame named,
//! off its working set — is mapped present again, no I/O; a copy-on-write page is severed and a
//! guard page fired, as the address-space manager has always done ([`vm::copy_on_write`],
//! [`vm::fire_guard`]); anything else — a section's page, a paging-file page, no entry at all —
//! is left to the exception path. True when the page is mapped and the faulting access resumes.

use super::fault::{self, Resolution};
use super::vm::{self, Pages, PAGE, USER_HIGH};

/// The frame's place in an entry: bits 12-31.
const FRAME_MASK: u32 = 0xFFFF_F000;
/// The protection index's place: bits 9-11.
const INDEX_SHIFT: u32 = 9;

/// The base protection an entry's index bits record.
fn protect_of(entry: u32) -> u32 {
    match (entry >> INDEX_SHIFT) & 7 {
        1 => vm::PAGE_READONLY,
        2 => vm::PAGE_READWRITE,
        3 => vm::PAGE_WRITECOPY,
        4 => vm::PAGE_EXECUTE,
        5 => vm::PAGE_EXECUTE_READ,
        6 => vm::PAGE_EXECUTE_READWRITE,
        7 => vm::PAGE_EXECUTE_WRITECOPY,
        _ => vm::PAGE_NOACCESS,
    }
}

/// Classify the faulting access at `va` — `write` for a store, `user` when it came from ring 3 —
/// and map the page when the resolution is one that needs no exception and no I/O: a demand-zero
/// page's zeroed frame ([`vm::map_demand_zero`]), a transition page's named frame
/// ([`vm::map_named_frame`]) — the entries are the address-space manager's to write. True when
/// the page is mapped now and the access can resume; false when the resolution is anything else
/// (copy-on-write, guard, a section's page, a paging-file page, nothing at all) or no frame was
/// left for a demand-zero page, in which case the entry is as it was. The caller's own paths take
/// the rest.
pub fn map(pages: &mut impl Pages, va: u32, write: bool, user: bool) -> bool {
    if va >= USER_HIGH {
        return false;
    }
    let page = va & !(PAGE - 1);
    let entry = pages.entry(page);
    match fault::resolve(entry, write, user) {
        Resolution::DemandZero => vm::map_demand_zero(pages, page, protect_of(entry)),
        Resolution::Transition => {
            vm::map_named_frame(pages, page, entry & FRAME_MASK, protect_of(entry));
            true
        }
        _ => false,
    }
}

/// Classify the faulting access at `va` — `write` for a store, `user` when it came from ring 3 —
/// and apply what it resolves to (see the module notes): [`map`] for the demand-zero and
/// transition pages, [`vm::copy_on_write`] and [`vm::fire_guard`] for the copy-on-write and guard
/// pages, as the address-space manager has always done. True when the fault was resolved and the
/// access can resume; false when nothing resolved it (the fault stands).
pub fn apply(pages: &mut impl Pages, va: u32, write: bool, user: bool) -> bool {
    if map(pages, va, write, user) {
        return true;
    }
    if va >= USER_HIGH {
        return false;
    }
    let page = va & !(PAGE - 1);
    match fault::resolve(pages.entry(page), write, user) {
        Resolution::CopyOnWrite => vm::copy_on_write(pages, va),
        Resolution::Guard => vm::fire_guard(pages, va),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::mem::pte::{self, PteKind};
    use crate::mem::vm::{PAGE_GUARD, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY};

    /// The frame a transition entry names.
    const FRAME: u32 = 0x0050_0000;

    /// Page tables as a map, frames numbered from 1 MiB: their extra holders, their words and
    /// their contents (a frame's first word stands for its contents), the frames given back, and
    /// how many more frames there are to give (none: no end).
    #[derive(Default)]
    struct Fake {
        entries: HashMap<u32, u32>,
        next: u32,
        freed: Vec<u32>,
        holders: HashMap<u32, u32>,
        words: HashMap<(u32, u32), u32>,
        budget: Option<u32>,
    }

    impl Pages for Fake {
        fn entry(&self, va: u32) -> u32 {
            *self.entries.get(&va).unwrap_or(&0)
        }

        fn set_entry(&mut self, va: u32, entry: u32) {
            self.entries.insert(va, entry);
        }

        fn zeroed_frame(&mut self) -> Option<u32> {
            if let Some(budget) = &mut self.budget {
                *budget = budget.checked_sub(1)?;
            }
            self.next += 1;
            Some(0x0010_0000 + self.next * PAGE)
        }

        fn free_frame(&mut self, frame: u32) {
            match self.holders.get_mut(&frame) {
                Some(extra) if *extra > 0 => *extra -= 1,
                _ => self.freed.push(frame),
            }
        }

        fn share_frame(&mut self, frame: u32) {
            *self.holders.entry(frame).or_default() += 1;
        }

        fn frame_shared(&self, frame: u32) -> bool {
            self.holders.get(&frame).is_some_and(|&extra| extra > 0)
        }

        fn copy_frame(&mut self, from: u32, to: u32) {
            let word = self.frame_word(from, 0);
            self.set_frame_word(to, 0, word);
        }

        fn frame_word(&self, frame: u32, index: u32) -> u32 {
            *self.words.get(&(frame, index)).unwrap_or(&0)
        }

        fn set_frame_word(&mut self, frame: u32, index: u32, value: u32) {
            self.words.insert((frame, index), value);
        }
    }

    /// Plant an entry in the fake tables.
    fn plant(pages: &mut Fake, va: u32, entry: u32) {
        pages.entries.insert(va, entry);
    }

    /// A committed, never touched page at `page`: a demand-zero entry, as a commit writes it.
    fn demand_zero(pages: &mut Fake, page: u32, protect: u32) {
        plant(pages, page, pte::encode(PteKind::DemandZero, 0, protect));
    }

    /// A page evicted to a backing list: the frame named, the transition tag set, the
    /// protection in the index bits — the entry a fault reads as a transition page.
    fn transition(pages: &mut Fake, page: u32, frame: u32, protect: u32) {
        let index = match protect {
            vm::PAGE_READONLY => 1,
            vm::PAGE_READWRITE => 2,
            vm::PAGE_WRITECOPY => 3,
            _ => 2,
        };
        plant(pages, page, fault::TRANSITION | frame | (index << INDEX_SHIFT));
    }

    /// A demand-zero page's first touch — a read or a write, from ring 3 or the kernel — maps a
    /// zeroed frame present with the recorded protection, and the access resumes.
    #[test]
    fn a_demand_zero_page_faults_in_a_zeroed_frame() {
        let mut pages = Fake::default();
        let page = 0x0040_0000;
        demand_zero(&mut pages, page, PAGE_READWRITE);
        assert!(apply(&mut pages, page + 0x10, false, true));
        let entry = pages.entry(page);
        assert_eq!(pte::classify(entry), PteKind::Present);
        assert!(pte::writable(entry));
        let (_, frame, protect) = pte::decode(entry).unwrap();
        assert_ne!(frame, 0);
        assert_eq!(protect, PAGE_READWRITE);
        assert_eq!(pages.frame_word(frame, 0), 0, "the frame is zeroed");
        // From the kernel, and on a write, the same.
        demand_zero(&mut pages, page + PAGE, PAGE_READWRITE);
        assert!(apply(&mut pages, page + PAGE, true, false));
        assert_eq!(pte::classify(pages.entry(page + PAGE)), PteKind::Present);
        // A fault on the now-present page stands unresolved.
        assert!(!apply(&mut pages, page, true, true));
    }

    /// A demand-zero read-only page fills on a read; a write to it is the violation, and the
    /// entry is untouched.
    #[test]
    fn a_demand_zero_read_only_page_refuses_a_write() {
        let mut pages = Fake::default();
        let page = 0x0040_0000;
        demand_zero(&mut pages, page, PAGE_READONLY);
        assert!(apply(&mut pages, page, false, true));
        let (_, frame, protect) = pte::decode(pages.entry(page)).unwrap();
        assert_eq!((pte::classify(pages.entry(page)), protect), (PteKind::Present, PAGE_READONLY));
        assert!(!pte::writable(pages.entry(page)));
        assert_ne!(frame, 0);
        demand_zero(&mut pages, page + PAGE, PAGE_READONLY);
        let before = pages.entry(page + PAGE);
        assert!(!apply(&mut pages, page + PAGE, true, true));
        assert_eq!(pages.entry(page + PAGE), before, "nothing was mapped");
    }

    /// A demand-zero copy-on-write page fills held copy-on-write: the frame is mapped, but
    /// read-only to the hardware, the first write severing it.
    #[test]
    fn a_demand_zero_copy_on_write_page_fills_held_back() {
        let mut pages = Fake::default();
        let page = 0x0040_0000;
        demand_zero(&mut pages, page, PAGE_WRITECOPY);
        assert!(apply(&mut pages, page, true, true));
        let entry = pages.entry(page);
        assert_eq!(pte::classify(entry), PteKind::CopyOnWrite);
        assert!(!pte::writable(entry));
        assert_eq!(pte::decode(entry).unwrap().2, PAGE_WRITECOPY);
    }

    /// A demand-zero page with no frame left is not applied: the fault stands, the entry as it
    /// was.
    #[test]
    fn a_demand_zero_page_without_a_frame_stands() {
        let mut pages = Fake::default();
        let page = 0x0040_0000;
        demand_zero(&mut pages, page, PAGE_READWRITE);
        pages.budget = Some(0);
        let before = pages.entry(page);
        assert!(!apply(&mut pages, page, false, true));
        assert_eq!(pages.entry(page), before);
        assert_eq!(pte::classify(pages.entry(page)), PteKind::DemandZero);
    }

    /// A transition page is mapped present again from its named frame, no I/O and no new frame,
    /// on a read and on a write; a write its protection refuses is the violation.
    #[test]
    fn a_transition_page_maps_its_named_frame() {
        let mut pages = Fake::default();
        let page = 0x0040_0000;
        transition(&mut pages, page, FRAME, PAGE_READWRITE);
        assert!(apply(&mut pages, page, false, true));
        let entry = pages.entry(page);
        assert_eq!(pte::classify(entry), PteKind::Present);
        assert_eq!(pte::decode(entry), Some((PteKind::Present, FRAME, PAGE_READWRITE)));
        assert!(pte::writable(entry));
        assert!(pages.freed.is_empty(), "the frame was not given back");

        transition(&mut pages, page + PAGE, FRAME, PAGE_READONLY);
        assert!(apply(&mut pages, page + PAGE, false, true));
        assert_eq!(
            pte::decode(pages.entry(page + PAGE)),
            Some((PteKind::Present, FRAME, PAGE_READONLY))
        );
        // A write the recorded protection refuses stands.
        transition(&mut pages, page + 2 * PAGE, FRAME, PAGE_READONLY);
        let before = pages.entry(page + 2 * PAGE);
        assert!(!apply(&mut pages, page + 2 * PAGE, true, true));
        assert_eq!(pages.entry(page + 2 * PAGE), before);
        // A copy-on-write transition page fills held back.
        transition(&mut pages, page + 3 * PAGE, FRAME, PAGE_WRITECOPY);
        assert!(apply(&mut pages, page + 3 * PAGE, true, true));
        assert_eq!(pte::classify(pages.entry(page + 3 * PAGE)), PteKind::CopyOnWrite);
    }

    /// A present copy-on-write page written is severed, as the address-space manager always did.
    #[test]
    fn a_copy_on_write_page_is_severed() {
        let mut pages = Fake::default();
        let page = 0x0040_0000;
        plant(&mut pages, page, vm::encode(FRAME, PAGE_WRITECOPY));
        pages.holders.insert(FRAME, 1);
        assert!(apply(&mut pages, page, true, true));
        let (frame, protect) = vm::decode(pages.entry(page)).unwrap();
        assert_ne!(frame, FRAME, "a copy was made for the process");
        assert_eq!(protect, PAGE_READWRITE);
        assert!(!pages.frame_shared(FRAME));
    }

    /// A guard page touched fires once, as the address-space manager always did.
    #[test]
    fn a_guard_page_fires() {
        let mut pages = Fake::default();
        let page = 0x0040_0000;
        plant(&mut pages, page, vm::encode(FRAME, PAGE_READWRITE | PAGE_GUARD));
        assert!(apply(&mut pages, page, false, true));
        assert_eq!(
            vm::decode(pages.entry(page)),
            Some((FRAME, PAGE_READWRITE)),
            "the guard flag is spent"
        );
    }

    /// Nothing resolves an uncommitted page, a no-access page, a write to a present read-only
    /// page, or an address outside the application range; the entry is left alone.
    #[test]
    fn the_unresolved_faults_stand() {
        let mut pages = Fake::default();
        let page = 0x0040_0000;
        assert!(!apply(&mut pages, page, false, true), "no entry");
        demand_zero(&mut pages, page, PAGE_NOACCESS);
        assert!(!apply(&mut pages, page, false, true), "a no-access page");
        plant(&mut pages, page, vm::encode(FRAME, PAGE_READONLY));
        assert!(!apply(&mut pages, page, true, true), "a write to a read-only page");
        assert!(!apply(&mut pages, USER_HIGH, false, true), "outside the application range");
        assert!(!apply(&mut pages, USER_HIGH + 0x1000, true, true));
    }
}
