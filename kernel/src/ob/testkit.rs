//! The object manager tests' rig: leaked records at their final addresses, as the scheduler's
//! tests build them. Each directory comes with a fresh dispatcher of its own, holding its
//! dispatcher objects' bodies.

use super::*;

/// `text`'s UTF-16 units: a name as a UNICODE_STRING gives it.
pub(super) fn w(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

thread_local! {
    /// The pages this test thread's slot pools grow from.
    static PAGES: core::cell::Cell<&'static crate::slots::HostPages> =
        core::cell::Cell::new(&crate::slots::KERNEL_PAGES);
}

/// The pages the directory's slot pools grow from, on this test thread.
pub(super) fn pages() -> &'static crate::slots::HostPages {
    PAGES.with(core::cell::Cell::get)
}

/// From now on, this thread's slot pools grow from `budget` pages only: a pool past its made
/// chunks then refuses as when the nonpaged pool is spent.
pub(super) fn page_budget(budget: usize) {
    let pages = Box::leak(Box::new(crate::slots::HostPages::with_budget(budget)));
    PAGES.with(|cell| cell.set(pages));
}

/// Everything `make` makes until its first refusal.
pub(super) fn until_refused<T>(mut make: impl FnMut() -> Option<T>) -> Vec<T> {
    core::iter::from_fn(|| make()).collect()
}

pub(super) fn directory() -> &'static mut Directory {
    crate::sched::testkit::dispatcher();
    let mut directory = Box::<Directory>::new_uninit();
    // SAFETY: the box is valid, aligned and the records' final address once leaked.
    unsafe { Directory::write_empty(directory.as_mut_ptr()) };
    // SAFETY: written whole just above.
    Box::leak(unsafe { directory.assume_init() })
}

/// The dispatcher of the newest directory.
pub(super) fn dispatcher() -> crate::sched::testkit::Disp {
    crate::sched::testkit::installed()
}

/// Close a handle to `id`, collecting what the caller must finish.
pub(super) fn closed(directory: &mut Directory, id: ObjectId) -> Vec<Followup> {
    directory.handle_closed(id).iter().collect()
}

/// The sweep at quiescence, step by step as the reap runs it: how many leaks it took, and
/// what their deletions left.
pub(super) fn sweep(directory: &mut Directory) -> (usize, Vec<Followup>) {
    let mut leaks = 0;
    let mut left = Vec::new();
    while let Some(leak) = directory.sweep_next() {
        leaks += 1;
        left.extend(leak.followup);
    }
    directory.sweep_end();
    (leaks, left)
}

/// A published object, as a create leaves it: one handle, the creator's reference dropped.
pub(super) fn published(directory: &mut Directory, id: ObjectId) {
    assert!(directory.handle_opened(id));
    assert_eq!(directory.dereference(id), None);
}
