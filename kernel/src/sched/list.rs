//! Index-linked lists: the dispatcher database's queues, linked by record index.
//!
//! The scheduler links through its records, never around them, as Windows 2000's LIST_ENTRY lists
//! do: a thread sits on a ready queue by carrying the link itself, so queueing allocates nothing.
//! The links here name records by index instead of by address. A list is a head (its first and
//! last entries) and a link in every record that can join it (the list it is on, and its two
//! neighbours); the arena that holds both — the dispatcher database — resolves a list's name to its
//! head and an entry's name to its link. Every operation is a few short borrows of the one arena,
//! so a list's head may live in a record of the same pool its entries do (a thread's APC queue, its
//! own suspend APC among the entries).
//!
//! A list is named by a value of its kind ([`ListKind`]): the ready queue of a priority, the
//! waiters of an object, a thread's APC queue of a mode. The kind fixes the entries' type. An entry
//! is on at most one list of a kind at a time, and its link records which, so taking it off needs
//! no search.

use core::fmt::Debug;

/// A kind of list: its values name the lists of the kind, and [`ListKind::Entry`] names the
/// records that join them.
pub trait ListKind: Copy + Eq + Debug {
    /// What the lists of this kind link: a record index, or a record's part.
    type Entry: Copy + Eq + Debug;
}

/// A list's head: its first and last entries, none while empty.
pub struct IndexList<L: ListKind> {
    first: Option<L::Entry>,
    last: Option<L::Entry>,
}

impl<L: ListKind> Clone for IndexList<L> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<L: ListKind> Copy for IndexList<L> {}

impl<L: ListKind> Debug for IndexList<L> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IndexList")
            .field("first", &self.first)
            .field("last", &self.last)
            .finish()
    }
}

impl<L: ListKind> IndexList<L> {
    /// An empty list.
    pub const fn new() -> Self {
        IndexList {
            first: None,
            last: None,
        }
    }

    /// Whether no entry is linked.
    pub fn is_empty(&self) -> bool {
        self.first.is_none()
    }

    /// The first entry, none while empty.
    pub fn first(&self) -> Option<L::Entry> {
        self.first
    }

    /// The last entry, none while empty.
    pub fn last(&self) -> Option<L::Entry> {
        self.last
    }
}

impl<L: ListKind> Default for IndexList<L> {
    fn default() -> Self {
        Self::new()
    }
}

/// A record's membership in one list of kind `L`: the list it is on and its neighbours there, or
/// detached.
pub struct Link<L: ListKind> {
    list: Option<L>,
    prev: Option<L::Entry>,
    next: Option<L::Entry>,
}

impl<L: ListKind> Clone for Link<L> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<L: ListKind> Copy for Link<L> {}

impl<L: ListKind> Debug for Link<L> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Link")
            .field("list", &self.list)
            .field("prev", &self.prev)
            .field("next", &self.next)
            .finish()
    }
}

impl<L: ListKind> Link<L> {
    /// A link on no list.
    pub const fn detached() -> Self {
        Link {
            list: None,
            prev: None,
            next: None,
        }
    }

    /// The list the record is on, none while detached.
    pub fn list(&self) -> Option<L> {
        self.list
    }

    /// Whether the record is on a list.
    pub fn is_linked(&self) -> bool {
        self.list.is_some()
    }

    /// The entry after this one on its list.
    pub fn next(&self) -> Option<L::Entry> {
        self.next
    }

    /// The entry before this one on its list.
    pub fn prev(&self) -> Option<L::Entry> {
        self.prev
    }
}

impl<L: ListKind> Default for Link<L> {
    fn default() -> Self {
        Self::detached()
    }
}

/// What holds the lists of kind `L` and their entries: resolves a list to its head and an entry to
/// its link.
pub trait Arena<L: ListKind> {
    /// The head of `list`.
    fn list(&self, list: L) -> &IndexList<L>;
    /// The head of `list`, to change.
    fn list_mut(&mut self, list: L) -> &mut IndexList<L>;
    /// The link of `entry`.
    fn link(&self, entry: L::Entry) -> &Link<L>;
    /// The link of `entry`, to change.
    fn link_mut(&mut self, entry: L::Entry) -> &mut Link<L>;
}

/// Link `entry` between `prev` and `next` on `list` (either none at an end).
fn splice<L: ListKind, A: Arena<L> + ?Sized>(
    arena: &mut A,
    list: L,
    prev: Option<L::Entry>,
    next: Option<L::Entry>,
    entry: L::Entry,
) {
    debug_assert!(
        !arena.link(entry).is_linked(),
        "an entry joins a list from none"
    );
    *arena.link_mut(entry) = Link {
        list: Some(list),
        prev,
        next,
    };
    match prev {
        Some(prev) => arena.link_mut(prev).next = Some(entry),
        None => arena.list_mut(list).first = Some(entry),
    }
    match next {
        Some(next) => arena.link_mut(next).prev = Some(entry),
        None => arena.list_mut(list).last = Some(entry),
    }
}

/// Link `entry` at the back of `list`.
pub fn push_back<L: ListKind, A: Arena<L> + ?Sized>(arena: &mut A, list: L, entry: L::Entry) {
    let last = arena.list(list).last;
    splice(arena, list, last, None, entry);
}

/// Link `entry` at the front of `list`.
pub fn push_front<L: ListKind, A: Arena<L> + ?Sized>(arena: &mut A, list: L, entry: L::Entry) {
    let first = arena.list(list).first;
    splice(arena, list, None, first, entry);
}

/// Link `entry` on `list` right before `before`, or at the back for none.
pub fn insert_before<L: ListKind, A: Arena<L> + ?Sized>(
    arena: &mut A,
    list: L,
    before: Option<L::Entry>,
    entry: L::Entry,
) {
    match before {
        Some(before) => {
            debug_assert_eq!(arena.link(before).list, Some(list));
            let prev = arena.link(before).prev;
            splice(arena, list, prev, Some(before), entry);
        }
        None => push_back(arena, list, entry),
    }
}

/// Link `entry` on `list` right after `after`, or at the front for none.
pub fn insert_after<L: ListKind, A: Arena<L> + ?Sized>(
    arena: &mut A,
    list: L,
    after: Option<L::Entry>,
    entry: L::Entry,
) {
    match after {
        Some(after) => {
            debug_assert_eq!(arena.link(after).list, Some(list));
            let next = arena.link(after).next;
            splice(arena, list, Some(after), next, entry);
        }
        None => push_front(arena, list, entry),
    }
}

/// Take `entry` off the list it is on, returning that list; none (nothing changed) when it is on
/// no list.
pub fn unlink<L: ListKind, A: Arena<L> + ?Sized>(arena: &mut A, entry: L::Entry) -> Option<L> {
    let Link { list, prev, next } = *arena.link(entry);
    let list = list?;
    match prev {
        Some(prev) => arena.link_mut(prev).next = next,
        None => arena.list_mut(list).first = next,
    }
    match next {
        Some(next) => arena.link_mut(next).prev = prev,
        None => arena.list_mut(list).last = prev,
    }
    *arena.link_mut(entry) = Link::detached();
    Some(list)
}

/// Take `entry` off `list`, which it must be on.
pub fn remove<L: ListKind, A: Arena<L> + ?Sized>(arena: &mut A, list: L, entry: L::Entry) {
    let was = unlink(arena, entry);
    debug_assert_eq!(was, Some(list), "an entry leaves the list it is on");
}

/// Take the first entry off `list`, none when it is empty.
pub fn pop_front<L: ListKind, A: Arena<L> + ?Sized>(arena: &mut A, list: L) -> Option<L::Entry> {
    let first = arena.list(list).first?;
    remove(arena, list, first);
    Some(first)
}

/// The first entry of `list`, none when it is empty.
pub fn first<L: ListKind, A: Arena<L> + ?Sized>(arena: &A, list: L) -> Option<L::Entry> {
    arena.list(list).first
}

/// The last entry of `list`, none when it is empty.
pub fn last<L: ListKind, A: Arena<L> + ?Sized>(arena: &A, list: L) -> Option<L::Entry> {
    arena.list(list).last
}

/// Whether `list` is empty.
pub fn is_empty<L: ListKind, A: Arena<L> + ?Sized>(arena: &A, list: L) -> bool {
    arena.list(list).is_empty()
}

/// The entries of `list`, front to back. The walk borrows the arena; a walk that changes the
/// records it visits uses a [`Cursor`] instead.
pub fn iter<'a, L: ListKind, A: Arena<L> + ?Sized>(
    arena: &'a A,
    list: L,
) -> impl Iterator<Item = L::Entry> + 'a
where
    L::Entry: 'a,
{
    core::iter::successors(arena.list(list).first, move |&entry| arena.link(entry).next)
}

/// A walk over a list that may change the arena between steps: each step returns the current entry
/// and reads the next one first, so the current entry may leave the list (or anything else may
/// happen to it) before the next step.
pub struct Cursor<L: ListKind> {
    next: Option<L::Entry>,
}

impl<L: ListKind> Cursor<L> {
    /// A walk from the front of `list`.
    pub fn front<A: Arena<L> + ?Sized>(arena: &A, list: L) -> Self {
        Cursor {
            next: arena.list(list).first,
        }
    }

    /// The current entry, the next one read ahead; none once the walk is past the back.
    pub fn next<A: Arena<L> + ?Sized>(&mut self, arena: &A) -> Option<L::Entry> {
        let entry = self.next?;
        self.next = arena.link(entry).next;
        Some(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test kind: lists 0 and 1 over eight records.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct Kind(u8);

    impl ListKind for Kind {
        type Entry = u8;
    }

    struct Records {
        lists: [IndexList<Kind>; 2],
        links: [Link<Kind>; 8],
    }

    impl Arena<Kind> for Records {
        fn list(&self, list: Kind) -> &IndexList<Kind> {
            &self.lists[list.0 as usize]
        }

        fn list_mut(&mut self, list: Kind) -> &mut IndexList<Kind> {
            &mut self.lists[list.0 as usize]
        }

        fn link(&self, entry: u8) -> &Link<Kind> {
            &self.links[entry as usize]
        }

        fn link_mut(&mut self, entry: u8) -> &mut Link<Kind> {
            &mut self.links[entry as usize]
        }
    }

    fn records() -> Records {
        Records {
            lists: [IndexList::new(); 2],
            links: [Link::detached(); 8],
        }
    }

    fn entries(records: &Records, list: Kind) -> Vec<u8> {
        iter(records, list).collect()
    }

    /// Push order is kept, a pop takes the front, and an interior unlink leaves the rest in order.
    #[test]
    fn list_discipline() {
        let mut r = records();
        let list = Kind(0);
        assert!(is_empty(&r, list));
        push_back(&mut r, list, 1);
        push_back(&mut r, list, 2);
        push_back(&mut r, list, 3);
        push_front(&mut r, list, 0);
        assert_eq!(entries(&r, list), [0, 1, 2, 3]);
        assert_eq!(first(&r, list), Some(0));
        assert_eq!(last(&r, list), Some(3));

        assert_eq!(unlink(&mut r, 2), Some(list));
        assert!(!r.link(2).is_linked());
        assert_eq!(
            unlink(&mut r, 2),
            None,
            "a detached entry unlinks as a no-op"
        );
        assert_eq!(entries(&r, list), [0, 1, 3]);
        assert_eq!(pop_front(&mut r, list), Some(0));
        assert_eq!(pop_front(&mut r, list), Some(1));
        assert_eq!(pop_front(&mut r, list), Some(3));
        assert_eq!(pop_front(&mut r, list), None);
        assert!(is_empty(&r, list));
    }

    /// Inserts relative to an anchor, at both ends included.
    #[test]
    fn inserts_around_an_anchor() {
        let mut r = records();
        let list = Kind(1);
        push_back(&mut r, list, 4);
        insert_before(&mut r, list, Some(4), 2);
        insert_after(&mut r, list, Some(4), 6);
        insert_after(&mut r, list, None, 1);
        insert_before(&mut r, list, None, 7);
        assert_eq!(entries(&r, list), [1, 2, 4, 6, 7]);
        assert_eq!(r.link(4).list(), Some(list));
        assert_eq!(r.link(4).prev(), Some(2));
        assert_eq!(r.link(4).next(), Some(6));
    }

    /// Two lists of one kind share the arena without touching each other.
    #[test]
    fn lists_of_one_kind_are_apart() {
        let mut r = records();
        push_back(&mut r, Kind(0), 1);
        push_back(&mut r, Kind(1), 2);
        push_back(&mut r, Kind(0), 3);
        assert_eq!(entries(&r, Kind(0)), [1, 3]);
        assert_eq!(entries(&r, Kind(1)), [2]);
        remove(&mut r, Kind(1), 2);
        assert!(is_empty(&r, Kind(1)));
        assert_eq!(entries(&r, Kind(0)), [1, 3]);
    }

    /// A cursor survives the removal of the entry it just returned.
    #[test]
    fn a_cursor_walks_past_removals() {
        let mut r = records();
        let list = Kind(0);
        for entry in 0..6 {
            push_back(&mut r, list, entry);
        }
        let mut cursor = Cursor::front(&r, list);
        let mut seen = Vec::new();
        while let Some(entry) = cursor.next(&r) {
            seen.push(entry);
            if entry % 2 == 0 {
                remove(&mut r, list, entry);
            }
        }
        assert_eq!(seen, [0, 1, 2, 3, 4, 5]);
        assert_eq!(entries(&r, list), [1, 3, 5]);
    }
}
