//! The object namespace: `\BaseNamedObjects`'s names, their session prefixes and their table.

use super::*;
use crate::slots::{per_page, KernelId, Record, Slots};

/// The units of `prefix`, an ASCII string.
const fn ascii_units<const N: usize>(prefix: &[u8; N]) -> [u16; N] {
    let mut units = [0u16; N];
    let mut index = 0;
    while index < N {
        units[index] = prefix[index] as u16;
        index += 1;
    }
    units
}

/// The session prefixes, `Global\` and `Local\`, as units.
const GLOBAL_PREFIX: [u16; 7] = ascii_units(b"Global\\");
const LOCAL_PREFIX: [u16; 6] = ascii_units(b"Local\\");

/// A program's object name as the namespace keeps it: without a `Global\` or `Local\` prefix.
/// There is one session, so the global namespace and the session's local one are the same
/// directory (Windows 2000 with Terminal Services keeps `\Sessions\<n>\BaseNamedObjects` apart).
/// The prefixes are matched as spelled.
pub fn namespace_name(name: &[u16]) -> &[u16] {
    name.strip_prefix(&GLOBAL_PREFIX[..])
        .or_else(|| name.strip_prefix(&LOCAL_PREFIX[..]))
        .unwrap_or(name)
}

/// Whether two names are the same one: unit for unit, or, `case_insensitive` (the caller's
/// OBJ_CASE_INSENSITIVE), each unit upper-cased by NT's upcase rule ([`rtl::text::upcase`]).
fn same_name(a: &[u16], b: &[u16], case_insensitive: bool) -> bool {
    if case_insensitive {
        rtl::text::eq_ignore_case(a, b)
    } else {
        a == b
    }
}

/// One name-table entry: the name's UTF-16 units, as the caller's UNICODE_STRING gave them.
#[derive(Clone, Copy)]
pub(super) struct NameEntry {
    object: Option<ObjectId>,
    length: u16,
    units: [u16; MAX_NAME],
}

impl NameEntry {
    const fn free() -> Self {
        NameEntry {
            object: None,
            length: 0,
            units: [0; MAX_NAME],
        }
    }

    fn name(&self) -> &[u16] {
        &self.units[..self.length as usize]
    }
}

// SAFETY: writes a whole entry.
unsafe impl Record for NameEntry {
    unsafe fn write_fresh(at: *mut Self, _: u32) {
        // SAFETY: the caller's contract.
        unsafe { at.write(NameEntry::free()) };
    }
}

/// The names' pool: one namespace, a page of entries at a time.
pub(super) type Names = Slots<NameEntry, KernelId<NameEntry>, { per_page::<NameEntry>() }>;

/// Why a name could not be bound.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NameError {
    /// The name is longer than an object name may be.
    TooLong,
    /// No page was left for the name table to grow.
    Full,
}

impl Directory {
    // --- Names -------------------------------------------------------------------------------

    /// The live object `name` binds (its session prefix aside, see [`namespace_name`]), compared
    /// exactly or, `case_insensitive` (OBJ_CASE_INSENSITIVE), folded (see [`same_name`]). A dying
    /// object's name, which its deletion is on its way to drop, binds nothing (see [`Counts`]).
    pub fn lookup_name(&self, name: &[u16], case_insensitive: bool) -> Option<ObjectId> {
        let name = namespace_name(name);
        self.names.iter().find_map(|(_, entry)| {
            entry
                .object
                .filter(|&id| same_name(entry.name(), name, case_insensitive) && self.is_live(id))
        })
    }

    /// The name `id` is bound to in the namespace, as the namespace keeps it (UTF-16 units, as
    /// its creator spelled them); none for an object without one.
    pub fn name_of(&self, id: ObjectId) -> Option<&[u16]> {
        self.names
            .iter()
            .find(|(_, entry)| entry.object == Some(id))
            .map(|(_, entry)| entry.name())
    }

    /// Bind `name` to `id` (its session prefix aside).
    pub fn bind_name(&mut self, name: &[u16], id: ObjectId) -> Result<(), NameError> {
        let name = namespace_name(name);
        if name.len() > MAX_NAME {
            return Err(NameError::TooLong);
        }
        let (_, entry) = self
            .names
            .allocate_or_grow(0, pages())
            .map_err(|_| NameError::Full)?;
        entry.object = Some(id);
        entry.length = name.len() as u16;
        entry.units[..name.len()].copy_from_slice(name);
        Ok(())
    }

    /// Forget the name bound to `id`, if any.
    pub(super) fn forget_name(&mut self, id: ObjectId) {
        loop {
            let bound = self
                .names
                .iter()
                .find(|(_, entry)| entry.object == Some(id))
                .map(|(name, _)| name);
            match bound {
                Some(name) => self.names.free(name),
                None => break,
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ob::testkit::*;
    use crate::sched::event::EventKind;

    /// A name binds a live object, compares exactly, and goes with the object's last handle — even
    /// while a reference (a wait) keeps the object itself alive.
    #[test]
    fn a_name_goes_with_the_last_handle() {
        let directory = directory();
        let id = directory.create_semaphore(0, 1).unwrap();
        published(directory, id);
        directory.bind_name(&w("F2K.sync.semaphore"), id).unwrap();
        assert_eq!(
            directory.lookup_name(&w("F2K.sync.semaphore"), false),
            Some(id)
        );
        assert_eq!(
            directory.lookup_name(&w("f2k.sync.semaphore"), false),
            None,
            "case-sensitive"
        );
        assert_eq!(directory.lookup_name(&w("F2K.sync"), false), None);
        assert!(directory.reference(id));
        assert_eq!(closed(directory, id), vec![]);
        assert!(directory.is_live(id));
        assert_eq!(
            directory.lookup_name(&w("F2K.sync.semaphore"), false),
            None,
            "the last handle took the name"
        );
        // The name is free for another object.
        let other = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        directory
            .bind_name(&w("F2K.sync.semaphore"), other)
            .unwrap();
        assert_eq!(
            directory.lookup_name(&w("F2K.sync.semaphore"), false),
            Some(other)
        );
    }

    /// A name is any UTF-16 units: a CJK name, one with a surrogate pair, and a lone surrogate each
    /// bind and look up as given, kept apart from the names they would collapse to in a code page.
    #[test]
    fn a_name_is_any_utf16_units() {
        let directory = directory();
        let cjk = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        let pair = directory.create_mutex().unwrap();
        let lone = directory.create_semaphore(0, 1).unwrap();
        directory.bind_name(&w("\u{4E8B}\u{4EF6}"), cjk).unwrap();
        directory.bind_name(&w("F2K.\u{1F600}"), pair).unwrap();
        directory.bind_name(&[0x41, 0xD800, 0x42], lone).unwrap();
        assert_eq!(
            directory.lookup_name(&w("\u{4E8B}\u{4EF6}"), false),
            Some(cjk)
        );
        assert_eq!(
            directory.lookup_name(&w("\u{4E8B}\u{4EF6}"), true),
            Some(cjk)
        );
        assert_eq!(
            directory.lookup_name(&w("F2K.\u{1F600}"), false),
            Some(pair)
        );
        assert_eq!(
            directory.lookup_name(&[0x41, 0xD800, 0x42], false),
            Some(lone)
        );
        assert_eq!(directory.lookup_name(&w("??"), false), None, "no best fit");
        assert_eq!(directory.lookup_name(&w("\u{4E8B}"), false), None);
        assert_eq!(
            directory.name_of(cjk),
            Some(&w("\u{4E8B}\u{4EF6}")[..]),
            "the units as given"
        );
        assert_eq!(directory.name_of(pair), Some(&w("F2K.\u{1F600}")[..]));
    }

    /// OBJ_CASE_INSENSITIVE folds the comparison by NT's upcase rule (ASCII, Latin-1 and Latin
    /// Extended-A letters among others; a unit without a case compares as it is); without it a
    /// name compares exactly.
    #[test]
    fn a_case_insensitive_lookup_folds() {
        let directory = directory();
        let id = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        directory.bind_name(&w("Caf\u{E9}.\u{4E8B}"), id).unwrap();
        assert_eq!(
            directory.lookup_name(&w("CAF\u{C9}.\u{4E8B}"), true),
            Some(id)
        );
        assert_eq!(
            directory.lookup_name(&w("caf\u{e9}.\u{4E8B}"), true),
            Some(id)
        );
        assert_eq!(directory.lookup_name(&w("CAF\u{C9}.\u{4E8B}"), false), None);
        assert_eq!(
            directory.lookup_name(&w("Caf\u{E9}.\u{4E8B}"), false),
            Some(id)
        );
        assert_eq!(directory.lookup_name(&w("Cafe.\u{4E8B}"), true), None);
        assert_eq!(
            directory.lookup_name(&w("Local\\CAF\u{C9}.\u{4E8B}"), true),
            Some(id),
            "past the session prefix"
        );
        let id = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        directory.bind_name(&w("Ma\u{161}ina"), id).unwrap();
        assert_eq!(directory.lookup_name(&w("MA\u{160}INA"), true), Some(id));
        assert_eq!(directory.lookup_name(&w("MA\u{160}INA"), false), None);
        assert_eq!(directory.lookup_name(&w("MASINA"), true), None);
    }

    /// The name table refuses an over-long name, grows past the 256 names it once held, and
    /// refuses a name only when no page is left for it.
    #[test]
    fn the_name_table_bounds() {
        let directory = directory();
        let id = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        assert_eq!(
            directory.bind_name(&[u16::from(b'x'); MAX_NAME + 1], id),
            Err(NameError::TooLong)
        );
        for index in 0..1000 {
            directory.bind_name(&w(&format!("n{index}")), id).unwrap();
        }
        // Each lookup walks the table, so looking every name up costs the square of the names;
        // under Miri, every 99th name and the last (names past the 256 among them) are enough.
        let step = if cfg!(miri) { 99 } else { 1 };
        for index in (0..1000).step_by(step).chain([999]) {
            assert_eq!(
                directory.lookup_name(&w(&format!("n{index}")), false),
                Some(id)
            );
        }
        page_budget(0);
        let more = until_refused(|| directory.bind_name(&w("more"), id).ok());
        assert!(
            more.len() < per_page::<NameEntry>(),
            "the made chunk's rest"
        );
        assert_eq!(
            directory.bind_name(&w("one more"), id),
            Err(NameError::Full)
        );
    }

    /// A full name table refuses the next name, and the names an object's deletion frees serve the
    /// next binds.
    #[test]
    fn the_name_table_fills_and_reuses() {
        let directory = directory();
        let first = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        let second = directory.create_mutex().unwrap();
        // The semaphores' pages (a record's, a body's), made before the pages run out.
        let spare = directory.create_semaphore(0, 1).unwrap();
        assert_eq!(directory.dereference(spare), None);
        for index in 0..300 {
            directory
                .bind_name(&w(&format!("n{index}")), first)
                .unwrap();
        }
        page_budget(0);
        until_refused(|| directory.bind_name(&w("n"), first).ok());
        assert_eq!(
            directory.bind_name(&w("second"), second),
            Err(NameError::Full)
        );
        // One name's room, for the second object.
        let freed = directory.names.iter().next().map(|(name, _)| name).unwrap();
        assert!(directory.names.free(freed));
        directory.bind_name(&w("second"), second).unwrap();
        assert_eq!(
            directory.bind_name(&w("refused"), second),
            Err(NameError::Full)
        );
        assert_eq!(
            directory.lookup_name(&w("refused"), false),
            None,
            "nothing bound"
        );

        assert_eq!(directory.dereference(second), None);
        assert_eq!(
            directory.lookup_name(&w("second"), false),
            None,
            "its name went with it"
        );
        let third = directory.create_semaphore(0, 1).unwrap();
        directory.bind_name(&w("third"), third).unwrap();
        assert_eq!(directory.lookup_name(&w("third"), false), Some(third));
        assert_eq!(
            directory.bind_name(&w("refused"), third),
            Err(NameError::Full)
        );
    }

    /// One namespace for every kind and both session prefixes: `Global\` and `Local\` name the same
    /// object as the bare name, and a name binds one object whatever kind asks.
    #[test]
    fn the_namespace_is_one_directory() {
        let directory = directory();
        let event = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        published(directory, event);
        directory.bind_name(&w("Global\\F2K.ready"), event).unwrap();
        assert_eq!(directory.lookup_name(&w("F2K.ready"), false), Some(event));
        assert_eq!(
            directory.lookup_name(&w("Local\\F2K.ready"), false),
            Some(event)
        );
        assert_eq!(
            directory.lookup_name(&w("Global\\F2K.ready"), false),
            Some(event)
        );
        assert_eq!(
            directory.lookup_name(&w("global\\F2K.ready"), false),
            None,
            "the prefix as spelled"
        );
        // Another kind finds the same binding: its create sees a kind mismatch.
        let found = directory.lookup_name(&w("F2K.ready"), false).unwrap();
        assert_eq!(found.kind, ObjectType::Event);
        assert_eq!(
            namespace_name(&w("Local\\")),
            w(""),
            "a bare prefix names nothing"
        );
        assert_eq!(namespace_name(&w("Session\\1")), w("Session\\1"));
    }
}
