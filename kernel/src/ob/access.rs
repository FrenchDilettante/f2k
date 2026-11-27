//! Access masks: what each kind of object grants a handle, and what its services ask of one.
//!
//! An access mask is the request's rights: specific ones (the kind's own, the low 16 bits),
//! standard ones (DELETE, READ_CONTROL, SYNCHRONIZE...), and the generic ones (GENERIC_READ,
//! WRITE, EXECUTE and ALL), which each kind maps to its own rights — its GENERIC_MAPPING, Windows
//! 2000's object types' (ExpEventMapping, ExpMutantMapping, MmpSectionMapping...). A handle keeps
//! the mapped mask ([`ObjectType::granted`], applied as each handle is made: a create, an open, a
//! duplicate), so ObjectBasicInformation.GrantedAccess shows the specific rights and a service
//! checks them as they are. MAXIMUM_ALLOWED is every right the kind has: F2K keeps no security
//! descriptor that would restrict it. A service asks the handle for its rights in
//! ObReferenceObjectByHandle's order (the handle, the kind, then the access: [`check`]), and a
//! handle short of them is STATUS_ACCESS_DENIED.

// The standard, generic and kinds' rights, from their one home.
pub use rtl::nt::access::{
    DIRECTORY_ALL_ACCESS,
    DIRECTORY_CREATE_OBJECT,
    DIRECTORY_CREATE_SUBDIRECTORY,
    DIRECTORY_QUERY,
    DIRECTORY_TRAVERSE,
    EVENT_MODIFY_STATE,
    EVENT_QUERY_STATE,
    GENERIC_ALL,
    GENERIC_EXECUTE,
    GENERIC_READ,
    GENERIC_WRITE,
    MAXIMUM_ALLOWED,
    MUTANT_ALL_ACCESS,
    MUTANT_QUERY_STATE,
    SECTION_MAP_EXECUTE,
    SECTION_MAP_READ,
    SECTION_MAP_WRITE,
    SECTION_QUERY,
    SEMAPHORE_ALL_ACCESS,
    SEMAPHORE_MODIFY_STATE,
    SEMAPHORE_QUERY_STATE,
    SYNCHRONIZE,
    TIMER_ALL_ACCESS,
    TIMER_MODIFY_STATE,
    TIMER_QUERY_STATE,
};
use rtl::nt::access::{STANDARD_RIGHTS_EXECUTE, STANDARD_RIGHTS_READ, STANDARD_RIGHTS_WRITE};

use super::ObjectType;
use crate::status::{NtStatus, STATUS_ACCESS_DENIED};
/// The specific and standard rights: what a mask names besides the generic ones (the process,
/// thread, file, key and token mappings keep the same).
const SPECIFIC_AND_STANDARD: u32 = 0x00FF_FFFF;

/// A kind's GENERIC_MAPPING: the rights each generic right stands for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenericMapping {
    pub read: u32,
    pub write: u32,
    pub execute: u32,
    pub all: u32,
}

impl GenericMapping {
    /// `access` with its generic rights mapped (RtlMapGenericMask), MAXIMUM_ALLOWED as every
    /// right.
    pub fn map(&self, access: u32) -> u32 {
        let mut granted = access & SPECIFIC_AND_STANDARD;
        for (generic, rights) in [
            (GENERIC_READ, self.read),
            (GENERIC_WRITE, self.write),
            (GENERIC_EXECUTE, self.execute),
            (GENERIC_ALL | MAXIMUM_ALLOWED, self.all),
        ] {
            if access & generic != 0 {
                granted |= rights;
            }
        }
        granted
    }
}

/// The event type's mapping: read queries, write sets and clears, execute waits.
pub const EVENT_MAPPING: GenericMapping = GenericMapping {
    read: STANDARD_RIGHTS_READ | EVENT_QUERY_STATE,
    write: STANDARD_RIGHTS_WRITE | EVENT_MODIFY_STATE,
    execute: STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE,
    all: super::EVENT_ALL_ACCESS,
};

/// The mutant type's mapping: read queries, write grants nothing of the mutant's own, execute
/// waits.
pub const MUTANT_MAPPING: GenericMapping = GenericMapping {
    read: STANDARD_RIGHTS_READ | MUTANT_QUERY_STATE,
    write: STANDARD_RIGHTS_WRITE,
    execute: STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE,
    all: MUTANT_ALL_ACCESS,
};

/// The semaphore type's mapping: read queries, write releases, execute waits.
pub const SEMAPHORE_MAPPING: GenericMapping = GenericMapping {
    read: STANDARD_RIGHTS_READ | SEMAPHORE_QUERY_STATE,
    write: STANDARD_RIGHTS_WRITE | SEMAPHORE_MODIFY_STATE,
    execute: STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE,
    all: SEMAPHORE_ALL_ACCESS,
};

/// The timer type's mapping: read queries, write sets and cancels, execute waits.
pub const TIMER_MAPPING: GenericMapping = GenericMapping {
    read: STANDARD_RIGHTS_READ | TIMER_QUERY_STATE,
    write: STANDARD_RIGHTS_WRITE | TIMER_MODIFY_STATE,
    execute: STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE,
    all: TIMER_ALL_ACCESS,
};

/// The section type's mapping: read queries and maps for reading, write maps for writing,
/// execute maps for executing. No right of a section's waits on it: it is no waitable object.
pub const SECTION_MAPPING: GenericMapping = GenericMapping {
    read: STANDARD_RIGHTS_READ | SECTION_QUERY | SECTION_MAP_READ,
    write: STANDARD_RIGHTS_WRITE | SECTION_MAP_WRITE,
    execute: STANDARD_RIGHTS_EXECUTE | SECTION_MAP_EXECUTE,
    all: super::SECTION_ALL_ACCESS,
};

/// The object directory type's mapping: read and execute query and traverse, write creates in
/// it.
pub const DIRECTORY_MAPPING: GenericMapping = GenericMapping {
    read: STANDARD_RIGHTS_READ | DIRECTORY_QUERY | DIRECTORY_TRAVERSE,
    write: STANDARD_RIGHTS_WRITE | DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY,
    execute: STANDARD_RIGHTS_EXECUTE | DIRECTORY_QUERY | DIRECTORY_TRAVERSE,
    all: DIRECTORY_ALL_ACCESS,
};

impl ObjectType {
    /// Whether this kind maps the generic rights to its own rights (a real GENERIC_MAPPING, as
    /// [`ObjectType::granted`] maps them); win32k's kinds (a window station, a desktop, the GDI
    /// objects) pass a mask through as it is.
    pub fn maps_generics(self) -> bool {
        !matches!(
            self,
            ObjectType::WindowStation
                | ObjectType::Desktop
                | ObjectType::Dc
                | ObjectType::Brush
                | ObjectType::Bitmap
                | ObjectType::Font
                | ObjectType::Region
        )
    }

    /// The access a handle to an object of this kind asking for `desired` is granted: its generic
    /// rights mapped as the kind maps them (see the module notes). The process, thread, file, key
    /// and token kinds map as their services always have ([`crate::nt::object::process_access`],
    /// [`crate::fs::file::rights::mapped`]...); win32k's kinds (a window station, a desktop, the
    /// GDI objects) keep the mask they are given.
    pub fn granted(self, desired: u32) -> u32 {
        match self {
            ObjectType::Event => EVENT_MAPPING.map(desired),
            ObjectType::Mutex => MUTANT_MAPPING.map(desired),
            ObjectType::Semaphore => SEMAPHORE_MAPPING.map(desired),
            ObjectType::Timer => TIMER_MAPPING.map(desired),
            ObjectType::Section => SECTION_MAPPING.map(desired),
            ObjectType::Directory => DIRECTORY_MAPPING.map(desired),
            ObjectType::Process => crate::nt::object::process_access(desired),
            ObjectType::Thread => crate::nt::object::thread_access(desired),
            ObjectType::File => crate::fs::file::rights::mapped(desired),
            ObjectType::Key => crate::nt::key::granted(desired),
            ObjectType::Token => crate::nt::token::granted(desired),
            ObjectType::WindowStation
            | ObjectType::Desktop
            | ObjectType::Dc
            | ObjectType::Brush
            | ObjectType::Bitmap
            | ObjectType::Font
            | ObjectType::Region => desired,
        }
    }
}

/// Whether a handle granted `granted` holds every right of `needed`: STATUS_ACCESS_DENIED
/// otherwise. Nothing needed is always granted.
pub fn check(granted: u32, needed: u32) -> Result<(), NtStatus> {
    if granted & needed != needed {
        return Err(STATUS_ACCESS_DENIED);
    }
    Ok(())
}

/// The right signaling an object of `kind` needs (NtSetEvent's, NtReleaseSemaphore's,
/// NtSignalAndWaitForSingleObject's signal): EVENT_MODIFY_STATE, SEMAPHORE_MODIFY_STATE, and none
/// for a mutant — only its owner releases it, whatever its handle grants, so Windows 2000's
/// NtReleaseMutant references its handle for no access. None for a kind no service signals.
pub fn signal_right(kind: ObjectType) -> Option<u32> {
    match kind {
        ObjectType::Event => Some(EVENT_MODIFY_STATE),
        ObjectType::Semaphore => Some(SEMAPHORE_MODIFY_STATE),
        ObjectType::Mutex => Some(0),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use rtl::nt::access::READ_CONTROL;

    use super::*;

    const KINDS: [ObjectType; 18] = [
        ObjectType::Event,
        ObjectType::Semaphore,
        ObjectType::Mutex,
        ObjectType::Timer,
        ObjectType::Thread,
        ObjectType::Process,
        ObjectType::Section,
        ObjectType::File,
        ObjectType::Directory,
        ObjectType::WindowStation,
        ObjectType::Desktop,
        ObjectType::Key,
        ObjectType::Dc,
        ObjectType::Brush,
        ObjectType::Bitmap,
        ObjectType::Font,
        ObjectType::Region,
        ObjectType::Token,
    ];

    #[test]
    fn the_all_access_masks_are_winnts() {
        assert_eq!(super::super::EVENT_ALL_ACCESS, 0x001F_0003);
        assert_eq!(MUTANT_ALL_ACCESS, 0x001F_0001);
        assert_eq!(SEMAPHORE_ALL_ACCESS, 0x001F_0003);
        assert_eq!(TIMER_ALL_ACCESS, 0x001F_0003);
        assert_eq!(super::super::SECTION_ALL_ACCESS, 0x000F_001F);
        assert_eq!(DIRECTORY_ALL_ACCESS, 0x000F_000F);
    }

    #[test]
    fn the_generic_rights_map_to_each_kinds_own() {
        let event = ObjectType::Event;
        assert_eq!(event.granted(GENERIC_READ), 0x0002_0001);
        assert_eq!(event.granted(GENERIC_WRITE), 0x0002_0002);
        assert_eq!(event.granted(GENERIC_EXECUTE), 0x0012_0000);
        assert_eq!(event.granted(GENERIC_ALL), 0x001F_0003);
        let mutant = ObjectType::Mutex;
        assert_eq!(mutant.granted(GENERIC_READ), 0x0002_0001);
        assert_eq!(mutant.granted(GENERIC_WRITE), READ_CONTROL);
        assert_eq!(mutant.granted(GENERIC_EXECUTE), 0x0012_0000);
        assert_eq!(mutant.granted(GENERIC_ALL), 0x001F_0001);
        for kind in [ObjectType::Semaphore, ObjectType::Timer] {
            assert_eq!(kind.granted(GENERIC_READ), 0x0002_0001);
            assert_eq!(kind.granted(GENERIC_WRITE), 0x0002_0002);
            assert_eq!(kind.granted(GENERIC_EXECUTE), 0x0012_0000);
            assert_eq!(kind.granted(GENERIC_ALL), 0x001F_0003);
        }
        let section = ObjectType::Section;
        assert_eq!(section.granted(GENERIC_READ), 0x0002_0005);
        assert_eq!(section.granted(GENERIC_WRITE), 0x0002_0002);
        assert_eq!(section.granted(GENERIC_EXECUTE), 0x0002_0008);
        assert_eq!(section.granted(GENERIC_ALL), 0x000F_001F);
        let directory = ObjectType::Directory;
        assert_eq!(directory.granted(GENERIC_READ), 0x0002_0003);
        assert_eq!(directory.granted(GENERIC_WRITE), 0x0002_000C);
        assert_eq!(directory.granted(GENERIC_ALL), 0x000F_000F);
    }

    #[test]
    fn specific_rights_stay_and_maximum_allowed_is_everything() {
        let event = ObjectType::Event;
        assert_eq!(event.granted(SYNCHRONIZE), SYNCHRONIZE);
        assert_eq!(event.granted(EVENT_MODIFY_STATE), EVENT_MODIFY_STATE);
        assert_eq!(event.granted(0), 0);
        assert_eq!(
            event.granted(GENERIC_READ | EVENT_MODIFY_STATE),
            0x0002_0003
        );
        assert_eq!(event.granted(MAXIMUM_ALLOWED), 0x001F_0003);
        assert_eq!(
            ObjectType::Mutex.granted(MAXIMUM_ALLOWED),
            MUTANT_ALL_ACCESS
        );
        assert_eq!(ObjectType::Section.granted(MAXIMUM_ALLOWED), 0x000F_001F);
    }

    #[test]
    fn mapping_is_idempotent_for_every_kind() {
        // A duplicate maps its source's access again: an access mapped once maps to itself.
        for kind in KINDS {
            for desired in [
                0,
                SYNCHRONIZE,
                GENERIC_READ,
                GENERIC_WRITE,
                GENERIC_EXECUTE,
                GENERIC_ALL,
                MAXIMUM_ALLOWED,
                GENERIC_READ | GENERIC_WRITE | 0x0001,
            ] {
                let granted = kind.granted(desired);
                assert_eq!(kind.granted(granted), granted, "{kind:?} {desired:#x}");
            }
        }
    }

    #[test]
    fn the_kinds_that_mapped_themselves_still_do() {
        use crate::nt::object::{process_access, thread_access};
        for desired in [
            GENERIC_READ,
            GENERIC_WRITE,
            GENERIC_EXECUTE,
            GENERIC_ALL,
            0x0400,
        ] {
            assert_eq!(
                ObjectType::Process.granted(desired),
                process_access(desired)
            );
            assert_eq!(ObjectType::Thread.granted(desired), thread_access(desired));
            assert_eq!(
                ObjectType::File.granted(desired),
                crate::fs::file::rights::mapped(desired)
            );
            assert_eq!(
                ObjectType::Key.granted(desired),
                crate::nt::key::granted(desired)
            );
            assert_eq!(
                ObjectType::Token.granted(desired),
                crate::nt::token::granted(desired)
            );
        }
        // win32k's kinds keep the mask they are given.
        assert_eq!(ObjectType::Dc.granted(GENERIC_ALL), GENERIC_ALL);
    }

    #[test]
    fn the_kinds_with_a_real_mapping_are_told_from_win32ks() {
        for kind in KINDS {
            let maps = !matches!(
                kind,
                ObjectType::WindowStation
                    | ObjectType::Desktop
                    | ObjectType::Dc
                    | ObjectType::Brush
                    | ObjectType::Bitmap
                    | ObjectType::Font
                    | ObjectType::Region
            );
            assert_eq!(kind.maps_generics(), maps, "{kind:?}");
        }
        assert!(ObjectType::Event.maps_generics());
        assert!(!ObjectType::Desktop.maps_generics());
    }

    #[test]
    fn a_check_needs_every_right() {
        assert_eq!(check(EVENT_MODIFY_STATE, EVENT_MODIFY_STATE), Ok(()));
        assert_eq!(
            check(SYNCHRONIZE, EVENT_MODIFY_STATE),
            Err(STATUS_ACCESS_DENIED)
        );
        assert_eq!(check(SYNCHRONIZE, 0), Ok(()));
        assert_eq!(check(0, 0), Ok(()));
        assert_eq!(
            check(SECTION_MAP_READ, SECTION_MAP_READ | SECTION_MAP_EXECUTE),
            Err(STATUS_ACCESS_DENIED)
        );
    }

    #[test]
    fn signaling_needs_the_modify_right_but_a_mutants_owner_needs_none() {
        assert_eq!(signal_right(ObjectType::Event), Some(EVENT_MODIFY_STATE));
        assert_eq!(
            signal_right(ObjectType::Semaphore),
            Some(SEMAPHORE_MODIFY_STATE)
        );
        assert_eq!(signal_right(ObjectType::Mutex), Some(0));
        assert_eq!(signal_right(ObjectType::Timer), None);
        assert_eq!(signal_right(ObjectType::File), None);
    }

    #[test]
    fn a_file_handle_reduced_to_reading_neither_writes_nor_maps_for_writing() {
        // The file services and a file's section take the handle's access, not its open's: a
        // duplicate asking GENERIC_READ of a read-write open grants no write right.
        use crate::fs::file::rights::{share_access, FILE_APPEND_DATA, FILE_WRITE_DATA};
        use crate::fs::file::ACCESS_READ;
        let read = ObjectType::File.granted(GENERIC_READ);
        assert_eq!(read & (FILE_WRITE_DATA | FILE_APPEND_DATA), 0);
        assert_eq!(share_access(read), ACCESS_READ);
    }
}
