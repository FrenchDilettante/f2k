//! Access masks: what each kind of object grants a handle, and what its services ask of one.
//!
//! An access mask is the request's rights: specific ones (the kind's own, the low 16 bits),
//! standard ones (DELETE, READ_CONTROL, SYNCHRONIZE...), and the generic ones (GENERIC_READ,
//! WRITE, EXECUTE and ALL), which each kind maps to its own rights — its GENERIC_MAPPING, Windows
//! 2000's object types' (ExpEventMapping, ExpMutantMapping, MmpSectionMapping...). A handle keeps
//! the mapped mask ([`ObjectType::granted`], applied as each handle is made: a create, an open, a
//! duplicate), so ObjectBasicInformation.GrantedAccess shows the specific rights and a service
//! checks them as they are. MAXIMUM_ALLOWED is every right the kind has: F2K keeps no security
//! descriptor that would restrict it.

use super::ObjectType;

/// The standard rights.
pub const READ_CONTROL: u32 = 0x0002_0000;
pub const SYNCHRONIZE: u32 = 0x0010_0000;
pub const STANDARD_RIGHTS_REQUIRED: u32 = 0x000F_0000;
/// What the generic rights carry of the standard ones: READ_CONTROL alone, each.
const STANDARD_RIGHTS_READ: u32 = READ_CONTROL;
const STANDARD_RIGHTS_WRITE: u32 = READ_CONTROL;
const STANDARD_RIGHTS_EXECUTE: u32 = READ_CONTROL;

/// The generic rights, and MAXIMUM_ALLOWED.
pub const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
pub const GENERIC_ALL: u32 = 0x1000_0000;
pub const GENERIC_EXECUTE: u32 = 0x2000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const GENERIC_READ: u32 = 0x8000_0000;
/// The specific and standard rights: what a mask names besides the generic ones (the process,
/// thread, file, key and token mappings keep the same).
const SPECIFIC_AND_STANDARD: u32 = 0x00FF_FFFF;

/// The event rights (winnt.h).
pub const EVENT_QUERY_STATE: u32 = 0x0001;
pub const EVENT_MODIFY_STATE: u32 = 0x0002;
/// The mutant rights: querying alone (releasing is the owner's, whatever its handle grants).
pub const MUTANT_QUERY_STATE: u32 = 0x0001;
pub const MUTANT_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | MUTANT_QUERY_STATE;
/// The semaphore rights.
pub const SEMAPHORE_QUERY_STATE: u32 = 0x0001;
pub const SEMAPHORE_MODIFY_STATE: u32 = 0x0002;
pub const SEMAPHORE_ALL_ACCESS: u32 =
    STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | SEMAPHORE_QUERY_STATE | SEMAPHORE_MODIFY_STATE;
/// The timer rights.
pub const TIMER_QUERY_STATE: u32 = 0x0001;
pub const TIMER_MODIFY_STATE: u32 = 0x0002;
pub const TIMER_ALL_ACCESS: u32 =
    STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | TIMER_QUERY_STATE | TIMER_MODIFY_STATE;
/// The section rights.
pub const SECTION_QUERY: u32 = 0x0001;
pub const SECTION_MAP_WRITE: u32 = 0x0002;
pub const SECTION_MAP_READ: u32 = 0x0004;
pub const SECTION_MAP_EXECUTE: u32 = 0x0008;
/// The object directory rights.
pub const DIRECTORY_QUERY: u32 = 0x0001;
pub const DIRECTORY_TRAVERSE: u32 = 0x0002;
pub const DIRECTORY_CREATE_OBJECT: u32 = 0x0004;
pub const DIRECTORY_CREATE_SUBDIRECTORY: u32 = 0x0008;
pub const DIRECTORY_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED | 0x000F;

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
            | ObjectType::Font => desired,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KINDS: [ObjectType; 17] = [
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
}
