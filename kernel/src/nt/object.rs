//! The object services every handle shares: NtClose, and the handle side of NtDuplicateObject
//! (the service itself is `sync`'s, on the calling process's handle table); and which handles name
//! the calling process.

use super::call::{
    Fault, Handle, NtCall, NtResult, Status, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER,
    STATUS_SUCCESS,
};
use crate::ob::Entry;

/// NtDuplicateObject's options: close the source handle, and give the duplicate the source's
/// access.
pub const DUPLICATE_CLOSE_SOURCE: u32 = 1;
pub const DUPLICATE_SAME_ACCESS: u32 = 2;

/// STATUS_INSUFFICIENT_RESOURCES: no handle could be made.
pub const STATUS_INSUFFICIENT_RESOURCES: Status = Status(0xC000_009A);

/// NtCurrentThread's pseudo-handle (GetCurrentThread's): the calling thread, in every thread
/// service.
pub const CURRENT_THREAD: u32 = 0xFFFF_FFFE;
/// The current-process pseudo-handle (NtCurrentProcess).
pub const CURRENT_PROCESS: u32 = 0xFFFF_FFFF;

/// Whether `handle` is a console handle (the console server's pseudo-handles: the low two tag
/// bits set, bit 28 clear — so INVALID_HANDLE_VALUE is not one). Console handles are the console
/// server's, never decoded as object-table handles.
pub(crate) fn is_console_handle(handle: u32) -> bool {
    handle & 0x1000_0003 == 0x3
}

/// Whether `handle` names the calling process: its pseudo-handle, or a handle to its object. No
/// other process is reachable.
#[cfg(target_arch = "x86")]
pub(crate) fn names_current_process(handle: u32) -> bool {
    let process = crate::process::current();
    handle == CURRENT_PROCESS
        || process
            .handles()
            .lookup(handle)
            .and_then(|entry| entry.object_id())
            == Some(process.object())
}

/// Host builds have no process table: only the pseudo-handle.
#[cfg(not(target_arch = "x86"))]
pub(crate) fn names_current_process(handle: u32) -> bool {
    handle == CURRENT_PROCESS
}

/// NtClose: the handle's entry released from the calling process's handle table (the object goes
/// once its last reference does). STATUS_INVALID_HANDLE for a handle naming no entry.
pub fn close(call: &mut NtCall, handle: Handle) -> NtResult {
    #[cfg(target_arch = "x86")]
    {
        if call.process().close_handle(handle.raw()) {
            Ok(STATUS_SUCCESS)
        } else {
            Err(STATUS_INVALID_HANDLE)
        }
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = (call, handle);
        Err(STATUS_INVALID_HANDLE)
    }
}

/// The handle table a duplicate goes into (the calling process's), behind a seam so the order of
/// [`duplicate_entry`]'s steps is host-tested.
pub trait DuplicateTable {
    /// A new handle for `entry`, zero when none can be made (a full table, or an object at its
    /// handle count's limit).
    fn insert(&mut self, entry: Entry) -> u32;
    /// Close `handle`, releasing what it named.
    fn close(&mut self, handle: u32);
}

/// NtDuplicateObject's target-process argument.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TargetProcess {
    /// None given (a null handle): the call can only close the source.
    None,
    /// The calling process.
    Current,
    /// A handle naming no process F2K can reach.
    Invalid,
}

/// NtDuplicateObject once its source handle is found, as `entry`: a new handle naming the same
/// object in the target process, with `access` or the source's (DUPLICATE_SAME_ACCESS), inheritable
/// when the attributes say OBJ_INHERIT, written through `write`. `closable` is the source handle
/// when DUPLICATE_CLOSE_SOURCE can close it (none for a pseudo-handle). From here on the option
/// closes the source whatever the outcome, as Windows 2000's does: with no target process that
/// is the whole call (STATUS_SUCCESS; STATUS_INVALID_PARAMETER without the option); a target
/// process naming none is STATUS_INVALID_HANDLE, a handle that cannot be made
/// STATUS_INSUFFICIENT_RESOURCES, and a target the write cannot reach STATUS_ACCESS_VIOLATION,
/// the new handle closed again. The duplicate is made before the source closes, so the object
/// never loses its last handle in between.
#[allow(clippy::too_many_arguments)]
pub fn duplicate_entry(
    table: &mut impl DuplicateTable,
    entry: Entry,
    closable: Option<u32>,
    target_process: TargetProcess,
    access: u32,
    attributes: u32,
    options: u32,
    write: impl FnOnce(u32) -> Result<(), Fault>,
) -> NtResult {
    let close_source = options & DUPLICATE_CLOSE_SOURCE != 0;
    let result = match target_process {
        TargetProcess::None if close_source => Ok(STATUS_SUCCESS),
        TargetProcess::None => Err(STATUS_INVALID_PARAMETER),
        TargetProcess::Invalid => Err(STATUS_INVALID_HANDLE),
        TargetProcess::Current => {
            let access = if options & DUPLICATE_SAME_ACCESS != 0 {
                entry.access
            } else {
                access
            };
            let inherit = attributes & super::attributes::OBJ_INHERIT != 0;
            match table.insert(Entry {
                target: entry.target,
                access,
                inherit,
            }) {
                0 => Err(STATUS_INSUFFICIENT_RESOURCES),
                handle => write(handle).map(|()| STATUS_SUCCESS).map_err(|fault| {
                    table.close(handle);
                    Status::from(fault)
                }),
            }
        }
    };
    if let (true, Some(source)) = (close_source, closable) {
        table.close(source);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nt::call::STATUS_ACCESS_VIOLATION;
    use crate::ob::{ObjectId, ObjectType};

    const SOURCE: u32 = 0x44;
    const NEW: u32 = 0x48;

    /// A handle table that records what the duplication did to it.
    struct Table {
        full: bool,
        inserted: Vec<Entry>,
        closed: Vec<u32>,
    }

    impl Table {
        fn new(full: bool) -> Self {
            Table {
                full,
                inserted: Vec::new(),
                closed: Vec::new(),
            }
        }
    }

    impl DuplicateTable for Table {
        fn insert(&mut self, entry: Entry) -> u32 {
            if self.full {
                return 0;
            }
            self.inserted.push(entry);
            NEW
        }

        fn close(&mut self, handle: u32) {
            self.closed.push(handle);
        }
    }

    fn event() -> Entry {
        Entry::object(
            ObjectId {
                kind: ObjectType::Event,
                index: 3,
                generation: 1,
            },
            0x1F_0003,
            false,
        )
    }

    fn duplicate(
        table: &mut Table,
        target: TargetProcess,
        options: u32,
        write: Result<(), Fault>,
    ) -> NtResult {
        duplicate_entry(
            table,
            event(),
            Some(SOURCE),
            target,
            0x10_0000,
            0,
            options,
            |handle| {
                assert_eq!(handle, NEW);
                write
            },
        )
    }

    /// A duplicate names the source's object, with the access asked for or the source's, and the
    /// inheritance the attributes ask; the source is closed only when asked.
    #[test]
    fn a_duplicate_names_the_object_with_its_access() {
        let mut table = Table::new(false);
        assert_eq!(
            duplicate(&mut table, TargetProcess::Current, 0, Ok(())),
            Ok(STATUS_SUCCESS)
        );
        assert_eq!(
            table.inserted,
            [Entry {
                access: 0x10_0000,
                ..event()
            }]
        );
        assert!(table.closed.is_empty());

        let mut table = Table::new(false);
        let result = duplicate_entry(
            &mut table,
            event(),
            Some(SOURCE),
            TargetProcess::Current,
            0,
            super::super::attributes::OBJ_INHERIT,
            DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE,
            |_| Ok(()),
        );
        assert_eq!(result, Ok(STATUS_SUCCESS));
        assert_eq!(
            table.inserted,
            [Entry {
                inherit: true,
                ..event()
            }]
        );
        assert_eq!(table.closed, [SOURCE]);
    }

    /// DUPLICATE_CLOSE_SOURCE closes the source whatever the outcome once it is found: a
    /// target process naming none, a handle that cannot be made, a target handle the write cannot
    /// reach (whose new handle goes again). Without it, a failure leaves the source alone.
    #[test]
    fn close_source_closes_on_the_failure_paths_too() {
        let mut table = Table::new(false);
        let result = duplicate(
            &mut table,
            TargetProcess::Invalid,
            DUPLICATE_CLOSE_SOURCE,
            Ok(()),
        );
        assert_eq!(result, Err(STATUS_INVALID_HANDLE));
        assert!(table.inserted.is_empty());
        assert_eq!(table.closed, [SOURCE]);

        let mut table = Table::new(true);
        let result = duplicate(
            &mut table,
            TargetProcess::Current,
            DUPLICATE_CLOSE_SOURCE,
            Ok(()),
        );
        assert_eq!(result, Err(STATUS_INSUFFICIENT_RESOURCES));
        assert_eq!(table.closed, [SOURCE]);

        let mut table = Table::new(false);
        let result = duplicate(
            &mut table,
            TargetProcess::Current,
            DUPLICATE_CLOSE_SOURCE,
            Err(Fault),
        );
        assert_eq!(result, Err(STATUS_ACCESS_VIOLATION));
        assert_eq!(table.closed, [NEW, SOURCE]);

        let mut table = Table::new(true);
        assert_eq!(
            duplicate(&mut table, TargetProcess::Current, 0, Ok(())),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );
        assert!(table.closed.is_empty());
    }

    /// With no target process, closing the source is the whole call: STATUS_SUCCESS with
    /// DUPLICATE_CLOSE_SOURCE, STATUS_INVALID_PARAMETER (and the source kept) without it.
    #[test]
    fn no_target_process_only_closes_the_source() {
        let mut table = Table::new(false);
        assert_eq!(
            duplicate(
                &mut table,
                TargetProcess::None,
                DUPLICATE_CLOSE_SOURCE,
                Ok(())
            ),
            Ok(STATUS_SUCCESS)
        );
        assert!(table.inserted.is_empty());
        assert_eq!(table.closed, [SOURCE]);

        let mut table = Table::new(false);
        assert_eq!(
            duplicate(&mut table, TargetProcess::None, 0, Ok(())),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert!(table.inserted.is_empty() && table.closed.is_empty());
    }

    /// A pseudo-handle source (the current thread or process) has nothing to close.
    #[test]
    fn a_pseudo_handle_source_is_never_closed() {
        let mut table = Table::new(true);
        let result = duplicate_entry(
            &mut table,
            event(),
            None,
            TargetProcess::Current,
            0,
            0,
            DUPLICATE_CLOSE_SOURCE,
            |_| Ok(()),
        );
        assert_eq!(result, Err(STATUS_INSUFFICIENT_RESOURCES));
        assert!(table.closed.is_empty());
    }

    /// The console tag: every std handle the process parameters carry has it and object handles
    /// (multiples of four) never do, so the object services can route on it; INVALID_HANDLE_VALUE
    /// is not a console handle (the bit-28 mask).
    #[test]
    fn console_handles_are_told_apart_from_object_handles() {
        use crate::user::params::{STD_ERROR, STD_INPUT, STD_OUTPUT};
        const INVALID_HANDLE_VALUE: u32 = 0xFFFF_FFFF;
        for handle in [STD_INPUT, STD_OUTPUT, STD_ERROR] {
            assert!(is_console_handle(handle), "{handle:#x}");
        }
        for handle in [4, 8, 12, 0x3C] {
            assert!(!is_console_handle(handle), "{handle:#x}");
        }
        assert!(!is_console_handle(INVALID_HANDLE_VALUE));
        assert!(!is_console_handle(0));
    }
}
