//! NT status codes: the documented NTSTATUS values the kernel reports, through its system services
//! and its internal APIs alike.
//!
//! The type and the numbers are rtl's ([`rtl::status`]), the one table the DLLs share; this module
//! names, as typed [`NtStatus`] values, every code the kernel produces or checks for. A status's
//! top two bits are its severity: success and informational codes pass NT_SUCCESS
//! ([`NtStatus::is_success`]), warnings and errors do not. Only at the very edge, a register or a
//! word of user memory, is a status its raw `u32` (`.0`).

pub use rtl::status::NtStatus;

/// Each name, typed, from rtl's number of the same name.
macro_rules! statuses {
    ($($(#[$doc:meta])* $name:ident,)*) => {
        $(
            $(#[$doc])*
            pub const $name: NtStatus = NtStatus(rtl::status::$name);
        )*
    };
}

statuses! {
    // Success.
    /// The operation completed.
    STATUS_SUCCESS,
    /// A wait took a mutex its previous owner ended holding: the wait succeeded, and the protected
    /// state may be inconsistent. OR'd with the satisfying index (`WAIT_ABANDONED_0 + n`).
    STATUS_ABANDONED,
    /// A wait broken so a user APC could be delivered: an alertable wait returns it once the queued
    /// APCs have run (the Win32 wait returns it raw, `WAIT_IO_COMPLETION`).
    STATUS_USER_APC,
    /// A wait broken so a kernel APC could be delivered. The wait replays; the APC machinery
    /// reports this to itself, never to a caller.
    STATUS_KERNEL_APC,
    /// A wait's timeout elapsed first. The Win32 wait returns this value raw (`WAIT_TIMEOUT`).
    STATUS_TIMEOUT,
    /// The operation has not completed: a live process's exit status (kernel32's STILL_ACTIVE).
    #[cfg(test)]
    STATUS_PENDING,

    // Informational.
    /// A create that opened an object of the name that already existed.
    STATUS_OBJECT_NAME_EXISTS,
    /// An image's view mapped away from its preferred base, which another region holds.
    STATUS_IMAGE_NOT_AT_BASE,
    /// A yield found no thread to hand the processor to (SwitchToThread returns FALSE).
    STATUS_NO_YIELD_PERFORMED,
    /// A timer set to resume the system, which this one cannot.
    STATUS_TIMER_RESUME_IGNORED,

    // Warnings.
    /// The answer did not fit the caller's buffer: what fits is written, and the call reports it.
    STATUS_BUFFER_OVERFLOW,
    /// A directory listing has no entry left.
    STATUS_NO_MORE_FILES,
    /// A copy between address spaces stopped at a page of the process's it could not reach
    /// (kernel32's ERROR_PARTIAL_COPY, "only part of a ReadProcessMemory or WriteProcessMemory
    /// request was completed"). The count copied is written all the same.
    STATUS_PARTIAL_COPY,
    /// An enumeration (of a key's subkeys or values) has no entry at the index.
    STATUS_NO_MORE_ENTRIES,

    // Errors.
    /// The operation failed, for no more particular reason.
    STATUS_UNSUCCESSFUL,
    /// A service or a request that is not implemented.
    STATUS_NOT_IMPLEMENTED,
    /// An information class the service does not answer.
    STATUS_INVALID_INFO_CLASS,
    /// A buffer of the wrong length for the information class's structure.
    STATUS_INFO_LENGTH_MISMATCH,
    /// A fault in the caller's memory.
    STATUS_ACCESS_VIOLATION,
    /// A handle that names nothing in the table.
    STATUS_INVALID_HANDLE,
    /// A client id naming no thread of the process.
    STATUS_INVALID_CID,
    /// A parameter is out of range (a block read past the device's end).
    STATUS_INVALID_PARAMETER,
    /// No such device (no usable disk where one was asked for).
    STATUS_NO_SUCH_DEVICE,
    /// No such file: a path component names no entry of its directory.
    STATUS_NO_SUCH_FILE,
    /// A request the object does not take (a read or write of a directory).
    STATUS_INVALID_DEVICE_REQUEST,
    /// A read at or past the end of the file.
    STATUS_END_OF_FILE,
    /// No virtual memory left to reserve or commit.
    STATUS_NO_MEMORY,
    /// A range that overlaps memory already reserved.
    STATUS_CONFLICTING_ADDRESSES,
    /// An address that is no mapped view's base.
    STATUS_NOT_MAPPED_VIEW,
    /// A view's size past its section's.
    STATUS_INVALID_VIEW_SIZE,
    /// A file a section cannot be made of.
    STATUS_INVALID_FILE_FOR_SECTION,
    /// The handle or the object was not granted the access the service needs.
    STATUS_ACCESS_DENIED,
    /// The caller's buffer cannot hold the data (a file read into less than the file's size).
    STATUS_BUFFER_TOO_SMALL,
    /// A name or handle of another kind of object.
    STATUS_OBJECT_TYPE_MISMATCH,
    /// A range that is not committed.
    STATUS_NOT_COMMITTED,
    /// Parameters that cannot be given together (or not one of them given).
    STATUS_INVALID_PARAMETER_MIX,
    /// The name is malformed (an empty path or component, or a component that is not an 8.3 name).
    STATUS_OBJECT_NAME_INVALID,
    /// An open of a missing name.
    STATUS_OBJECT_NAME_NOT_FOUND,
    /// A create of a name that exists.
    STATUS_OBJECT_NAME_COLLISION,
    /// A path's directory is missing (or a component on the way is a file).
    STATUS_OBJECT_PATH_NOT_FOUND,
    /// A path that is not absolute where one must be.
    STATUS_OBJECT_PATH_SYNTAX_BAD,
    /// A section larger than its file, or than the kernel can hold.
    STATUS_SECTION_TOO_BIG,
    /// An open of the same file excludes this one.
    STATUS_SHARING_VIOLATION,
    /// A page protection that is not one of the documented values.
    STATUS_INVALID_PAGE_PROTECTION,
    /// A mutex release by a thread that does not own it.
    STATUS_MUTANT_NOT_OWNED,
    /// A semaphore release would push the count past its limit.
    STATUS_SEMAPHORE_LIMIT_EXCEEDED,
    /// The image information of a data section.
    STATUS_SECTION_NOT_IMAGE,
    /// A thread's suspend count is at its documented maximum (127).
    STATUS_SUSPEND_COUNT_EXCEEDED,
    /// The thread is terminating; operations that would queue work on it are refused.
    STATUS_THREAD_IS_TERMINATING,
    /// A view's protection the section's does not allow.
    STATUS_SECTION_PROTECTION,
    /// The file is being deleted: it goes with its last open's cleanup, and no new open is allowed.
    STATUS_DELETE_PENDING,
    /// The bytes are no image the loader accepts.
    STATUS_INVALID_IMAGE_FORMAT,
    /// The volume has no free cluster left.
    STATUS_DISK_FULL,
    /// A table the call needs is full (the handle table, a key's records).
    STATUS_INSUFFICIENT_RESOURCES,
    /// A release of memory at an address that is not its allocation's base.
    STATUS_FREE_VM_NOT_AT_BASE,
    /// A release of memory that is not allocated.
    STATUS_MEMORY_NOT_ALLOCATED,
    /// The device, or the file, takes no writes.
    STATUS_MEDIA_WRITE_PROTECTED,
    /// A device did not respond in time.
    STATUS_IO_TIMEOUT,
    /// The path names a directory where a file must be.
    STATUS_FILE_IS_A_DIRECTORY,
    /// NtTerminateThread with no handle from a process's only thread (kernel32's ExitThread then
    /// ends the process instead).
    STATUS_CANT_TERMINATE_SELF,
    /// A buffer that passed the probe but could not be read.
    STATUS_INVALID_USER_BUFFER,
    /// The service's first parameter is invalid.
    STATUS_INVALID_PARAMETER_1,
    /// The service's second parameter is invalid.
    STATUS_INVALID_PARAMETER_2,
    /// The service's third parameter is invalid.
    STATUS_INVALID_PARAMETER_3,
    /// The service's fourth parameter is invalid.
    STATUS_INVALID_PARAMETER_4,
    /// The service's fifth parameter is invalid.
    STATUS_INVALID_PARAMETER_5,
    /// The service's sixth parameter is invalid.
    STATUS_INVALID_PARAMETER_6,
    /// The service's eighth parameter is invalid.
    STATUS_INVALID_PARAMETER_8,
    /// The service's ninth parameter is invalid.
    STATUS_INVALID_PARAMETER_9,
    /// A directory removed while it still holds entries.
    STATUS_DIRECTORY_NOT_EMPTY,
    /// The file's on-volume structure is corrupt (a broken cluster chain or directory).
    STATUS_FILE_CORRUPT_ERROR,
    /// A path continues through something that is not a directory.
    STATUS_NOT_A_DIRECTORY,
    /// A name longer than the object manager or the file system takes.
    STATUS_NAME_TOO_LONG,
    /// The process has ended (kernel32 maps it to ERROR_ACCESS_DENIED, as the spawn fixture's
    /// TerminateProcess of an ended process prints).
    STATUS_PROCESS_IS_TERMINATING,
    /// An image in the 16-bit Windows (NE) format.
    STATUS_INVALID_IMAGE_NE_FORMAT,
    /// A mapping of a file of no bytes.
    STATUS_MAPPED_FILE_SIZE_ZERO,
    /// Every open-file record or file object is taken.
    STATUS_TOO_MANY_OPENED_FILES,
    /// A file or key that cannot be deleted (read-only; a key with subkeys, or a hive's root).
    STATUS_CANNOT_DELETE,
    /// An image in the LE (virtual device driver) format.
    STATUS_INVALID_IMAGE_LE_FORMAT,
    /// A file that does not start with MZ.
    STATUS_INVALID_IMAGE_NOT_MZ,
    /// An image whose protection the loader cannot honour.
    STATUS_INVALID_IMAGE_PROTECT,
    /// A 16-bit Windows image.
    STATUS_INVALID_IMAGE_WIN_16,
    /// The volume holds no file system the kernel recognizes (a refused mount).
    STATUS_UNRECOGNIZED_VOLUME,
    /// A key deleted while a handle still named it: what every service answers through that
    /// handle.
    STATUS_KEY_DELETED,
    /// A device reported an error.
    STATUS_IO_DEVICE_ERROR,
    /// An image section whose alignment the mapping cannot honour.
    STATUS_MAPPED_ALIGNMENT,
    /// NtClose of a handle protected from close (ntstatus.h: "NtClose was called on a handle that
    /// was protected from close via NtSetInformationObject").
    STATUS_HANDLE_NOT_CLOSABLE,
    /// A file with a mapped view, which cannot be truncated or deleted.
    STATUS_USER_MAPPED_FILE,
    /// A system service number past its table, or of a table that does not exist.
    STATUS_INVALID_SYSTEM_SERVICE,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The documented values, and their severity: success and the timeout are non-negative
    /// (success and informational), the I/O failures are errors.
    #[test]
    fn the_documented_values_and_their_severity() {
        assert_eq!(STATUS_SUCCESS.0, 0x0000_0000);
        assert_eq!(STATUS_TIMEOUT.0, 0x0000_0102);
        assert_eq!(STATUS_KERNEL_APC.0, 0x0000_0100);
        assert_eq!(STATUS_USER_APC.0, 0x0000_00C0);
        assert_eq!(STATUS_SUSPEND_COUNT_EXCEEDED.0, 0xC000_004A);
        assert_eq!(STATUS_SEMAPHORE_LIMIT_EXCEEDED.0, 0xC000_0047);
        assert_eq!(STATUS_THREAD_IS_TERMINATING.0, 0xC000_004B);
        assert_eq!(STATUS_INVALID_PARAMETER.0, 0xC000_000D);
        assert_eq!(STATUS_NO_SUCH_DEVICE.0, 0xC000_000E);
        assert_eq!(STATUS_IO_TIMEOUT.0, 0xC000_00B5);
        assert_eq!(STATUS_IO_DEVICE_ERROR.0, 0xC000_0185);
        assert_eq!(STATUS_UNRECOGNIZED_VOLUME.0, 0xC000_014F);
        assert_eq!(STATUS_NO_SUCH_FILE.0, 0xC000_000F);
        assert_eq!(STATUS_BUFFER_TOO_SMALL.0, 0xC000_0023);
        assert_eq!(STATUS_OBJECT_NAME_INVALID.0, 0xC000_0033);
        assert_eq!(STATUS_FILE_CORRUPT_ERROR.0, 0xC000_0102);
        assert_eq!(STATUS_NOT_A_DIRECTORY.0, 0xC000_0103);

        assert!(STATUS_SUCCESS.is_success());
        assert!(STATUS_TIMEOUT.is_success());
        for status in [
            STATUS_INVALID_PARAMETER,
            STATUS_NO_SUCH_DEVICE,
            STATUS_IO_TIMEOUT,
            STATUS_IO_DEVICE_ERROR,
            STATUS_UNRECOGNIZED_VOLUME,
            STATUS_NO_SUCH_FILE,
            STATUS_BUFFER_TOO_SMALL,
            STATUS_OBJECT_NAME_INVALID,
            STATUS_FILE_CORRUPT_ERROR,
            STATUS_NOT_A_DIRECTORY,
        ] {
            assert!(!status.is_success(), "{status:?} is an error");
        }
    }
}
