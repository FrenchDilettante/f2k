//! ntoskrnl.exe's exports a legacy driver calls (`kernel/exports.toml`'s natives): each one's
//! `f2k_export_<name>` body, in the export's calling convention (stdcall but where the DDK says
//! otherwise: IofCompleteRequest is fastcall, _vsnprintf cdecl), over the I/O manager
//! ([`super::io`]). The kernel's image exports them by name at Windows 2000's ordinals; the
//! `.sys` loader snaps a driver's imports to them ([`super::loader`]).

#[cfg(target_arch = "x86")]
pub use target::*;

/// The largest MaximumLength RtlInitUnicodeString gives a string: the even bytes a USHORT holds.
const MAX_USTRING: usize = 0xFFFE;

/// RtlInitUnicodeString's counts for a string of `units` units before its NUL: its Length and its
/// MaximumLength (the NUL's room too), in bytes. A string too long for a UNICODE_STRING is clamped
/// as Windows clamps it (Length 0xFFFC, MaximumLength 0xFFFE), where a 16-bit sum overflowed.
pub fn unicode_lengths(units: usize) -> (u16, u16) {
    let length = units.saturating_mul(2).min(MAX_USTRING - 2);
    (length as u16, (length + 2) as u16)
}

#[cfg(target_arch = "x86")]
mod target {
    use super::super::io;
    use super::super::ntddk::UnicodeString;
    use crate::status::*;

    /// The status a body returns: its code's bits, as an NTSTATUS's.
    fn status(result: Result<(), NtStatus>) -> i32 {
        match result {
            Ok(()) => STATUS_SUCCESS.0 as i32,
            Err(status) => status.0 as i32,
        }
    }

    // --- Io ---------------------------------------------------------------------------------

    /// IoCreateDevice(DriverObject, DeviceExtensionSize, DeviceName, DeviceType,
    /// DeviceCharacteristics, Exclusive, DeviceObject): the device made, its address in
    /// *DeviceObject; NULL there when it is refused.
    #[no_mangle]
    pub extern "stdcall" fn f2k_export_IoCreateDevice(
        driver: u32,
        extension: u32,
        name: u32,
        device_type: u32,
        characteristics: u32,
        exclusive: u8,
        device: *mut u32,
    ) -> i32 {
        let named = (name != 0).then(|| io::counted(name));
        let made = io::create_device(&io::DeviceRequest {
            driver,
            extension,
            name: named,
            device_type,
            characteristics,
            exclusive: exclusive != 0,
        });
        // SAFETY: the driver's out parameter.
        unsafe { *device = *made.as_ref().unwrap_or(&0) };
        status(made.map(|_| ()))
    }

    /// IoDeleteDevice(DeviceObject).
    #[no_mangle]
    pub extern "stdcall" fn f2k_export_IoDeleteDevice(device: u32) {
        io::delete_device(device);
    }

    /// IoCreateSymbolicLink(SymbolicLinkName, DeviceName).
    #[no_mangle]
    pub extern "stdcall" fn f2k_export_IoCreateSymbolicLink(link: u32, target: u32) -> i32 {
        status(io::create_link(io::counted(link), io::counted(target)))
    }

    /// IoDeleteSymbolicLink(SymbolicLinkName).
    #[no_mangle]
    pub extern "stdcall" fn f2k_export_IoDeleteSymbolicLink(link: u32) -> i32 {
        status(io::delete_link(io::counted(link)))
    }

    /// IofCompleteRequest(Irp, PriorityBoost), fastcall: the IRP completed up its stack, its
    /// waiting sender woken with the PriorityBoost as its wake's increment.
    #[no_mangle]
    pub extern "fastcall" fn f2k_export_IofCompleteRequest(irp: u32, boost: i8) {
        io::complete_irp(irp, boost);
    }

    /// IoGetCurrentProcess: the current process's stand-in (PsGetCurrentProcess is the DDK's
    /// macro over it).
    #[no_mangle]
    pub extern "stdcall" fn f2k_export_IoGetCurrentProcess() -> u32 {
        io::current_process()
    }

    // --- Ps, Ke, Ex -------------------------------------------------------------------------

    /// PsGetCurrentProcessId: the current process's client id.
    #[no_mangle]
    pub extern "stdcall" fn f2k_export_PsGetCurrentProcessId() -> u32 {
        io::current_process_id()
    }

    /// PsGetCurrentThreadId: the running thread's client id.
    #[no_mangle]
    pub extern "stdcall" fn f2k_export_PsGetCurrentThreadId() -> u32 {
        io::current_thread_id()
    }

    /// KeGetCurrentThread: the running thread's stand-in (PsGetCurrentThread is the DDK's macro
    /// over it).
    #[no_mangle]
    pub extern "stdcall" fn f2k_export_KeGetCurrentThread() -> u32 {
        io::current_thread()
    }

    /// ExGetPreviousMode: the mode the current request came from.
    #[no_mangle]
    pub extern "stdcall" fn f2k_export_ExGetPreviousMode() -> u8 {
        io::previous_mode()
    }

    /// PsInitialSystemProcess, a variable: the System process's stand-in.
    #[repr(transparent)]
    pub struct ProcessPointer(core::cell::UnsafeCell<u32>);

    // SAFETY: written once, at boot, before any driver loads; only read afterwards.
    unsafe impl Sync for ProcessPointer {}

    #[no_mangle]
    pub static f2k_export_PsInitialSystemProcess: ProcessPointer =
        ProcessPointer(core::cell::UnsafeCell::new(0));

    /// Point PsInitialSystemProcess at the System process's stand-in. Once, at boot.
    pub fn init() {
        // SAFETY: the boot's one write, before any driver reads it.
        unsafe { *f2k_export_PsInitialSystemProcess.0.get() = io::system_process() };
    }

    // --- Rtl --------------------------------------------------------------------------------

    /// RtlInitUnicodeString(DestinationString, SourceString): the string counted up to its NUL,
    /// its room the NUL's too; NULL counts nothing.
    #[no_mangle]
    pub extern "stdcall" fn f2k_export_RtlInitUnicodeString(
        destination: *mut UnicodeString,
        source: u32,
    ) {
        let (length, maximum_length) = super::unicode_lengths(io::terminated(source).len());
        // SAFETY: the driver's string to fill.
        unsafe {
            *destination = UnicodeString {
                length,
                maximum_length: if source == 0 { 0 } else { maximum_length },
                buffer: source,
            };
        }
    }

    /// RTL_REGISTRY_ABSOLUTE, and the flag RtlWriteRegistryValue's RelativeTo may carry.
    const RTL_REGISTRY_ABSOLUTE: u32 = 0;
    const RTL_REGISTRY_OPTIONAL: u32 = 0x8000_0000;

    /// RtlWriteRegistryValue(RelativeTo, Path, ValueName, ValueType, ValueData, ValueLength): an
    /// absolute path's key (which must exist) given the value. The other roots are the stub path.
    #[no_mangle]
    pub extern "stdcall" fn f2k_export_RtlWriteRegistryValue(
        relative_to: u32,
        path: u32,
        value_name: u32,
        value_type: u32,
        data: *const u8,
        length: u32,
    ) -> i32 {
        if relative_to & !RTL_REGISTRY_OPTIONAL != RTL_REGISTRY_ABSOLUTE {
            crate::dbgprint::unhandled(
                "ntoskrnl",
                "RtlWriteRegistryValue",
                format_args!("RelativeTo={relative_to:#x}"),
                format_args!("a path relative to another root than the registry's own"),
            );
            return STATUS_NOT_IMPLEMENTED.0 as i32;
        }
        let bytes: &[u8] = if data.is_null() || length == 0 {
            &[]
        } else {
            // SAFETY: the driver's data, `length` bytes of kernel memory.
            unsafe { core::slice::from_raw_parts(data, length as usize) }
        };
        status(io::write_registry_value(
            io::terminated(path),
            io::terminated(value_name),
            value_type,
            bytes,
        ))
    }

    /// _vsnprintf(buffer, count, format, argptr), cdecl: the C runtime's conversions
    /// (`rtl::printf`, DbgPrint's) over the driver's va_list, placed as the C runtime places them
    /// ([`io::place`]). A conversion the formatter does not serve is the stub path (-1).
    #[no_mangle]
    pub extern "C" fn f2k_export__vsnprintf(
        buffer: *mut u8,
        count: u32,
        format: *const u8,
        arguments: *const u32,
    ) -> i32 {
        /// The text, as long as a line of the driver's could want it.
        const ROOM: usize = 1024;
        struct Text {
            bytes: [u8; ROOM],
            length: usize,
            over: bool,
        }
        impl rtl::printf::Sink for Text {
            fn put(&mut self, bytes: &[u8]) {
                let room = ROOM - self.length;
                let n = bytes.len().min(room);
                self.bytes[self.length..self.length + n].copy_from_slice(&bytes[..n]);
                self.length += n;
                self.over |= n < bytes.len();
            }
        }
        struct VaList(*const u32);
        impl rtl::printf::Args for VaList {
            fn next_u32(&mut self) -> u32 {
                // SAFETY: the driver's argument list, read as far as its format asks.
                let value = unsafe { self.0.read_unaligned() };
                self.0 = self.0.wrapping_add(1);
                value
            }

            fn next_u64(&mut self) -> u64 {
                let low = self.next_u32();
                u64::from(low) | u64::from(self.next_u32()) << 32
            }

            fn next_ptr(&mut self) -> usize {
                self.next_u32() as usize
            }
        }
        struct Kernel;
        impl rtl::stub::Memory for Kernel {
            fn readable(&self, address: usize) -> bool {
                address >= rtl::stub::LOWEST_MAPPED
            }
        }
        let format_text = io::bytes_terminated(format as u32);
        let mut text = Text {
            bytes: [0; ROOM],
            length: 0,
            over: false,
        };
        if rtl::printf::format(format_text, &mut VaList(arguments), &Kernel, &mut text).is_err() {
            crate::dbgprint::unhandled(
                "ntoskrnl",
                "_vsnprintf",
                format_args!(
                    "format={:?}",
                    core::str::from_utf8(format_text).unwrap_or("?")
                ),
                format_args!("a conversion the formatter does not serve"),
            );
            return -1;
        }
        if buffer.is_null() {
            return -1;
        }
        // SAFETY: the driver's buffer, `count` bytes.
        let out = unsafe { core::slice::from_raw_parts_mut(buffer, count as usize) };
        if text.over {
            io::place(out, &text.bytes[..text.length]);
            return -1;
        }
        io::place(out, &text.bytes[..text.length])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A string's counts: its bytes and its NUL's; past a UNICODE_STRING's room, the clamp
    /// (where 0x7FFF units overflowed `length + 2`, and 0x8000 `units * 2`).
    #[test]
    fn rtl_init_unicode_string_clamps_a_long_string() {
        assert_eq!(unicode_lengths(0), (0, 2));
        assert_eq!(unicode_lengths(5), (10, 12));
        assert_eq!(unicode_lengths(0x7FFD), (0xFFFA, 0xFFFC));
        assert_eq!(unicode_lengths(0x7FFE), (0xFFFC, 0xFFFE));
        assert_eq!(unicode_lengths(0x7FFF), (0xFFFC, 0xFFFE));
        assert_eq!(unicode_lengths(0x8000), (0xFFFC, 0xFFFE));
        assert_eq!(unicode_lengths(usize::MAX), (0xFFFC, 0xFFFE));
    }
}
