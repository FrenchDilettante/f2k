//! The thread and process environment blocks: the NT layouts user code reads through FS.
//!
//! Compilers, the C runtime and kernel32's user-mode exports read these fields directly — fs:[18h]
//! for the TEB's own linear address, fs:[30h] for the PEB, fs:[34h] for the last error, fs:[0] for
//! the exception chain, fs:[20h] and fs:[24h] for the client ids — so the offsets are Windows
//! 2000's, not F2K's choice: the layouts are `rtl::peb`'s, the ones ntdll and kernel32 read them
//! with. A thread's TEB page is built once, when the thread is created, field by field (the TEB is
//! nearly a page long); the PEB page once per process, when its image is loaded, from a whole
//! [`Peb`] value. Everything not written here stays zero.

use core::marker::PhantomData;
use core::mem::size_of;

use rtl::nt::UnicodeString;
use rtl::peb::{Peb, Teb};
use rtl::pod::Pod;

use crate::user::args::UserPtr;

/// A field of the TEB, typed: its offset in [`Teb`] and its type, as [`teb_field!`] names it.
#[derive(Clone, Copy, Debug)]
pub struct TebField<T> {
    offset: usize,
    value: PhantomData<fn() -> T>,
}

impl<T: Pod> TebField<T> {
    /// The field `project` borrows, at `offset`: [`teb_field!`]'s, which takes both from the one
    /// field name (`offset_of!` and the borrow), so they agree.
    #[doc(hidden)]
    pub fn new(offset: usize, _project: fn(&Teb<u32>) -> &T) -> Self {
        TebField {
            offset,
            value: PhantomData,
        }
    }

    /// The field's offset in the TEB.
    pub fn offset(self) -> u32 {
        self.offset as u32
    }

    /// The field of the TEB at user address `teb`.
    pub fn of(self, teb: u32) -> UserPtr<T> {
        UserPtr::at(teb + self.offset())
    }
}

/// The TEB's field `$field` (a [`Teb`] field name), as a [`TebField`] of its type.
macro_rules! teb_field {
    ($field:ident) => {
        $crate::user::teb::TebField::new(core::mem::offset_of!(rtl::peb::Teb<u32>, $field), |teb| {
            &teb.$field
        })
    };
}
pub(crate) use teb_field;

/// The empty SEH chain's terminator: the frame link Windows starts every thread with.
pub const END_OF_CHAIN: u32 = rtl::seh::END_OF_CHAIN;

/// What a new thread's TEB records.
#[derive(Clone, Copy, Debug)]
pub struct TebInit {
    /// The TEB page's linear address.
    pub teb: u32,
    /// One past the top of the thread's user stack.
    pub stack_base: u32,
    /// The lowest committed address of the thread's user stack.
    pub stack_limit: u32,
    /// The base of the thread's stack reservation.
    pub deallocation_stack: u32,
    /// The owning process's client id.
    pub process_id: u32,
    /// The thread's client id.
    pub thread_id: u32,
    /// The process's PEB page.
    pub peb: u32,
}

/// The locale a thread starts in: the system's default, English (United States), as Windows 2000
/// starts every thread in its default thread locale.
pub const DEFAULT_LOCALE: u32 = 0x0409;

/// A fresh TEB's fields, each handed to `write` with its offset in the TEB and its bytes (on a
/// zeroed page): the exception chain terminated, the stack's bounds and reservation, the self
/// pointer, the client ids, the PEB and the default locale. The last error and the TLS words stay
/// zero: TlsSetValue makes the expansion slots on first use.
pub fn write_fresh_teb(init: &TebInit, mut write: impl FnMut(u32, &[u8])) {
    let mut put = |field: TebField<u32>, value: u32| write(field.offset(), value.as_bytes());
    put(teb_field!(exception_list), END_OF_CHAIN);
    put(teb_field!(stack_base), init.stack_base);
    put(teb_field!(stack_limit), init.stack_limit);
    put(teb_field!(deallocation_stack), init.deallocation_stack);
    put(teb_field!(self_), init.teb);
    put(teb_field!(unique_process), init.process_id);
    put(teb_field!(unique_thread), init.thread_id);
    put(teb_field!(process_environment_block), init.peb);
    put(teb_field!(current_locale), DEFAULT_LOCALE);
}

/// What a new process's PEB records of its image.
#[derive(Clone, Copy, Debug)]
pub struct PebInit {
    /// The image's base.
    pub image_base: u32,
    /// The process parameters' address: a boot's program's, which the kernel writes; zero for a
    /// process another process created (NtCreateProcess), whose creator writes its parameters
    /// into it and the pointer into its PEB, as Windows 2000's kernel32 does.
    pub parameters: u32,
    /// The image's subsystem, and the subsystem version it was linked for (major, minor).
    pub subsystem: u16,
    pub subsystem_version: (u16, u16),
}

/// The system's version, GetVersion's replay (captured on a real Windows 2000 SP4 machine): 5.0,
/// build 2195, NT. The PEB's version fields hold it apart.
pub const VERSION: u32 = 0x0893_0005;

/// The system's service pack, as OSCSDVersion holds it: 4.0, the major number in the high byte
/// (GetVersionExA's "Service Pack 4").
const OS_CSD_VERSION: u16 = 0x0400;
/// The service pack's name, as CSDVersion holds it.
pub const CSD_VERSION_TEXT: &[u8] = b"Service Pack 4";
/// VER_PLATFORM_WIN32_NT.
const PLATFORM_WIN32_NT: u32 = 2;

/// The heap-handle array ProcessHeaps points at: right past Windows 2000's PEB proper (0x1E8
/// bytes), on its page, as NT's PEB creation places it.
pub const PROCESS_HEAPS_ARRAY: u32 = size_of::<Peb<u32>>() as u32;
/// How many heaps the array holds: as many as ntdll's heap list keeps.
pub const HEAPS: u32 = rtl::heap::HEAPS;
/// The service pack's name CSDVersion points at, UTF-16: past the PEB proper and the heap array on
/// its page, so every process has it from its creation (a process another process created gets its
/// parameters from its creator, later).
pub const CSD_VERSION_BUFFER: u32 = 0xA00;
// Past the PEB proper, the kernel keeps only the heap-handle array and the service pack's name.
// The PEB's lock, loader lock and TLS bitmap fields point into ntdll's own data, and the system
// DLLs keep the rest of their per-process state in their own data sections, as on Windows 2000.

/// A fresh PEB, for the PEB at `peb`: the image's base, the process parameters, the heap list's
/// room (its array, empty, and its size: ntdll's LdrInitializeThunk makes the process heap, the
/// list's first entry), the system's version (GetVersion's: 5.0, build 2195, service pack 4, NT),
/// the image's subsystem and its version, and the service pack's name (its text on the PEB's page,
/// [`map_peb`]'s). The loader's module lists, the process heap, the PEB lock, the loader lock and
/// the TLS bitmaps' headers are ntdll's to make (their fields stay null until its process
/// initialization), and every TLS index is free.
pub fn fresh_peb(peb: u32, init: &PebInit) -> Peb<u32> {
    let length = 2 * CSD_VERSION_TEXT.len() as u16;
    Peb {
        image_base_address: init.image_base,
        process_parameters: init.parameters,
        maximum_number_of_heaps: HEAPS,
        process_heaps: peb + PROCESS_HEAPS_ARRAY,
        os_major_version: VERSION & 0xFF,
        os_minor_version: (VERSION >> 8) & 0xFF,
        os_build_number: (VERSION >> 16 & 0x7FFF) as u16,
        os_csd_version: OS_CSD_VERSION,
        os_platform_id: PLATFORM_WIN32_NT,
        image_subsystem: u32::from(init.subsystem),
        image_subsystem_major_version: u32::from(init.subsystem_version.0),
        image_subsystem_minor_version: u32::from(init.subsystem_version.1),
        csd_version: UnicodeString {
            length,
            maximum_length: length + 2,
            buffer: peb + CSD_VERSION_BUFFER,
        },
        ..Peb::default()
    }
}

/// Map a thread's TEB page at `init.teb` into `space`: one zeroed frame carrying the fresh TEB's
/// fields.
#[cfg(target_arch = "x86")]
pub fn map_teb(space: &mut crate::mem::vm::AddressSpace, init: &TebInit) {
    use crate::mem::{paging, vm};
    let frame = vm::map_zeroed(space, init.teb, vm::PAGE_READWRITE);
    write_fresh_teb(init, |offset, bytes| {
        paging::write_frame(frame, offset as usize, bytes)
    });
}

/// Map the process's PEB page at [`crate::user::PEB_PAGE`] into `space`, recording `init`, the
/// service pack's name past the PEB proper.
#[cfg(target_arch = "x86")]
pub fn map_peb(space: &mut crate::mem::vm::AddressSpace, init: &PebInit) {
    use crate::mem::{paging, vm};
    let peb = crate::user::PEB_PAGE;
    let frame = vm::map_zeroed(space, peb, vm::PAGE_READWRITE);
    paging::write_frame(frame, 0, fresh_peb(peb, init).as_bytes());
    let mut name = [0u8; 2 * CSD_VERSION_TEXT.len()];
    let length = crate::user::params::widen(CSD_VERSION_TEXT, &mut name);
    paging::write_frame(frame, CSD_VERSION_BUFFER as usize, &name[..length]);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fresh TEB as user code reads it: the fields written into a zeroed TEB, read back
    /// through its layout.
    fn fresh_teb(init: &TebInit) -> Teb<u32> {
        let mut bytes = vec![0u8; size_of::<Teb<u32>>()];
        write_fresh_teb(init, |offset, value| {
            bytes[offset as usize..][..value.len()].copy_from_slice(value)
        });
        Teb::from_bytes(&bytes).unwrap()
    }

    /// The fields user code depends on, at Windows 2000's offsets.
    #[test]
    fn fields_are_the_nt_layout() {
        assert_eq!(teb_field!(exception_list).offset(), 0x00);
        assert_eq!(teb_field!(stack_base).offset(), 0x04);
        assert_eq!(teb_field!(stack_limit).offset(), 0x08);
        assert_eq!(teb_field!(self_).offset(), 0x18);
        assert_eq!(teb_field!(unique_process).offset(), 0x20);
        assert_eq!(teb_field!(unique_thread).offset(), 0x24);
        assert_eq!(teb_field!(process_environment_block).offset(), 0x30);
        assert_eq!(teb_field!(last_error_value).offset(), 0x34);
        assert_eq!(teb_field!(current_locale).offset(), 0xC4);
        assert_eq!(teb_field!(deallocation_stack).offset(), 0xE0C);
        assert_eq!(teb_field!(tls_slots).offset(), 0xE10);
        assert_eq!(teb_field!(tls_expansion_slots).offset(), 0xF94);
        assert_eq!(
            teb_field!(stack_base).of(0x7FFD_E000).addr().raw(),
            0x7FFD_E004
        );
        assert_eq!(PROCESS_HEAPS_ARRAY, 0x1E8);
        assert_eq!(HEAPS, 16);
        assert_eq!(PROCESS_HEAPS_ARRAY + 4 * HEAPS, 0x228);
    }

    /// A fresh TEB: the chain terminated, the self pointer and the ids in place, the locale the
    /// default, the last error left zero, and the TLS words zero; nothing past the TEB.
    #[test]
    fn a_fresh_teb() {
        let init = TebInit {
            teb: 0x7FFD_E000,
            stack_base: 0x0013_0000,
            stack_limit: 0x0012_E000,
            deallocation_stack: 0x0003_0000,
            process_id: 8,
            thread_id: 12,
            peb: 0x7FFD_F000,
        };
        let teb = fresh_teb(&init);
        assert_eq!(teb.exception_list, END_OF_CHAIN);
        assert_eq!(teb.self_, 0x7FFD_E000);
        assert_eq!(teb.stack_base, 0x0013_0000);
        assert_eq!(teb.stack_limit, 0x0012_E000);
        assert_eq!(teb.deallocation_stack, 0x0003_0000);
        assert_eq!(teb.unique_process, 8);
        assert_eq!(teb.unique_thread, 12);
        assert_eq!(teb.process_environment_block, 0x7FFD_F000);
        assert_eq!(teb.current_locale, 0x0409);
        assert_eq!(teb.last_error_value, 0);
        assert_eq!(teb.tls_slots, [0; 64]);
        assert_eq!(teb.tls_expansion_slots, 0, "TlsSetValue's to make");
        let mut writes = 0;
        write_fresh_teb(&init, |offset, value| {
            assert_eq!(offset % 4, 0);
            assert!(offset as usize + value.len() <= size_of::<Teb<u32>>());
            writes += 1;
        });
        assert_eq!(writes, 9);
        // The other fields stay zero.
        let blank = Teb {
            exception_list: teb.exception_list,
            stack_base: teb.stack_base,
            stack_limit: teb.stack_limit,
            self_: teb.self_,
            unique_process: teb.unique_process,
            unique_thread: teb.unique_thread,
            process_environment_block: teb.process_environment_block,
            current_locale: teb.current_locale,
            deallocation_stack: teb.deallocation_stack,
            ..Teb::default()
        };
        assert_eq!(teb.as_bytes(), blank.as_bytes());
    }

    /// A console image linked for subsystem 4.0, as MSVC 6 links one.
    const CONSOLE_4_0: PebInit = PebInit {
        image_base: 0x0040_0000,
        parameters: 0x0002_0000,
        subsystem: 3,
        subsystem_version: (4, 0),
    };

    /// The dword at `offset` of a PEB's bytes.
    fn word(peb: &Peb<u32>, offset: usize) -> u32 {
        u32::from_bytes(&peb.as_bytes()[offset..]).unwrap()
    }

    /// A fresh PEB's version fields (SEH-11c): the system's — 5.0, build 2195, service pack 4.0
    /// (OSCSDVersion's major byte high), the NT platform — and the image's subsystem and its
    /// version, from its optional header.
    #[test]
    fn fresh_peb_version_fields() {
        let peb = fresh_peb(0x7FFD_F000, &CONSOLE_4_0);
        assert_eq!(word(&peb, 0xA4), 5, "OSMajorVersion");
        assert_eq!(word(&peb, 0xA8), 0, "OSMinorVersion");
        assert_eq!(
            word(&peb, 0xAC),
            2195 | 0x0400 << 16,
            "OSBuildNumber, OSCSDVersion"
        );
        assert_eq!(word(&peb, 0xB0), 2, "OSPlatformId: VER_PLATFORM_WIN32_NT");
        assert_eq!(word(&peb, 0xB4), 3, "ImageSubsystem: the console");
        assert_eq!(word(&peb, 0xB8), 4, "ImageSubsystemMajorVersion");
        assert_eq!(word(&peb, 0xBC), 0, "ImageSubsystemMinorVersion");
        assert_eq!(
            word(&peb, 0x1DC),
            28 | 30 << 16,
            "CSDVersion: \"Service Pack 4\", terminated"
        );
        assert_eq!(word(&peb, 0x1E0), 0x7FFD_FA00, "past the PEB proper");
        // A process another process created: no parameters yet, the name all the same.
        let bare = fresh_peb(
            0x7FFD_F000,
            &PebInit {
                parameters: 0,
                ..CONSOLE_4_0
            },
        );
        assert_eq!(bare.process_parameters, 0);
        assert_eq!(
            (word(&bare, 0x1DC), word(&bare, 0x1E0)),
            (28 | 30 << 16, 0x7FFD_FA00)
        );
    }

    /// A fresh PEB: the image and the parameters; no module lists and no process heap yet
    /// (ntdll's LdrInitializeThunk makes them), the heap list empty over its 16-entry array past
    /// the PEB proper; no TLS bitmap headers, PEB lock or loader lock yet (ntdll's
    /// LdrInitializeThunk makes them, in its own data), every TLS index free. Nothing past the PEB
    /// proper but the service pack's name ([`map_peb`]'s).
    #[test]
    fn a_fresh_peb() {
        let at = 0x7FFD_F000;
        let peb = fresh_peb(at, &CONSOLE_4_0);
        assert_eq!(word(&peb, 0x08), 0x0040_0000, "ImageBaseAddress");
        assert_eq!(word(&peb, 0x10), 0x0002_0000, "ProcessParameters");
        assert_eq!(peb.ldr, 0, "ntdll's to make");
        assert_eq!(peb.process_heap, 0);
        assert_eq!(peb.number_of_heaps, 0, "no heap yet");
        assert_eq!(word(&peb, 0x8C), 16, "MaximumNumberOfHeaps");
        assert_eq!(word(&peb, 0x90), at + 0x1E8, "ProcessHeaps");
        assert_eq!(peb.tls_bitmap, 0, "ntdll's to make");
        assert_eq!(peb.tls_expansion_bitmap, 0, "ntdll's to make");
        assert_eq!(peb.tls_bitmap_bits, [0; 2], "every index free");
        assert_eq!(peb.fast_peb_lock, 0, "ntdll's to make");
        assert_eq!(peb.loader_lock, 0, "ntdll's to make");
        // Nothing else: eleven nonzero dwords, the four above, the version's three, the
        // subsystem's two and the name's two (OSMinorVersion and the subsystem's minor version are
        // zero).
        let nonzero = peb
            .as_bytes()
            .chunks_exact(4)
            .filter(|word| word.iter().any(|&byte| byte != 0))
            .count();
        assert_eq!(nonzero, 11);
        // The service pack's name sits past the heap-handle array, and fits the page.
        assert!(CSD_VERSION_BUFFER >= PROCESS_HEAPS_ARRAY + 4 * HEAPS);
        assert!(CSD_VERSION_BUFFER as usize + 2 * CSD_VERSION_TEXT.len() + 2 <= 0x1000);
    }

    /// The version dword splits into the CRT's globals (its own shift/mask recipe, restated
    /// independently).
    #[test]
    fn version_splits_like_the_crt() {
        assert_eq!(VERSION, 0x0893_0005);
        let major = VERSION & 0xFF;
        let minor = (VERSION >> 8) & 0xFF;
        let build = (VERSION >> 16) & 0xFFFF;
        let platform = VERSION >> 31;
        assert_eq!(major, 5);
        assert_eq!(minor, 0);
        assert_eq!(build, 2195);
        assert_eq!(platform, 0);
        assert_eq!((major << 8) | minor, 0x0500); // _winver
        assert_eq!((platform << 15) | build, 0x0893); // _osver
    }
}
