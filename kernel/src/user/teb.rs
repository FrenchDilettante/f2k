//! The thread and process environment blocks: the NT layouts user code reads through FS.
//!
//! Compilers, the C runtime and kernel32's user-mode exports read these fields directly — fs:[18h]
//! for the TEB's own linear address, fs:[30h] for the PEB, fs:[34h] for the last error, fs:[0] for
//! the exception chain, fs:[20h] and fs:[24h] for the client ids — so the offsets are Windows
//! 2000's, not F2K's choice. A thread's TEB page is built once, when the thread is created; the PEB
//! page once per process, when its image is loaded. Everything not listed here stays zero.

// The layouts' fields user code reads, whether the kernel writes them or not (kernel32 reads the
// startup values and its narrow copies' room by these offsets).
#![allow(dead_code)]

/// TEB field offsets (the NT_TIB head, then the TEB proper).
pub mod teb_offset {
    /// NT_TIB.ExceptionList: the head of the thread's SEH frame chain.
    pub const EXCEPTION_LIST: u32 = 0x00;
    /// NT_TIB.StackBase: one past the top of the thread's stack.
    pub const STACK_BASE: u32 = 0x04;
    /// NT_TIB.StackLimit: the lowest committed address of the stack.
    pub const STACK_LIMIT: u32 = 0x08;
    /// NT_TIB.Self: the TEB's own linear address.
    pub const SELF: u32 = 0x18;
    /// ClientId.UniqueProcess.
    pub const PROCESS_ID: u32 = 0x20;
    /// ClientId.UniqueThread.
    pub const THREAD_ID: u32 = 0x24;
    /// ProcessEnvironmentBlock.
    pub const PEB: u32 = 0x30;
    /// LastErrorValue: what GetLastError reads and SetLastError writes.
    pub const LAST_ERROR: u32 = 0x34;
    /// DeallocationStack: the base of the thread's stack reservation, its lowest address.
    pub const DEALLOCATION_STACK: u32 = 0xE0C;
}

/// PEB field offsets.
pub mod peb_offset {
    /// ImageBaseAddress: the process image's base, what GetModuleHandle(NULL) returns.
    pub const IMAGE_BASE_ADDRESS: u32 = 0x08;
    /// ProcessParameters: the RTL_USER_PROCESS_PARAMETERS block (see `user::params`).
    pub const PROCESS_PARAMETERS: u32 = 0x10;
    /// ProcessHeap: what GetProcessHeap returns (ntdll's process start writes it; zero until the
    /// heap moves to ntdll).
    pub const PROCESS_HEAP: u32 = 0x18;
    /// The system's version, as the kernel's process creation writes it (GetVersion reads it on
    /// the platform): OSMajorVersion, OSMinorVersion, OSBuildNumber (a word) with OSCSDVersion (the
    /// next word: the service pack, its major number in the high byte), OSPlatformId.
    pub const OS_MAJOR_VERSION: u32 = 0xA4;
    pub const OS_MINOR_VERSION: u32 = 0xA8;
    pub const OS_BUILD_NUMBER: u32 = 0xAC;
    pub const OS_PLATFORM_ID: u32 = 0xB0;
    /// The image's subsystem and the subsystem version it was linked for (its optional header's).
    pub const IMAGE_SUBSYSTEM: u32 = 0xB4;
    pub const IMAGE_SUBSYSTEM_MAJOR_VERSION: u32 = 0xB8;
    pub const IMAGE_SUBSYSTEM_MINOR_VERSION: u32 = 0xBC;
    /// CSDVersion: the service pack's name, a UNICODE_STRING (GetVersionExA's szCSDVersion; its
    /// buffer on the process parameters' pages, `user::params::CSD_VERSION_BUFFER`).
    pub const CSD_VERSION: u32 = 0x1DC;
    /// kernel32's top-level exception filter (SetUnhandledExceptionFilter's): past the PEB proper on
    /// its page; kernel32's natives reach it through FS (the system DLLs' assembly reads the value
    /// off this line, see tools/exportgen's `abi`).
    pub const TOP_LEVEL_FILTER: u32 = 0x800;
    // Past the PEB proper (0x1E8 bytes), the system DLLs' own data (they keep no writable
    // sections): kernel32's top-level filter (0x800, above), its narrow command line and startup
    // information (0x8A0, 0x8A4: pointers, see `user::params`). The page starts zeroed; the kernel
    // writes none of them.
}

/// The empty SEH chain's terminator: the frame link Windows starts every thread with.
pub const END_OF_CHAIN: u32 = 0xFFFF_FFFF;

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

/// A fresh TEB's nonzero words, as (offset, value).
pub fn teb_words(init: &TebInit) -> [(u32, u32); 8] {
    [
        (teb_offset::EXCEPTION_LIST, END_OF_CHAIN),
        (teb_offset::STACK_BASE, init.stack_base),
        (teb_offset::STACK_LIMIT, init.stack_limit),
        (teb_offset::DEALLOCATION_STACK, init.deallocation_stack),
        (teb_offset::SELF, init.teb),
        (teb_offset::PROCESS_ID, init.process_id),
        (teb_offset::THREAD_ID, init.thread_id),
        (teb_offset::PEB, init.peb),
    ]
}

/// What a new process's PEB records of its image.
#[derive(Clone, Copy, Debug)]
pub struct PebInit {
    /// The image's base.
    pub image_base: u32,
    /// The process parameters' address (none: zero).
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
const OS_CSD_VERSION: u32 = 0x0400;
/// VER_PLATFORM_WIN32_NT.
const PLATFORM_WIN32_NT: u32 = 2;

/// A fresh PEB's nonzero words, as (offset, value): the image's base, the process parameters, the
/// system's version (GetVersion's: 5.0, build 2195, service pack 4, NT), the image's subsystem and
/// its version, and the service pack's name (on the parameters' pages: none without them).
pub fn peb_words(init: &PebInit) -> [(u32, u32); 11] {
    use peb_offset::*;
    [
        (IMAGE_BASE_ADDRESS, init.image_base),
        (PROCESS_PARAMETERS, init.parameters),
        (OS_MAJOR_VERSION, VERSION & 0xFF),
        (OS_MINOR_VERSION, (VERSION >> 8) & 0xFF),
        (
            OS_BUILD_NUMBER,
            (VERSION >> 16 & 0x7FFF) | OS_CSD_VERSION << 16,
        ),
        (OS_PLATFORM_ID, PLATFORM_WIN32_NT),
        (IMAGE_SUBSYSTEM, u32::from(init.subsystem)),
        (
            IMAGE_SUBSYSTEM_MAJOR_VERSION,
            u32::from(init.subsystem_version.0),
        ),
        (
            IMAGE_SUBSYSTEM_MINOR_VERSION,
            u32::from(init.subsystem_version.1),
        ),
        (
            CSD_VERSION,
            if init.parameters == 0 {
                0
            } else {
                csd_version_lengths()
            },
        ),
        (
            CSD_VERSION + 4,
            if init.parameters == 0 {
                0
            } else {
                init.parameters + crate::user::params::CSD_VERSION_BUFFER
            },
        ),
    ]
}

/// CSDVersion's Length and MaximumLength words, as one dword: the name's bytes, and its bytes with
/// the terminator.
fn csd_version_lengths() -> u32 {
    let length = 2 * crate::user::params::CSD_VERSION_TEXT.len() as u32;
    length | (length + 2) << 16
}

/// Map a thread's TEB page at `init.teb` into `space`: one zeroed frame carrying the fresh TEB's
/// words.
#[cfg(target_arch = "x86")]
pub fn map_teb(space: &mut crate::mem::vm::AddressSpace, init: &TebInit) {
    use crate::mem::{paging, vm};
    let frame = vm::map_zeroed(space, init.teb, vm::PAGE_READWRITE);
    for (offset, value) in teb_words(init) {
        paging::write_frame(frame, offset as usize, &value.to_le_bytes());
    }
}

/// Map the process's PEB page at [`crate::user::PEB_PAGE`] into `space`, recording `init`.
#[cfg(target_arch = "x86")]
pub fn map_peb(space: &mut crate::mem::vm::AddressSpace, init: &PebInit) {
    use crate::mem::{paging, vm};
    let frame = vm::map_zeroed(space, crate::user::PEB_PAGE, vm::PAGE_READWRITE);
    for (offset, value) in peb_words(init) {
        paging::write_frame(frame, offset as usize, &value.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The offsets user code depends on, as Windows 2000 lays them out.
    #[test]
    fn offsets_are_the_nt_layout() {
        assert_eq!(teb_offset::EXCEPTION_LIST, 0x00);
        assert_eq!(teb_offset::STACK_BASE, 0x04);
        assert_eq!(teb_offset::STACK_LIMIT, 0x08);
        assert_eq!(teb_offset::SELF, 0x18);
        assert_eq!(teb_offset::PROCESS_ID, 0x20);
        assert_eq!(teb_offset::THREAD_ID, 0x24);
        assert_eq!(teb_offset::PEB, 0x30);
        assert_eq!(teb_offset::LAST_ERROR, 0x34);
        assert_eq!(teb_offset::DEALLOCATION_STACK, 0xE0C);
        assert_eq!(peb_offset::IMAGE_BASE_ADDRESS, 0x08);
        assert_eq!(peb_offset::PROCESS_PARAMETERS, 0x10);
        assert_eq!(peb_offset::PROCESS_HEAP, 0x18);
    }

    /// A fresh TEB: the chain terminated, the self pointer and the ids in place, the last error
    /// left zero (no word written for it).
    #[test]
    fn fresh_teb_words() {
        let init = TebInit {
            teb: 0x0031_0000,
            stack_base: 0x0030_1000,
            stack_limit: 0x002F_F000,
            deallocation_stack: 0x002F_F000,
            process_id: 8,
            thread_id: 12,
            peb: 0x0033_0000,
        };
        let words = teb_words(&init);
        let value = |offset| words.iter().find(|&&(o, _)| o == offset).map(|&(_, v)| v);
        assert_eq!(value(teb_offset::EXCEPTION_LIST), Some(END_OF_CHAIN));
        assert_eq!(value(teb_offset::SELF), Some(0x0031_0000));
        assert_eq!(value(teb_offset::STACK_BASE), Some(0x0030_1000));
        assert_eq!(value(teb_offset::STACK_LIMIT), Some(0x002F_F000));
        assert_eq!(value(teb_offset::DEALLOCATION_STACK), Some(0x002F_F000));
        assert_eq!(value(teb_offset::PROCESS_ID), Some(8));
        assert_eq!(value(teb_offset::THREAD_ID), Some(12));
        assert_eq!(value(teb_offset::PEB), Some(0x0033_0000));
        assert_eq!(value(teb_offset::LAST_ERROR), None);
        for &(offset, _) in &words {
            assert_eq!(offset % 4, 0);
            assert!(offset < 0x1000);
        }
    }

    /// A console image linked for subsystem 4.0, as MSVC 6 links one.
    const CONSOLE_4_0: PebInit = PebInit {
        image_base: 0x0040_0000,
        parameters: 0x0032_0000,
        subsystem: 3,
        subsystem_version: (4, 0),
    };

    /// A fresh PEB's version fields (SEH-11c): the system's — 5.0, build 2195, service pack 4.0
    /// (OSCSDVersion's major byte high), the NT platform — and the image's subsystem and its
    /// version, from its optional header.
    #[test]
    fn fresh_peb_version_fields() {
        let words = peb_words(&CONSOLE_4_0);
        let value = |offset| words.iter().find(|&&(o, _)| o == offset).map(|&(_, v)| v);
        assert_eq!(value(0xA4), Some(5), "OSMajorVersion");
        assert_eq!(value(0xA8), Some(0), "OSMinorVersion");
        assert_eq!(
            value(0xAC),
            Some(2195 | 0x0400 << 16),
            "OSBuildNumber, OSCSDVersion"
        );
        assert_eq!(value(0xB0), Some(2), "OSPlatformId: VER_PLATFORM_WIN32_NT");
        assert_eq!(value(0xB4), Some(3), "ImageSubsystem: the console");
        assert_eq!(value(0xB8), Some(4), "ImageSubsystemMajorVersion");
        assert_eq!(value(0xBC), Some(0), "ImageSubsystemMinorVersion");
        assert_eq!(
            value(0x1DC),
            Some(28 | 30 << 16),
            "CSDVersion: \"Service Pack 4\", terminated"
        );
        assert_eq!(
            value(0x1E0),
            Some(0x0032_0000 + crate::user::params::CSD_VERSION_BUFFER)
        );
        let bare = peb_words(&PebInit {
            parameters: 0,
            ..CONSOLE_4_0
        });
        assert!(
            bare.contains(&(0x1DC, 0)) && bare.contains(&(0x1E0, 0)),
            "no parameters, no name"
        );
    }

    /// A fresh PEB: the image and the parameters; no process heap yet (the kernel's user heap
    /// stands in until ntdll makes one).
    #[test]
    fn fresh_peb_words() {
        let words = peb_words(&CONSOLE_4_0);
        let value = |offset| words.iter().find(|&&(o, _)| o == offset).map(|&(_, v)| v);
        assert_eq!(value(peb_offset::IMAGE_BASE_ADDRESS), Some(0x0040_0000));
        assert_eq!(value(peb_offset::PROCESS_PARAMETERS), Some(0x0032_0000));
        assert_eq!(value(peb_offset::PROCESS_HEAP), None);
        for &(offset, _) in &words {
            assert_eq!(offset % 4, 0);
            assert!(offset < 0x1E8, "inside the PEB proper");
        }
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
