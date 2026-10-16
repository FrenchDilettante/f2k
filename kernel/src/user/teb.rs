//! The thread and process environment blocks: the NT layouts user code reads through FS.
//!
//! Compilers, the C runtime and kernel32's user-mode exports read these fields directly — fs:[18h]
//! for the TEB's own linear address, fs:[30h] for the PEB, fs:[34h] for the last error, fs:[0] for
//! the exception chain — so the offsets are Windows 2000's, not F2K's choice. A thread's TEB page is
//! built once, when the thread is created; the PEB page once per process, when its image is
//! loaded. Everything not listed here stays zero.

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
    /// ThreadLocalStoragePointer: the implicit-TLS block array (see [`crate::user::tls`]).
    pub const THREAD_LOCAL_STORAGE_POINTER: u32 = 0x2C;
    /// ProcessEnvironmentBlock.
    pub const PEB: u32 = 0x30;
    /// LastErrorValue: what GetLastError reads and SetLastError writes.
    pub const LAST_ERROR: u32 = 0x34;
    /// TlsSlots: the first 64 TLS slots.
    pub const TLS_SLOTS: u32 = 0xE10;
    /// TlsExpansionSlots: the page holding the other 1024.
    pub const TLS_EXPANSION_SLOTS: u32 = 0xF94;
}

/// PEB field offsets.
pub mod peb_offset {
    /// ImageBaseAddress: the process image's base, what GetModuleHandle(NULL) returns.
    pub const IMAGE_BASE_ADDRESS: u32 = 0x08;
    /// ProcessHeap: what GetProcessHeap returns.
    pub const PROCESS_HEAP: u32 = 0x18;
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
    /// The lowest address of the thread's user stack.
    pub stack_limit: u32,
    /// The owning process's client id.
    pub process_id: u32,
    /// The thread's client id.
    pub thread_id: u32,
    /// The process's PEB page.
    pub peb: u32,
    /// The thread's implicit-TLS block array; zero for an image without TLS.
    pub tls_pointer: u32,
    /// The thread's TLS expansion-slot page.
    pub tls_expansion: u32,
}

/// A fresh TEB's nonzero words, as (offset, value).
pub fn teb_words(init: &TebInit) -> [(u32, u32); 9] {
    [
        (teb_offset::EXCEPTION_LIST, END_OF_CHAIN),
        (teb_offset::STACK_BASE, init.stack_base),
        (teb_offset::STACK_LIMIT, init.stack_limit),
        (teb_offset::SELF, init.teb),
        (teb_offset::PROCESS_ID, init.process_id),
        (teb_offset::THREAD_ID, init.thread_id),
        (teb_offset::PEB, init.peb),
        (teb_offset::THREAD_LOCAL_STORAGE_POINTER, init.tls_pointer),
        (teb_offset::TLS_EXPANSION_SLOTS, init.tls_expansion),
    ]
}

/// A fresh PEB's nonzero words, as (offset, value).
pub fn peb_words(image_base: u32, process_heap: u32) -> [(u32, u32); 2] {
    [
        (peb_offset::IMAGE_BASE_ADDRESS, image_base),
        (peb_offset::PROCESS_HEAP, process_heap),
    ]
}

/// Map a thread's TEB page at `init.teb`: one zeroed frame carrying the fresh TEB's words.
#[cfg(target_arch = "x86")]
pub fn map_teb(init: &TebInit) {
    use crate::mem::paging;
    let frame = paging::allocate_frame_phys();
    paging::init_frame(frame, 0, &[]);
    for (offset, value) in teb_words(init) {
        paging::write_frame(frame, offset as usize, &value.to_le_bytes());
    }
    paging::map_user_page(init.teb, frame, true);
}

/// Map the current process's PEB page at [`crate::user::PEB_PAGE`].
#[cfg(target_arch = "x86")]
pub fn map_peb(image_base: u32, process_heap: u32) {
    use crate::mem::paging;
    let frame = paging::allocate_frame_phys();
    paging::init_frame(frame, 0, &[]);
    for (offset, value) in peb_words(image_base, process_heap) {
        paging::write_frame(frame, offset as usize, &value.to_le_bytes());
    }
    paging::map_user_page(crate::user::PEB_PAGE, frame, true);
}

/// Set the calling thread's last error: the TEB slot GetLastError reads. Services call this on the
/// failure paths the documented contracts name; a thread without a TEB (none runs services) is left
/// alone.
#[cfg(target_arch = "x86")]
pub fn set_last_error(code: u32) {
    // SAFETY: the current thread's record is live while it runs a service.
    let teb_va = unsafe { (*crate::sched::idle::dispatcher().current_thread()).teb_va() };
    if teb_va != 0 {
        // The TEB page is the thread's own, mapped writable for its whole life.
        let written =
            crate::user::syscall::write_user(teb_va + teb_offset::LAST_ERROR, &code.to_le_bytes());
        debug_assert!(written.is_ok(), "the calling thread's TEB is mapped");
    }
}

/// Host builds compile the services but never run them.
#[cfg(not(target_arch = "x86"))]
pub fn set_last_error(_code: u32) {}

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
        assert_eq!(teb_offset::THREAD_LOCAL_STORAGE_POINTER, 0x2C);
        assert_eq!(teb_offset::TLS_SLOTS, 0xE10);
        assert_eq!(teb_offset::TLS_EXPANSION_SLOTS, 0xF94);
        assert_eq!(peb_offset::IMAGE_BASE_ADDRESS, 0x08);
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
            process_id: 8,
            thread_id: 12,
            peb: 0x0033_0000,
            tls_pointer: 0x0088_1000,
            tls_expansion: 0x0088_0000,
        };
        let words = teb_words(&init);
        let value = |offset| words.iter().find(|&&(o, _)| o == offset).map(|&(_, v)| v);
        assert_eq!(value(teb_offset::EXCEPTION_LIST), Some(END_OF_CHAIN));
        assert_eq!(value(teb_offset::SELF), Some(0x0031_0000));
        assert_eq!(value(teb_offset::STACK_BASE), Some(0x0030_1000));
        assert_eq!(value(teb_offset::STACK_LIMIT), Some(0x002F_F000));
        assert_eq!(value(teb_offset::PROCESS_ID), Some(8));
        assert_eq!(value(teb_offset::THREAD_ID), Some(12));
        assert_eq!(value(teb_offset::PEB), Some(0x0033_0000));
        assert_eq!(
            value(teb_offset::THREAD_LOCAL_STORAGE_POINTER),
            Some(0x0088_1000)
        );
        assert_eq!(value(teb_offset::TLS_EXPANSION_SLOTS), Some(0x0088_0000));
        assert_eq!(value(teb_offset::LAST_ERROR), None);
        for &(offset, _) in &words {
            assert_eq!(offset % 4, 0);
            assert!(offset < 0x1000);
        }
    }

    #[test]
    fn fresh_peb_words() {
        let words = peb_words(0x0040_0000, 0x0200_0000);
        assert!(words.contains(&(peb_offset::IMAGE_BASE_ADDRESS, 0x0040_0000)));
        assert!(words.contains(&(peb_offset::PROCESS_HEAP, 0x0200_0000)));
    }
}
