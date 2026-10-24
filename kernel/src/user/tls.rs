//! Thread-local storage: the TLS slots TlsAlloc hands out.
//!
//! Slots, as Windows 2000 keeps them: indexes 0..64 live in the TEB itself (TlsSlots, TEB+0xE10),
//! indexes 64..1088 in the thread's expansion slots (TlsExpansionSlots, TEB+0xF94: 1024 dwords on
//! the process heap, which kernel32's TlsSetValue allocates on first use). TlsGetValue and
//! TlsSetValue are user-mode reads and writes of those words, TlsAlloc and TlsFree user-mode code
//! over the PEB's bitmaps of indexes (kernel32's native exports; the kernel plants the bitmaps'
//! headers, `user::teb`); the kernel's part is NtSetInformationThread's ThreadZeroTlsCell, which
//! TlsFree asks to zero the freed index's slot in every thread that has one (`nt::thread`).
//!
//! Implicit TLS (an image's `__declspec(thread)` data) is user memory too: ntdll's thread
//! initialization (LdrInitializeThunk) makes each thread's block on the process heap from the
//! image's TLS directory, its pointer at TEB+0x2C, and LdrShutdownThread gives it back.

/// The TEB's own slots.
pub const TEB_SLOTS: u32 = 64;
/// The expansion slots (1024 dwords on the process heap).
pub const EXPANSION_SLOTS: u32 = 1024;
/// Every TLS index a process can allocate.
pub const INDEXES: u32 = TEB_SLOTS + EXPANSION_SLOTS;

use crate::user::teb::teb_offset::TLS_SLOTS as TEB_TLS_SLOTS;

/// The user address of index `index`'s slot for the thread whose TEB is at `teb` and whose
/// expansion slots are at `expansion` (zero: none yet); none past the last index, or for an
/// expansion index of a thread without expansion slots (its value reads zero).
pub fn slot_address(teb: u32, expansion: u32, index: u32) -> Option<u32> {
    if index < TEB_SLOTS {
        Some(teb + TEB_TLS_SLOTS + index * 4)
    } else if index < INDEXES && expansion != 0 {
        Some(expansion + (index - TEB_SLOTS) * 4)
    } else {
        None
    }
}

/// The user address of index `index`'s slot for the thread whose TEB is at `teb`, its expansion
/// slots read from the TEB (a TEB the program made unreadable has none).
#[cfg(target_arch = "x86")]
pub fn thread_slot(teb: u32, index: u32) -> Option<u32> {
    let mut expansion = [0u8; 4];
    let at = teb + crate::user::teb::teb_offset::TLS_EXPANSION_SLOTS;
    let expansion = match crate::user::syscall::read_user(at, &mut expansion) {
        Ok(()) => u32::from_le_bytes(expansion),
        Err(_) => 0,
    };
    slot_address(teb, expansion, index)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The slots: the TEB's first, then the expansion slots' (none before they exist).
    #[test]
    fn slots_address_the_teb_then_the_expansion_slots() {
        let (teb, expansion) = (0x7FFD_E000, 0x0014_2000);
        assert_eq!(slot_address(teb, expansion, 0), Some(teb + 0xE10));
        assert_eq!(slot_address(teb, expansion, 63), Some(teb + 0xE10 + 63 * 4));
        assert_eq!(slot_address(teb, expansion, 64), Some(expansion));
        assert_eq!(
            slot_address(teb, expansion, 1087),
            Some(expansion + 1023 * 4)
        );
        assert_eq!(slot_address(teb, expansion, 1088), None);
        assert_eq!(slot_address(teb, 0, 64), None, "no expansion slots yet");
        assert_eq!(slot_address(teb, 0, 63), Some(teb + 0xE10 + 63 * 4));
        // The TEB's slots end before its expansion pointer.
        assert!(TEB_TLS_SLOTS + TEB_SLOTS * 4 <= crate::user::teb::teb_offset::TLS_EXPANSION_SLOTS);
    }
}
