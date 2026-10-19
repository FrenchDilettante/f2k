//! The TLS indexes: kernel32's own code over the PEB's bitmaps, as on Windows 2000. The thread
//! calls themselves (CreateThread, ExitThread, the priorities and boosts) join them with B7.
//!
//! The TLS indexes are the PEB's two bitmaps (TlsBitmap, indexes 0..64; TlsExpansionBitmap,
//! 64..1088), changed under the PEB lock; a thread's slots are its TEB's TlsSlots and, past 64, its
//! TlsExpansionSlots (made by TlsSetValue on first use, on the process heap: src/natives.s, and
//! `f2k_k32_tls_expansion` in src/main.rs; a set that finds no room fails with
//! ERROR_NOT_ENOUGH_MEMORY).

use rtl::status::nt_success;

use crate::base::{
    peb, read, read_pointer, set_last_nt_error, teb_address, under_peb_lock, write, CURRENT_THREAD,
};
use crate::nt;

/// NtSetInformationThread's ThreadZeroTlsCell.
const THREAD_ZERO_TLS_CELL: u32 = 10;

const STATUS_NO_MEMORY: u32 = 0xC000_0017;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

/// TlsAlloc's failure.
const TLS_OUT_OF_INDEXES: u32 = 0xFFFF_FFFF;

/// The PEB's TlsBitmap and TlsExpansionBitmap (pointers to their RTL_BITMAP headers), and the TEB's
/// TlsSlots and TlsExpansionSlots.
const PEB_TLS_BITMAP: usize = 0x40;
const PEB_TLS_EXPANSION_BITMAP: usize = 0x150;
const TEB_TLS_SLOTS: usize = 0xE10;
const TEB_TLS_EXPANSION_SLOTS: usize = 0xF94;

/// The TEB's own slots: the indexes below are TlsBitmap's, the rest TlsExpansionBitmap's.
const TEB_SLOTS: u32 = 64;

/// RtlFindClearBitsAndSet(bitmap, 1, 0), for the RTL_BITMAP at `header`: its lowest clear bit, set;
/// none when every bit is.
fn find_clear_and_set(header: usize) -> Option<u32> {
    let (size, buffer) = (read(header), read_pointer(header + 4));
    for word in 0..size.div_ceil(32) {
        let at = buffer + 4 * word as usize;
        let bits = read(at);
        let index = 32 * word + bits.trailing_ones();
        if index < size && bits != u32::MAX {
            write(at, bits | 1 << (index % 32));
            return Some(index);
        }
    }
    None
}

/// Whether bit `index` of the RTL_BITMAP at `header` is set (RtlAreBitsSet: false past its end).
fn bit_set(header: usize, index: u32) -> bool {
    let (size, buffer) = (read(header), read_pointer(header + 4));
    index < size && read(buffer + 4 * (index / 32) as usize) & 1 << (index % 32) != 0
}

/// Clear bit `index` of the RTL_BITMAP at `header`.
fn clear_bit(header: usize, index: u32) {
    let at = read_pointer(header + 4) + 4 * (index / 32) as usize;
    write(at, read(at) & !(1 << (index % 32)));
}

/// TlsAlloc: the lowest free index — the TEB's slots' first, then the expansion slots' — marked in
/// the PEB's bitmap under the PEB lock, its slot cleared in the calling thread (TlsFree cleared it
/// in every other; an expansion index of a thread without expansion slots reads zero already);
/// TLS_OUT_OF_INDEXES with ERROR_NOT_ENOUGH_MEMORY when all 1088 are taken.
#[unsafe(export_name = "f2k_export_TlsAlloc")]
pub extern "system" fn tls_alloc() -> u32 {
    let (peb, teb) = (peb(), teb_address());
    under_peb_lock(|| {
        if let Some(index) = find_clear_and_set(read_pointer(peb + PEB_TLS_BITMAP)) {
            write(teb + TEB_TLS_SLOTS + 4 * index as usize, 0);
            index
        } else if let Some(index) = find_clear_and_set(read_pointer(peb + PEB_TLS_EXPANSION_BITMAP))
        {
            let expansion = read_pointer(teb + TEB_TLS_EXPANSION_SLOTS);
            if expansion != 0 {
                write(expansion + 4 * index as usize, 0);
            }
            TEB_SLOTS + index
        } else {
            set_last_nt_error(STATUS_NO_MEMORY);
            TLS_OUT_OF_INDEXES
        }
    })
}

/// TlsFree: an allocated index's slot zeroed in every thread of the process
/// (NtSetInformationThread's ThreadZeroTlsCell), then its bit cleared, under the PEB lock;
/// ERROR_INVALID_PARAMETER for an index not allocated (or past the last).
#[unsafe(export_name = "f2k_export_TlsFree")]
pub extern "system" fn tls_free(index: u32) -> u32 {
    let peb = peb();
    let (header, bit) = if index >= TEB_SLOTS {
        (
            read_pointer(peb + PEB_TLS_EXPANSION_BITMAP),
            index - TEB_SLOTS,
        )
    } else {
        (read_pointer(peb + PEB_TLS_BITMAP), index)
    };
    under_peb_lock(|| {
        let freed = bit_set(header, bit) && {
            // SAFETY: ntdll's export, over the index.
            let status = unsafe {
                nt::NtSetInformationThread(
                    CURRENT_THREAD,
                    THREAD_ZERO_TLS_CELL,
                    (&index as *const u32).cast(),
                    4,
                )
            };
            nt_success(status)
        };
        if freed {
            clear_bit(header, bit);
        } else {
            set_last_nt_error(STATUS_INVALID_PARAMETER);
        }
        u32::from(freed)
    })
}
