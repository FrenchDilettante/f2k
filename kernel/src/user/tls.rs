//! Thread-local storage: the TLS slots TlsAlloc hands out, and the image's `__declspec(thread)`
//! data.
//!
//! Slots, as Windows 2000 keeps them: indexes 0..64 live in the TEB itself (TlsSlots, TEB+0xE10),
//! indexes 64..1088 in the thread's expansion page (TlsExpansionSlots, TEB+0xF94, 1024 dwords).
//! TlsGetValue and TlsSetValue are user-mode reads and writes of those words (kernel32's native
//! exports); TlsAlloc and TlsFree are the process's bitmap of indexes, and freeing an index zeroes
//! its slot in every thread.
//!
//! Implicit TLS: an image with a TLS directory gets index 0 written to its index variable, and every
//! thread a block copied from the image's template (the raw data, then the zero fill), reached
//! through the thread's ThreadLocalStoragePointer (TEB+0x2C): a one-entry pointer array at the
//! start of the thread's implicit-TLS page, the block after it. TLS callbacks are not run.
//!
//! Each thread's two pages (expansion, implicit) sit in the TLS region by the thread's ordinal (0
//! for the main thread).

use crate::mem::paging::PAGE_SIZE;

/// The TEB's own slots.
pub const TEB_SLOTS: u32 = 64;
/// The expansion page's slots.
pub const EXPANSION_SLOTS: u32 = 1024;
/// Every TLS index a process can allocate.
pub const INDEXES: u32 = TEB_SLOTS + EXPANSION_SLOTS;
/// TlsAlloc's failure return.
pub const TLS_OUT_OF_INDEXES: u32 = 0xFFFF_FFFF;

use crate::user::teb::teb_offset::TLS_SLOTS as TEB_TLS_SLOTS;

/// The region the threads' TLS pages live in: two pages per thread ordinal.
pub const TLS_REGION: u32 = 0x0088_0000;
/// The bytes of a thread's implicit-TLS page the block may use (the pointer array leads it).
pub const IMPLICIT_ROOM: u32 = PAGE_SIZE - IMPLICIT_BLOCK_OFFSET;
/// Where the implicit-TLS block starts in its page.
const IMPLICIT_BLOCK_OFFSET: u32 = 16;

/// The expansion page of thread `ordinal`.
pub const fn expansion_page(ordinal: u32) -> u32 {
    TLS_REGION + ordinal * 2 * PAGE_SIZE
}

/// The implicit-TLS page of thread `ordinal`.
pub const fn implicit_page(ordinal: u32) -> u32 {
    expansion_page(ordinal) + PAGE_SIZE
}

/// The user address of index `index`'s slot for the thread whose TEB is at `teb` and whose
/// expansion page is `expansion`; none past the last index.
pub fn slot_address(teb: u32, expansion: u32, index: u32) -> Option<u32> {
    if index < TEB_SLOTS {
        Some(teb + TEB_TLS_SLOTS + index * 4)
    } else if index < INDEXES {
        Some(expansion + (index - TEB_SLOTS) * 4)
    } else {
        None
    }
}

/// A process's TLS indexes.
pub struct TlsIndexes {
    words: [u32; INDEXES as usize / 32],
}

impl TlsIndexes {
    /// None allocated.
    pub const fn empty() -> TlsIndexes {
        TlsIndexes {
            words: [0; INDEXES as usize / 32],
        }
    }

    /// Allocate the lowest free index; none when all are taken.
    pub fn alloc(&mut self) -> Option<u32> {
        for (word_index, word) in self.words.iter_mut().enumerate() {
            if *word != u32::MAX {
                let bit = word.trailing_ones();
                *word |= 1 << bit;
                return Some(word_index as u32 * 32 + bit);
            }
        }
        None
    }

    /// Free `index`: false when it is not allocated.
    pub fn free(&mut self, index: u32) -> bool {
        if index >= INDEXES {
            return false;
        }
        let (word, bit) = ((index / 32) as usize, index % 32);
        let allocated = self.words[word] & (1 << bit) != 0;
        self.words[word] &= !(1 << bit);
        allocated
    }
}

/// An image's implicit-TLS template: where its raw data starts and ends (user addresses, the image
/// at its base) and how many zero bytes follow it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Template {
    pub start: u32,
    pub end: u32,
    pub zero_fill: u32,
}

impl Template {
    /// The block's size: the raw data and the zero fill.
    pub fn size(&self) -> u64 {
        (self.end - self.start) as u64 + self.zero_fill as u64
    }
}

/// IMAGE_TLS_DIRECTORY32's fields, as (start, end, index address, callbacks address, zero fill).
pub fn parse_directory(bytes: &[u8]) -> Option<(u32, u32, u32, u32, u32)> {
    let word = |offset: usize| -> Option<u32> {
        Some(u32::from_le_bytes(
            bytes.get(offset..offset + 4)?.try_into().ok()?,
        ))
    };
    Some((word(0)?, word(4)?, word(8)?, word(12)?, word(16)?))
}

/// Map thread `ordinal`'s TLS pages: its expansion page (zeroed), and with an image `template` its
/// implicit-TLS page carrying the block copied from the image's template (already mapped in the
/// current address space). Returns the TEB words to record: (ThreadLocalStoragePointer,
/// TlsExpansionSlots).
#[cfg(target_arch = "x86")]
pub fn map_thread_pages(ordinal: u32, template: Option<Template>) -> (u32, u32) {
    use crate::mem::paging;
    let expansion = expansion_page(ordinal);
    let frame = paging::allocate_frame_phys();
    paging::init_frame(frame, 0, &[]);
    paging::map_user_page(expansion, frame, true);
    let Some(template) = template else {
        return (0, expansion);
    };
    let page = implicit_page(ordinal);
    let block = page + IMPLICIT_BLOCK_OFFSET;
    let frame = paging::allocate_frame_phys();
    paging::init_frame(frame, 0, &block.to_le_bytes());
    // The raw data, copied from the image (the zero fill is the page's own zeroes).
    let mut chunk = [0u8; 256];
    let mut copied = 0;
    while copied < template.end - template.start {
        let take = (template.end - template.start - copied).min(chunk.len() as u32) as usize;
        // The image is mapped in the current address space; its template pages are readable.
        let read = crate::user::syscall::read_user(template.start + copied, &mut chunk[..take]);
        assert!(read.is_ok(), "the TLS template lies in the mapped image");
        paging::write_frame(
            frame,
            (IMPLICIT_BLOCK_OFFSET + copied) as usize,
            &chunk[..take],
        );
        copied += take as u32;
    }
    paging::map_user_page(page, frame, true);
    (page, expansion)
}

/// Unmap and release thread `ordinal`'s TLS pages (a reused thread record's).
#[cfg(target_arch = "x86")]
pub fn release_thread_pages(ordinal: u32) {
    use crate::mem::frame::FrameState;
    use crate::mem::paging;
    for va in [expansion_page(ordinal), implicit_page(ordinal)] {
        if let Some(frame) = paging::unmap_user_page(va) {
            crate::mem::bootmem::with_frame_db(|db| {
                db.release(frame / PAGE_SIZE, FrameState::Free);
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Indexes allocate lowest first, all 1088 of them, then none; a freed index comes back.
    #[test]
    fn indexes_allocate_lowest_first() {
        let mut indexes = TlsIndexes::empty();
        for expected in 0..INDEXES {
            assert_eq!(indexes.alloc(), Some(expected));
        }
        assert_eq!(indexes.alloc(), None);
        assert!(indexes.free(70));
        assert!(!indexes.free(70), "a double free");
        assert!(!indexes.free(INDEXES));
        assert_eq!(indexes.alloc(), Some(70));
    }

    /// The slots: the TEB's first, then the expansion page's.
    #[test]
    fn slots_address_the_teb_then_the_expansion_page() {
        let (teb, expansion) = (0x0031_0000, expansion_page(0));
        assert_eq!(slot_address(teb, expansion, 0), Some(teb + 0xE10));
        assert_eq!(slot_address(teb, expansion, 63), Some(teb + 0xE10 + 63 * 4));
        assert_eq!(slot_address(teb, expansion, 64), Some(expansion));
        assert_eq!(
            slot_address(teb, expansion, 1087),
            Some(expansion + 1023 * 4)
        );
        assert_eq!(slot_address(teb, expansion, 1088), None);
        // The TEB's slots end before its expansion pointer.
        assert!(TEB_TLS_SLOTS + TEB_SLOTS * 4 <= crate::user::teb::teb_offset::TLS_EXPANSION_SLOTS);
    }

    /// The pages: two per ordinal, the main thread's first, all below the thread stacks.
    #[test]
    fn tls_pages_tile_their_region() {
        assert_eq!(expansion_page(0), TLS_REGION);
        assert_eq!(implicit_page(0), TLS_REGION + PAGE_SIZE);
        assert_eq!(expansion_page(1), TLS_REGION + 2 * PAGE_SIZE);
        let last = implicit_page(crate::process::CHILD_THREADS as u32) + PAGE_SIZE;
        assert!(last <= crate::user::THREAD_STACK_REGION);
        assert!(
            TLS_REGION
                >= crate::user::THREAD_TEB_REGION
                    + crate::process::CHILD_THREADS as u32 * PAGE_SIZE
        );
    }

    #[test]
    fn the_directory_parses() {
        let mut bytes = [0u8; 24];
        for (i, value) in [0x0040_8000u32, 0x0040_8014, 0x0040_9000, 0x0040_a000, 8]
            .iter()
            .enumerate()
        {
            bytes[i * 4..i * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        assert_eq!(
            parse_directory(&bytes),
            Some((0x0040_8000, 0x0040_8014, 0x0040_9000, 0x0040_a000, 8))
        );
        assert_eq!(parse_directory(&bytes[..12]), None);
        let template = Template {
            start: 0x0040_8000,
            end: 0x0040_8014,
            zero_fill: 8,
        };
        assert_eq!(template.size(), 28);
    }
}
