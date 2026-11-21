//! The window manager's texts: the windows' titles, a creation's window name, the texts a message
//! carries to another process. Windows 2000 allocates each from its desktop's heap, as long as the
//! caller makes it; F2K's [`Texts`] is that heap's stand-in, a [`KernelHeap`] over each of a few
//! segments of the nonpaged pool, taken as the texts need them and given back once emptied (so
//! that a process's texts leave no page behind it once its windows and messages are gone). A text
//! is bounded only by the memory: one too long for a segment gets a segment of its own, sized to
//! it.
//!
//! A [`Text`] names its units: a segment and an offset in it, and its length (no terminator), a
//! copy of which any record may hold; the store's owner frees it once. The empty text takes no
//! block.
//!
//! The services read a caller's string, and copy a text out to the caller, through [`Staged`]: on
//! the stack when it is short, in a block of the pool otherwise, so that no user memory is touched
//! under the window manager's lock.

use core::alloc::Layout;
use core::ptr::NonNull;

use crate::mem::heap::KernelHeap;

/// How many segments a store holds at once.
const SEGMENTS: usize = 32;

/// A segment's size, unless one text needs more: 64 KiB.
const SEGMENT_BYTES: usize = 64 * 1024;

/// A segment's bytes beyond its texts' own: the heap's tags around its one free block.
const SEGMENT_OVERHEAD: usize = 16;

/// A segment's memory: a block of the nonpaged pool (on the host, a boxed buffer).
#[cfg(target_arch = "x86")]
type Memory = crate::mem::pool::Block;
#[cfg(not(target_arch = "x86"))]
type Memory = std::boxed::Box<[u64]>;

/// The memory for a segment of `bytes` bytes (a multiple of 8): none when the pool has no room.
fn take_memory(bytes: usize) -> Option<Memory> {
    #[cfg(target_arch = "x86")]
    {
        crate::mem::pool::allocate(bytes)
    }
    #[cfg(not(target_arch = "x86"))]
    {
        Some(std::vec![0u64; bytes / 8].into_boxed_slice())
    }
}

/// A segment's memory as bytes.
fn memory_bytes(memory: &mut Memory) -> &mut [u8] {
    #[cfg(target_arch = "x86")]
    {
        memory.as_mut()
    }
    #[cfg(not(target_arch = "x86"))]
    {
        // SAFETY: the buffer's u64s viewed as their bytes: any bits make a byte, and the length is
        // the buffer's own.
        unsafe { core::slice::from_raw_parts_mut(memory.as_mut_ptr().cast(), 8 * memory.len()) }
    }
}

/// A text's place: its segment, the offset of its units in it, and how many units it has (0: the
/// empty text, no block).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Text {
    segment: u8,
    offset: u32,
    length: u32,
}

impl Text {
    /// The empty text.
    pub const EMPTY: Self = Text {
        segment: 0,
        offset: 0,
        length: 0,
    };

    /// Its length, in units.
    pub fn len(self) -> usize {
        self.length as usize
    }

    pub fn is_empty(self) -> bool {
        self.length == 0
    }
}

/// A segment: its heap, over its memory, and how many texts it holds.
struct Segment {
    heap: KernelHeap,
    base: NonNull<u8>,
    bytes: usize,
    live: u32,
    /// Owns the memory the heap carves: given back when the segment goes.
    _memory: Memory,
}

// SAFETY: the segment owns its memory (the heap and the base point into it, and nothing else
// does), so moving it to another thread moves that ownership with it.
unsafe impl Send for Segment {}

impl Segment {
    /// A segment of at least `bytes` bytes: none when the pool has no room.
    fn new(bytes: usize) -> Option<Segment> {
        let bytes = bytes.max(SEGMENT_BYTES).next_multiple_of(4096);
        let mut memory = take_memory(bytes)?;
        let pool = memory_bytes(&mut memory);
        let base = NonNull::new(pool.as_mut_ptr())?;
        // SAFETY: the memory is the segment's alone, and lives as long as the segment (it is
        // dropped with it, after the heap, which holds no reference past the segment's life). Its
        // address does not move with the segment: the pool's pages, or the box's buffer, stay put.
        let pool: &'static mut [u8] =
            unsafe { core::slice::from_raw_parts_mut(base.as_ptr(), bytes) };
        Some(Segment {
            heap: KernelHeap::new(pool),
            base,
            bytes,
            live: 0,
            _memory: memory,
        })
    }
}

/// A store of texts: the segments their units live in.
pub struct Texts {
    segments: [Option<Segment>; SEGMENTS],
}

impl Default for Texts {
    fn default() -> Self {
        Texts::EMPTY
    }
}

impl Texts {
    /// A store with no segment yet.
    pub const EMPTY: Self = Texts {
        segments: [const { None }; SEGMENTS],
    };

    /// A copy of `units` in the store: none when no segment has room and no new one can be taken
    /// (the pool, or the store's segments, run out).
    pub fn store(&mut self, units: &[u16]) -> Option<Text> {
        if units.is_empty() {
            return Some(Text::EMPTY);
        }
        let length = u32::try_from(units.len()).ok()?;
        let layout = Layout::from_size_align(2 * units.len(), 8).ok()?;
        let (segment, at) = self.allocate(layout)?;
        let text = Text {
            segment: segment as u8,
            offset: (at.as_ptr() as usize - self.segment(segment).base.as_ptr() as usize) as u32,
            length,
        };
        // SAFETY: a block of the segment's heap, just allocated, of `2 * units.len()` bytes and
        // 8-aligned; nothing else refers to it.
        let out =
            unsafe { core::slice::from_raw_parts_mut(at.as_ptr().cast::<u16>(), units.len()) };
        out.copy_from_slice(units);
        Some(text)
    }

    /// A block for `layout` in the lowest segment with room, a new segment taken when none has
    /// any: the segment's index and the block.
    fn allocate(&mut self, layout: Layout) -> Option<(usize, NonNull<u8>)> {
        for (index, slot) in self.segments.iter_mut().enumerate() {
            if let Some(segment) = slot {
                if let Some(at) = segment.heap.alloc(layout) {
                    segment.live += 1;
                    return Some((index, at));
                }
            }
        }
        let index = self.segments.iter().position(Option::is_none)?;
        let mut segment = Segment::new(layout.size().next_multiple_of(8) + SEGMENT_OVERHEAD)?;
        let at = segment.heap.alloc(layout)?;
        segment.live = 1;
        self.segments[index] = Some(segment);
        Some((index, at))
    }

    fn segment(&self, index: usize) -> &Segment {
        self.segments[index]
            .as_ref()
            .expect("a live text's segment is there")
    }

    /// The units of `text`, one of this store's live texts.
    pub fn units(&self, text: Text) -> &[u16] {
        if text.is_empty() {
            return &[];
        }
        let segment = self.segment(text.segment as usize);
        assert!(
            text.offset as usize + 2 * text.len() <= segment.bytes,
            "a text inside its segment"
        );
        // SAFETY: a live block of the segment's heap (the caller's contract), `length` units long
        // at an 8-aligned offset, inside the segment (checked above); the store's borrow keeps it
        // from being freed or written meanwhile.
        unsafe {
            core::slice::from_raw_parts(
                segment
                    .base
                    .as_ptr()
                    .add(text.offset as usize)
                    .cast::<u16>(),
                text.len(),
            )
        }
    }

    /// Give `text` back, once: an emptied segment goes back to the pool.
    pub fn free(&mut self, text: Text) {
        if text.is_empty() {
            return;
        }
        let index = text.segment as usize;
        let segment = self.segments[index]
            .as_mut()
            .expect("a live text's segment is there");
        // SAFETY: inside the segment's memory, at a block the heap handed out.
        let at = unsafe { NonNull::new_unchecked(segment.base.as_ptr().add(text.offset as usize)) };
        segment.heap.dealloc(at);
        segment.live -= 1;
        if segment.live == 0 {
            self.segments[index] = None;
        }
    }

    /// `text` replaced with a copy of `units`, the old text given back; false, `text` unchanged,
    /// when there is no room for the new one.
    pub fn replace(&mut self, text: &mut Text, units: &[u16]) -> bool {
        let Some(new) = self.store(units) else {
            return false;
        };
        self.free(*text);
        *text = new;
        true
    }

    /// How many texts the store holds, and how many segments.
    #[cfg(test)]
    pub(crate) fn counts(&self) -> (u32, usize) {
        let live = self.segments.iter().flatten().map(|s| s.live).sum();
        (live, self.segments.iter().flatten().count())
    }
}

#[cfg(target_arch = "x86")]
pub use target::*;

#[cfg(target_arch = "x86")]
mod target {
    use rtl::pod::Pod;

    use crate::mem::pool::{self, Block};
    use crate::status::*;
    use crate::user::args::UserAddr;

    /// The units a staged text holds on the stack; a longer one is staged in a block of the pool.
    const SHORT: usize = 128;

    /// The bytes of a page: a caller's string is scanned no further than its page at a time.
    const PAGE: u32 = 4096;

    /// A text on its way between the caller and the store: on the stack when it is short, in a
    /// block of the pool otherwise (the short form's room on the stack is the point of it).
    #[allow(clippy::large_enum_variant)]
    pub enum Staged {
        Short([u16; SHORT], usize),
        Long(Block, usize),
    }

    /// A pool block's bytes as units.
    fn block_units(block: &mut Block) -> &mut [u16] {
        let bytes = block.as_mut();
        // SAFETY: a block starts on a page boundary, so its bytes are aligned for units, and any
        // bits make a unit; the length is the block's own, halved.
        unsafe { core::slice::from_raw_parts_mut(bytes.as_mut_ptr().cast(), bytes.len() / 2) }
    }

    impl Staged {
        /// Room for `length` units, zeroed: none when the pool has none.
        pub fn with_length(length: usize) -> Option<Staged> {
            if length <= SHORT {
                return Some(Staged::Short([0; SHORT], length));
            }
            Some(Staged::Long(pool::allocate(2 * length)?, length))
        }

        /// A copy of `units`: none when the pool has no room for it.
        pub fn copy_of(units: &[u16]) -> Option<Staged> {
            let mut staged = Staged::with_length(units.len())?;
            staged.units_mut().copy_from_slice(units);
            Some(staged)
        }

        pub fn units(&self) -> &[u16] {
            match self {
                Staged::Short(units, length) => &units[..*length],
                Staged::Long(block, length) => {
                    let bytes = block.as_ref();
                    // SAFETY: as in `block_units`.
                    let units: &[u16] = unsafe {
                        core::slice::from_raw_parts(bytes.as_ptr().cast(), bytes.len() / 2)
                    };
                    &units[..*length]
                }
            }
        }

        pub fn units_mut(&mut self) -> &mut [u16] {
            match self {
                Staged::Short(units, length) => &mut units[..*length],
                Staged::Long(block, length) => &mut block_units(block)[..*length],
            }
        }

        /// The caller's NUL-terminated UTF-16 string at `at`, whole (null: the empty text):
        /// STATUS_ACCESS_VIOLATION for one the caller's memory does not hold, STATUS_NO_MEMORY
        /// when the pool has no room for it.
        pub fn read(at: UserAddr) -> Result<Staged, NtStatus> {
            if at.is_null() {
                return Ok(Staged::Short([0; SHORT], 0));
            }
            let length = string_length(at)?;
            let mut staged = Staged::with_length(length).ok_or(STATUS_NO_MEMORY)?;
            at.read_units(staged.units_mut())?;
            Ok(staged)
        }
    }

    /// The length, in units, of the caller's NUL-terminated string at `at`, read no further than
    /// a page at a time, so that a string ending before an unreadable page is read whole.
    pub fn string_length(at: UserAddr) -> Result<usize, NtStatus> {
        let mut buffer = [0u16; 64];
        let mut length = 0usize;
        loop {
            let here = at.offset(2 * length as u32);
            let to_page = (PAGE - here.raw() % PAGE) as usize;
            let count = (to_page / 2).clamp(1, buffer.len());
            here.read(&mut buffer.as_bytes_mut()[..2 * count])?;
            if let Some(end) = buffer[..count].iter().position(|&unit| unit == 0) {
                return Ok(length + end);
            }
            length += count;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn units(length: usize, seed: u16) -> std::vec::Vec<u16> {
        (0..length).map(|i| seed.wrapping_add(i as u16)).collect()
    }

    /// A text is copied whole, however long: 10,000 units, and one past a segment's size.
    #[test]
    fn a_text_is_kept_whole() {
        let mut texts = Texts::EMPTY;
        let short = texts.store(&units(5, 0x41)).unwrap();
        let long = texts.store(&units(10_000, 0x100)).unwrap();
        let huge = texts.store(&units(SEGMENT_BYTES, 0x200)).unwrap();
        assert_eq!(texts.units(short), &units(5, 0x41)[..]);
        assert_eq!(texts.units(long), &units(10_000, 0x100)[..]);
        assert_eq!(texts.units(huge), &units(SEGMENT_BYTES, 0x200)[..]);
        assert_eq!(
            texts.counts(),
            (3, 2),
            "the huge text has a segment of its own"
        );
        texts.free(huge);
        assert_eq!(texts.counts(), (2, 1), "its segment goes with it");
        texts.free(short);
        texts.free(long);
        assert_eq!(
            texts.counts(),
            (0, 0),
            "the last segment goes with the last text"
        );
    }

    /// The empty text takes no block; a freed text's room is taken again, in the segment a live
    /// text keeps.
    #[test]
    fn freed_room_is_reused() {
        let mut texts = Texts::EMPTY;
        assert_eq!(texts.store(&[]), Some(Text::EMPTY));
        assert_eq!(texts.counts(), (0, 0));
        let kept = texts.store(&units(10, 7)).unwrap();
        for round in 0..1000 {
            let text = texts.store(&units(1000, round)).unwrap();
            assert_eq!(texts.units(text)[0], round);
            texts.free(text);
        }
        assert_eq!(texts.counts(), (1, 1));
        assert_eq!(texts.units(kept), &units(10, 7)[..]);
    }

    /// A replacement frees the text it replaces.
    #[test]
    fn a_replacement_frees_the_old_text() {
        let mut texts = Texts::EMPTY;
        let mut text = Text::EMPTY;
        assert!(texts.replace(&mut text, &units(300, 1)));
        assert!(texts.replace(&mut text, &units(20, 2)));
        assert_eq!(texts.units(text), &units(20, 2)[..]);
        assert_eq!(texts.counts().0, 1);
        assert!(texts.replace(&mut text, &[]));
        assert_eq!(texts.counts().0, 0);
    }
}
