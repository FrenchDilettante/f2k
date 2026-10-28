//! The on-disk structures' building blocks: little-endian fields as FAT stores them, and the
//! conversion between a structure and the block of bytes it is read from or written to.
//!
//! A field is a byte array, so a `#[repr(C)]` structure built of them has no alignment and no
//! padding, and lays out exactly as the volume does — the boot sector's words at odd offsets
//! included. Such a structure is plain data ([`Pod`]): any bytes make one, so it is read from a
//! sector by value, changed through its fields, and written back as bytes, without `unsafe`.

use core::mem::size_of;

use rtl::pod::Pod;

/// A 16-bit little-endian field, at any alignment.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct Le16(pub [u8; 2]);

impl Le16 {
    pub const fn get(self) -> u16 {
        u16::from_le_bytes(self.0)
    }

    pub fn set(&mut self, value: u16) {
        self.0 = value.to_le_bytes();
    }
}

/// A 32-bit little-endian field, at any alignment.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct Le32(pub [u8; 4]);

impl Le32 {
    pub const fn get(self) -> u32 {
        u32::from_le_bytes(self.0)
    }

    pub fn set(&mut self, value: u32) {
        self.0 = value.to_le_bytes();
    }
}

// SAFETY: four bytes, transparently: no padding, and every bit pattern is a value. A FAT sector
// is an array of them.
unsafe impl Pod for Le32 {}

/// The structure `block` holds, which is exactly its size (checked at compile time).
pub fn from_block<T: Pod, const N: usize>(block: &[u8; N]) -> T {
    const { assert!(size_of::<T>() == N, "a block is its structure's size") };
    let mut value = T::zeroed();
    value.as_bytes_mut().copy_from_slice(block);
    value
}

/// The bytes of `value`, as the block of exactly its size it is written to (checked at compile
/// time).
pub fn to_block<T: Pod, const N: usize>(value: &T) -> [u8; N] {
    const { assert!(size_of::<T>() == N, "a block is its structure's size") };
    let mut block = [0u8; N];
    block.copy_from_slice(value.as_bytes());
    block
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_are_little_endian() {
        let mut word = Le16::default();
        word.set(0x1234);
        assert_eq!(word.0, [0x34, 0x12]);
        assert_eq!(word.get(), 0x1234);
        let mut long = Le32([0x78, 0x56, 0x34, 0x12]);
        assert_eq!(long.get(), 0x1234_5678);
        long.set(0xAABB_CCDD);
        assert_eq!(long.0, [0xDD, 0xCC, 0xBB, 0xAA]);
    }

    #[test]
    fn fields_have_no_alignment() {
        assert_eq!(core::mem::align_of::<Le16>(), 1);
        assert_eq!(core::mem::align_of::<Le32>(), 1);
    }

    #[test]
    fn a_block_round_trips() {
        let words: [Le32; 2] = from_block(&[1, 0, 0, 0, 0x78, 0x56, 0x34, 0x12]);
        assert_eq!((words[0].get(), words[1].get()), (1, 0x1234_5678));
        assert_eq!(to_block(&words), [1, 0, 0, 0, 0x78, 0x56, 0x34, 0x12]);
    }
}
