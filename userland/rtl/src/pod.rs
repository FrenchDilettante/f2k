//! Plain data: the types whose values are their bytes and nothing more, so that any bytes of their
//! size make one and their bytes can be handed out as they are. The structures the system services
//! fill or take, the blocks one process writes into another's memory and the layouts the kernel
//! reads from a user buffer are such types; [`Pod`] lets the code over them view a value as bytes,
//! or make one from bytes, without an `unsafe` block of its own.

use core::mem::size_of;

/// A plain-data type: integers, arrays of them and `#[repr(C)]` structures of them.
///
/// # Safety
///
/// An implementing type has no padding (every byte of a value is initialized) and every bit
/// pattern of its size is a valid value (no `bool`, `char`, enum, reference or `NonNull` field).
/// Its alignment may be anything: [`Pod::from_bytes`] reads unaligned.
pub unsafe trait Pod: Copy {
    /// The value's bytes.
    fn as_bytes(&self) -> &[u8] {
        // SAFETY: the value is `size_of::<Self>()` bytes, all of them initialized (the trait's
        // contract: no padding), borrowed for as long as the value is.
        unsafe { core::slice::from_raw_parts((self as *const Self).cast(), size_of::<Self>()) }
    }

    /// The value's bytes, writable: whatever is written leaves a valid value.
    fn as_bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: as above, borrowed exclusively; any bytes written make a valid value (the
        // trait's contract: every bit pattern is one).
        unsafe { core::slice::from_raw_parts_mut((self as *mut Self).cast(), size_of::<Self>()) }
    }

    /// The value the first `size_of::<Self>()` bytes of `bytes` make, at any alignment; none when
    /// `bytes` is shorter.
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let bytes = bytes.get(..size_of::<Self>())?;
        // SAFETY: `bytes` holds `size_of::<Self>()` initialized bytes, read unaligned, and any bit
        // pattern of that size is a valid value (the trait's contract).
        Some(unsafe { bytes.as_ptr().cast::<Self>().read_unaligned() })
    }

    /// The value of all-zero bytes.
    fn zeroed() -> Self {
        // SAFETY: all zeros is a bit pattern of the type's size, so a valid value (the trait's
        // contract).
        unsafe { core::mem::zeroed() }
    }
}

macro_rules! integers {
    ($($integer:ty),*) => {
        // SAFETY: an integer has no padding, and every bit pattern is one of its values.
        $(unsafe impl Pod for $integer {})*
    };
}

integers!(u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize);

// SAFETY: an array is its elements back to back, with no padding between or after them (an
// element's size is a multiple of its alignment), and each element is plain data.
unsafe impl<T: Pod, const N: usize> Pod for [T; N] {}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Pair {
        low: u16,
        high: u16,
        word: u32,
    }

    // SAFETY: integers, 8 bytes without padding.
    unsafe impl Pod for Pair {}

    #[test]
    fn a_value_is_its_bytes() {
        let value = 0x1122_3344u32;
        assert_eq!(value.as_bytes(), &[0x44, 0x33, 0x22, 0x11]);
        let pair = Pair {
            low: 0x0201,
            high: 0x0403,
            word: 0x0807_0605,
        };
        assert_eq!(pair.as_bytes(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn written_bytes_make_the_value() {
        let mut pair = Pair::zeroed();
        pair.as_bytes_mut()
            .copy_from_slice(&[1, 0, 2, 0, 3, 0, 0, 0]);
        assert_eq!(
            pair,
            Pair {
                low: 1,
                high: 2,
                word: 3
            }
        );
        let mut array = [0u8; 2];
        array.as_bytes_mut()[1] = 9;
        assert_eq!(array, [0, 9]);
    }

    #[test]
    fn bytes_make_a_value_at_any_alignment() {
        let bytes = [0xFF, 1, 0, 0, 0, 2, 0, 0, 0];
        assert_eq!(u32::from_bytes(&bytes[1..]), Some(1));
        assert_eq!(<[u32; 2]>::from_bytes(&bytes[1..]), Some([1, 2]));
        assert_eq!(u32::from_bytes(&bytes[6..]), None);
        assert_eq!(u16::from_bytes(&bytes[7..]), Some(0));
    }

    #[test]
    fn zeroed_is_all_zeros() {
        assert_eq!(<[u64; 3]>::zeroed(), [0; 3]);
        assert_eq!(i32::zeroed(), 0);
    }
}
