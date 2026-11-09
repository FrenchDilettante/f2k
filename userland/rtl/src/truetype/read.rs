//! Bounded big-endian reads: every value a TrueType file holds is read here, at an offset into a
//! slice, and a read that would run past the slice's end is [`Error::Truncated`], never a panic or
//! a read outside it. A font file is untrusted input, so no offset it holds is used unchecked.

use super::Error;

/// The `length` bytes at `offset` in `data`.
pub(crate) fn bytes(data: &[u8], offset: usize, length: usize) -> Result<&[u8], Error> {
    let end = offset.checked_add(length).ok_or(Error::Truncated)?;
    data.get(offset..end).ok_or(Error::Truncated)
}

/// The bytes from `offset` to the end of `data`.
pub(crate) fn rest(data: &[u8], offset: usize) -> Result<&[u8], Error> {
    data.get(offset..).ok_or(Error::Truncated)
}

/// The `N` bytes at `offset` in `data`.
fn array<const N: usize>(data: &[u8], offset: usize) -> Result<[u8; N], Error> {
    let mut value = [0; N];
    value.copy_from_slice(bytes(data, offset, N)?);
    Ok(value)
}

pub(crate) fn u8(data: &[u8], offset: usize) -> Result<u8, Error> {
    data.get(offset).copied().ok_or(Error::Truncated)
}

pub(crate) fn i8(data: &[u8], offset: usize) -> Result<i8, Error> {
    Ok(u8(data, offset)? as i8)
}

pub(crate) fn u16(data: &[u8], offset: usize) -> Result<u16, Error> {
    Ok(u16::from_be_bytes(array(data, offset)?))
}

pub(crate) fn i16(data: &[u8], offset: usize) -> Result<i16, Error> {
    Ok(i16::from_be_bytes(array(data, offset)?))
}

pub(crate) fn u32(data: &[u8], offset: usize) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(array(data, offset)?))
}

pub(crate) fn i32(data: &[u8], offset: usize) -> Result<i32, Error> {
    Ok(i32::from_be_bytes(array(data, offset)?))
}
