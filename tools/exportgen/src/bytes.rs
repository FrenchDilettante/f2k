//! The cursors the image writers and readers ([`crate::pe`], [`crate::elf`]) share, both
//! little-endian: [`Out`] writes a structure's fields in their declared order, [`Fields`] reads
//! them back.

/// A write cursor: each field in declared order, little-endian.
pub(crate) struct Out(pub(crate) Vec<u8>);

impl Out {
    pub(crate) fn u8(&mut self, value: u8) {
        self.0.push(value);
    }

    pub(crate) fn u16(&mut self, value: u16) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    pub(crate) fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) {
        self.0.extend_from_slice(value);
    }

    /// Pad with zeros to a multiple of `alignment`.
    pub(crate) fn align(&mut self, alignment: usize) {
        self.0.resize(self.0.len().next_multiple_of(alignment), 0);
    }
}

/// A read cursor over a structure's bytes: each field in declared order, little-endian.
pub(crate) struct Fields<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Fields<'a> {
    /// The `size` bytes at `offset` of `file`, if it holds them; the error names `what` lies
    /// there. The fields read from them are the structure's: reading past `size` is the reader's
    /// own error, and panics.
    pub(crate) fn at(
        file: &'a [u8],
        offset: usize,
        size: usize,
        what: &str,
    ) -> Result<Self, String> {
        let bytes = offset
            .checked_add(size)
            .and_then(|end| file.get(offset..end))
            .ok_or_else(|| format!("the file ends inside {what} (at {offset:#x})"))?;
        Ok(Fields { bytes, at: 0 })
    }

    pub(crate) fn take<const N: usize>(&mut self) -> [u8; N] {
        let field = self.bytes[self.at..self.at + N].try_into().unwrap();
        self.at += N;
        field
    }

    pub(crate) fn u8(&mut self) -> u8 {
        self.take::<1>()[0]
    }

    pub(crate) fn u16(&mut self) -> u16 {
        u16::from_le_bytes(self.take())
    }

    pub(crate) fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.take())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_are_written_and_read_back_in_order() {
        let mut out = Out(Vec::new());
        out.u8(1);
        out.u16(0x0302);
        out.u32(0x0706_0504);
        out.bytes(&[8, 9]);
        out.align(4);
        assert_eq!(out.0, [1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0]);
        let mut fields = Fields::at(&out.0, 1, 7, "the fields").unwrap();
        assert_eq!(fields.u16(), 0x0302);
        assert_eq!(fields.u32(), 0x0706_0504);
        assert_eq!(fields.u8(), 8);
    }

    #[test]
    fn a_structure_past_the_file_is_an_error() {
        let file = [0u8; 8];
        assert!(Fields::at(&file, 4, 4, "it").is_ok());
        assert_eq!(
            Fields::at(&file, 6, 4, "the header").err().unwrap(),
            "the file ends inside the header (at 0x6)"
        );
        assert!(Fields::at(&file, usize::MAX, 2, "it").is_err());
    }
}
