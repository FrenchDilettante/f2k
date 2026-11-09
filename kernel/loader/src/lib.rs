//! The boot loader's work on the kernel's image, apart from the machine: what the loader does to
//! ntoskrnl.exe between the Multiboot loader's hand-off and the kernel's entry, the way Windows
//! 2000's loader readies its kernel. Host-tested; the loader binary (`main.rs`) runs it over
//! physical memory with paging off.
//!
//! The image arrives as its file, at the physical address where it is to run ([`Image::parse`]
//! reads its headers there). [`Image::map_in_place`] turns the file into the mapped image where it
//! lies: each section's contents moved from its file offset up to its RVA (with page alignment for
//! file and sections, only the sections the image keeps past its uninitialized data move), and
//! everything the file does not carry zeroed. [`Image::relocate`] applies the image's base
//! relocations for a load away from its base.

#![cfg_attr(not(test), no_std)]

use core::mem::size_of;

use rtl::image::{
    data_directory,
    nt_headers_offset,
    ImageDataDirectory,
    ImageNtHeaders32,
    ImageSectionHeader,
    DIRECTORY_BASERELOC,
    NT_SIGNATURE,
    PE32_MAGIC,
};
use rtl::pod::Pod;

/// IMAGE_FILE_MACHINE_I386.
pub const MACHINE_I386: u16 = 0x014C;
/// IMAGE_SUBSYSTEM_NATIVE: a kernel-mode image.
pub const SUBSYSTEM_NATIVE: u16 = 1;
/// The base relocation types the loader applies: IMAGE_REL_BASED_ABSOLUTE (padding, skipped) and
/// IMAGE_REL_BASED_HIGHLOW (the delta added to the dword at the offset).
pub const REL_BASED_ABSOLUTE: u16 = 0;
pub const REL_BASED_HIGHLOW: u16 = 3;

/// IMAGE_BASE_RELOCATION: a block of base relocations, the fixups of one page. Its 16-bit entries
/// follow it: each a type in the top four bits, an offset into the page in the rest.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageBaseRelocation {
    /// The page's RVA.
    pub virtual_address: u32,
    /// The block's size, this header and its entries.
    pub size_of_block: u32,
}

const _: () = assert!(size_of::<ImageBaseRelocation>() == 8);

// SAFETY: two integers, 8 bytes without padding: every byte belongs to a field, and every bit
// pattern is a value.
unsafe impl Pod for ImageBaseRelocation {}

/// Why the loader refuses an image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// No MZ header, or no PE32 headers where it points.
    NotPe32,
    /// Not an i386 image of the native subsystem.
    NotKernel,
    /// The headers or a section run past the file, or a section past the image.
    Truncated,
    /// The sections are out of order, overlap, or lie in the file past where they map: the image
    /// cannot be mapped where its file lies.
    Misplaced,
    /// The image does not fit the memory it is to run in.
    TooLarge,
    /// The image must move and has no base relocations.
    NotRelocatable,
    /// A base relocation of a type the loader does not apply, or outside the image.
    BadRelocation,
}

impl Refusal {
    /// What the loader reports.
    pub fn text(self) -> &'static str {
        match self {
            Refusal::NotPe32 => "the kernel image is not a PE32 image",
            Refusal::NotKernel => "the kernel image is not an i386 native image",
            Refusal::Truncated => "the kernel image is truncated",
            Refusal::Misplaced => "the kernel image's sections cannot be mapped in place",
            Refusal::TooLarge => "the kernel image outgrows its memory",
            Refusal::NotRelocatable => "the kernel image must move and has no base relocations",
            Refusal::BadRelocation => "the kernel image has a base relocation the loader refuses",
        }
    }
}

/// A section as the loader places it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Placement {
    /// Where its contents lie in the file, and how many bytes of them the image keeps.
    file_offset: usize,
    contents: usize,
    /// Where it lies in the image, and its extent there (its size in memory, section-aligned).
    rva: usize,
    extent: usize,
}

/// A kernel image's headers, read from its file: what the loader needs to map it and enter it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Image {
    nt: ImageNtHeaders32,
    /// The section table's offset in the file, and its rows.
    sections_at: usize,
    sections: usize,
}

impl Image {
    /// The headers of the image whose file is `file`: a PE32 image for the i386 of the native
    /// subsystem, whose sections lie in the file and in the image, in order and apart, each in the
    /// file at or below where it maps (so it can be mapped where its file lies).
    pub fn parse(file: &[u8]) -> Result<Image, Refusal> {
        let offset = nt_headers_offset(&Pod::from_bytes(file).ok_or(Refusal::Truncated)?)
            .ok_or(Refusal::NotPe32)?;
        let nt: ImageNtHeaders32 = Pod::from_bytes(file.get(offset..).ok_or(Refusal::Truncated)?)
            .ok_or(Refusal::Truncated)?;
        if nt.signature != NT_SIGNATURE || nt.optional_header.magic != PE32_MAGIC {
            return Err(Refusal::NotPe32);
        }
        if nt.file_header.machine != MACHINE_I386
            || nt.optional_header.subsystem != SUBSYSTEM_NATIVE
        {
            return Err(Refusal::NotKernel);
        }
        // The section table follows the optional header, whatever its declared size.
        let sections_at = offset
            + 4
            + size_of::<rtl::image::ImageFileHeader>()
            + nt.file_header.size_of_optional_header as usize;
        let image = Image {
            nt,
            sections_at,
            sections: nt.file_header.number_of_sections as usize,
        };
        let headers = image.size_of_headers();
        let table_end = sections_at + image.sections * size_of::<ImageSectionHeader>();
        if headers > file.len() || table_end > headers {
            return Err(Refusal::Truncated);
        }
        let alignment = nt.optional_header.section_alignment as usize;
        if alignment == 0 || !alignment.is_power_of_two() {
            return Err(Refusal::Misplaced);
        }
        // In order and apart, in the image and in the file; each section's contents in the file
        // at or below where they map.
        let (mut next_rva, mut next_offset) = (headers, 0);
        for index in 0..image.sections {
            let section = image.placement(file, index)?;
            if section.rva < next_rva {
                return Err(Refusal::Misplaced);
            }
            if section.rva + section.extent > image.size_of_image() {
                return Err(Refusal::Truncated);
            }
            if section.contents > 0 {
                if section.file_offset < next_offset.max(headers)
                    || section.file_offset > section.rva
                {
                    return Err(Refusal::Misplaced);
                }
                if section.file_offset + section.contents > file.len() {
                    return Err(Refusal::Truncated);
                }
                next_offset = section.file_offset + section.contents;
            }
            next_rva = section.rva + section.extent;
        }
        Ok(image)
    }

    /// Section `index`'s placement, from its row of the table in `headers` (the image's first
    /// SizeOfHeaders bytes, file or mapped alike).
    fn placement(&self, headers: &[u8], index: usize) -> Result<Placement, Refusal> {
        let at = self.sections_at + index * size_of::<ImageSectionHeader>();
        let row: ImageSectionHeader = Pod::from_bytes(headers.get(at..).ok_or(Refusal::Truncated)?)
            .ok_or(Refusal::Truncated)?;
        let alignment = self.nt.optional_header.section_alignment as usize;
        let extent = (row.virtual_size as usize)
            .checked_next_multiple_of(alignment)
            .ok_or(Refusal::Truncated)?;
        Ok(Placement {
            file_offset: row.pointer_to_raw_data as usize,
            contents: (row.size_of_raw_data as usize).min(extent),
            rva: row.virtual_address as usize,
            extent,
        })
    }

    /// The address the image is linked at (ImageBase).
    pub fn image_base(&self) -> u32 {
        self.nt.optional_header.image_base
    }

    /// Its entry point's RVA (AddressOfEntryPoint).
    pub fn entry(&self) -> u32 {
        self.nt.optional_header.address_of_entry_point
    }

    /// The image's size in memory (SizeOfImage).
    pub fn size_of_image(&self) -> usize {
        self.nt.optional_header.size_of_image as usize
    }

    fn size_of_headers(&self) -> usize {
        self.nt.optional_header.size_of_headers as usize
    }

    /// Turn the image's file into the mapped image where it lies: `image` is the image's memory
    /// ([`Image::size_of_image`] bytes), whose first `file_len` bytes hold the file this image's
    /// headers were parsed from. Each section's contents move from their file offset up to their
    /// RVA, the last section first, so no move overwrites contents still to move (each lies in the
    /// file at or below where it maps, in order: [`Image::parse`]); then every byte of a section
    /// the file does not carry is zeroed. The headers stay where they are.
    pub fn map_in_place(&self, image: &mut [u8], file_len: usize) -> Result<(), Refusal> {
        if image.len() != self.size_of_image() {
            return Err(Refusal::TooLarge);
        }
        if file_len < self.size_of_headers() {
            return Err(Refusal::Truncated);
        }
        for index in (0..self.sections).rev() {
            let section = self.placement(image, index)?;
            if section.contents > 0 && section.file_offset != section.rva {
                let from = section.file_offset..section.file_offset + section.contents;
                image.copy_within(from, section.rva);
            }
        }
        for index in 0..self.sections {
            let section = self.placement(image, index)?;
            image[section.rva + section.contents..section.rva + section.extent].fill(0);
        }
        Ok(())
    }

    /// Apply the mapped image's base relocations for a load `delta` bytes from its base: each
    /// HIGHLOW fixup's dword gets `delta` added (wrapping, as the address arithmetic does).
    /// `image` is the mapped image ([`Image::map_in_place`]).
    pub fn relocate(&self, image: &mut [u8], delta: u32) -> Result<(), Refusal> {
        let ImageDataDirectory {
            virtual_address,
            size,
        } = data_directory(&self.nt, DIRECTORY_BASERELOC).ok_or(Refusal::NotRelocatable)?;
        let (start, end) = (
            virtual_address as usize,
            virtual_address as usize + size as usize,
        );
        if end > image.len() {
            return Err(Refusal::BadRelocation);
        }
        let mut at = start;
        while at < end {
            let block: ImageBaseRelocation =
                Pod::from_bytes(&image[at..end]).ok_or(Refusal::BadRelocation)?;
            let length = block.size_of_block as usize;
            if length < size_of::<ImageBaseRelocation>()
                || !length.is_multiple_of(2)
                || at + length > end
            {
                return Err(Refusal::BadRelocation);
            }
            let page = block.virtual_address as usize;
            for entry in (at + size_of::<ImageBaseRelocation>()..at + length).step_by(2) {
                let entry = u16::from_le_bytes([image[entry], image[entry + 1]]);
                match entry >> 12 {
                    REL_BASED_ABSOLUTE => {}
                    REL_BASED_HIGHLOW => {
                        let site = page + (entry & 0xFFF) as usize;
                        let word = image
                            .get_mut(site..site + 4)
                            .ok_or(Refusal::BadRelocation)?;
                        let value = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
                        word.copy_from_slice(&value.wrapping_add(delta).to_le_bytes());
                    }
                    _ => return Err(Refusal::BadRelocation),
                }
            }
            at += length;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use exportgen::pe::{self, Linked, LinkedSection, LinkedSymbol, SectionKind};

    use super::*;

    const BASE: u32 = 0x8040_0000;

    /// A link of the four sections, its code and data holding absolute addresses of the image at
    /// its fixups, then the image exportgen emits from it (the kernel's own spec: nothing
    /// implemented, an empty export directory).
    fn emitted() -> (Linked, Vec<u8>) {
        let mut text: Vec<u8> = (0..0x1800).map(|i| (i * 7) as u8).collect();
        text[0x10..0x14].copy_from_slice(&(BASE + 0x3000).to_le_bytes());
        text[0x1100..0x1104].copy_from_slice(&(BASE + 0x6008).to_le_bytes());
        let mut data = vec![0x44; 0x1004];
        data[0x20..0x24].copy_from_slice(&(BASE + 0x1000).to_le_bytes());
        let linked = Linked {
            image_base: BASE,
            entry: 0x1000,
            sections: vec![
                LinkedSection {
                    name: ".text".into(),
                    kind: SectionKind::Code,
                    rva: 0x1000,
                    size: 0x1800,
                    data: text,
                },
                LinkedSection {
                    name: ".rdata".into(),
                    kind: SectionKind::ReadOnly,
                    rva: 0x3000,
                    size: 0x10,
                    data: vec![0x52; 0x10],
                },
                LinkedSection {
                    name: ".data".into(),
                    kind: SectionKind::Data,
                    rva: 0x4000,
                    size: 0x1004,
                    data,
                },
                LinkedSection {
                    name: ".bss".into(),
                    kind: SectionKind::Uninitialized,
                    rva: 0x6000,
                    size: 0x2800,
                    data: Vec::new(),
                },
            ],
            fixups: vec![0x1010, 0x2100, 0x4020],
            symbols: vec![LinkedSymbol {
                name: "_start".into(),
                rva: 0x1000,
                size: 4,
                kind: exportgen::elf::STT_FUNC,
            }],
        };
        let spec = exportgen::parse_spec("[[export]]\nname = \"KeBugCheckEx\"\n").unwrap();
        let file = pe::emit(&linked, &spec, "ntoskrnl.exe").unwrap();
        (linked, file)
    }

    /// The image's memory as the Multiboot loader leaves it: the file at its start, garbage past
    /// it (the loader zeroes nothing the loader binary does not ask it to).
    fn loaded(file: &[u8], size: usize) -> Vec<u8> {
        let mut memory = vec![0xCC; size];
        memory[..file.len()].copy_from_slice(file);
        memory
    }

    /// Mapped where it lies, the image holds its headers, each section's contents at its RVA, and
    /// zeros wherever the file carries nothing: .bss, the sections' tails, and where the moved
    /// sections' file contents lay. The export directory and base relocations, which follow .bss,
    /// moved up from the file to their RVAs.
    #[test]
    fn the_file_becomes_the_image_where_it_lies() {
        let (linked, file) = emitted();
        let image = Image::parse(&file).unwrap();
        assert_eq!(image.image_base(), BASE);
        assert_eq!(image.entry(), 0x1000);
        let read = pe::read(&file).unwrap();
        assert_eq!(image.size_of_image(), read.size_of_image as usize);
        let mut memory = loaded(&file, image.size_of_image());
        image.map_in_place(&mut memory, file.len()).unwrap();
        assert_eq!(&memory[..0x1000], &file[..0x1000], "the headers stay");
        for section in &linked.sections {
            let at = section.rva as usize;
            let extent = (section.size as usize).next_multiple_of(0x1000);
            if section.kind == SectionKind::Uninitialized {
                assert!(
                    memory[at..at + extent].iter().all(|&b| b == 0),
                    "{}",
                    section.name
                );
            } else {
                assert_eq!(
                    &memory[at..at + section.data.len()],
                    &section.data[..],
                    "{}",
                    section.name
                );
                assert!(memory[at + section.data.len()..at + extent]
                    .iter()
                    .all(|&b| b == 0));
            }
        }
        for moved in &read.sections[4..] {
            let (rva, offset) = (moved.virtual_address as usize, moved.raw_offset as usize);
            assert!(offset < rva, "{} moves up", moved.name);
            let size = moved.virtual_size as usize;
            assert_eq!(
                &memory[rva..rva + size],
                &file[offset..offset + size],
                "{}",
                moved.name
            );
        }
        // Mapped, the image reads back as its file does: its export directory and relocations
        // where the headers say.
        let mapped = Image::parse(&memory).unwrap();
        assert_eq!(mapped, image);
    }

    /// Relocated by a delta, every fixup's dword is moved by it and nothing else changes; by the
    /// opposite delta, the image is back as it was mapped.
    #[test]
    fn relocation_moves_every_fixup_by_the_delta() {
        let (linked, file) = emitted();
        let image = Image::parse(&file).unwrap();
        let mut memory = loaded(&file, image.size_of_image());
        image.map_in_place(&mut memory, file.len()).unwrap();
        let mapped = memory.clone();
        let delta = 0x0010_0000u32.wrapping_neg(); // a load 1 MiB below the base
        image.relocate(&mut memory, delta).unwrap();
        let word = |memory: &[u8], rva: u32| {
            u32::from_le_bytes(memory[rva as usize..rva as usize + 4].try_into().unwrap())
        };
        for &fixup in &linked.fixups {
            assert_eq!(
                word(&memory, fixup),
                word(&mapped, fixup).wrapping_add(delta)
            );
        }
        assert_eq!(word(&memory, 0x1010), BASE - 0x10_0000 + 0x3000);
        let changed: Vec<usize> = (0..memory.len())
            .filter(|&i| memory[i] != mapped[i])
            .collect();
        assert!(changed.iter().all(|&i| linked
            .fixups
            .iter()
            .any(|&f| (f as usize..f as usize + 4).contains(&i))));
        image.relocate(&mut memory, delta.wrapping_neg()).unwrap();
        assert_eq!(memory, mapped);
    }

    /// What cannot be loaded is refused: not a PE32 image, not a native i386 one, truncated, a
    /// section lying in the file past where it maps, an image larger than its memory, a move
    /// without base relocations.
    #[test]
    fn what_cannot_be_loaded_is_refused() {
        let (linked, file) = emitted();
        let lfanew = u32::from_le_bytes(file[0x3C..0x40].try_into().unwrap()) as usize;
        let mut not_mz = file.clone();
        not_mz[0] = b'N';
        assert_eq!(Image::parse(&not_mz), Err(Refusal::NotPe32));
        let mut not_pe = file.clone();
        not_pe[lfanew] = b'N';
        assert_eq!(Image::parse(&not_pe), Err(Refusal::NotPe32));
        let mut windows = file.clone();
        windows[lfanew + 4 + 20 + 0x44] = 2; // IMAGE_SUBSYSTEM_WINDOWS_GUI
        assert_eq!(Image::parse(&windows), Err(Refusal::NotKernel));
        assert_eq!(Image::parse(&file[..0x800]), Err(Refusal::Truncated));
        assert_eq!(
            Image::parse(&file[..file.len() - 0x1000]),
            Err(Refusal::Truncated)
        );
        // .text's file offset (the first section row's PointerToRawData) past its RVA.
        let row = lfanew + 4 + 20 + 0xE0;
        let mut misplaced = file.clone();
        misplaced[row + 0x14..row + 0x18].copy_from_slice(&0x2000u32.to_le_bytes());
        assert_eq!(Image::parse(&misplaced), Err(Refusal::Misplaced));

        let image = Image::parse(&file).unwrap();
        let mut short = loaded(&file, image.size_of_image() - 0x1000);
        assert_eq!(
            image.map_in_place(&mut short, file.len()),
            Err(Refusal::TooLarge)
        );

        let mut bare = linked.clone();
        bare.fixups.clear();
        let spec = exportgen::parse_spec("").unwrap();
        let stripped = pe::emit(&bare, &spec, "ntoskrnl.exe").unwrap();
        let image = Image::parse(&stripped).unwrap();
        let mut memory = loaded(&stripped, image.size_of_image());
        image.map_in_place(&mut memory, stripped.len()).unwrap();
        assert_eq!(
            image.relocate(&mut memory, 0x1000),
            Err(Refusal::NotRelocatable)
        );
    }
}
