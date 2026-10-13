//! PE32 image parsing and import resolution for the image loader.
//!
//! Pure logic over a byte slice, with no kernel state: [`Image::parse`]
//! validates a PE32 executable's headers and section table,
//! [`Image::map_into`] builds the in-memory image under the eager
//! mapping rule (headers verbatim, then each section's raw bytes,
//! zero-fill to the section extent), and [`Image::snap_imports`]
//! resolves the import directory against a caller-supplied export
//! table, writing thunk addresses into the IAT slots.
//!
//! Failure discipline: questions of identity ("is this an image we
//! load?") come back as [`Reject`]s; malformed bytes that would read
//! past the buffer, and violations of the load contract, panic naming
//! the violated contract. A run-to-completion image must have at least
//! one live import, so a snap that resolves nothing is a contract
//! violation, not a success.

/// The DOS-header magic ("MZ").
const DOS_MAGIC: u16 = 0x5A4D;

/// The NT-header signature ("PE\0\0").
const PE_SIGNATURE: u32 = 0x0000_4550;

/// The only machine type this loader accepts: i386.
const MACHINE_I386: u16 = 0x014C;

/// The only optional-header layout this loader accepts: PE32 (not PE32+).
const OPT_MAGIC_PE32: u16 = 0x010B;

/// The only subsystem this loader accepts: console.
const SUBSYSTEM_CUI: u16 = 3;

/// The fixed mapping base for user images: no relocation machinery
/// exists, so an image must be linked to load exactly here.
pub const IMAGE_BASE: u32 = 0x0040_0000;

/// The largest image this loader will map (the fixed base plus this
/// cap bounds where images can live).
pub const MAX_IMAGE_SIZE: u32 = 0x0100_0000;

/// The section-count cap.
const MAX_SECTIONS: usize = 96;

/// The data-directory array cap (the format's maximum).
const MAX_DIRECTORIES: usize = 16;

/// Data-directory indices the loader consumes.
pub const DIR_IMPORT: usize = 1;
pub const DIR_BASERELOC: usize = 5;
pub const DIR_IAT: usize = 12;

/// The high bit of a thunk marks an import by ordinal, not by name.
const ORDINAL_FLAG: u32 = 0x8000_0000;

/// Section-characteristic bits the loader maps to page protection.
const SCN_EXECUTE: u32 = 0x2000_0000;
const SCN_READ: u32 = 0x4000_0000;
const SCN_WRITE: u32 = 0x8000_0000;

// Header geometry: offsets and sizes within the file image.
const OFF_E_LFANEW: usize = 0x3C;
const SIZE_DOS_HEADER: usize = 0x40;
const SIZE_NT_SIGNATURE: usize = 4;
const SIZE_FILE_HEADER: usize = 20;
const SIZE_SECTION_HEADER: usize = 40;
/// The optional header's standard fields, before the directory array.
const SIZE_OPT_STANDARD: usize = 96;
const SIZE_DIRECTORY_ENTRY: usize = 8;
/// One import descriptor: five dwords, terminated by an all-zero one.
const SIZE_IMPORT_DESCRIPTOR: usize = 20;

/// Why an image is not loadable. Identity questions only: bytes that
/// merely do not describe a loadable PE32 image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// No DOS-header magic.
    NotDos,
    /// No PE signature at the NT-header offset.
    NotPe,
    /// Not an i386 image.
    WrongMachine,
    /// Not a PE32 (32-bit) optional header.
    NotPe32,
    /// More data directories than the format allows.
    TooManyDirectories,
    /// The optional header is too small to hold its directories.
    OptionalHeaderTooSmall,
    /// No sections.
    NoSections,
    /// More sections than the loader accepts.
    TooManySections,
    /// The section table does not fit inside the header region.
    TableOutsideHeaders,
    /// The header region does not fit inside the image.
    HeadersOutsideImage,
    /// The alignment bundle is violated.
    BadAlignment,
    /// SizeOfImage does not match the section layout.
    SizeOfImageMismatch,
    /// Not linked for the fixed mapping base.
    WrongImageBase,
    /// Not a console image.
    WrongSubsystem,
    /// No entry point.
    NoEntryPoint,
    /// The entry point is not inside an executable section.
    EntryNotExecutable,
    /// Sections are not contiguous and ordered.
    SectionDiscontiguous,
    /// A section's raw data reaches past its mapped extent.
    RawBeyondExtent,
    /// A section occupies no address space.
    ZeroExtent,
    /// The image exceeds the loader's size cap.
    ImageTooLarge,
}

/// One data-directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataDirectory {
    pub rva: u32,
    pub size: u32,
}

/// One section-table row, with the zero-raw-size fix applied (a
/// section with no raw data has no meaningful raw offset either).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Section {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_offset: u32,
    pub characteristics: u32,
}

impl Section {
    /// The section name; an 8-byte name has no terminator, by format.
    pub fn name_str(&self) -> &str {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        core::str::from_utf8(&self.name[..len]).unwrap_or_else(|_| {
            panic!("section name is not valid UTF-8");
        })
    }

    /// The size that counts for mapping: the virtual size, or the raw
    /// size when the virtual size is zero.
    fn effective_vsize(&self) -> u32 {
        if self.virtual_size == 0 {
            self.raw_size
        } else {
            self.virtual_size
        }
    }

    /// The section's footprint in the image, rounded up to the section
    /// alignment.
    fn extent(&self, section_alignment: u32) -> u32 {
        round_up(self.effective_vsize().max(self.raw_size), section_alignment)
    }

    /// How many raw bytes the mapping copies for this section: the raw
    /// data, capped at the rounded-up virtual size.
    fn copy_len(&self, section_alignment: u32) -> u32 {
        self.raw_size
            .min(round_up(self.effective_vsize(), section_alignment))
    }

    /// The (read, write, execute) protection this section maps with.
    pub fn protection(&self) -> (bool, bool, bool) {
        (
            self.characteristics & SCN_READ != 0,
            self.characteristics & SCN_WRITE != 0,
            self.characteristics & SCN_EXECUTE != 0,
        )
    }
}

/// A parsed PE32 image: the fields the loader needs, plus the section
/// table. Borrows nothing: everything is copied out at parse time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Image {
    pub entry_rva: u32,
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub subsystem: u16,
    directories: [DataDirectory; MAX_DIRECTORIES],
    num_directories: usize,
    sections: [Section; MAX_SECTIONS],
    num_sections: usize,
}

/// The outcome of an import snap: descriptors walked and IAT slots
/// written.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SnapResult {
    pub descriptors: usize,
    pub thunks: usize,
}

/// Bounds-check a read: `what` at `[off, off + len)` must fit inside
/// `bytes`. Violations are malformed-image bounds, so they panic
/// naming what was being read.
fn need(bytes: &[u8], off: usize, len: usize, what: &str) {
    let end = off.checked_add(len).unwrap_or_else(|| {
        panic!("{what} at 0x{off:x} wraps");
    });
    assert!(
        end <= bytes.len(),
        "{what} at [0x{off:x}, 0x{end:x}) exceeds the buffer size 0x{:x}",
        bytes.len()
    );
}

fn read_u16(bytes: &[u8], off: usize, what: &str) -> u16 {
    need(bytes, off, 2, what);
    u16::from_le_bytes([bytes[off], bytes[off + 1]])
}

fn read_u32(bytes: &[u8], off: usize, what: &str) -> u32 {
    need(bytes, off, 4, what);
    u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

fn write_u32(bytes: &mut [u8], off: usize, value: u32, what: &str) {
    need(bytes, off, 4, what);
    bytes[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

/// A NUL-terminated string at `off`. An unterminated string is
/// malformed bytes, so it panics; so does a non-UTF-8 one.
fn read_cstr<'a>(bytes: &'a [u8], off: usize, what: &str) -> &'a str {
    need(bytes, off, 1, what);
    let end = bytes[off..]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or_else(|| panic!("{what} at 0x{off:x} is not NUL-terminated"));
    core::str::from_utf8(&bytes[off..off + end])
        .unwrap_or_else(|_| panic!("{what} is not valid UTF-8"))
}

/// Round `v` up to a multiple of `align` (which must be nonzero).
fn round_up(v: u32, align: u32) -> u32 {
    let bumped = v
        .checked_add(align - 1)
        .unwrap_or_else(|| panic!("0x{v:x} does not round up to 0x{align:x}"));
    (bumped / align) * align
}

impl Image {
    /// Parse and validate a PE32 executable.
    ///
    /// `Err` means the bytes are not an image this loader accepts;
    /// panics mean the bytes are malformed in a way that would read
    /// past the buffer (each panic names what was being read).
    pub fn parse(file: &[u8]) -> Result<Image, Reject> {
        // DOS header.
        need(file, 0, SIZE_DOS_HEADER, "DOS header");
        if read_u16(file, 0, "DOS magic") != DOS_MAGIC {
            return Err(Reject::NotDos);
        }
        let nt = read_u32(file, OFF_E_LFANEW, "e_lfanew") as usize;
        need(
            file,
            nt,
            SIZE_NT_SIGNATURE + SIZE_FILE_HEADER,
            "NT header",
        );
        if read_u32(file, nt, "PE signature") != PE_SIGNATURE {
            return Err(Reject::NotPe);
        }

        // File header.
        let machine = read_u16(file, nt + 4, "machine");
        let num_sections = read_u16(file, nt + 6, "section count") as usize;
        let size_optional = read_u16(file, nt + 20, "SizeOfOptionalHeader") as usize;
        let opt = nt + SIZE_NT_SIGNATURE + SIZE_FILE_HEADER;

        if machine != MACHINE_I386 {
            return Err(Reject::WrongMachine);
        }

        // Optional header.
        need(file, opt, SIZE_OPT_STANDARD, "optional header");
        let magic = read_u16(file, opt, "optional-header magic");
        if magic != OPT_MAGIC_PE32 {
            return Err(Reject::NotPe32);
        }
        let num_directories =
            read_u32(file, opt + 92, "NumberOfRvaAndSizes") as usize;
        if num_directories > MAX_DIRECTORIES {
            return Err(Reject::TooManyDirectories);
        }
        if SIZE_OPT_STANDARD + num_directories * SIZE_DIRECTORY_ENTRY > size_optional {
            return Err(Reject::OptionalHeaderTooSmall);
        }
        need(file, opt, size_optional, "optional header");

        let entry_rva = read_u32(file, opt + 16, "AddressOfEntryPoint");
        let image_base = read_u32(file, opt + 28, "ImageBase");
        let section_alignment = read_u32(file, opt + 32, "SectionAlignment");
        let file_alignment = read_u32(file, opt + 36, "FileAlignment");
        let size_of_image = read_u32(file, opt + 56, "SizeOfImage");
        let size_of_headers = read_u32(file, opt + 60, "SizeOfHeaders");
        let subsystem = read_u16(file, opt + 68, "Subsystem");

        let mut directories = [DataDirectory { rva: 0, size: 0 }; MAX_DIRECTORIES];
        for i in 0..num_directories {
            let at = opt + SIZE_OPT_STANDARD + i * SIZE_DIRECTORY_ENTRY;
            directories[i] = DataDirectory {
                rva: read_u32(file, at, "data directory"),
                size: read_u32(file, at + 4, "data directory"),
            };
        }

        // Identity contracts.
        if num_sections == 0 {
            return Err(Reject::NoSections);
        }
        if image_base != IMAGE_BASE {
            return Err(Reject::WrongImageBase);
        }
        if subsystem != SUBSYSTEM_CUI {
            return Err(Reject::WrongSubsystem);
        }
        if entry_rva == 0 {
            return Err(Reject::NoEntryPoint);
        }
        if size_of_image > MAX_IMAGE_SIZE {
            return Err(Reject::ImageTooLarge);
        }

        // The alignment bundle.
        if file_alignment == 0 {
            return Err(Reject::BadAlignment);
        }
        if file_alignment % 512 != 0 && file_alignment != section_alignment {
            return Err(Reject::BadAlignment);
        }
        if file_alignment & (file_alignment - 1) != 0 {
            return Err(Reject::BadAlignment);
        }
        if section_alignment < file_alignment {
            return Err(Reject::BadAlignment);
        }

        // Section table: it lives inside the header region, which lives
        // inside the image.
        let table = opt + size_optional;
        need(
            file,
            table,
            num_sections * SIZE_SECTION_HEADER,
            "section table",
        );
        if num_sections > MAX_SECTIONS {
            return Err(Reject::TooManySections);
        }
        let table_end = table + num_sections * SIZE_SECTION_HEADER;
        if table_end > size_of_headers as usize {
            return Err(Reject::TableOutsideHeaders);
        }
        if size_of_headers >= size_of_image {
            return Err(Reject::HeadersOutsideImage);
        }

        // Sections and their mapping plan.
        let mut sections = [Section {
            name: [0; 8],
            virtual_size: 0,
            virtual_address: 0,
            raw_size: 0,
            raw_offset: 0,
            characteristics: 0,
        }; MAX_SECTIONS];
        // The header region ends at the first section; sections must
        // tile the image from there, contiguously and in order.
        let mut running_va = round_up(size_of_headers, section_alignment) as u64;
        for i in 0..num_sections {
            let at = table + i * SIZE_SECTION_HEADER;
            let mut name = [0u8; 8];
            name.copy_from_slice(&file[at..at + 8]);
            let mut section = Section {
                name,
                virtual_size: read_u32(file, at + 8, "section header"),
                virtual_address: read_u32(file, at + 12, "section header"),
                raw_size: read_u32(file, at + 16, "section header"),
                raw_offset: read_u32(file, at + 20, "section header"),
                characteristics: read_u32(file, at + 36, "section header"),
            };
            // A section with no raw data has no meaningful raw offset.
            if section.raw_size == 0 {
                section.raw_offset = 0;
            }
            let name_str = section.name_str();
            // The raw range must not wrap and must exist in the file.
            assert!(
                section.raw_offset.checked_add(section.raw_size).is_some(),
                "section {name_str} raw range 0x{:x}+0x{:x} wraps",
                section.raw_offset,
                section.raw_size
            );
            assert!(
                (section.raw_offset + section.raw_size) as usize <= file.len(),
                "section {name_str} raw data [0x{:x}, 0x{:x}) exceeds the file length 0x{:x}",
                section.raw_offset,
                section.raw_offset + section.raw_size,
                file.len()
            );
            let extent = section.extent(section_alignment);
            if extent == 0 {
                return Err(Reject::ZeroExtent);
            }
            if round_up(section.effective_vsize(), section_alignment) < section.raw_size {
                return Err(Reject::RawBeyondExtent);
            }
            if section.virtual_address as u64 != running_va {
                return Err(Reject::SectionDiscontiguous);
            }
            running_va += extent as u64;
            sections[i] = section;
        }

        // SizeOfImage is the rounded-up end of the last section.
        if size_of_image % section_alignment != 0 {
            return Err(Reject::SizeOfImageMismatch);
        }
        if running_va != size_of_image as u64 {
            return Err(Reject::SizeOfImageMismatch);
        }

        // The entry point must be inside an executable section.
        let entry_covered = (0..num_sections).any(|i| {
            let s = &sections[i];
            entry_rva >= s.virtual_address
                && entry_rva < s.virtual_address + s.extent(section_alignment)
                && s.characteristics & SCN_EXECUTE != 0
        });
        if !entry_covered {
            return Err(Reject::EntryNotExecutable);
        }

        // An image without an import directory is legal: it imports
        // nothing and must end by fault (the fault-containment
        // fixture) — the loader snaps zero imports.
        Ok(Image {
            entry_rva,
            image_base,
            section_alignment,
            file_alignment,
            size_of_image,
            size_of_headers,
            subsystem,
            directories,
            num_directories,
            sections,
            num_sections,
        })
    }

    pub fn section(&self, index: usize) -> &Section {
        &self.sections[index]
    }

    pub fn num_sections(&self) -> usize {
        self.num_sections
    }

    /// The section whose raw data backs `rva`, if any. The bound is the
    /// raw size: file-mode lookups can only find bytes that exist in
    /// the file.
    pub fn section_for_rva(&self, rva: u32) -> Option<usize> {
        (0..self.num_sections).find(|&i| {
            let s = &self.sections[i];
            rva >= s.virtual_address && rva < s.virtual_address + s.raw_size
        })
    }

    /// File-mode RVA to file offset: header-region RVAs resolve
    /// directly, others through the section table.
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        if rva < self.size_of_headers {
            return Some(rva as usize);
        }
        let i = self.section_for_rva(rva)?;
        let s = &self.sections[i];
        Some((rva - s.virtual_address + s.raw_offset) as usize)
    }

    /// A data directory, if the image has it. A directory whose RVA
    /// points outside the image is malformed bytes, not an absent
    /// directory.
    pub fn directory(&self, index: usize) -> Option<(u32, u32)> {
        if index >= self.num_directories {
            return None;
        }
        let d = self.directories[index];
        if d.rva == 0 {
            return None;
        }
        assert!(
            d.rva < self.size_of_image,
            "directory {index} RVA 0x{:x} is outside the image 0x{:x}",
            d.rva,
            self.size_of_image
        );
        Some((d.rva, d.size))
    }

    /// The section's footprint in the image.
    pub fn section_extent(&self, index: usize) -> u32 {
        self.sections[index].extent(self.section_alignment)
    }

    /// How many raw bytes the mapping copies for the section.
    pub fn section_copy_len(&self, index: usize) -> u32 {
        self.sections[index].copy_len(self.section_alignment)
    }

    /// The entry point's virtual address.
    pub fn entry_va(&self) -> u32 {
        self.image_base + self.entry_rva
    }

    /// Build the in-memory image: headers verbatim, then each
    /// section's raw bytes, zero-filled to the section extent.
    /// `out` must be at least `size_of_image` bytes.
    pub fn map_into(&self, file: &[u8], out: &mut [u8]) {
        assert!(
            out.len() >= self.size_of_image as usize,
            "destination 0x{:x} is smaller than the image 0x{:x}",
            out.len(),
            self.size_of_image
        );
        assert!(
            self.size_of_headers as usize <= file.len(),
            "SizeOfHeaders 0x{:x} exceeds the file length 0x{:x}",
            self.size_of_headers,
            file.len()
        );
        let headers = self.size_of_headers as usize;
        out[..headers].copy_from_slice(&file[..headers]);
        for i in 0..self.num_sections {
            let s = &self.sections[i];
            let dst = s.virtual_address as usize;
            let copy_len = s.copy_len(self.section_alignment) as usize;
            if copy_len > 0 {
                need(file, s.raw_offset as usize, copy_len, "section raw data");
                need(out, dst, copy_len, "section mapping");
                out[dst..dst + copy_len]
                    .copy_from_slice(&file[s.raw_offset as usize..s.raw_offset as usize + copy_len]);
            }
            let extent = s.extent(self.section_alignment) as usize;
            if extent > copy_len {
                need(out, dst + copy_len, extent - copy_len, "section mapping");
                out[dst + copy_len..dst + extent].fill(0);
            }
        }
    }

    /// The IAT region: the IAT directory when the linker emitted one,
    /// else the whole raw extent of the section holding the import
    /// directory. Call only when an import directory exists (the
    /// zero-import image never reaches here).
    fn iat_region(&self) -> (u32, u32) {
        if let Some((rva, size)) = self.directory(DIR_IAT) {
            return (rva, size);
        }
        let (import_rva, _) = self
            .directory(DIR_IMPORT)
            .expect("the caller checked for an import directory");
        for i in 0..self.num_sections {
            let s = &self.sections[i];
            if import_rva >= s.virtual_address && import_rva < s.virtual_address + s.raw_size {
                let size = if s.virtual_size == 0 {
                    s.raw_size
                } else {
                    s.virtual_size
                };
                return (s.virtual_address, size);
            }
        }
        panic!("unable to locate the IAT region");
    }

    /// Read one import's name out of the file bytes. The name must
    /// live in file-backed bytes: the zero tail cannot hold names.
    /// The hint is read but never authoritative. Ordinal imports have
    /// no surface on the kernel's name-keyed export table.
    fn import_name<'a>(&self, file: &'a [u8], thunk: u32) -> &'a str {
        if thunk & ORDINAL_FLAG != 0 {
            panic!(
                "ordinal import 0x{:04x} against the kernel export table",
                thunk & 0xFFFF
            );
        }
        assert!(
            thunk < self.size_of_image,
            "import name RVA 0x{thunk:x} is outside the image 0x{:x}",
            self.size_of_image
        );
        let off = self.rva_to_offset(thunk).unwrap_or_else(|| {
            panic!("import name RVA 0x{thunk:x} is not backed by file data");
        });
        need(file, off, 2, "hint/name entry");
        let _hint = read_u16(file, off, "hint/name entry");
        read_cstr(file, off + 2, "import name")
    }

    /// Resolve the import directory against an export table: `dll` is
    /// the only module this kernel synthesizes, and `resolve` maps an
    /// export name to its thunk address. Each IAT slot receives the
    /// resolved address; the original thunk array is left untouched.
    /// Descriptor and thunk reads come from the mapped image (what the
    /// loader actually walks); import names come from the file bytes
    /// (they must be file-backed).
    pub fn snap_imports(
        &self,
        file: &[u8],
        image: &mut [u8],
        dll: &str,
        mut resolve: impl FnMut(&str) -> Option<u32>,
    ) -> SnapResult {
        let Some((import_rva, _)) = self.directory(DIR_IMPORT) else {
            // No import directory: nothing to snap (an importless
            // image must end by fault).
            return SnapResult::default();
        };
        let (iat_base, iat_size) = self.iat_region();
        let mut result = SnapResult::default();
        let mut off = import_rva as usize;
        loop {
            need(image, off, SIZE_IMPORT_DESCRIPTOR, "import descriptor");
            let original_first_thunk = read_u32(image, off, "import descriptor");
            let name_rva = read_u32(image, off + 12, "import descriptor");
            let first_thunk = read_u32(image, off + 16, "import descriptor");
            // The all-zero descriptor ends the array.
            if name_rva == 0 || first_thunk == 0 {
                break;
            }
            result.descriptors += 1;
            let module = read_cstr(image, name_rva as usize, "import module name");
            if !module.eq_ignore_ascii_case(dll) {
                panic!("import module '{module}' is not the kernel export module '{dll}'");
            }
            // An import with no live references is skipped.
            if read_u32(image, first_thunk as usize, "thunk slot") == 0 {
                off += SIZE_IMPORT_DESCRIPTOR;
                continue;
            }
            // A thunk array pointer that does not point inside the
            // image is bogus; the first-thunk array is walked in
            // place instead.
            let lookup = if original_first_thunk < self.size_of_headers
                || original_first_thunk >= self.size_of_image
            {
                first_thunk
            } else {
                original_first_thunk
            };
            let mut lookup_off = lookup as usize;
            let mut slot_off = first_thunk as usize;
            loop {
                let thunk = read_u32(image, lookup_off, "thunk slot");
                // The zero slot ends the array.
                if thunk == 0 {
                    break;
                }
                let name = self.import_name(file, thunk);
                let address = resolve(name)
                    .unwrap_or_else(|| panic!("entry point '{name}' not found in {dll}"));
                need(image, slot_off, 4, "IAT slot");
                write_u32(image, slot_off, address, "IAT slot");
                assert!(
                    slot_off >= iat_base as usize
                        && slot_off + 4 <= iat_base as usize + iat_size as usize,
                    "IAT slot at RVA 0x{slot_off:x} lies outside the IAT region [0x{iat_base:x}, 0x{:x})",
                    iat_base + iat_size
                );
                result.thunks += 1;
                lookup_off += 4;
                slot_off += 4;
            }
            off += SIZE_IMPORT_DESCRIPTOR;
        }
        // A run-to-completion image must resolve at least one import:
        // its exit path.
        assert!(
            result.thunks > 0,
            "image has no live imports (run-to-completion contract)"
        );
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXIT0: &[u8] = include_bytes!("../../tests/exit0/exit0.exe");
    const RET0: &[u8] = include_bytes!("../../tests/ret0/ret0.exe");

    // exit0: NT at 0xb8, optional header at 0xd0, section table at 0x1b0;
    // ret0: NT at 0xc8, optional header at 0xe0, section table at 0x1c0.
    // Import surfaces: exit0 has one import (KERNEL32.dll!ExitProcess,
    // hint/name at 0x2038, IL at 0x2030, IAT at 0x2000, module name at
    // 0x2046); ret0 has 35 (IL at 0x441c, IAT at 0x4000, module name at
    // 0x4708).

    /// The ret0 import order, as the linker emitted it.
    const RET0_IMPORTS: [&str; 35] = [
        "VirtualFree",
        "GetVersion",
        "ExitProcess",
        "TerminateProcess",
        "GetCurrentProcess",
        "UnhandledExceptionFilter",
        "GetModuleFileNameA",
        "FreeEnvironmentStringsA",
        "FreeEnvironmentStringsW",
        "WideCharToMultiByte",
        "GetEnvironmentStrings",
        "GetEnvironmentStringsW",
        "SetHandleCount",
        "GetStdHandle",
        "GetFileType",
        "GetStartupInfoA",
        "HeapDestroy",
        "HeapCreate",
        "GetCommandLineA",
        "HeapFree",
        "RtlUnwind",
        "WriteFile",
        "HeapAlloc",
        "GetCPInfo",
        "GetACP",
        "GetOEMCP",
        "VirtualAlloc",
        "HeapReAlloc",
        "GetProcAddress",
        "LoadLibraryA",
        "MultiByteToWideChar",
        "LCMapStringA",
        "LCMapStringW",
        "GetStringTypeA",
        "GetStringTypeW",
    ];

    fn r16(b: &[u8], off: usize) -> u16 {
        u16::from_le_bytes([b[off], b[off + 1]])
    }

    fn r32(b: &[u8], off: usize) -> u32 {
        u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
    }

    fn w16(b: &mut [u8], off: usize, v: u16) {
        b[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }

    fn w32(b: &mut [u8], off: usize, v: u32) {
        b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn patched(src: &[u8], f: impl FnOnce(&mut [u8])) -> Vec<u8> {
        let mut v = src.to_vec();
        f(&mut v);
        v
    }

    // Header offsets, computed the way the parser computes them.
    fn off_nt(b: &[u8]) -> usize {
        r32(b, 0x3c) as usize
    }
    fn off_opt(b: &[u8]) -> usize {
        off_nt(b) + 24
    }
    fn off_table(b: &[u8]) -> usize {
        off_nt(b) + 4 + 20 + r16(b, off_nt(b) + 20) as usize
    }
    fn off_dir(b: &[u8], i: usize) -> usize {
        off_opt(b) + 96 + 8 * i
    }
    fn off_sec(b: &[u8], i: usize) -> usize {
        off_table(b) + 40 * i
    }

    // Section-header field offsets.
    const S_NAME: usize = 0;
    const S_VSIZE: usize = 8;
    const S_VADDR: usize = 12;
    const S_RAWSIZE: usize = 16;
    const S_RAWOFF: usize = 20;
    const S_CHARS: usize = 36;

    fn parse_ok(file: &[u8]) -> Image {
        Image::parse(file).expect("fixture parses")
    }

    /// Map a fixture (or a mutated copy) and snap its imports against
    /// `table`, recording every name the resolver saw.
    fn snap(
        file: &[u8],
        table: &[(&str, u32)],
    ) -> (Image, Vec<u8>, SnapResult, Vec<String>) {
        let image = parse_ok(file);
        let mut mapped = vec![0u8; image.size_of_image as usize];
        image.map_into(file, &mut mapped);
        let mut seen: Vec<String> = Vec::new();
        let result = image.snap_imports(file, &mut mapped, "KERNEL32.dll", |name: &str| {
            seen.push(name.to_string());
            table.iter().find(|(n, _)| *n == name).map(|(_, a)| *a)
        });
        (image, mapped, result, seen)
    }

    fn snap_default(file: &[u8]) -> (Image, Vec<u8>, SnapResult, Vec<String>) {
        // A full kernel32 stand-in covering both fixtures; the ret0
        // list contains ExitProcess (index 2).
        let table: Vec<(&str, u32)> = RET0_IMPORTS
            .iter()
            .enumerate()
            .map(|(i, n)| (*n, 0x5000_0000 + i as u32))
            .collect();
        snap(file, &table)
    }

    // ---- header identity ----

    #[test]
    fn fixtures_parse_with_expected_headers() {
        let e = parse_ok(EXIT0);
        assert_eq!(e.entry_rva, 0x1000);
        assert_eq!(e.image_base, 0x400000);
        assert_eq!(e.section_alignment, 0x1000);
        assert_eq!(e.file_alignment, 0x1000);
        assert_eq!(e.size_of_image, 0x3000);
        assert_eq!(e.size_of_headers, 0x1000);
        assert_eq!(e.subsystem, 3);
        assert_eq!(e.num_sections(), 2);
        assert_eq!(e.entry_va(), 0x401000);

        let r = parse_ok(RET0);
        assert_eq!(r.entry_rva, 0x1007);
        assert_eq!(r.image_base, 0x400000);
        assert_eq!(r.section_alignment, 0x1000);
        assert_eq!(r.file_alignment, 0x1000);
        assert_eq!(r.size_of_image, 0x6000);
        assert_eq!(r.size_of_headers, 0x1000);
        assert_eq!(r.subsystem, 3);
        assert_eq!(r.num_sections(), 3);
        assert_eq!(r.entry_va(), 0x401007);
    }

    #[test]
    fn dos_magic_rejects() {
        for src in [EXIT0, RET0] {
            let bad = patched(src, |b| b[0] = 0x4e);
            assert_eq!(Image::parse(&bad), Err(Reject::NotDos));
        }
    }

    #[test]
    #[should_panic(expected = "exceeds the buffer size")]
    fn lfanew_straddling_eof_panics() {
        let bad = patched(EXIT0, |b| w32(b, 0x3c, (b.len() - 1) as u32));
        let _ = Image::parse(&bad);
    }

    #[test]
    #[should_panic(expected = "exceeds the buffer size")]
    fn lfanew_wrapping_panics() {
        let bad = patched(EXIT0, |b| w32(b, 0x3c, 0xffff_fff0));
        let _ = Image::parse(&bad);
    }

    #[test]
    fn lfanew_without_signature_rejects() {
        // 0x100 is inside the file but in the DOS stub: the offset is
        // readable, the content is not a PE signature. A clean reject,
        // not a bounds panic.
        let bad = patched(EXIT0, |b| w32(b, 0x3c, 0x100));
        assert_eq!(Image::parse(&bad), Err(Reject::NotPe));
    }

    #[test]
    fn pe_signature_rejects() {
        let bad = patched(EXIT0, |b| b[off_nt(b) + 3] = 1);
        assert_eq!(Image::parse(&bad), Err(Reject::NotPe));
    }

    #[test]
    fn non_i386_machine_rejects() {
        let bad = patched(EXIT0, |b| w16(b, off_nt(b) + 4, 0x8664));
        assert_eq!(Image::parse(&bad), Err(Reject::WrongMachine));
    }

    #[test]
    fn pe32plus_rejects() {
        let bad = patched(EXIT0, |b| w16(b, off_opt(b), 0x20b));
        assert_eq!(Image::parse(&bad), Err(Reject::NotPe32));
    }

    #[test]
    fn section_table_offset_is_honored() {
        // The table follows SizeOfOptionalHeader, not a fixed offset:
        // exit0 0x1b0, ret0 0x1c0, each starting with ".text".
        let e = parse_ok(EXIT0);
        assert_eq!(e.section(0).name_str(), ".text");
        assert_eq!(off_table(EXIT0), 0x1b0);
        let r = parse_ok(RET0);
        assert_eq!(r.section(0).name_str(), ".text");
        assert_eq!(off_table(RET0), 0x1c0);
    }

    #[test]
    fn no_sections_rejects() {
        let bad = patched(EXIT0, |b| w16(b, off_nt(b) + 6, 0));
        assert_eq!(Image::parse(&bad), Err(Reject::NoSections));
    }

    #[test]
    #[should_panic(expected = "exceeds the buffer size")]
    fn section_table_beyond_file_panics() {
        let bad = patched(EXIT0, |b| w16(b, off_nt(b) + 6, 0x200));
        let _ = Image::parse(&bad);
    }

    #[test]
    fn section_table_outside_headers_rejects() {
        // 96 sections still fit the file, but not the header region.
        let bad = patched(EXIT0, |b| w16(b, off_nt(b) + 6, 96));
        assert_eq!(Image::parse(&bad), Err(Reject::TableOutsideHeaders));
    }

    #[test]
    fn optional_header_too_small_rejects() {
        // 0xd8 cannot hold the standard fields plus 16 directories.
        let bad = patched(EXIT0, |b| w16(b, off_nt(b) + 20, 0xd8));
        assert_eq!(Image::parse(&bad), Err(Reject::OptionalHeaderTooSmall));
    }

    // ---- optional-header contracts ----

    #[test]
    fn zero_entry_point_rejects() {
        let bad = patched(EXIT0, |b| w32(b, off_opt(b) + 16, 0));
        assert_eq!(Image::parse(&bad), Err(Reject::NoEntryPoint));
    }

    #[test]
    fn entry_point_outside_image_rejects() {
        let bad = patched(EXIT0, |b| w32(b, off_opt(b) + 16, 0x3000));
        assert_eq!(Image::parse(&bad), Err(Reject::EntryNotExecutable));
    }

    #[test]
    fn foreign_image_base_rejects() {
        let bad = patched(EXIT0, |b| w32(b, off_opt(b) + 28, 0x500000));
        assert_eq!(Image::parse(&bad), Err(Reject::WrongImageBase));
    }

    #[test]
    fn bad_alignment_bundle_rejects() {
        let not_pow2 = patched(EXIT0, |b| w32(b, off_opt(b) + 36, 0x801));
        assert_eq!(Image::parse(&not_pow2), Err(Reject::BadAlignment));
        let zero = patched(EXIT0, |b| w32(b, off_opt(b) + 36, 0));
        assert_eq!(Image::parse(&zero), Err(Reject::BadAlignment));
        let small = patched(EXIT0, |b| w32(b, off_opt(b) + 32, 0x200));
        assert_eq!(Image::parse(&small), Err(Reject::BadAlignment));
    }

    #[test]
    fn size_of_image_mismatch_rejects() {
        let shrunk = patched(EXIT0, |b| w32(b, off_opt(b) + 56, 0x2000));
        assert_eq!(Image::parse(&shrunk), Err(Reject::SizeOfImageMismatch));
        let unaligned = patched(EXIT0, |b| w32(b, off_opt(b) + 56, 0x3001));
        assert_eq!(Image::parse(&unaligned), Err(Reject::SizeOfImageMismatch));
    }

    #[test]
    fn headers_region_contract_rejects() {
        let small = patched(EXIT0, |b| w32(b, off_opt(b) + 60, 0x100));
        assert_eq!(Image::parse(&small), Err(Reject::TableOutsideHeaders));
        let huge = patched(EXIT0, |b| w32(b, off_opt(b) + 60, 0x3000));
        assert_eq!(Image::parse(&huge), Err(Reject::HeadersOutsideImage));
    }

    #[test]
    fn non_console_subsystem_rejects() {
        let bad = patched(EXIT0, |b| w16(b, off_opt(b) + 68, 5));
        assert_eq!(Image::parse(&bad), Err(Reject::WrongSubsystem));
    }

    // ---- section table and mapping plan ----

    #[test]
    fn section_fields_parse() {
        let e = parse_ok(EXIT0);
        let text = e.section(0);
        assert_eq!(text.name_str(), ".text");
        assert_eq!(text.virtual_size, 0xd);
        assert_eq!(text.virtual_address, 0x1000);
        assert_eq!(text.raw_size, 0x1000);
        assert_eq!(text.raw_offset, 0x1000);
        assert_eq!(text.characteristics, 0x6000_0020);
        let rdata = e.section(1);
        assert_eq!(rdata.name_str(), ".rdata");
        assert_eq!(rdata.virtual_size, 0x54);
        assert_eq!(rdata.virtual_address, 0x2000);
        assert_eq!(rdata.raw_size, 0x1000);
        assert_eq!(rdata.raw_offset, 0x2000);
        assert_eq!(rdata.characteristics, 0x4000_0040);

        let r = parse_ok(RET0);
        let text = r.section(0);
        assert_eq!(text.name_str(), ".text");
        assert_eq!(text.virtual_size, 0x27ce);
        assert_eq!(text.virtual_address, 0x1000);
        assert_eq!(text.raw_size, 0x3000);
        assert_eq!(text.raw_offset, 0x1000);
        assert_eq!(text.characteristics, 0x6000_0020);
        let rdata = r.section(1);
        assert_eq!(rdata.name_str(), ".rdata");
        assert_eq!(rdata.virtual_size, 0x716);
        assert_eq!(rdata.virtual_address, 0x4000);
        assert_eq!(rdata.raw_size, 0x1000);
        assert_eq!(rdata.raw_offset, 0x4000);
        assert_eq!(rdata.characteristics, 0x4000_0040);
        let data = r.section(2);
        assert_eq!(data.name_str(), ".data");
        assert_eq!(data.virtual_size, 0x79c);
        assert_eq!(data.virtual_address, 0x5000);
        assert_eq!(data.raw_size, 0x1000);
        assert_eq!(data.raw_offset, 0x5000);
        assert_eq!(data.characteristics, 0xc000_0040);
    }

    #[test]
    fn eight_byte_section_name_has_no_terminator() {
        let bad = patched(EXIT0, |b| {
            let at = off_sec(b, 0) + S_NAME;
            b[at..at + 8].copy_from_slice(b"longtext");
        });
        let image = parse_ok(&bad);
        assert_eq!(image.section(0).name_str(), "longtext");
    }

    #[test]
    fn section_extents_and_copy_lengths() {
        let e = parse_ok(EXIT0);
        assert_eq!(e.section_extent(0), 0x1000);
        assert_eq!(e.section_copy_len(0), 0x1000);
        assert_eq!(e.section_extent(1), 0x1000);
        assert_eq!(e.section_copy_len(1), 0x1000);

        let r = parse_ok(RET0);
        assert_eq!(r.section_extent(0), 0x3000);
        assert_eq!(r.section_copy_len(0), 0x3000);
        assert_eq!(r.section_extent(1), 0x1000);
        assert_eq!(r.section_copy_len(1), 0x1000);
        assert_eq!(r.section_extent(2), 0x1000);
        assert_eq!(r.section_copy_len(2), 0x1000);
    }

    #[test]
    fn zero_only_section_maps_zeroes() {
        // .rdata loses its raw data: the mapping plan shows a full
        // zero extent. The import surface then has no file-backed
        // bytes, which the snap enforces.
        let bad = patched(EXIT0, |b| w32(b, off_sec(b, 1) + S_RAWSIZE, 0));
        let image = parse_ok(&bad);
        assert_eq!(image.section_copy_len(1), 0);
        assert_eq!(image.section_extent(1), 0x1000);
        let mut mapped = vec![0u8; image.size_of_image as usize];
        image.map_into(&bad, &mut mapped);
        assert!(mapped[0x2000..0x3000].iter().all(|&b| b == 0));
    }

    #[test]
    fn tail_bytes_between_vsize_and_raw_come_from_the_file() {
        let e = parse_ok(EXIT0);
        let mut mapped = vec![0u8; e.size_of_image as usize];
        e.map_into(EXIT0, &mut mapped);
        // .text holds 0xd live bytes; the rest of the page is the
        // file's own padding, mapped as-is.
        assert_eq!(&mapped[0x1000..0x100d], &EXIT0[0x1000..0x100d]);
        assert_eq!(&mapped[0x100d..0x2000], &EXIT0[0x100d..0x2000]);
    }

    #[test]
    fn zero_tail_when_vsize_exceeds_raw() {
        let bad = patched(EXIT0, |b| {
            w32(b, off_sec(b, 1) + S_VSIZE, 0x2000);
            w32(b, off_opt(b) + 56, 0x4000);
        });
        let image = parse_ok(&bad);
        assert_eq!(image.section_extent(1), 0x2000);
        assert_eq!(image.section_copy_len(1), 0x1000);
        let mut mapped = vec![0u8; image.size_of_image as usize];
        image.map_into(&bad, &mut mapped);
        assert_eq!(&mapped[0x2000..0x3000], &EXIT0[0x2000..0x3000]);
        assert!(mapped[0x3000..0x4000].iter().all(|&b| b == 0));
    }

    #[test]
    fn zero_vsize_maps_the_raw_size() {
        let bad = patched(EXIT0, |b| w32(b, off_sec(b, 0) + S_VSIZE, 0));
        let image = parse_ok(&bad);
        assert_eq!(image.section_extent(0), 0x1000);
        assert_eq!(image.section_copy_len(0), 0x1000);
    }

    #[test]
    fn section_order_swap_rejects() {
        let bad = patched(EXIT0, |b| {
            w32(b, off_sec(b, 0) + S_VADDR, 0x2000);
            w32(b, off_sec(b, 1) + S_VADDR, 0x1000);
        });
        assert_eq!(Image::parse(&bad), Err(Reject::SectionDiscontiguous));
    }

    #[test]
    fn headers_map_verbatim() {
        for src in [EXIT0, RET0] {
            let image = parse_ok(src);
            let mut mapped = vec![0u8; image.size_of_image as usize];
            image.map_into(src, &mut mapped);
            assert_eq!(&mapped[..0x1000], &src[..0x1000]);
        }
    }

    #[test]
    #[should_panic(expected = "wraps")]
    fn raw_range_wrap_panics() {
        let bad = patched(EXIT0, |b| {
            w32(b, off_sec(b, 0) + S_RAWOFF, 0xffff_f000);
        });
        let _ = Image::parse(&bad);
    }

    #[test]
    #[should_panic(expected = "exceeds the file length")]
    fn raw_data_past_eof_panics() {
        let bad = patched(EXIT0, |b| w32(b, off_sec(b, 1) + S_RAWSIZE, 0x2000));
        let _ = Image::parse(&bad);
    }

    #[test]
    fn raw_data_beyond_extent_rejects() {
        let bad = patched(RET0, |b| w32(b, off_sec(b, 0) + S_VSIZE, 0x2000));
        assert_eq!(Image::parse(&bad), Err(Reject::RawBeyondExtent));
    }

    #[test]
    fn protections_follow_characteristics() {
        let e = parse_ok(EXIT0);
        assert_eq!(e.section(0).protection(), (true, false, true));
        assert_eq!(e.section(1).protection(), (true, false, false));
        let r = parse_ok(RET0);
        assert_eq!(r.section(2).protection(), (true, true, false));
    }

    #[test]
    fn discardable_bit_does_not_change_the_plan() {
        let bad = patched(EXIT0, |b| {
            let chars = r32(b, off_sec(b, 0) + S_CHARS);
            w32(b, off_sec(b, 0) + S_CHARS, chars | 0x0200_0000);
        });
        let image = parse_ok(&bad);
        assert_eq!(image.section_copy_len(0), 0x1000);
    }

    // ---- RVA mapping ----

    #[test]
    fn section_lookup_by_rva() {
        let e = parse_ok(EXIT0);
        assert_eq!(e.section_for_rva(0x1000), Some(0));
        assert_eq!(e.section_for_rva(0x2008), Some(1));
        assert_eq!(e.section_for_rva(0x2030), Some(1));
        assert_eq!(e.section_for_rva(0x2fff), Some(1));
        assert_eq!(e.section_for_rva(0x3000), None);

        let r = parse_ok(RET0);
        assert_eq!(r.section_for_rva(0x1007), Some(0));
        assert_eq!(r.section_for_rva(0x43f4), Some(1));
        assert_eq!(r.section_for_rva(0x441c), Some(1));
        assert_eq!(r.section_for_rva(0x4000), Some(1));
        assert_eq!(r.section_for_rva(0x5000), Some(2));
        assert_eq!(r.section_for_rva(0x6000), None);
        assert_eq!(r.section_for_rva(0x5fff), Some(2));
    }

    #[test]
    fn header_region_rvas_resolve_directly() {
        let e = parse_ok(EXIT0);
        assert_eq!(e.rva_to_offset(0x100), Some(0x100));
        // 0xfff is below the first section: no section backs it, but
        // the header region resolves it directly.
        assert_eq!(e.section_for_rva(0xfff), None);
        assert_eq!(e.rva_to_offset(0xfff), Some(0xfff));
    }

    #[test]
    fn section_rvas_resolve_through_the_table() {
        let e = parse_ok(EXIT0);
        assert_eq!(e.rva_to_offset(0x2008), Some(0x2008));
        assert_eq!(e.rva_to_offset(0x2038), Some(0x2038));
        let r = parse_ok(RET0);
        assert_eq!(r.rva_to_offset(0x441c), Some(0x441c));
        assert_eq!(r.rva_to_offset(0x4708), Some(0x4708));
    }

    #[test]
    fn raw_tail_rva_resolves_file_mode() {
        // 0x100d is past .text's virtual size but inside its raw
        // data: the file-mode bound is the raw size.
        let e = parse_ok(EXIT0);
        assert_eq!(e.rva_to_offset(0x100d), Some(0x100d));
    }

    #[test]
    fn zero_tail_rva_has_no_file_backing() {
        let bad = patched(EXIT0, |b| {
            w32(b, off_sec(b, 1) + S_VSIZE, 0x2000);
            w32(b, off_opt(b) + 56, 0x4000);
        });
        let image = parse_ok(&bad);
        // 0x3000 is inside the section extent but past the raw data:
        // valid zero memory in the image, no file backing.
        assert_eq!(image.section_for_rva(0x3000), None);
        assert_eq!(image.rva_to_offset(0x3000), None);
        let mut mapped = vec![0u8; image.size_of_image as usize];
        image.map_into(&bad, &mut mapped);
        assert!(mapped[0x3000..0x4000].iter().all(|&b| b == 0));
    }

    // ---- data directories ----

    #[test]
    fn directories_parse() {
        let e = parse_ok(EXIT0);
        assert_eq!(e.directory(DIR_IMPORT), Some((0x2008, 0x28)));
        assert_eq!(e.directory(DIR_IAT), Some((0x2000, 8)));
        assert_eq!(e.directory(DIR_BASERELOC), None);
        let r = parse_ok(RET0);
        assert_eq!(r.directory(DIR_IMPORT), Some((0x43f4, 0x28)));
        assert_eq!(r.directory(DIR_IAT), Some((0x4000, 0x90)));
        assert_eq!(r.directory(DIR_BASERELOC), None);
    }

    #[test]
    fn fixtures_have_no_reloc_section() {
        for src in [EXIT0, RET0] {
            let image = parse_ok(src);
            for i in 0..image.num_sections() {
                assert_ne!(image.section(i).name_str(), ".reloc");
            }
        }
    }

    #[test]
    fn directory_count_bounds_lookups() {
        // Twelve directories: the IAT slot (index 12) reads as absent
        // even though its bytes are still in the file.
        let bad = patched(EXIT0, |b| w32(b, off_opt(b) + 92, 12));
        let image = parse_ok(&bad);
        assert_eq!(image.directory(DIR_IAT), None);
        assert_eq!(image.directory(DIR_IMPORT), Some((0x2008, 0x28)));
    }

    #[test]
    fn absent_import_directory_snaps_zero_imports() {
        let bad = patched(EXIT0, |b| w32(b, off_dir(b, DIR_IMPORT), 0));
        let image = parse_ok(&bad);
        let mut mapped = vec![0u8; image.size_of_image as usize];
        image.map_into(&bad, &mut mapped);
        // Nothing to snap: the image imports nothing and must end by
        // fault.
        assert_eq!(
            image.snap_imports(&bad, &mut mapped, "KERNEL32.dll", |_| None),
            SnapResult::default()
        );
    }

    #[test]
    #[should_panic(expected = "outside the image")]
    fn import_directory_outside_image_panics() {
        let bad = patched(EXIT0, |b| w32(b, off_dir(b, DIR_IMPORT), 0x5000));
        let image = parse_ok(&bad);
        let _ = image.directory(DIR_IMPORT);
    }

    #[test]
    fn header_region_directory_resolves_directly() {
        let bad = patched(EXIT0, |b| w32(b, off_dir(b, DIR_IMPORT), 0x200));
        let image = parse_ok(&bad);
        assert_eq!(image.directory(DIR_IMPORT), Some((0x200, 0x28)));
        assert_eq!(image.rva_to_offset(0x200), Some(0x200));
    }

    #[test]
    fn unconsumed_directories_are_enumerated_but_not_interpreted() {
        let bad = patched(EXIT0, |b| {
            w32(b, off_dir(b, 10), 0x2100);
            w32(b, off_dir(b, 10) + 4, 0x40);
        });
        let image = parse_ok(&bad);
        assert_eq!(image.directory(10), Some((0x2100, 0x40)));
    }

    // ---- import walk and IAT snap ----

    #[test]
    fn exit0_snaps_its_single_import() {
        let (image, mapped, result, seen) = snap_default(EXIT0);
        assert_eq!(result.descriptors, 1);
        assert_eq!(result.thunks, 1);
        assert_eq!(seen, vec!["ExitProcess"]);
        // ExitProcess sits at index 2 of the stand-in table.
        assert_eq!(r32(&mapped, 0x2000), 0x5000_0002);
        // The terminator slot stays zero.
        assert_eq!(r32(&mapped, 0x2004), 0);
        assert_eq!(image.directory(DIR_IAT), Some((0x2000, 8)));
    }

    #[test]
    fn ret0_snaps_its_crt_startup_surface() {
        let (image, mapped, result, seen) = snap_default(RET0);
        assert_eq!(result.descriptors, 1);
        assert_eq!(result.thunks, 35);
        assert_eq!(seen.len(), 35);
        for (i, name) in RET0_IMPORTS.iter().enumerate() {
            assert_eq!(seen[i], *name);
            assert_eq!(r32(&mapped, 0x4000 + 4 * i), 0x5000_0000 + i as u32);
        }
        // The terminator slot stays zero.
        assert_eq!(r32(&mapped, 0x4000 + 4 * 35), 0);
        assert_eq!(image.directory(DIR_IAT), Some((0x4000, 0x90)));
    }

    #[test]
    fn lookup_array_is_preserved_by_the_snap() {
        for (src, il_rva, count) in [(EXIT0, 0x2030usize, 1usize), (RET0, 0x441c, 35)] {
            let (_, mapped, _, _) = snap_default(src);
            for i in 0..=count {
                let original = r32(src, il_rva + 4 * i);
                assert_eq!(r32(&mapped, il_rva + 4 * i), original);
            }
        }
    }

    #[test]
    fn iat_holds_lookup_values_before_the_snap() {
        let image = parse_ok(EXIT0);
        let mut mapped = vec![0u8; image.size_of_image as usize];
        image.map_into(EXIT0, &mut mapped);
        assert_eq!(r32(&mapped, 0x2000), 0x2038);
        assert_eq!(r32(&mapped, 0x2030), 0x2038);
    }

    #[test]
    fn bogus_lookup_pointer_falls_back_to_the_iat() {
        for oft in [0u32, 0x3000] {
            let bad = patched(EXIT0, |b| w32(b, 0x2008, oft));
            let (_, _, result, seen) =
                snap(&bad, &[("ExitProcess", 0x5000_1000)]);
            assert_eq!(result.thunks, 1);
            assert_eq!(seen, vec!["ExitProcess"]);
        }
    }

    #[test]
    #[should_panic(expected = "outside the image")]
    fn terminator_slot_is_not_assumed() {
        // The walk stops at the zero slot, not at a count: a nonzero
        // value where the terminator should be is walked as an import
        // and fails on the bogus name.
        let bad = patched(EXIT0, |b| w32(b, 0x2034, 0x0000_beef));
        let _ = snap_default(&bad);
    }

    #[test]
    #[should_panic(expected = "ordinal import 0x2038")]
    fn ordinal_import_panics() {
        let bad = patched(EXIT0, |b| w32(b, 0x2030, 0x8000_2038));
        let _ = snap_default(&bad);
    }

    #[test]
    #[should_panic(expected = "no live imports")]
    fn import_with_no_references_has_no_live_thunks() {
        let bad = patched(EXIT0, |b| w32(b, 0x2000, 0));
        let _ = snap_default(&bad);
    }

    #[test]
    #[should_panic(expected = "no live imports")]
    fn lookup_pointer_into_padding_yields_no_imports() {
        let bad = patched(EXIT0, |b| w32(b, 0x2008, 0x2ff0));
        let _ = snap_default(&bad);
    }

    #[test]
    #[should_panic(expected = "exceeds the buffer size")]
    fn lookup_pointer_at_image_end_panics() {
        let bad = patched(EXIT0, |b| w32(b, 0x2008, 0x2ffd));
        let _ = snap_default(&bad);
    }

    #[test]
    #[should_panic(expected = "exceeds the buffer size")]
    fn module_name_outside_image_panics() {
        let bad = patched(EXIT0, |b| w32(b, 0x2008 + 12, 0x5000));
        let _ = snap_default(&bad);
    }

    #[test]
    #[should_panic(expected = "not NUL-terminated")]
    fn unterminated_module_name_panics() {
        // Point the module name at a tail with no NUL before the image
        // ends.
        let bad = patched(EXIT0, |b| {
            w32(b, 0x2008 + 12, 0x2ff8);
            b[0x2ff8..0x3000].fill(0xaa);
        });
        let _ = snap_default(&bad);
    }

    #[test]
    #[should_panic(expected = "exceeds the buffer size")]
    fn descriptor_at_image_end_panics() {
        let bad = patched(EXIT0, |b| w32(b, off_dir(b, DIR_IMPORT), 0x2ff8));
        let _ = snap_default(&bad);
    }

    #[test]
    fn hint_is_never_authoritative() {
        let wrong_hint = patched(EXIT0, |b| w16(b, 0x2038, 1));
        let (_, _, result, _) = snap(&wrong_hint, &[("ExitProcess", 0x5000_1000)]);
        assert_eq!(result.thunks, 1);
    }

    #[test]
    #[should_panic(expected = "not found in KERNEL32.dll")]
    fn renamed_export_misses() {
        let renamed = patched(EXIT0, |b| {
            b[0x203a..0x203a + 4].copy_from_slice(b"XitP");
        });
        let _ = snap_default(&renamed);
    }

    #[test]
    #[should_panic(expected = "not found in KERNEL32.dll")]
    fn missing_export_panics() {
        let _ = snap(EXIT0, &[("SomethingElse", 1)]);
    }

    #[test]
    #[should_panic(expected = "is not the kernel export module")]
    fn foreign_module_panics() {
        let bad = patched(EXIT0, |b| {
            b[0x2046..0x2046 + 10].copy_from_slice(b"USER32.dll");
        });
        let _ = snap_default(&bad);
    }

    #[test]
    #[should_panic(expected = "outside the image")]
    fn import_name_outside_image_panics() {
        let bad = patched(EXIT0, |b| w32(b, 0x2030, 0x9000));
        let _ = snap_default(&bad);
    }

    #[test]
    #[should_panic(expected = "not backed by file data")]
    fn import_name_in_the_zero_tail_panics() {
        let bad = patched(EXIT0, |b| {
            w32(b, off_sec(b, 1) + S_VSIZE, 0x2000);
            w32(b, off_opt(b) + 56, 0x4000);
            w32(b, 0x2030, 0x3000);
        });
        let _ = snap_default(&bad);
    }

    // ---- malformed files ----

    #[test]
    #[should_panic(expected = "exceeds the file length")]
    fn file_cut_to_headers_panics() {
        let _ = Image::parse(&EXIT0[..0x1000]);
    }

    #[test]
    #[should_panic(expected = "exceeds the buffer size")]
    fn file_cut_to_dos_header_panics() {
        let _ = Image::parse(&EXIT0[..0x40]);
    }

    #[test]
    #[should_panic(expected = "exceeds the file length")]
    fn file_missing_last_raw_byte_panics() {
        let _ = Image::parse(&EXIT0[..EXIT0.len() - 1]);
    }

    #[test]
    fn cross_field_contract_holds_on_fixtures() {
        for src in [EXIT0, RET0] {
            let (image, _, result, _) = snap_default(src);
            // The IAT directory covers every slot the walk writes,
            // terminator included.
            let (iat_rva, iat_size) = image.directory(DIR_IAT).unwrap();
            let ft = r32(src, image.directory(DIR_IMPORT).unwrap().0 as usize + 16);
            assert!(ft >= iat_rva);
            assert!(ft + (result.thunks as u32 + 1) * 4 <= iat_rva + iat_size);
            // The entry point lies inside the executable section.
            assert_eq!(image.section(0).name_str(), ".text");
            assert!(image.entry_rva >= image.section(0).virtual_address);
            assert!(image.entry_rva < image.section(0).virtual_address + image.section_extent(0));
        }
    }
}
