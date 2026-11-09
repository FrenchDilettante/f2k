//! The kernel's image, `ntoskrnl.exe`: a PE32 image emitted from the kernel's ELF link, as the
//! Microsoft PE/COFF specification lays one out.
//!
//! The link ([`Linked::from_elf`]) lays the kernel out the way the image maps it: its headers'
//! page at the image base, then `.text`, `.rdata`, `.data` and `.bss`, each page-aligned and
//! adjacent, so their RVAs are final when the linker is done. What only the finished link can
//! give comes after them, as the two sections the specification names for it: `.edata`, the
//! export directory, generated from the kernel's spec (each implemented export's name and its
//! ordinal to its `f2k_export_<body>` symbol's RVA), and `.reloc`, the base relocations, one
//! `IMAGE_REL_BASED_HIGHLOW` per absolute address the link wrote into the image (from the
//! relocations `--emit-relocs` keeps). The image imports nothing.
//!
//! The section and file alignments are both a page, so the headers and the initialized sections
//! lie in the file where they lie in the image; only `.edata` and `.reloc`, which follow `.bss`
//! in the image, sit lower in the file than in memory. The checksum is the image checksum Windows
//! computes (CheckSumMappedFile's): the file's 16-bit words summed with their carries folded
//! back, the checksum field counted as zero, plus the file's length.
//!
//! [`read`] reads an image back; [`check`] holds an emitted image to what it was emitted from.

use std::collections::HashMap;

use crate::elf::{self, Elf};
use crate::{Implementation, Spec};

/// The headers' size, and both alignments: a page.
pub const ALIGNMENT: u32 = 0x1000;
/// IMAGE_FILE_MACHINE_I386.
pub const MACHINE_I386: u16 = 0x014C;
/// The optional header's magic: PE32.
pub const PE32_MAGIC: u16 = 0x010B;
/// IMAGE_SUBSYSTEM_NATIVE: a kernel-mode image, no Win32 subsystem.
pub const SUBSYSTEM_NATIVE: u16 = 1;
/// The file header's characteristics: IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE
/// (relocations kept: the image may be rebased).
pub const CHARACTERISTICS: u16 = 0x0002 | 0x0100;
/// IMAGE_FILE_RELOCS_STRIPPED: an image without base relocations, which loads only at its base.
pub const RELOCS_STRIPPED: u16 = 0x0001;
/// The section characteristics: code, initialized data, uninitialized data; discardable;
/// executable, readable, writable.
pub const SCN_CNT_CODE: u32 = 0x0000_0020;
pub const SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
pub const SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
pub const SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
pub const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const SCN_MEM_READ: u32 = 0x4000_0000;
pub const SCN_MEM_WRITE: u32 = 0x8000_0000;
/// The data directories the image fills: the export table, the base relocation table.
pub const DIRECTORY_EXPORT: usize = 0;
pub const DIRECTORY_BASERELOC: usize = 5;
const DIRECTORIES: usize = 16;
/// A base relocation's type: IMAGE_REL_BASED_ABSOLUTE (padding), IMAGE_REL_BASED_HIGHLOW (the
/// delta added to the dword at the offset).
pub const REL_BASED_ABSOLUTE: u16 = 0;
pub const REL_BASED_HIGHLOW: u16 = 3;
/// The prefix a spec's native body carries as a symbol of the kernel.
pub const EXPORT_PREFIX: &str = "f2k_export_";

/// IMAGE_DOS_HEADER's size, IMAGE_FILE_HEADER's, IMAGE_OPTIONAL_HEADER32's,
/// IMAGE_EXPORT_DIRECTORY's.
const DOS_HEADER_SIZE: usize = 0x40;
const FILE_HEADER_SIZE: usize = 0x14;
const OPTIONAL_HEADER_SIZE: usize = 0xE0;
const EXPORT_DIRECTORY_SIZE: usize = 0x28;
/// The checksum's offset in the optional header.
const CHECKSUM_FIELD: usize = 0x40;

/// The DOS stub's program, run from the paragraph after the 64-byte header: print the message
/// that follows it (`push cs; pop ds; mov dx, 14; mov ah, 9; int 21h`), then exit with code 1
/// (`mov ax, 4C01h; int 21h`).
const DOS_PROGRAM: [u8; 14] = [
    0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21,
];
const DOS_MESSAGE: &[u8] = b"This image is the F2K kernel: it does not run under DOS.\r\n$";

fn align_up(value: u32, alignment: u32) -> u32 {
    value.next_multiple_of(alignment)
}

/// What a linked section holds, as its PE section is marked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectionKind {
    /// Code: executable, readable (`.text`).
    Code,
    /// Constant data: readable (`.rdata`).
    ReadOnly,
    /// Initialized data: readable, writable (`.data`).
    Data,
    /// Zero-filled data, without file contents: readable, writable (`.bss`).
    Uninitialized,
}

impl SectionKind {
    /// Its section characteristics.
    pub fn characteristics(self) -> u32 {
        match self {
            SectionKind::Code => SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ,
            SectionKind::ReadOnly => SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ,
            SectionKind::Data => SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ | SCN_MEM_WRITE,
            SectionKind::Uninitialized => SCN_CNT_UNINITIALIZED_DATA | SCN_MEM_READ | SCN_MEM_WRITE,
        }
    }
}

/// The sections the link lays out, in their order, by their names (the ELF's output sections and
/// the image's alike).
pub const LINKED_SECTIONS: [(&str, SectionKind); 4] = [
    (".text", SectionKind::Code),
    (".rdata", SectionKind::ReadOnly),
    (".data", SectionKind::Data),
    (".bss", SectionKind::Uninitialized),
];

/// One of the link's sections, as the image carries it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkedSection {
    pub name: String,
    pub kind: SectionKind,
    pub rva: u32,
    /// Its size in memory.
    pub size: u32,
    /// Its contents (`size` bytes; none for an uninitialized section).
    pub data: Vec<u8>,
}

/// One symbol the link defines in the image: a function, a data object, or a plain label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkedSymbol {
    pub name: String,
    pub rva: u32,
    pub size: u32,
    /// Its ELF type ([`elf::STT_FUNC`], [`elf::STT_OBJECT`], or another).
    pub kind: u8,
}

/// The kernel's link, as the image is made of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Linked {
    /// The address the image is linked at (the link's `__ImageBase`).
    pub image_base: u32,
    /// The entry point's RVA.
    pub entry: u32,
    /// The [`LINKED_SECTIONS`], in order.
    pub sections: Vec<LinkedSection>,
    /// Where the link wrote an absolute address of the image: each dword's RVA, ascending.
    pub fixups: Vec<u32>,
    /// The symbols the link defines in the image.
    pub symbols: Vec<LinkedSymbol>,
}

impl Linked {
    /// The link as the ELF `elf` holds it: its four sections where the image maps them (the first
    /// a page past `__ImageBase`, each page-aligned right after the previous one), its entry, its
    /// symbols, and the fixups its `R_386_32` relocations call for. A relocation against a symbol
    /// of the image moves with it; one against an absolute symbol whose value lies outside the
    /// image needs nothing; the other cases cannot be rebased and are refused, as is any other
    /// relocation type.
    pub fn from_elf(elf: &Elf) -> Result<Linked, String> {
        let image_base = elf
            .symbol("__ImageBase")
            .ok_or("the link defines no __ImageBase")?
            .value;
        let allocated: Vec<&elf::Section> = elf
            .sections
            .iter()
            .filter(|s| s.allocated() && s.size > 0)
            .collect();
        let names: Vec<&str> = allocated.iter().map(|s| s.name.as_str()).collect();
        let expected: Vec<&str> = LINKED_SECTIONS.iter().map(|(name, _)| *name).collect();
        if names != expected {
            return Err(format!(
                "the link's allocated sections are {names:?}, not {expected:?}"
            ));
        }
        let mut sections = Vec::new();
        let mut next = image_base
            .checked_add(ALIGNMENT)
            .ok_or("__ImageBase too high")?;
        for (section, (name, kind)) in allocated.iter().zip(LINKED_SECTIONS) {
            if section.address != next {
                return Err(format!(
                    "{name} is linked at {:#x}, not {next:#x} (a page past the image base, or \
                     page-aligned right after the previous section)",
                    section.address
                ));
            }
            let (writable, executable) = (
                section.flags & elf::SHF_WRITE != 0,
                section.flags & elf::SHF_EXECINSTR != 0,
            );
            let flags_fit = match kind {
                SectionKind::Code => executable && !writable,
                SectionKind::ReadOnly => !executable && !writable,
                SectionKind::Data => !executable && writable,
                SectionKind::Uninitialized => writable && section.kind == elf::SHT_NOBITS,
            };
            if !flags_fit
                || (kind != SectionKind::Uninitialized) == (section.kind == elf::SHT_NOBITS)
            {
                return Err(format!(
                    "{name}'s flags or type do not fit a {kind:?} section"
                ));
            }
            sections.push(LinkedSection {
                name: name.to_string(),
                kind,
                rva: section.address - image_base,
                size: section.size,
                data: elf.data(section)?.to_vec(),
            });
            next = align_up(section.address + section.size, ALIGNMENT);
        }
        let image_end = next;
        let image_sections: Vec<usize> = allocated.iter().map(|s| s.index).collect();
        let in_image = |section: u16| image_sections.contains(&(section as usize));

        let entry = elf.entry.wrapping_sub(image_base);
        let text = &sections[0];
        if !(text.rva..text.rva + text.size).contains(&entry) {
            return Err(format!("the entry point {:#x} is not in .text", elf.entry));
        }

        let mut fixups = Vec::new();
        for table in elf.sections.iter().filter(|s| s.kind == elf::SHT_REL) {
            // Relocations of sections the image does not map (debugging information) do not
            // concern it.
            let Some(position) = allocated
                .iter()
                .position(|s| s.index == table.info as usize)
            else {
                continue;
            };
            let target = &sections[position];
            for relocation in elf.relocations(table)? {
                let symbol = elf.symbols.get(relocation.symbol).ok_or_else(|| {
                    format!(
                        "{}: a relocation names symbol {}, past the table",
                        table.name, relocation.symbol
                    )
                })?;
                let rva = relocation.offset.wrapping_sub(image_base);
                let at = rva.wrapping_sub(target.rva) as usize;
                if at + 4 > target.data.len() {
                    return Err(format!(
                        "{}: a relocation at {:#x} lies outside {}",
                        table.name, relocation.offset, target.name
                    ));
                }
                let word = u32::from_le_bytes(target.data[at..at + 4].try_into().unwrap());
                let names_image = in_image(symbol.section);
                let names = || {
                    if symbol.name.is_empty() {
                        "a section".to_string()
                    } else {
                        symbol.name.clone()
                    }
                };
                match relocation.kind {
                    elf::R_386_NONE => {}
                    elf::R_386_32 if names_image => fixups.push(rva),
                    elf::R_386_32 if symbol.section == elf::SHN_ABS => {
                        if (image_base..=image_end).contains(&word) {
                            return Err(format!(
                                "{:#x}: an absolute symbol ({}) gives an address of the image: \
                                 define it in a section, so the image can be rebased",
                                relocation.offset,
                                names()
                            ));
                        }
                    }
                    elf::R_386_PC32 if names_image => {}
                    kind @ (elf::R_386_32 | elf::R_386_PC32) => {
                        return Err(format!(
                            "{:#x}: a relocation of type {kind} against {} (outside the image) \
                             cannot be rebased",
                            relocation.offset,
                            names()
                        ))
                    }
                    kind => {
                        return Err(format!(
                            "{:#x}: relocation type {kind} (only R_386_32 and R_386_PC32 can be \
                             carried into the image)",
                            relocation.offset
                        ))
                    }
                }
            }
        }
        fixups.sort_unstable();
        fixups.dedup();

        let symbols = elf
            .symbols
            .iter()
            .filter(|s| !s.name.is_empty() && in_image(s.section) && s.kind() != 3 && s.kind() != 4)
            .map(|s| LinkedSymbol {
                name: s.name.clone(),
                rva: s.value - image_base,
                size: s.size,
                kind: s.kind(),
            })
            .collect();
        Ok(Linked {
            image_base,
            entry,
            sections,
            fixups,
            symbols,
        })
    }

    /// The RVA just past the link's last section, page-aligned.
    pub fn end(&self) -> u32 {
        let last = self.sections.last().expect("a link has its sections");
        align_up(last.rva + last.size, ALIGNMENT)
    }
}

/// A write cursor: each field in declared order, little-endian.
struct Out(Vec<u8>);

impl Out {
    fn u8(&mut self, value: u8) {
        self.0.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    fn bytes(&mut self, value: &[u8]) {
        self.0.extend_from_slice(value);
    }

    fn align(&mut self, alignment: usize) {
        self.0.resize(self.0.len().next_multiple_of(alignment), 0);
    }
}

/// One exported entry point: its name, its ordinal, its RVA.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Exported {
    pub name: String,
    pub ordinal: u16,
    pub rva: u32,
}

/// The exports `spec` gives the image linked as `linked`: each implemented export (a native, the
/// only kind the kernel's spec has), at its ordinal ([`Spec::ordinals`]) and its body's symbol's
/// RVA, in spec order.
pub fn exports(linked: &Linked, spec: &Spec) -> Result<Vec<Exported>, String> {
    let symbols: HashMap<&str, u32> = linked
        .symbols
        .iter()
        .rev()
        .map(|s| (s.name.as_str(), s.rva))
        .collect();
    let mut ordinals = spec.ordinals();
    spec.exports
        .iter()
        .map(|export| {
            if !matches!(export.implementation, Implementation::Native(_)) {
                return Err(format!(
                    "{}: only a native is the image's own entry point",
                    export.name
                ));
            }
            let symbol = format!("{EXPORT_PREFIX}{}", export.body());
            let rva = *symbols
                .get(symbol.as_str())
                .ok_or_else(|| format!("{}: the link defines no {symbol}", export.name))?;
            Ok(Exported {
                name: export.name.clone(),
                ordinal: ordinals.assign(export.ordinal),
                rva,
            })
        })
        .collect()
}

/// The export directory for `exports` of the module `module`, laid out at `rva`: the directory,
/// the address table (one slot per ordinal from the lowest to the highest, a gap's slot zero), the
/// name pointer table in the names' byte order (the loader's binary search relies on it), the
/// ordinal table beside it, then the module's name and the export names.
fn export_directory(rva: u32, module: &str, exports: &[Exported]) -> Vec<u8> {
    let base = exports.iter().map(|e| e.ordinal).min().unwrap_or(1) as u32;
    let functions = exports
        .iter()
        .map(|e| e.ordinal as u32 - base + 1)
        .max()
        .unwrap_or(0);
    let mut named: Vec<&Exported> = exports.iter().collect();
    named.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
    let address_table = rva + EXPORT_DIRECTORY_SIZE as u32;
    let name_pointers = address_table + 4 * functions;
    let ordinal_table = name_pointers + 4 * named.len() as u32;
    let strings = align_up(ordinal_table + 2 * named.len() as u32, 4);

    let mut text = Out(Vec::new());
    let module_name = strings;
    text.bytes(module.as_bytes());
    text.u8(0);
    let mut name_rvas = Vec::new();
    for export in &named {
        name_rvas.push(strings + text.0.len() as u32);
        text.bytes(export.name.as_bytes());
        text.u8(0);
    }

    let mut out = Out(Vec::new());
    out.u32(0); // Characteristics
    out.u32(0); // TimeDateStamp
    out.u16(0); // MajorVersion
    out.u16(0); // MinorVersion
    out.u32(module_name);
    out.u32(base);
    out.u32(functions);
    out.u32(named.len() as u32);
    out.u32(address_table);
    out.u32(name_pointers);
    out.u32(ordinal_table);
    let mut slots = vec![0u32; functions as usize];
    for export in exports {
        slots[(export.ordinal as u32 - base) as usize] = export.rva;
    }
    for slot in slots {
        out.u32(slot);
    }
    for name in name_rvas {
        out.u32(name);
    }
    for export in &named {
        out.u16((export.ordinal as u32 - base) as u16);
    }
    out.align(4);
    out.bytes(&text.0);
    out.0
}

/// The base relocation table for `fixups` (RVAs, ascending): one block per page holding any, its
/// HIGHLOW entries in order, padded with an ABSOLUTE entry to a dword.
fn base_relocations(fixups: &[u32]) -> Vec<u8> {
    let mut out = Out(Vec::new());
    let mut rest = fixups;
    while let Some(&first) = rest.first() {
        let page = first & !(ALIGNMENT - 1);
        let count = rest
            .iter()
            .take_while(|&&rva| rva & !(ALIGNMENT - 1) == page)
            .count();
        let padded = count.next_multiple_of(2);
        out.u32(page);
        out.u32(8 + 2 * padded as u32);
        for &rva in &rest[..count] {
            out.u16(REL_BASED_HIGHLOW << 12 | (rva - page) as u16);
        }
        if padded > count {
            out.u16(REL_BASED_ABSOLUTE << 12);
        }
        rest = &rest[count..];
    }
    out.0
}

/// The image checksum of `file`, whose checksum field lies at `field` (counted as zero): its
/// 16-bit little-endian words (an odd last byte the low byte of a last word) summed, each carry
/// out of the low 16 bits folded back in, plus the file's length.
pub fn checksum(file: &[u8], field: usize) -> u32 {
    let mut sum: u32 = 0;
    for (index, pair) in file.chunks(2).enumerate() {
        let at = index * 2;
        let word = if (field..field + 4).contains(&at) {
            0
        } else {
            u16::from_le_bytes([pair[0], pair.get(1).copied().unwrap_or(0)]) as u32
        };
        sum += word;
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum.wrapping_add(file.len() as u32)
}

/// One section of an emitted image, as its header describes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageSection {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_offset: u32,
    pub characteristics: u32,
}

/// The PE32 image of the link `linked`, named `module`, exporting what `spec` implements.
pub fn emit(linked: &Linked, spec: &Spec, module: &str) -> Result<Vec<u8>, String> {
    let exported = exports(linked, spec)?;
    let edata_rva = linked.end();
    let edata = export_directory(edata_rva, module, &exported);
    let reloc_rva = align_up(edata_rva + edata.len() as u32, ALIGNMENT);
    let relocations = base_relocations(&linked.fixups);

    // Every section: (name, characteristics, rva, size in memory, contents; none for .bss).
    let mut sections: Vec<(&str, u32, u32, u32, Option<&[u8]>)> = linked
        .sections
        .iter()
        .map(|s| {
            let contents = (s.kind != SectionKind::Uninitialized).then_some(s.data.as_slice());
            (
                s.name.as_str(),
                s.kind.characteristics(),
                s.rva,
                s.size,
                contents,
            )
        })
        .collect();
    sections.push((
        ".edata",
        SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ,
        edata_rva,
        edata.len() as u32,
        Some(&edata),
    ));
    if !relocations.is_empty() {
        sections.push((
            ".reloc",
            SCN_CNT_INITIALIZED_DATA | SCN_MEM_DISCARDABLE | SCN_MEM_READ,
            reloc_rva,
            relocations.len() as u32,
            Some(&relocations),
        ));
    }
    let size_of_image = {
        let (_, _, rva, size, _) = sections.last().unwrap();
        align_up(rva + size, ALIGNMENT)
    };

    // The file: the headers' page, then each initialized section's contents, page-aligned.
    let mut rows = Vec::new();
    let mut body = Out(Vec::new());
    let (mut code, mut initialized, mut uninitialized) = (0, 0, 0);
    for &(name, characteristics, rva, size, contents) in &sections {
        let (raw_offset, raw_size) = match contents {
            Some(contents) => {
                let offset = ALIGNMENT + body.0.len() as u32;
                body.bytes(contents);
                body.align(ALIGNMENT as usize);
                (offset, align_up(contents.len() as u32, ALIGNMENT))
            }
            None => (0, 0),
        };
        if characteristics & SCN_CNT_CODE != 0 {
            code += raw_size;
        } else if characteristics & SCN_CNT_INITIALIZED_DATA != 0 {
            initialized += raw_size;
        } else {
            uninitialized += align_up(size, ALIGNMENT);
        }
        rows.push(ImageSection {
            name: name.to_string(),
            virtual_size: size,
            virtual_address: rva,
            raw_size,
            raw_offset,
            characteristics,
        });
    }

    let lfanew = (DOS_HEADER_SIZE + DOS_PROGRAM.len() + DOS_MESSAGE.len()).next_multiple_of(8);
    let mut headers = Out(Vec::new());
    // IMAGE_DOS_HEADER: the stub is the header and its program, `lfanew` bytes.
    headers.u16(0x5A4D); // e_magic, "MZ"
    headers.u16((lfanew % 512) as u16); // e_cblp: the bytes in the last page
    headers.u16(lfanew.div_ceil(512) as u16); // e_cp: the pages
    headers.u16(0); // e_crlc: no relocations
    headers.u16((DOS_HEADER_SIZE / 16) as u16); // e_cparhdr: the header's paragraphs
    headers.u16(0); // e_minalloc
    headers.u16(0xFFFF); // e_maxalloc
    headers.u16(0); // e_ss
    headers.u16(0x00B8); // e_sp
    headers.u16(0); // e_csum
    headers.u16(0); // e_ip
    headers.u16(0); // e_cs
    headers.u16(DOS_HEADER_SIZE as u16); // e_lfarlc
    headers.u16(0); // e_ovno
    headers.bytes(&[0; 8]); // e_res
    headers.u16(0); // e_oemid
    headers.u16(0); // e_oeminfo
    headers.bytes(&[0; 20]); // e_res2
    headers.u32(lfanew as u32); // e_lfanew
    headers.bytes(&DOS_PROGRAM);
    headers.bytes(DOS_MESSAGE);
    headers.align(8);
    debug_assert_eq!(headers.0.len(), lfanew);
    headers.bytes(b"PE\0\0");
    // IMAGE_FILE_HEADER.
    headers.u16(MACHINE_I386);
    headers.u16(rows.len() as u16);
    headers.u32(0); // TimeDateStamp: none, so a build is reproducible
    headers.u32(0); // PointerToSymbolTable
    headers.u32(0); // NumberOfSymbols
    headers.u16(OPTIONAL_HEADER_SIZE as u16);
    headers.u16(if relocations.is_empty() {
        CHARACTERISTICS | RELOCS_STRIPPED
    } else {
        CHARACTERISTICS
    });
    // IMAGE_OPTIONAL_HEADER32.
    let optional = headers.0.len();
    headers.u16(PE32_MAGIC);
    headers.u8(0); // MajorLinkerVersion
    headers.u8(0); // MinorLinkerVersion
    headers.u32(code); // SizeOfCode
    headers.u32(initialized); // SizeOfInitializedData
    headers.u32(uninitialized); // SizeOfUninitializedData
    headers.u32(linked.entry); // AddressOfEntryPoint
    headers.u32(linked.sections[0].rva); // BaseOfCode
    headers.u32(linked.sections[1].rva); // BaseOfData
    headers.u32(linked.image_base); // ImageBase
    headers.u32(ALIGNMENT); // SectionAlignment
    headers.u32(ALIGNMENT); // FileAlignment
    headers.u16(5); // MajorOperatingSystemVersion: Windows 2000's, 5.0
    headers.u16(0); // MinorOperatingSystemVersion
    headers.u16(5); // MajorImageVersion
    headers.u16(0); // MinorImageVersion
    headers.u16(5); // MajorSubsystemVersion
    headers.u16(0); // MinorSubsystemVersion
    headers.u32(0); // Win32VersionValue
    headers.u32(size_of_image); // SizeOfImage
    headers.u32(ALIGNMENT); // SizeOfHeaders
    headers.u32(0); // CheckSum, set below
    headers.u16(SUBSYSTEM_NATIVE); // Subsystem
    headers.u16(0); // DllCharacteristics
                    // The stack and heap reservations: the linker's defaults, 1 MiB reserved and a
                    // page committed, which nothing loading a kernel reads.
    headers.u32(0x0010_0000); // SizeOfStackReserve
    headers.u32(ALIGNMENT); // SizeOfStackCommit
    headers.u32(0x0010_0000); // SizeOfHeapReserve
    headers.u32(ALIGNMENT); // SizeOfHeapCommit
    headers.u32(0); // LoaderFlags
    headers.u32(DIRECTORIES as u32); // NumberOfRvaAndSizes
    for index in 0..DIRECTORIES {
        let (rva, size) = match index {
            DIRECTORY_EXPORT => (edata_rva, edata.len() as u32),
            DIRECTORY_BASERELOC if !relocations.is_empty() => (reloc_rva, relocations.len() as u32),
            _ => (0, 0),
        };
        headers.u32(rva);
        headers.u32(size);
    }
    debug_assert_eq!(headers.0.len() - optional, OPTIONAL_HEADER_SIZE);
    // The section table.
    for row in &rows {
        let mut name = [0u8; 8];
        name[..row.name.len()].copy_from_slice(row.name.as_bytes());
        headers.bytes(&name);
        headers.u32(row.virtual_size);
        headers.u32(row.virtual_address);
        headers.u32(row.raw_size);
        headers.u32(row.raw_offset);
        headers.u32(0); // PointerToRelocations
        headers.u32(0); // PointerToLinenumbers
        headers.u16(0); // NumberOfRelocations
        headers.u16(0); // NumberOfLinenumbers
        headers.u32(row.characteristics);
    }
    if headers.0.len() > ALIGNMENT as usize {
        return Err("the headers outgrow their page".into());
    }
    headers.align(ALIGNMENT as usize);
    headers.bytes(&body.0);
    let mut file = headers.0;
    let field = optional + CHECKSUM_FIELD;
    let sum = checksum(&file, field);
    file[field..field + 4].copy_from_slice(&sum.to_le_bytes());
    Ok(file)
}

/// An image read back: what its headers say, its export directory, its base relocations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Image {
    pub machine: u16,
    pub characteristics: u16,
    pub image_base: u32,
    pub entry: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub subsystem: u16,
    pub subsystem_version: (u16, u16),
    pub checksum: u32,
    /// The checksum field's offset in the file.
    pub checksum_field: usize,
    /// The data directories: (RVA, size).
    pub directories: Vec<(u32, u32)>,
    pub sections: Vec<ImageSection>,
    /// The export directory's module name, and its exports, by ordinal.
    pub module: String,
    pub exports: Vec<Exported>,
    /// The HIGHLOW fixups' RVAs, ascending.
    pub fixups: Vec<u32>,
}

/// A read cursor over a structure's bytes: each field in declared order, little-endian.
struct Fields<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Fields<'a> {
    fn at(file: &'a [u8], offset: usize, what: &str) -> Result<Self, String> {
        let bytes = file
            .get(offset..)
            .ok_or_else(|| format!("{what} lies past the end of the file"))?;
        Ok(Fields { bytes, at: 0 })
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], String> {
        let field = self
            .bytes
            .get(self.at..self.at + N)
            .ok_or("the file ends inside a header")?
            .try_into()
            .unwrap();
        self.at += N;
        Ok(field)
    }

    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(self.take()?))
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take()?))
    }
}

impl Image {
    /// The file offset of `rva`, through the section holding it in the file.
    pub fn offset_of(&self, rva: u32) -> Option<usize> {
        if rva < self.size_of_headers {
            return Some(rva as usize);
        }
        self.sections
            .iter()
            .find(|s| (s.virtual_address..s.virtual_address + s.raw_size).contains(&rva))
            .map(|s| (rva - s.virtual_address + s.raw_offset) as usize)
    }
}

/// Read `file` as a PE32 image.
pub fn read(file: &[u8]) -> Result<Image, String> {
    let mut dos = Fields::at(file, 0, "the DOS header")?;
    if dos.u16()? != 0x5A4D {
        return Err("no MZ signature".into());
    }
    let lfanew = u32::from_le_bytes(
        file.get(0x3C..0x40)
            .ok_or("the file ends inside the DOS header")?
            .try_into()
            .unwrap(),
    ) as usize;
    let mut nt = Fields::at(file, lfanew, "the NT headers")?;
    if nt.take::<4>()? != *b"PE\0\0" {
        return Err("no PE signature".into());
    }
    let machine = nt.u16()?;
    let section_count = nt.u16()? as usize;
    let _timestamp = nt.u32()?;
    let _symbols = nt.u32()?;
    let _symbol_count = nt.u32()?;
    let optional_size = nt.u16()? as usize;
    let characteristics = nt.u16()?;
    let optional = lfanew + 4 + FILE_HEADER_SIZE;
    if nt.u16()? != PE32_MAGIC {
        return Err("not a PE32 optional header".into());
    }
    let _linker: [u8; 2] = nt.take()?;
    let _code = nt.u32()?;
    let _initialized = nt.u32()?;
    let _uninitialized = nt.u32()?;
    let entry = nt.u32()?;
    let _base_of_code = nt.u32()?;
    let _base_of_data = nt.u32()?;
    let image_base = nt.u32()?;
    let section_alignment = nt.u32()?;
    let file_alignment = nt.u32()?;
    let _os: [u8; 4] = nt.take()?;
    let _image_version: [u8; 4] = nt.take()?;
    let subsystem_version = (nt.u16()?, nt.u16()?);
    let _win32 = nt.u32()?;
    let size_of_image = nt.u32()?;
    let size_of_headers = nt.u32()?;
    let checksum = nt.u32()?;
    let subsystem = nt.u16()?;
    let _dll_characteristics = nt.u16()?;
    let _reservations: [u8; 16] = nt.take()?;
    let _loader_flags = nt.u32()?;
    let directory_count = nt.u32()? as usize;
    let mut directories = Vec::new();
    for _ in 0..directory_count.min(DIRECTORIES) {
        directories.push((nt.u32()?, nt.u32()?));
    }
    let mut table = Fields::at(file, optional + optional_size, "the section table")?;
    let mut sections = Vec::new();
    for _ in 0..section_count {
        let name: [u8; 8] = table.take()?;
        let end = name.iter().position(|&b| b == 0).unwrap_or(8);
        let section = ImageSection {
            name: String::from_utf8_lossy(&name[..end]).into_owned(),
            virtual_size: table.u32()?,
            virtual_address: table.u32()?,
            raw_size: table.u32()?,
            raw_offset: table.u32()?,
            characteristics: {
                let _rest: [u8; 12] = table.take()?;
                table.u32()?
            },
        };
        sections.push(section);
    }
    let mut image = Image {
        machine,
        characteristics,
        image_base,
        entry,
        section_alignment,
        file_alignment,
        size_of_image,
        size_of_headers,
        subsystem,
        subsystem_version,
        checksum,
        checksum_field: optional + CHECKSUM_FIELD,
        directories,
        sections,
        module: String::new(),
        exports: Vec::new(),
        fixups: Vec::new(),
    };
    let string_at = |image: &Image, rva: u32| -> Result<String, String> {
        let offset = image.offset_of(rva).ok_or("a name outside the file")?;
        let tail = file.get(offset..).ok_or("a name outside the file")?;
        let end = tail
            .iter()
            .position(|&b| b == 0)
            .ok_or("an unterminated name")?;
        Ok(String::from_utf8_lossy(&tail[..end]).into_owned())
    };
    let word_at = |image: &Image, rva: u32| -> Result<u32, String> {
        let offset = image.offset_of(rva).ok_or("a table outside the file")?;
        Ok(u32::from_le_bytes(
            file.get(offset..offset + 4)
                .ok_or("a table outside the file")?
                .try_into()
                .unwrap(),
        ))
    };
    if let Some(&(rva, _)) = image.directories.get(DIRECTORY_EXPORT).filter(|d| d.0 != 0) {
        let offset = image
            .offset_of(rva)
            .ok_or("the export directory lies outside the file")?;
        let mut directory = Fields::at(file, offset, "the export directory")?;
        let _fixed: [u8; 12] = directory.take()?;
        let name = directory.u32()?;
        let base = directory.u32()?;
        let functions = directory.u32()?;
        let names = directory.u32()?;
        let address_table = directory.u32()?;
        let name_pointers = directory.u32()?;
        let ordinal_table = directory.u32()?;
        image.module = string_at(&image, name)?;
        let mut exports = Vec::new();
        for index in 0..names {
            let name = string_at(&image, word_at(&image, name_pointers + 4 * index)?)?;
            let slot_offset = image
                .offset_of(ordinal_table + 2 * index)
                .ok_or("the ordinal table lies outside the file")?;
            let slot = u16::from_le_bytes(
                file.get(slot_offset..slot_offset + 2)
                    .ok_or("the ordinal table lies outside the file")?
                    .try_into()
                    .unwrap(),
            ) as u32;
            if slot >= functions {
                return Err(format!(
                    "{name}: its ordinal slot {slot} is past the address table"
                ));
            }
            exports.push(Exported {
                name,
                ordinal: (base + slot) as u16,
                rva: word_at(&image, address_table + 4 * slot)?,
            });
        }
        image.exports = exports;
    }
    if let Some(&(rva, size)) = image
        .directories
        .get(DIRECTORY_BASERELOC)
        .filter(|d| d.0 != 0)
    {
        let mut at = 0;
        while at < size {
            let page = word_at(&image, rva + at)?;
            let block = word_at(&image, rva + at + 4)?;
            if block < 8 || block % 2 != 0 {
                return Err(format!("a base relocation block of {block} bytes"));
            }
            for entry in (8..block).step_by(2) {
                let offset = image
                    .offset_of(rva + at + entry)
                    .ok_or("the base relocations lie outside the file")?;
                let value = u16::from_le_bytes([file[offset], file[offset + 1]]);
                match value >> 12 {
                    REL_BASED_ABSOLUTE => {}
                    REL_BASED_HIGHLOW => image.fixups.push(page + (value & 0xFFF) as u32),
                    other => return Err(format!("base relocation type {other}")),
                }
            }
            at += block;
        }
    }
    Ok(image)
}

/// Hold the emitted image `file` to what it was emitted from (the link `linked`, the spec `spec`,
/// the module name `module`): a PE32 image of a native subsystem at the link's base, with a
/// correct checksum, the link's sections and contents where the link put them, its entry point,
/// the spec's export directory, and the link's fixups. The boot image's build runs it on every
/// image it embeds; the tests on the images they emit.
pub fn check(file: &[u8], linked: &Linked, spec: &Spec, module: &str) -> Result<(), String> {
    let image = read(file)?;
    let expect = |holds: bool, what: &str| {
        if holds {
            Ok(())
        } else {
            Err(format!("the emitted image: {what}"))
        }
    };
    expect(image.machine == MACHINE_I386, "not an i386 image")?;
    expect(
        image.image_base == linked.image_base,
        "not at the link's base",
    )?;
    expect(image.subsystem == SUBSYSTEM_NATIVE, "not a native image")?;
    expect(
        image.checksum == checksum(file, image.checksum_field),
        "its checksum is wrong",
    )?;
    expect(image.entry == linked.entry, "not the link's entry point")?;
    for section in &linked.sections {
        let found = image
            .sections
            .iter()
            .find(|s| s.name == section.name)
            .ok_or_else(|| format!("the emitted image has no {}", section.name))?;
        expect(
            found.virtual_address == section.rva && found.virtual_size == section.size,
            &format!("{} is not where the link put it", section.name),
        )?;
        expect(
            found.characteristics == section.kind.characteristics(),
            &format!("{}'s characteristics", section.name),
        )?;
        if section.kind != SectionKind::Uninitialized {
            let start = found.raw_offset as usize;
            expect(
                file.get(start..start + section.data.len()) == Some(&section.data[..]),
                &format!("{}'s contents differ from the link's", section.name),
            )?;
        }
    }
    let mut expected = exports(linked, spec)?;
    let mut found = image.exports.clone();
    expected.sort();
    found.sort();
    expect(found == expected, "its exports are not the spec's")?;
    expect(
        image.module == module,
        "its export directory names another module",
    )?;
    expect(
        image.fixups == linked.fixups,
        "its base relocations are not the link's",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::tests::Built;
    use crate::elf::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHT_NOBITS, SHT_PROGBITS};
    use crate::parse_spec;

    const BASE: u32 = 0x8040_0000;

    /// A kernel spec: two natives (one a variable, one with the platform's ordinal), and the
    /// catalogue, one record numbered and one not.
    const KERNEL: &str = r#"
[[group]]
key = "rtl"
title = "runtime library"

[[export]]
name = "RtlInitAnsiString"
group = "rtl"
args = ["ptr DestinationString", "strA? SourceString"]
impl = { native = "RtlInitAnsiString" }
fails = "void"

[[export]]
name = "KeTickCount"
group = "rtl"
impl = { native = "KeTickCount" }
data = true
ordinal = 4

[[export]]
name = "ExAllocatePool"
ordinal = 2

[[export]]
name = "KeBugCheckEx"
"#;

    /// A link of the four sections: .text at a page past the base (two pages of it), .rdata,
    /// .data, then .bss; the natives' bodies and two other symbols; fixups on two pages.
    fn linked() -> Linked {
        let section = |name: &str, kind, rva, data: Vec<u8>, size| LinkedSection {
            name: name.into(),
            kind,
            rva,
            size,
            data,
        };
        let symbol = |name: &str, rva, size, kind| LinkedSymbol {
            name: name.into(),
            rva,
            size,
            kind,
        };
        Linked {
            image_base: BASE,
            entry: 0x1010,
            sections: vec![
                section(
                    ".text",
                    SectionKind::Code,
                    0x1000,
                    (0..0x1800).map(|i| i as u8).collect(),
                    0x1800,
                ),
                section(
                    ".rdata",
                    SectionKind::ReadOnly,
                    0x3000,
                    vec![0x52; 0x100],
                    0x100,
                ),
                section(
                    ".data",
                    SectionKind::Data,
                    0x4000,
                    vec![0x44; 0x1004],
                    0x1004,
                ),
                section(
                    ".bss",
                    SectionKind::Uninitialized,
                    0x6000,
                    Vec::new(),
                    0x3000,
                ),
            ],
            fixups: vec![0x1004, 0x1100, 0x2008, 0x4000],
            symbols: vec![
                symbol("_start", 0x1010, 0x20, elf::STT_FUNC),
                symbol("f2k_export_RtlInitAnsiString", 0x1200, 0x40, elf::STT_FUNC),
                symbol("f2k_export_KeTickCount", 0x6010, 8, elf::STT_OBJECT),
                symbol("memcpy", 0x1400, 12, elf::STT_FUNC),
            ],
        }
    }

    fn spec() -> Spec {
        let spec = parse_spec(KERNEL).unwrap();
        crate::check_kernel(&spec).unwrap();
        spec
    }

    /// The headers: MZ and its stub, the PE signature, an i386 PE32 image at the link's base with
    /// page alignments and its headers' page, the native subsystem at version 5.0, relocations
    /// kept, the entry point the link's.
    #[test]
    fn the_headers_are_a_native_pe32_image_at_the_links_base() {
        let file = emit(&linked(), &spec(), "ntoskrnl.exe").unwrap();
        assert_eq!(&file[..2], b"MZ");
        let lfanew = u32::from_le_bytes(file[0x3C..0x40].try_into().unwrap()) as usize;
        assert_eq!(&file[lfanew..lfanew + 4], b"PE\0\0");
        assert!(file[0x40..lfanew].windows(4).any(|w| w == b"F2K "));
        let image = read(&file).unwrap();
        assert_eq!(image.machine, MACHINE_I386);
        assert_eq!(image.characteristics, 0x0102);
        assert_eq!(image.image_base, BASE);
        assert_eq!(
            (image.section_alignment, image.file_alignment),
            (0x1000, 0x1000)
        );
        assert_eq!(image.size_of_headers, 0x1000);
        assert_eq!(image.subsystem, SUBSYSTEM_NATIVE);
        assert_eq!(image.subsystem_version, (5, 0));
        assert_eq!(image.entry, 0x1010);
        // The import directory is empty: the image imports nothing.
        assert_eq!(image.directories[1], (0, 0));
        assert_eq!(image.directories.len(), 16);
    }

    /// The sections: the link's four at their RVAs and sizes, marked by their kinds, the
    /// initialized ones' contents where the image maps them, .bss without file data; then the
    /// export directory and the base relocations after .bss, adjacent, and the image's size their
    /// end.
    #[test]
    fn the_sections_are_the_links_then_the_directories() {
        let linked = linked();
        let file = emit(&linked, &spec(), "ntoskrnl.exe").unwrap();
        let image = read(&file).unwrap();
        let names: Vec<&str> = image.sections.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            [".text", ".rdata", ".data", ".bss", ".edata", ".reloc"]
        );
        let text = &image.sections[0];
        assert_eq!((text.virtual_address, text.virtual_size), (0x1000, 0x1800));
        assert_eq!(text.characteristics, 0x6000_0020);
        assert_eq!(image.sections[1].characteristics, 0x4000_0040);
        assert_eq!(image.sections[2].characteristics, 0xC000_0040);
        let bss = &image.sections[3];
        assert_eq!((bss.virtual_address, bss.virtual_size), (0x6000, 0x3000));
        assert_eq!(
            (bss.raw_offset, bss.raw_size, bss.characteristics),
            (0, 0, 0xC000_0080)
        );
        for section in &image.sections[..3] {
            // The headers and the initialized sections lie in the file where they lie in memory.
            assert_eq!(
                section.raw_offset, section.virtual_address,
                "{}",
                section.name
            );
            assert_eq!(section.raw_size % 0x1000, 0);
        }
        for linked in &linked.sections[..3] {
            let at = linked.rva as usize;
            assert_eq!(
                &file[at..at + linked.data.len()],
                &linked.data[..],
                "{}",
                linked.name
            );
        }
        let (edata, reloc) = (&image.sections[4], &image.sections[5]);
        assert_eq!(edata.virtual_address, 0x9000);
        assert_eq!(edata.characteristics, 0x4000_0040);
        assert_eq!(reloc.virtual_address, 0xA000);
        assert_eq!(reloc.characteristics, 0x4200_0040);
        // In the file, they follow .data: .bss takes no room there.
        assert_eq!(edata.raw_offset, 0x6000);
        assert_eq!(reloc.raw_offset, 0x7000);
        assert_eq!(file.len(), 0x8000);
        assert_eq!(image.size_of_image, 0xB000);
        assert_eq!(image.directories[DIRECTORY_EXPORT].0, 0x9000);
        assert_eq!(
            image.directories[DIRECTORY_BASERELOC],
            (0xA000, reloc.virtual_size)
        );
        check(&file, &linked, &spec(), "ntoskrnl.exe").unwrap();
    }

    /// The export directory: the module's name, each native at its body's RVA, the ordinals the
    /// spec gives or the next ones free (the catalogue's numbered record holds its own); the
    /// catalogued records exported by none; the name table in byte order.
    #[test]
    fn the_export_directory_is_the_specs() {
        let file = emit(&linked(), &spec(), "ntoskrnl.exe").unwrap();
        let image = read(&file).unwrap();
        assert_eq!(image.module, "ntoskrnl.exe");
        assert_eq!(
            image.exports,
            [
                Exported {
                    name: "KeTickCount".into(),
                    ordinal: 4,
                    rva: 0x6010
                },
                Exported {
                    name: "RtlInitAnsiString".into(),
                    ordinal: 1,
                    rva: 0x1200
                },
            ]
        );
        // The address table runs from ordinal 1 to 4: the two gaps' slots are zero.
        let (directory, _) = image.directories[DIRECTORY_EXPORT];
        let at = image.offset_of(directory).unwrap();
        let word = |offset: usize| {
            u32::from_le_bytes(file[at + offset..at + offset + 4].try_into().unwrap())
        };
        assert_eq!((word(0x10), word(0x14), word(0x18)), (1, 4, 2));
        let table = image.offset_of(word(0x1C)).unwrap();
        let slots: Vec<u32> = (0..4)
            .map(|i| u32::from_le_bytes(file[table + 4 * i..table + 4 * i + 4].try_into().unwrap()))
            .collect();
        assert_eq!(slots, [0x1200, 0, 0, 0x6010]);
        // A native whose body the link does not define is refused.
        let mut missing = linked();
        missing
            .symbols
            .retain(|s| s.name != "f2k_export_KeTickCount");
        let error = emit(&missing, &spec(), "ntoskrnl.exe").unwrap_err();
        assert!(error.contains("f2k_export_KeTickCount"), "{error}");
    }

    /// The spec with nothing implemented gives an empty directory that still names the module.
    #[test]
    fn a_spec_without_implementations_exports_nothing() {
        let spec = parse_spec("[[export]]\nname = \"KeBugCheckEx\"\n").unwrap();
        let file = emit(&linked(), &spec, "ntoskrnl.exe").unwrap();
        let image = read(&file).unwrap();
        assert_eq!(image.module, "ntoskrnl.exe");
        assert!(image.exports.is_empty());
        check(&file, &linked(), &spec, "ntoskrnl.exe").unwrap();
    }

    /// The base relocations: one block per page, HIGHLOW entries at the fixups' offsets, an odd
    /// count padded; read back, the link's fixups. Without fixups the image has no .reloc and says
    /// its relocations are stripped.
    #[test]
    fn the_base_relocations_are_the_links_fixups() {
        let table = base_relocations(&[0x1004, 0x1100, 0x2008]);
        assert_eq!(
            table,
            [
                0x00, 0x10, 0, 0, 12, 0, 0, 0, 0x04, 0x30, 0x00, 0x31, //
                0x00, 0x20, 0, 0, 12, 0, 0, 0, 0x08, 0x30, 0x00, 0x00,
            ]
        );
        let file = emit(&linked(), &spec(), "ntoskrnl.exe").unwrap();
        assert_eq!(read(&file).unwrap().fixups, linked().fixups);
        let mut bare = linked();
        bare.fixups.clear();
        let image = read(&emit(&bare, &spec(), "ntoskrnl.exe").unwrap()).unwrap();
        assert_eq!(image.sections.len(), 5);
        assert_eq!(image.characteristics & RELOCS_STRIPPED, RELOCS_STRIPPED);
        assert_eq!(image.directories[DIRECTORY_BASERELOC], (0, 0));
    }

    /// The checksum: words summed with their carries folded, the field skipped, the length added;
    /// the emitted image carries its own, and any change to the file changes it.
    #[test]
    fn the_checksum_is_the_images() {
        assert_eq!(checksum(&[1, 0, 2, 0], 100), 3 + 4);
        assert_eq!(checksum(&[0xFF, 0xFF, 2, 0], 100), 2 + 4);
        assert_eq!(checksum(&[1, 0, 0xAA, 0xBB, 0xCC, 0xDD, 2], 2), 3 + 7);
        let file = emit(&linked(), &spec(), "ntoskrnl.exe").unwrap();
        let image = read(&file).unwrap();
        assert_ne!(image.checksum, 0);
        assert_eq!(image.checksum, checksum(&file, image.checksum_field));
        let mut changed = file.clone();
        changed[0x1100] ^= 1;
        assert!(check(&changed, &linked(), &spec(), "ntoskrnl.exe")
            .unwrap_err()
            .contains("checksum"));
    }

    /// The ELF link a test builds: the four sections where the image maps them, `__ImageBase`, a
    /// function and a variable, and `.rel.text`'s relocations (offset, type, symbol index):
    /// symbol 1 is `.text`'s section symbol, 2 `__ImageBase` (absolute), 3 a function, 4 a
    /// variable in .data, 5 an absolute constant outside the image.
    fn elf_link(relocations: Vec<(u32, u8, u32)>, text_address: u32) -> Vec<u8> {
        let mut text = vec![0u8; 0x20];
        // The words the relocations' sites hold: .data's variable's address, an absolute
        // constant, and the image base itself.
        text[4..8].copy_from_slice(&(BASE + 0x3000).to_le_bytes());
        text[8..12].copy_from_slice(&0x0000_B800u32.to_le_bytes());
        text[12..16].copy_from_slice(&BASE.to_le_bytes());
        Built {
            kind: elf::ET_EXEC,
            entry: BASE + 0x1000,
            sections: vec![
                (
                    ".text".into(),
                    SHT_PROGBITS,
                    SHF_ALLOC | SHF_EXECINSTR,
                    text_address,
                    text,
                    0,
                ),
                (
                    ".rdata".into(),
                    SHT_PROGBITS,
                    SHF_ALLOC,
                    BASE + 0x2000,
                    vec![1, 2, 3],
                    0,
                ),
                (
                    ".data".into(),
                    SHT_PROGBITS,
                    SHF_ALLOC | SHF_WRITE,
                    BASE + 0x3000,
                    vec![9; 8],
                    0,
                ),
                (
                    ".bss".into(),
                    SHT_NOBITS,
                    SHF_ALLOC | SHF_WRITE,
                    BASE + 0x4000,
                    Vec::new(),
                    0x1800,
                ),
                (".comment".into(), SHT_PROGBITS, 0, 0, b"ld\0".to_vec(), 0),
            ],
            symbols: vec![
                (String::new(), BASE + 0x1000, 0, 3, 1),
                ("__ImageBase".into(), BASE, 0, 0x10, elf::SHN_ABS),
                ("_start".into(), BASE + 0x1000, 0x20, 0x12, 1),
                ("COUNTER".into(), BASE + 0x3000, 4, 0x11, 3),
                ("VGA".into(), 0xB800, 0, 0x10, elf::SHN_ABS),
            ],
            relocations: vec![(1, relocations)],
        }
        .bytes()
    }

    /// From the ELF: the sections at their RVAs with their contents, the entry, the symbols of the
    /// image, and a fixup for each absolute relocation against the image's symbols, none for a
    /// PC-relative one or an absolute constant outside the image.
    #[test]
    fn the_link_is_read_from_the_elf() {
        let bytes = elf_link(
            vec![
                (BASE + 0x1004, elf::R_386_32, 4),
                (BASE + 0x1008, elf::R_386_32, 5),
                (BASE + 0x1010, elf::R_386_PC32, 3),
                (BASE + 0x1018, elf::R_386_32, 1),
                (BASE + 0x101C, elf::R_386_NONE, 0),
            ],
            BASE + 0x1000,
        );
        let linked = Linked::from_elf(&Elf::parse(&bytes).unwrap()).unwrap();
        assert_eq!(linked.image_base, BASE);
        assert_eq!(linked.entry, 0x1000);
        let layout: Vec<(&str, SectionKind, u32, u32)> = linked
            .sections
            .iter()
            .map(|s| (s.name.as_str(), s.kind, s.rva, s.size))
            .collect();
        assert_eq!(
            layout,
            [
                (".text", SectionKind::Code, 0x1000, 0x20),
                (".rdata", SectionKind::ReadOnly, 0x2000, 3),
                (".data", SectionKind::Data, 0x3000, 8),
                (".bss", SectionKind::Uninitialized, 0x4000, 0x1800),
            ]
        );
        assert_eq!(linked.sections[2].data, [9; 8]);
        assert_eq!(linked.fixups, [0x1004, 0x1018]);
        let names: Vec<&str> = linked.symbols.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["_start", "COUNTER"]);
        assert_eq!(linked.end(), 0x6000);
        let file = emit(&linked, &parse_spec("").unwrap(), "ntoskrnl.exe").unwrap();
        check(&file, &linked, &parse_spec("").unwrap(), "ntoskrnl.exe").unwrap();
    }

    /// What cannot be carried into a rebasable image is refused: an absolute symbol that is an
    /// address of the image, a PC-relative reference out of it, another relocation type, a
    /// section out of place.
    #[test]
    fn what_cannot_be_rebased_is_refused() {
        for (relocation, message) in [
            ((BASE + 0x100C, elf::R_386_32, 2), "absolute symbol"),
            ((BASE + 0x1010, elf::R_386_PC32, 5), "cannot be rebased"),
            ((BASE + 0x1010, 20, 3), "relocation type 20"),
        ] {
            let bytes = elf_link(vec![relocation], BASE + 0x1000);
            let error = Linked::from_elf(&Elf::parse(&bytes).unwrap()).unwrap_err();
            assert!(error.contains(message), "{relocation:?}: {error}");
        }
        let misplaced = elf_link(Vec::new(), BASE + 0x800);
        let error = Linked::from_elf(&Elf::parse(&misplaced).unwrap()).unwrap_err();
        assert!(error.contains(".text is linked at"), "{error}");
    }

    /// The kernel's own spec: it reads, holds to the kernel's terms, and its export directory is
    /// emitted against a link defining its natives' bodies.
    #[test]
    fn the_kernels_spec_emits() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../kernel/exports.toml");
        let spec = crate::load(&path).unwrap();
        crate::check_kernel(&spec).unwrap();
        assert!(spec
            .catalogued
            .iter()
            .any(|c| c.name == "KeServiceDescriptorTable" && c.data));
        let mut link = linked();
        for native in spec.natives() {
            link.symbols.push(LinkedSymbol {
                name: format!("{EXPORT_PREFIX}{}", native.body()),
                rva: 0x1300,
                size: 4,
                kind: elf::STT_FUNC,
            });
        }
        let file = emit(&link, &spec, "ntoskrnl.exe").unwrap();
        check(&file, &link, &spec, "ntoskrnl.exe").unwrap();
        assert_eq!(read(&file).unwrap().exports.len(), spec.natives().len());
    }

    /// The kernel's terms: natives only.
    #[test]
    fn the_kernel_implements_natives_only() {
        for (implementation, message) in [
            (
                "{ stub = \"not yet implemented\" }\nfails = \"void\"",
                "stub bodies",
            ),
            ("{ forward = \"HAL.KfRaiseIrql\" }", "forwards nothing"),
        ] {
            let text = format!(
                "[[group]]\nkey = \"k\"\ntitle = \"k\"\n\n[[export]]\nname = \"KeX\"\ngroup = \"k\"\nargs = []\nimpl = {implementation}\n"
            );
            let error = crate::check_kernel(&parse_spec(&text).unwrap()).unwrap_err();
            assert!(error.contains(message), "{error}");
        }
    }
}
