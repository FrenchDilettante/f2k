//! ELF32 for i386, little-endian, as far as the kernel's image needs it: the reader the image
//! emission starts from ([`Elf`]: the link's sections, its symbols, and the relocations
//! `--emit-relocs` keeps in it), and the relocatable object the boot image links the emitted image
//! in as ([`image_object`]). The layouts are the System V ABI's (`Elf32_Ehdr`, `Elf32_Shdr`,
//! `Elf32_Sym`, `Elf32_Rel`), each read and written field by field in its declared order.

use std::collections::HashMap;

/// `e_ident`'s first bytes: the magic, ELFCLASS32, ELFDATA2LSB, EV_CURRENT.
const IDENT: [u8; 7] = [0x7F, b'E', b'L', b'F', 1, 1, 1];
/// `e_type`: a relocatable object, an executable.
pub const ET_REL: u16 = 1;
pub const ET_EXEC: u16 = 2;
/// `e_machine`: Intel 80386.
pub const EM_386: u16 = 3;

/// `sh_type`: program data, the symbol table, a string table, relocations with explicit addends,
/// space without file data, relocations whose addends are in the section they apply to.
pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_RELA: u32 = 4;
pub const SHT_NOBITS: u32 = 8;
pub const SHT_REL: u32 = 9;
/// `sh_flags`: writable, occupies memory at run time, executable.
pub const SHF_WRITE: u32 = 0x1;
pub const SHF_ALLOC: u32 = 0x2;
pub const SHF_EXECINSTR: u32 = 0x4;
/// `st_shndx`: an undefined symbol, an absolute one.
pub const SHN_UNDEF: u16 = 0;
pub const SHN_ABS: u16 = 0xFFF1;
/// `st_info`'s type (its low nibble): a data object, a function; and its binding (the high
/// nibble): local.
pub const STT_OBJECT: u8 = 1;
pub const STT_FUNC: u8 = 2;
pub const STB_LOCAL: u8 = 0;
/// The i386 relocation types the kernel's link holds: none, a word's absolute address (S + A),
/// a word's PC-relative displacement (S + A - P).
pub const R_386_NONE: u8 = 0;
pub const R_386_32: u8 = 1;
pub const R_386_PC32: u8 = 2;

/// `Elf32_Ehdr`'s size, `Elf32_Shdr`'s, `Elf32_Sym`'s and `Elf32_Rel`'s.
const EHDR_SIZE: usize = 52;
const SHDR_SIZE: usize = 40;
const SYM_SIZE: usize = 16;
const REL_SIZE: usize = 8;

/// A read cursor over a structure's bytes: each field in declared order, little-endian.
struct Fields<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Fields<'a> {
    /// The `size` bytes at `offset` of `file`, if it holds them.
    fn at(file: &'a [u8], offset: usize, size: usize, what: &str) -> Result<Self, String> {
        let bytes = offset
            .checked_add(size)
            .and_then(|end| file.get(offset..end))
            .ok_or_else(|| format!("the file ends inside {what} (at {offset:#x})"))?;
        Ok(Fields { bytes, at: 0 })
    }

    fn take<const N: usize>(&mut self) -> [u8; N] {
        let field = self.bytes[self.at..self.at + N].try_into().unwrap();
        self.at += N;
        field
    }

    fn u8(&mut self) -> u8 {
        self.take::<1>()[0]
    }

    fn u16(&mut self) -> u16 {
        u16::from_le_bytes(self.take())
    }

    fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.take())
    }
}

/// One section header (`Elf32_Shdr`), its name resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    /// Its index in the section header table (what a symbol's `st_shndx` names).
    pub index: usize,
    pub name: String,
    pub kind: u32,
    pub flags: u32,
    pub address: u32,
    pub offset: u32,
    pub size: u32,
    pub link: u32,
    pub info: u32,
    pub entry_size: u32,
}

impl Section {
    /// Whether the section occupies memory at run time.
    pub fn allocated(&self) -> bool {
        self.flags & SHF_ALLOC != 0
    }
}

/// One symbol (`Elf32_Sym`), its name resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Symbol {
    pub name: String,
    pub value: u32,
    pub size: u32,
    pub info: u8,
    /// `st_shndx`: the section it is defined in, or [`SHN_UNDEF`], [`SHN_ABS`].
    pub section: u16,
}

impl Symbol {
    /// Its type (`STT_*`).
    pub fn kind(&self) -> u8 {
        self.info & 0xF
    }
}

/// One relocation (`Elf32_Rel`): in a linked file, the address it applied at, its type, and the
/// symbol it named (an index into [`Elf::symbols`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Relocation {
    pub offset: u32,
    pub kind: u8,
    pub symbol: usize,
}

/// An ELF32 i386 file read: its header's entry and type, its sections, its symbol table.
pub struct Elf<'a> {
    bytes: &'a [u8],
    pub kind: u16,
    pub entry: u32,
    pub sections: Vec<Section>,
    /// The symbol table's entries, in table order (the null symbol first); empty without one.
    pub symbols: Vec<Symbol>,
    by_name: HashMap<String, usize>,
}

impl std::fmt::Debug for Elf<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Elf")
            .field("kind", &self.kind)
            .field("entry", &self.entry)
            .field("sections", &self.sections.len())
            .field("symbols", &self.symbols.len())
            .finish()
    }
}

impl<'a> Elf<'a> {
    /// Read `bytes` as an ELF32 little-endian i386 file.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, String> {
        let mut header = Fields::at(bytes, 0, EHDR_SIZE, "the ELF header")?;
        let ident: [u8; 16] = header.take();
        if ident[..IDENT.len()] != IDENT {
            return Err("not an ELF32 little-endian file".into());
        }
        let kind = header.u16();
        let machine = header.u16();
        if machine != EM_386 {
            return Err(format!("e_machine {machine}, not EM_386"));
        }
        let _version = header.u32();
        let entry = header.u32();
        let _phoff = header.u32();
        let shoff = header.u32() as usize;
        let _flags = header.u32();
        let _ehsize = header.u16();
        let _phentsize = header.u16();
        let _phnum = header.u16();
        let shentsize = header.u16() as usize;
        let shnum = header.u16() as usize;
        let shstrndx = header.u16() as usize;
        if shnum != 0 && shentsize != SHDR_SIZE {
            return Err(format!("e_shentsize {shentsize}, not {SHDR_SIZE}"));
        }
        let mut raw = Vec::with_capacity(shnum);
        for index in 0..shnum {
            let mut fields = Fields::at(
                bytes,
                shoff + index * SHDR_SIZE,
                SHDR_SIZE,
                "the section headers",
            )?;
            let name = fields.u32();
            let section = Section {
                index,
                name: String::new(),
                kind: fields.u32(),
                flags: fields.u32(),
                address: fields.u32(),
                offset: fields.u32(),
                size: fields.u32(),
                link: fields.u32(),
                info: fields.u32(),
                entry_size: {
                    let _align = fields.u32();
                    fields.u32()
                },
            };
            raw.push((name, section));
        }
        let mut elf = Elf {
            bytes,
            kind,
            entry,
            sections: Vec::new(),
            symbols: Vec::new(),
            by_name: HashMap::new(),
        };
        let names = match raw.get(shstrndx) {
            Some((_, strings)) if shstrndx != 0 => Some(strings.clone()),
            _ => None,
        };
        for (name, mut section) in raw {
            if let Some(strings) = &names {
                section.name = elf.string(strings, name)?;
            }
            elf.sections.push(section);
        }
        if let Some(table) = elf.sections.iter().find(|s| s.kind == SHT_SYMTAB).cloned() {
            let strings = elf
                .sections
                .get(table.link as usize)
                .cloned()
                .ok_or("the symbol table names no string table")?;
            let data = elf.data(&table)?;
            for at in (0..data.len() / SYM_SIZE).map(|i| i * SYM_SIZE) {
                let mut fields = Fields::at(data, at, SYM_SIZE, "the symbol table")?;
                let name = fields.u32();
                let symbol = Symbol {
                    name: elf.string(&strings, name)?,
                    value: fields.u32(),
                    size: fields.u32(),
                    info: fields.u8(),
                    section: {
                        let _other = fields.u8();
                        fields.u16()
                    },
                };
                elf.symbols.push(symbol);
            }
        }
        // The first definition of a name wins: a local symbol may share its name with another.
        for (index, symbol) in elf.symbols.iter().enumerate().rev() {
            if !symbol.name.is_empty() && symbol.section != SHN_UNDEF {
                elf.by_name.insert(symbol.name.clone(), index);
            }
        }
        Ok(elf)
    }

    /// The NUL-terminated string at `offset` of the string table `table`.
    fn string(&self, table: &Section, offset: u32) -> Result<String, String> {
        let data = self.data(table)?;
        let tail = data
            .get(offset as usize..)
            .ok_or_else(|| format!("a name past the end of {}", table.name))?;
        let end = tail
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| format!("an unterminated name in {}", table.name))?;
        Ok(String::from_utf8_lossy(&tail[..end]).into_owned())
    }

    /// The file's bytes of `section` (none for a section without file data).
    pub fn data(&self, section: &Section) -> Result<&'a [u8], String> {
        if section.kind == SHT_NOBITS {
            return Ok(&[]);
        }
        let start = section.offset as usize;
        start
            .checked_add(section.size as usize)
            .and_then(|end| self.bytes.get(start..end))
            .ok_or_else(|| format!("{} lies past the end of the file", section.name))
    }

    /// The section named `name`.
    pub fn section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// The defined symbol named `name` (the table's first, when several share it).
    pub fn symbol(&self, name: &str) -> Option<&Symbol> {
        self.by_name.get(name).map(|&index| &self.symbols[index])
    }

    /// The relocations of the relocation section `section` (an `SHT_REL`).
    pub fn relocations(&self, section: &Section) -> Result<Vec<Relocation>, String> {
        let data = self.data(section)?;
        (0..data.len() / REL_SIZE)
            .map(|i| {
                let mut fields = Fields::at(data, i * REL_SIZE, REL_SIZE, &section.name)?;
                let offset = fields.u32();
                let info = fields.u32();
                Ok(Relocation {
                    offset,
                    kind: (info & 0xFF) as u8,
                    symbol: (info >> 8) as usize,
                })
            })
            .collect()
    }
}

/// One symbol of [`image_object`]'s: a local symbol of its `.image` section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectSymbol {
    pub name: String,
    /// Its offset in `.image`.
    pub offset: u32,
    pub size: u32,
    /// Its type, [`STT_FUNC`] or [`STT_OBJECT`].
    pub kind: u8,
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

    /// Pad with zeros to a multiple of `alignment`.
    fn align(&mut self, alignment: usize) {
        self.0.resize(self.0.len().next_multiple_of(alignment), 0);
    }
}

/// A string table under construction: its bytes, the empty name first.
struct Strings(Vec<u8>);

impl Strings {
    fn new() -> Self {
        Strings(vec![0])
    }

    fn add(&mut self, name: &str) -> u32 {
        let at = self.0.len() as u32;
        self.0.extend_from_slice(name.as_bytes());
        self.0.push(0);
        at
    }
}

/// The relocatable object the boot image links the kernel's image in as: `.image` (allocated,
/// page-aligned) holding `contents`, `.image_reserve` (allocated, without file data) of `reserve`
/// bytes for the linker to place right after it, and `symbols` as local symbols of `.image`, so the
/// boot image's own symbol table names the code its image carries. All of them local: no name
/// can clash with the boot image's own.
pub fn image_object(contents: &[u8], reserve: u32, symbols: &[ObjectSymbol]) -> Vec<u8> {
    const PAGE: usize = 0x1000;
    // Section indices: the null section, .image, .image_reserve, .symtab, .strtab, .shstrtab.
    const IMAGE: u16 = 1;
    let mut names = Strings::new();
    let mut strings = Strings::new();
    let mut table = Out(Vec::new());
    // The null symbol, then the section's own symbol, then the image's.
    table.0.resize(SYM_SIZE, 0);
    table.u32(0);
    table.u32(0);
    table.u32(0);
    table.u8(STB_LOCAL << 4 | 3); // STT_SECTION
    table.u8(0);
    table.u16(IMAGE);
    for symbol in symbols {
        table.u32(strings.add(&symbol.name));
        table.u32(symbol.offset);
        table.u32(symbol.size);
        table.u8(STB_LOCAL << 4 | symbol.kind);
        table.u8(0);
        table.u16(IMAGE);
    }
    let symbol_count = (table.0.len() / SYM_SIZE) as u32;

    let mut file = Out(vec![0; EHDR_SIZE]);
    file.align(PAGE);
    let image_offset = file.0.len();
    file.0.extend_from_slice(contents);
    file.align(4);
    let symtab_offset = file.0.len();
    file.0.extend_from_slice(&table.0);
    let strtab_offset = file.0.len();
    file.0.extend_from_slice(&strings.0);
    // name, type, flags, address, offset, size, link, info, alignment, entry size.
    let rows: [(&str, u32, u32, usize, usize, u32, u32, u32, u32); 5] = [
        (
            ".image",
            SHT_PROGBITS,
            SHF_ALLOC,
            image_offset,
            contents.len(),
            0,
            0,
            PAGE as u32,
            0,
        ),
        (
            ".image_reserve",
            SHT_NOBITS,
            SHF_ALLOC | SHF_WRITE,
            image_offset + contents.len(),
            reserve as usize,
            0,
            0,
            1,
            0,
        ),
        (
            ".symtab",
            SHT_SYMTAB,
            0,
            symtab_offset,
            table.0.len(),
            4,
            // Every symbol is local: the first non-local one is past the end.
            symbol_count,
            4,
            SYM_SIZE as u32,
        ),
        (
            ".strtab",
            SHT_STRTAB,
            0,
            strtab_offset,
            strings.0.len(),
            0,
            0,
            1,
            0,
        ),
        (".shstrtab", SHT_STRTAB, 0, 0, 0, 0, 0, 1, 0),
    ];
    let offsets: Vec<u32> = rows.iter().map(|row| names.add(row.0)).collect();
    let shstrtab_offset = file.0.len();
    file.0.extend_from_slice(&names.0);
    file.align(4);
    let shoff = file.0.len();
    file.0.resize(file.0.len() + SHDR_SIZE, 0);
    for (row, name) in rows.iter().zip(offsets) {
        let (_, kind, flags, offset, size, link, info, align, entry_size) = *row;
        let (offset, size) = if row.0 == ".shstrtab" {
            (shstrtab_offset, names.0.len())
        } else {
            (offset, size)
        };
        file.u32(name);
        file.u32(kind);
        file.u32(flags);
        file.u32(0);
        file.u32(offset as u32);
        file.u32(size as u32);
        file.u32(link);
        file.u32(info);
        file.u32(align);
        file.u32(entry_size);
    }

    let mut header = Out(Vec::new());
    header.0.extend_from_slice(&IDENT);
    header.0.resize(16, 0);
    header.u16(ET_REL);
    header.u16(EM_386);
    header.u32(1); // e_version
    header.u32(0); // e_entry
    header.u32(0); // e_phoff
    header.u32(shoff as u32);
    header.u32(0); // e_flags
    header.u16(EHDR_SIZE as u16);
    header.u16(0); // e_phentsize
    header.u16(0); // e_phnum
    header.u16(SHDR_SIZE as u16);
    header.u16(rows.len() as u16 + 1);
    header.u16(rows.len() as u16); // .shstrtab, the last
    file.0[..EHDR_SIZE].copy_from_slice(&header.0);
    file.0
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// An ELF32 i386 file built for the tests: `sections` as (name, type, flags, address, data or
    /// size), then `.symtab` holding `symbols` (name, value, size, info, section index; the null
    /// symbol is added first), `.strtab`, and one `.rel<target>` per `relocations` entry (target
    /// section index, (offset, type, symbol index) triples), then `.shstrtab`.
    pub(crate) struct Built {
        pub kind: u16,
        pub entry: u32,
        pub sections: Vec<(String, u32, u32, u32, Vec<u8>, u32)>,
        pub symbols: Vec<(String, u32, u32, u8, u16)>,
        pub relocations: Vec<(usize, Vec<(u32, u8, u32)>)>,
    }

    impl Built {
        pub(crate) fn bytes(&self) -> Vec<u8> {
            let mut names = Strings::new();
            let mut strings = Strings::new();
            let mut file = Out(vec![0; EHDR_SIZE]);
            // (name, type, flags, address, offset, size, link, info, entry size)
            let mut rows: Vec<(u32, u32, u32, u32, usize, usize, u32, u32, u32)> = Vec::new();
            for (name, kind, flags, address, data, size) in &self.sections {
                file.align(16);
                let offset = file.0.len();
                file.0.extend_from_slice(data);
                let size = if *kind == SHT_NOBITS {
                    *size as usize
                } else {
                    data.len()
                };
                rows.push((
                    names.add(name),
                    *kind,
                    *flags,
                    *address,
                    offset,
                    size,
                    0,
                    0,
                    0,
                ));
            }
            let symtab_index = rows.len() as u32 + 1;
            let mut table = Out(vec![0; SYM_SIZE]);
            for (name, value, size, info, section) in &self.symbols {
                table.u32(strings.add(name));
                table.u32(*value);
                table.u32(*size);
                table.u8(*info);
                table.u8(0);
                table.u16(*section);
            }
            file.align(4);
            rows.push((
                names.add(".symtab"),
                SHT_SYMTAB,
                0,
                0,
                file.0.len(),
                table.0.len(),
                symtab_index + 1,
                0,
                SYM_SIZE as u32,
            ));
            file.0.extend_from_slice(&table.0);
            rows.push((
                names.add(".strtab"),
                SHT_STRTAB,
                0,
                0,
                file.0.len(),
                strings.0.len(),
                0,
                0,
                0,
            ));
            file.0.extend_from_slice(&strings.0);
            for (target, entries) in &self.relocations {
                file.align(4);
                let offset = file.0.len();
                for &(at, kind, symbol) in entries {
                    file.u32(at);
                    file.u32(symbol << 8 | kind as u32);
                }
                let target_name = &self.sections[target - 1].0;
                rows.push((
                    names.add(&format!(".rel{target_name}")),
                    SHT_REL,
                    0,
                    0,
                    offset,
                    entries.len() * REL_SIZE,
                    symtab_index,
                    *target as u32,
                    REL_SIZE as u32,
                ));
            }
            let shstrndx = rows.len() + 1;
            let name = names.add(".shstrtab");
            rows.push((name, SHT_STRTAB, 0, 0, file.0.len(), 0, 0, 0, 0));
            let names_offset = file.0.len();
            file.0.extend_from_slice(&names.0);
            rows.last_mut().unwrap().4 = names_offset;
            rows.last_mut().unwrap().5 = names.0.len();
            file.align(4);
            let shoff = file.0.len();
            file.0.resize(shoff + SHDR_SIZE, 0);
            for (name, kind, flags, address, offset, size, link, info, entry_size) in rows.iter() {
                for word in [
                    *name,
                    *kind,
                    *flags,
                    *address,
                    *offset as u32,
                    *size as u32,
                    *link,
                    *info,
                    4,
                    *entry_size,
                ] {
                    file.u32(word);
                }
            }
            let mut header = Out(IDENT.to_vec());
            header.0.resize(16, 0);
            header.u16(self.kind);
            header.u16(EM_386);
            header.u32(1);
            header.u32(self.entry);
            header.u32(0);
            header.u32(shoff as u32);
            header.u32(0);
            header.u16(EHDR_SIZE as u16);
            header.u16(0);
            header.u16(0);
            header.u16(SHDR_SIZE as u16);
            header.u16(rows.len() as u16 + 1);
            header.u16(shstrndx as u16);
            file.0[..EHDR_SIZE].copy_from_slice(&header.0);
            file.0
        }
    }

    /// The reader takes the file's header, sections, symbols and relocations as they were built.
    #[test]
    fn reads_what_was_built() {
        let built = Built {
            kind: ET_EXEC,
            entry: 0x8040_1000,
            sections: vec![
                (
                    ".text".into(),
                    SHT_PROGBITS,
                    SHF_ALLOC | SHF_EXECINSTR,
                    0x8040_1000,
                    vec![0x90; 8],
                    0,
                ),
                (
                    ".bss".into(),
                    SHT_NOBITS,
                    SHF_ALLOC | SHF_WRITE,
                    0x8040_2000,
                    Vec::new(),
                    0x2000,
                ),
            ],
            symbols: vec![
                ("start".into(), 0x8040_1000, 8, 0x12, 1),
                ("counter".into(), 0x8040_2000, 4, 0x11, 2),
            ],
            relocations: vec![(1, vec![(0x8040_1004, R_386_32, 2)])],
        };
        let bytes = built.bytes();
        let elf = Elf::parse(&bytes).unwrap();
        assert_eq!((elf.kind, elf.entry), (ET_EXEC, 0x8040_1000));
        let text = elf.section(".text").unwrap();
        assert_eq!((text.index, text.address, text.size), (1, 0x8040_1000, 8));
        assert_eq!(elf.data(text).unwrap(), &[0x90; 8]);
        let bss = elf.section(".bss").unwrap();
        assert_eq!((bss.kind, bss.size), (SHT_NOBITS, 0x2000));
        assert!(elf.data(bss).unwrap().is_empty());
        let counter = elf.symbol("counter").unwrap();
        assert_eq!(
            (counter.value, counter.kind(), counter.section),
            (0x8040_2000, STT_OBJECT, 2)
        );
        assert_eq!(elf.symbol("start").unwrap().kind(), STT_FUNC);
        let rel = elf.section(".rel.text").unwrap();
        assert_eq!(rel.info, 1);
        assert_eq!(
            elf.relocations(rel).unwrap(),
            [Relocation {
                offset: 0x8040_1004,
                kind: R_386_32,
                symbol: 2
            }]
        );
        assert!(Elf::parse(&bytes[..20]).is_err());
        let mut other = bytes.clone();
        other[18] = 62; // EM_X86_64
        assert!(Elf::parse(&other).unwrap_err().contains("EM_386"));
    }

    /// The image object: its contents in an allocated, page-aligned `.image`, the reservation after
    /// it without file data, and the symbols local to `.image` at their offsets, typed and sized.
    #[test]
    fn the_image_object_carries_the_image_and_its_symbols() {
        let contents = vec![0xAB; 0x2000];
        let symbols = [
            ObjectSymbol {
                name: "memcpy".into(),
                offset: 0x1010,
                size: 12,
                kind: STT_FUNC,
            },
            ObjectSymbol {
                name: "_RNvCs1_6kernel4BOOT".into(),
                offset: 0x1800,
                size: 64,
                kind: STT_OBJECT,
            },
        ];
        let bytes = image_object(&contents, 0x5000, &symbols);
        let elf = Elf::parse(&bytes).unwrap();
        assert_eq!(elf.kind, ET_REL);
        let image = elf.section(".image").unwrap();
        assert_eq!((image.kind, image.flags), (SHT_PROGBITS, SHF_ALLOC));
        assert_eq!(image.offset % 0x1000, 0);
        assert_eq!(elf.data(image).unwrap(), &contents[..]);
        let reserve = elf.section(".image_reserve").unwrap();
        assert_eq!((reserve.kind, reserve.size), (SHT_NOBITS, 0x5000));
        assert!(reserve.allocated());
        let symtab = elf.section(".symtab").unwrap();
        assert_eq!(
            symtab.info as usize,
            elf.symbols.len(),
            "every symbol is local"
        );
        let memcpy = elf.symbol("memcpy").unwrap();
        assert_eq!(
            (memcpy.value, memcpy.size, memcpy.info, memcpy.section),
            (0x1010, 12, STT_FUNC, image.index as u16)
        );
        let object = elf.symbol("_RNvCs1_6kernel4BOOT").unwrap();
        assert_eq!((object.value, object.kind()), (0x1800, STT_OBJECT));
    }
}
