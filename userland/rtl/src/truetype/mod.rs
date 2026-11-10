//! TrueType fonts, read from a file's bytes as the TrueType and OpenType specifications lay them
//! out: win32k's font driver reads its faces through this module, as Windows 2000's TrueType
//! driver reads the files it maps.
//!
//! A [`Font`] is a view of the whole file in a slice. Its tables are found through the directory
//! ([`directory`]) and read on demand, each by its own module: the fixed-layout headers
//! ([`header`]: `head`, `hhea`, `maxp`, `OS/2`, `post`), the names ([`name`]), the character map
//! ([`cmap`]), the horizontal metrics ([`hmtx`]), the per-size tables ([`device`]: `hdmx`, `VDMX`,
//! `gasp`), the outlines ([`glyf`]: `loca` and `glyf`, in the units [`scale`] gives) and the
//! embedded bitmaps ([`embedded`]: `EBLC` and `EBDT`). A glyph at a size, as GetGlyphOutline
//! answers for it ([`glyph`]), comes from a strike or from its outline, scan-converted by
//! [`raster`].
//!
//! A font file is untrusted input: every read is bounded by the slice ([`read`]), and a file that
//! is truncated, points past its end or nests its composites without end gives an [`Error`],
//! never a panic or a read outside it. Nothing here allocates: an outline lands in buffers its
//! caller lends.

pub mod cmap;
pub mod device;
pub mod directory;
pub mod embedded;
pub mod glyf;
pub mod glyph;
pub mod header;
pub mod hmtx;
pub mod metrics;
pub mod name;
pub mod raster;
mod read;
pub mod scale;

use cmap::Cmap;
use device::{Gasp, Hdmx, Vdmx};
use directory::Directory;
use embedded::Strikes;
use glyf::Glyphs;
use header::{Head, Hhea, Maxp, Os2, Post};
use hmtx::Hmtx;
use name::Name;

/// Why a font, or a part of it, cannot be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A read past the end of the file, or of the table or subtable it lies in.
    Truncated,
    /// A table the font must have, which it lacks.
    MissingTable(Tag),
    /// A value the format does not allow: a wrong magic number or version, offsets that run
    /// backwards, a point index past its glyph's points.
    Malformed,
    /// A format this reader does not read: a TrueType collection, CFF outlines, composite
    /// embedded bitmaps.
    Unsupported,
    /// A composite glyph nested deeper than [`glyf::MAX_COMPONENT_DEPTH`] (one that contains
    /// itself), or one whose components number more than [`glyf::MAX_COMPONENTS`] in all.
    CompositeTooDeep,
    /// A glyph index past the font's last glyph.
    BadGlyph,
    /// A buffer the caller lent is too small for what was asked of it.
    BufferTooSmall,
}

/// A table's tag: four ASCII characters, as a big-endian 32-bit value (GetFontData's dwTable is
/// the same four bytes read little-endian).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tag(pub u32);

impl Tag {
    pub const CMAP: Self = Self::new(b"cmap");
    pub const EBDT: Self = Self::new(b"EBDT");
    pub const EBLC: Self = Self::new(b"EBLC");
    pub const FPGM: Self = Self::new(b"fpgm");
    pub const GASP: Self = Self::new(b"gasp");
    pub const GLYF: Self = Self::new(b"glyf");
    pub const HDMX: Self = Self::new(b"hdmx");
    pub const HEAD: Self = Self::new(b"head");
    pub const HHEA: Self = Self::new(b"hhea");
    pub const HMTX: Self = Self::new(b"hmtx");
    pub const LOCA: Self = Self::new(b"loca");
    pub const MAXP: Self = Self::new(b"maxp");
    pub const NAME: Self = Self::new(b"name");
    pub const OS2: Self = Self::new(b"OS/2");
    pub const POST: Self = Self::new(b"post");
    pub const PREP: Self = Self::new(b"prep");
    pub const VDMX: Self = Self::new(b"VDMX");

    pub const fn new(name: &[u8; 4]) -> Self {
        Self(u32::from_be_bytes(*name))
    }

    /// Its four characters.
    pub const fn bytes(&self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

impl core::fmt::Debug for Tag {
    fn fmt(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        let bytes = self.bytes();
        match core::str::from_utf8(&bytes) {
            Ok(text) => write!(formatter, "'{text}'"),
            Err(_) => write!(formatter, "{:#010x}", self.0),
        }
    }
}

/// A TrueType font: the whole file, its directory, and the headers every use of it reads (`head`,
/// `hhea`, `maxp`), parsed when it is opened. The other tables are parsed when asked for.
#[derive(Clone, Copy, Debug)]
pub struct Font<'a> {
    data: &'a [u8],
    directory: Directory<'a>,
    pub head: Head,
    pub hhea: Hhea,
    pub maxp: Maxp,
}

impl<'a> Font<'a> {
    /// The font the file `data` holds. Its directory, `head`, `hhea` and `maxp` must read, and its
    /// `hmtx` and `cmap` must be present.
    pub fn new(data: &'a [u8]) -> Result<Self, Error> {
        let directory = Directory::parse(data)?;
        let required = |tag| {
            directory
                .find(tag)
                .ok_or(Error::MissingTable(tag))?
                .bytes(data)
        };
        let font = Self {
            data,
            directory,
            head: Head::parse(required(Tag::HEAD)?)?,
            hhea: Hhea::parse(required(Tag::HHEA)?)?,
            maxp: Maxp::parse(required(Tag::MAXP)?)?,
        };
        required(Tag::HMTX)?;
        required(Tag::CMAP)?;
        Ok(font)
    }

    /// The whole file.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// The table directory.
    pub fn directory(&self) -> Directory<'a> {
        self.directory
    }

    /// The bytes of the table tagged `tag`, if the font has one: GetFontData's answer.
    pub fn table(&self, tag: Tag) -> Option<&'a [u8]> {
        // The directory checked every record against the file's length when it was parsed.
        self.directory.find(tag)?.bytes(self.data).ok()
    }

    /// The table tagged `tag`, which the font must have.
    fn required(&self, tag: Tag) -> Result<&'a [u8], Error> {
        self.table(tag).ok_or(Error::MissingTable(tag))
    }

    /// The number of glyphs (maxp's).
    pub fn glyph_count(&self) -> u16 {
        self.maxp.num_glyphs
    }

    /// The OS/2 and Windows metrics, if the font has them.
    pub fn os2(&self) -> Result<Option<Os2>, Error> {
        self.table(Tag::OS2).map(Os2::parse).transpose()
    }

    /// The PostScript table's header, if the font has one.
    pub fn post(&self) -> Result<Option<Post>, Error> {
        self.table(Tag::POST).map(Post::parse).transpose()
    }

    /// The naming table, if the font has one.
    pub fn name(&self) -> Result<Option<Name<'a>>, Error> {
        self.table(Tag::NAME).map(Name::parse).transpose()
    }

    /// The character map.
    pub fn cmap(&self) -> Result<Cmap<'a>, Error> {
        Cmap::parse(self.required(Tag::CMAP)?)
    }

    /// The horizontal metrics.
    pub fn hmtx(&self) -> Result<Hmtx<'a>, Error> {
        Hmtx::parse(
            self.required(Tag::HMTX)?,
            self.hhea.number_of_h_metrics,
            self.maxp.num_glyphs,
        )
    }

    /// The outlines (`loca` and `glyf`).
    pub fn glyphs(&self) -> Result<Glyphs<'a>, Error> {
        Glyphs::parse(
            self.required(Tag::LOCA)?,
            self.required(Tag::GLYF)?,
            self.head.index_to_loc_format,
            self.maxp.num_glyphs,
        )
    }

    /// The device metrics, if the font has them.
    pub fn hdmx(&self) -> Result<Option<Hdmx<'a>>, Error> {
        self.table(Tag::HDMX)
            .map(|data| Hdmx::parse(data, self.maxp.num_glyphs))
            .transpose()
    }

    /// The vertical device metrics, if the font has them.
    pub fn vdmx(&self) -> Result<Option<Vdmx<'a>>, Error> {
        self.table(Tag::VDMX).map(Vdmx::parse).transpose()
    }

    /// The grid-fitting and scan-conversion procedure, if the font has one.
    pub fn gasp(&self) -> Result<Option<Gasp<'a>>, Error> {
        self.table(Tag::GASP).map(Gasp::parse).transpose()
    }

    /// The embedded bitmap strikes, if the font has both their tables.
    pub fn strikes(&self) -> Result<Option<Strikes<'a>>, Error> {
        match (self.table(Tag::EBLC), self.table(Tag::EBDT)) {
            (Some(eblc), Some(ebdt)) => Strikes::parse(eblc, ebdt).map(Some),
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod glyph_tests;
#[cfg(test)]
mod tests;
