//! The font table: the TrueType faces loaded (Windows 2000's physical font table: each face its
//! file's bytes, whom it is loaded for and how many loads hold it), the mapper's choice of a face
//! for a LOGFONT ([`FontTable::map`]), and the fonts realised from the faces at a size, each with
//! its glyph cache ([`FontTable::with_glyph`]).
//!
//! The table holds its storage through [`Storage`]: blocks of the nonpaged pool on the target (a
//! face's file, a realised font's cache), vectors in the host tests. The rasteriser's lent buffers
//! (an outline's points and contour ends, a scan line's crossings) are the table's own, as it is a
//! static's, never a stack's.
//!
//! A face whose strikes are all it draws ([`rtl::truetype::bitmap`]: Wine's System and MS Sans
//! Serif) is a raster-style one, realised as Windows 2000 realises a raster font: at the strike
//! nearest the height asked for, never scaled, a glyph its strike lacks drawn as the strike's
//! missing glyph.
//!
//! A realised font is a face at an em size, emboldened or not. Its cache is direct-mapped: a glyph
//! goes to the slot its index picks, its GLYPHMETRICS and its GGO_BITMAP rows there, displacing
//! whatever glyph was in it. A glyph whose rows do not fit a slot is rendered each time it is
//! drawn, into a block of its own. The table keeps [`REALIZED`] fonts at once, the least recently
//! used one making way for a new one (Windows 2000 keeps a realised font per font object and DC;
//! keying it by its face and size shares one between the font objects that ask the same, the same
//! glyphs in it). A process's end empties every realised font, its cache's pages given back: a
//! cache is the processes' working state, and one outliving them would read, in the teardown's
//! audit of the frames, as the last one's leak; the next text realises its font again.

use rtl::gdi::{LogFontW, FW_NORMAL};
use rtl::pod::Pod;
use rtl::truetype::bitmap;
use rtl::truetype::glyf::Point;
use rtl::truetype::glyph::{self, GlyphMetrics, Options, Rendered, Workspace};
use rtl::truetype::metrics::{self, emboldens};
use rtl::truetype::raster::Crossing;
use rtl::truetype::{Error, Font};

use super::mapper::{self, FaceName, Name};

/// What the table's storage is: a block of bytes, its length the one asked for, zeroed.
pub trait Storage: AsRef<[u8]> + AsMut<[u8]> + Sized {
    /// A block of `bytes` bytes; none when there is no room.
    fn allocate(bytes: usize) -> Option<Self>;
}

/// How many faces can be loaded at once.
pub const FACES: usize = 16;
/// How many realised fonts the table keeps.
pub const REALIZED: usize = 8;
/// A realised font's cache: its slots, and each slot's bytes (the GLYPHMETRICS and the bitmap's
/// size, then the bitmap).
pub const CACHE_SLOTS: usize = 64;
const SLOT_BYTES: usize = 512;
const SLOT_HEADER: usize = core::mem::size_of::<GlyphMetrics>() + 4;
/// The largest bitmap a cache slot holds.
pub const SLOT_BITS: usize = SLOT_BYTES - SLOT_HEADER;

/// The rasteriser's buffers: an outline's points and contour ends, a scan line's crossings.
const POINTS: usize = 1024;
const CONTOURS: usize = 128;
const CROSSINGS: usize = 512;

/// A file's identity on the volume: its directory entry's (the directory's first cluster and the
/// entry's index there), which a removal names it by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileIdentity {
    pub parent_cluster: u32,
    pub index: u32,
}

/// Whom a face is loaded for: every process (a public load, or the boot's), or one alone
/// (AddFontResourceEx's FR_PRIVATE), by its process object's index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Owner {
    Public,
    Private(u16),
}

impl Owner {
    /// Whether a face loaded for `self` is visible to the process `process`.
    fn sees(self, process: u16) -> bool {
        match self {
            Owner::Public => true,
            Owner::Private(owner) => owner == process,
        }
    }
}

/// A loaded face: its file's bytes, where the file is, whom it is loaded for and how many loads
/// hold it, its names (from its naming table: the family, the style, the full name, the unique
/// name; OUTLINETEXTMETRIC's face name is the full one, its "full" name the unique one), its own
/// weight, and whether it is a raster-style face (see the module notes).
pub struct Face<B> {
    file: B,
    identity: FileIdentity,
    owner: Owner,
    loads: u32,
    pub weight: i32,
    pub raster: bool,
    pub family: FaceName,
    pub style: FaceName,
    pub full: Name<64>,
    pub unique: Name<64>,
}

impl<B: Storage> Face<B> {
    /// The face's font: its file, read (the table checked it reads when the face was loaded).
    pub fn font(&self) -> Option<Font<'_>> {
        Font::new(self.file.as_ref()).ok()
    }

    /// The file's bytes: GetFontData's whole file.
    pub fn bytes(&self) -> &[u8] {
        self.file.as_ref()
    }
}

/// A face's name in the table: its slot and the slot's generation (a slot reused for another face
/// names another).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaceId {
    slot: u8,
    generation: u16,
}

/// A font realised at a size: its face, its em, whether it is emboldened, and whether its face is
/// a raster-style one (its em one of its strikes'; it has no outline metrics, no font data and no
/// ABC widths, as a raster font has none).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key {
    pub face: FaceId,
    pub ppem: u16,
    pub bold: bool,
    pub raster: bool,
}

/// What a LOGFONT realises to for a process: a TrueType face at a size, or the built-in font; and
/// the name GetTextFace answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Realization {
    BuiltIn {
        name: FaceName,
    },
    TrueType {
        key: Key,
        /// The character set it answers (TEXTMETRIC's tmCharSet).
        char_set: u8,
        name: FaceName,
    },
}

impl Realization {
    /// GetTextFace's answer.
    pub fn name(&self) -> &FaceName {
        match self {
            Realization::BuiltIn { name } | Realization::TrueType { name, .. } => name,
        }
    }
}

/// Why a face could not be added.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddError {
    /// The file is no TrueType font this engine reads.
    NotAFont,
    /// The table is full.
    Full,
}

/// A realised font of the table: its key, when it was last used, its cache (made at its first
/// glyph) and the glyph each slot holds (none: [`EMPTY_SLOT`]).
struct Realized<B> {
    key: Option<Key>,
    used: u32,
    cache: Option<B>,
    glyphs: [u32; CACHE_SLOTS],
}

const EMPTY_SLOT: u32 = u32::MAX;

impl<B> Realized<B> {
    const fn empty() -> Self {
        Realized {
            key: None,
            used: 0,
            cache: None,
            glyphs: [EMPTY_SLOT; CACHE_SLOTS],
        }
    }
}

/// The rasteriser's buffers, the table's own.
struct Buffers {
    points: [Point; POINTS],
    contour_ends: [u16; CONTOURS],
    crossings: [Crossing; CROSSINGS],
}

impl Buffers {
    fn workspace(&mut self) -> Workspace<'_> {
        Workspace {
            points: &mut self.points,
            contour_ends: &mut self.contour_ends,
            crossings: &mut self.crossings,
        }
    }
}

/// The font table (see the module notes).
pub struct FontTable<B> {
    faces: [Option<Face<B>>; FACES],
    generations: [u16; FACES],
    realized: [Realized<B>; REALIZED],
    clock: u32,
    buffers: Buffers,
}

impl<B: Storage> Default for FontTable<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: Storage> FontTable<B> {
    /// An empty table.
    pub const fn new() -> Self {
        FontTable {
            faces: [const { None }; FACES],
            generations: [0; FACES],
            realized: [const { Realized::empty() }; REALIZED],
            clock: 0,
            buffers: Buffers {
                points: [Point {
                    x: 0,
                    y: 0,
                    flags: 0,
                }; POINTS],
                contour_ends: [0; CONTOURS],
                crossings: [Crossing {
                    position: 0,
                    winding: 0,
                }; CROSSINGS],
            },
        }
    }

    /// The face `id` names, while it is loaded.
    pub fn face(&self, id: FaceId) -> Option<&Face<B>> {
        let slot = id.slot as usize;
        (self.generations.get(slot) == Some(&id.generation))
            .then(|| self.faces[slot].as_ref())
            .flatten()
    }

    /// Another load of the face of the file `identity` for `owner`, when one is loaded: its loads
    /// one more, and whether it was there (a file already loaded is not read again).
    pub fn load_again(&mut self, identity: FileIdentity, owner: Owner) -> bool {
        match self.loaded(identity, owner) {
            Some(slot) => {
                let face = self.faces[slot].as_mut().expect("a loaded face");
                face.loads = face.loads.saturating_add(1);
                true
            }
            None => false,
        }
    }

    fn loaded(&self, identity: FileIdentity, owner: Owner) -> Option<usize> {
        self.faces.iter().position(|face| {
            face.as_ref()
                .is_some_and(|face| face.identity == identity && face.owner == owner)
        })
    }

    /// Load the face the file `file` holds, from `identity`, for `owner` (one load): the faces it
    /// added (a TrueType file holds one). See [`FontTable::load_again`] for a file already loaded,
    /// which the caller asks first.
    pub fn add(&mut self, file: B, identity: FileIdentity, owner: Owner) -> Result<u32, AddError> {
        if self.load_again(identity, owner) {
            return Ok(1);
        }
        let (family, style, full, unique, weight, raster) = {
            let font = Font::new(file.as_ref()).map_err(|_| AddError::NotAFont)?;
            let os2 = font.os2().ok().flatten();
            let names = font.name().ok().flatten();
            let read = |id: u16| {
                names
                    .and_then(|names| names.windows_string(id))
                    .filter(|record| record.is_utf16())
            };
            let family = read(1).ok_or(AddError::NotAFont)?;
            let style = read(2);
            let full = read(4).unwrap_or(family);
            let unique = read(3).unwrap_or(full);
            (
                FaceName::of(family.utf16()),
                style.map_or(FaceName::ascii("Regular"), |record| {
                    FaceName::of(record.utf16())
                }),
                Name::of(full.utf16()),
                Name::of(unique.utf16()),
                metrics::weight(&font, os2.as_ref()),
                bitmap::is_bitmap_only(&font),
            )
        };
        let slot = self
            .faces
            .iter()
            .position(Option::is_none)
            .ok_or(AddError::Full)?;
        self.generations[slot] = self.generations[slot].wrapping_add(1);
        self.faces[slot] = Some(Face {
            file,
            identity,
            owner,
            loads: 1,
            weight,
            raster,
            family,
            style,
            full,
            unique,
        });
        Ok(1)
    }

    /// One load of the face of the file `identity` for `owner` removed (the face goes with its
    /// last, and the fonts realised from it); whether there was one.
    pub fn remove(&mut self, identity: FileIdentity, owner: Owner) -> bool {
        let Some(slot) = self.loaded(identity, owner) else {
            return false;
        };
        let face = self.faces[slot].as_mut().expect("a loaded face");
        face.loads -= 1;
        if face.loads == 0 {
            self.unload(slot);
        }
        true
    }

    /// The face in `slot` goes, and the fonts realised from it (their caches kept for reuse).
    fn unload(&mut self, slot: usize) {
        self.faces[slot] = None;
        for realized in &mut self.realized {
            if realized
                .key
                .is_some_and(|key| key.face.slot as usize == slot)
            {
                realized.key = None;
            }
        }
    }

    /// The process `process` ended: the faces loaded for it alone go (a private font is its
    /// process's, as on Windows 2000), and every realised font with its cache (see the module
    /// notes).
    pub fn end_process(&mut self, process: u16) {
        for slot in 0..FACES {
            let private = self.faces[slot]
                .as_ref()
                .is_some_and(|face| face.owner == Owner::Private(process));
            if private {
                self.unload(slot);
            }
        }
        for realized in &mut self.realized {
            *realized = Realized::empty();
        }
    }

    /// The face of the family `name` that `process` sees for a request of `weight`: a bold one
    /// (its own weight FW_SEMIBOLD or more) for a bold request, a lighter one for another, when
    /// the family has one; else its first face.
    pub fn find(&self, name: &[u16], process: u16, weight: i32) -> Option<FaceId> {
        let bold = mapper::asks_bold(weight);
        let mut family = self
            .visible(process)
            .filter(|(_, face)| mapper::same_name(face.family.units(), name));
        let (first, face) = family.next()?;
        if mapper::asks_bold(face.weight) == bold {
            return Some(first);
        }
        Some(
            family
                .find(|(_, face)| mapper::asks_bold(face.weight) == bold)
                .map_or(first, |(id, _)| id),
        )
    }

    /// The faces `process` sees, in the table's order.
    pub fn visible(&self, process: u16) -> impl Iterator<Item = (FaceId, &Face<B>)> + '_ {
        self.faces
            .iter()
            .enumerate()
            .filter_map(move |(slot, face)| {
                let face = face.as_ref().filter(|face| face.owner.sees(process))?;
                Some((
                    FaceId {
                        slot: slot as u8,
                        generation: self.generations[slot],
                    },
                    face,
                ))
            })
    }

    /// What `log_font` realises to for `process` (see [`super::mapper`]): the face its name asks
    /// for (through a substitute or a stand-in), of the style its weight asks for, at the em its
    /// height asks for (a raster-style face's nearest strike), emboldened when its weight asks a
    /// lighter face for bold; for a name no face of the process's has, the default face, or the
    /// built-in font.
    pub fn map(&self, log_font: &LogFontW, process: u16) -> Realization {
        let asked = log_font.face();
        let weight = if log_font.weight == 0 {
            FW_NORMAL
        } else {
            log_font.weight
        };
        let substitute = mapper::substitute(asked);
        let target = substitute.map_or(FaceName::of(asked.iter().copied()), FaceName::ascii);
        let mut found = self.find(target.units(), process, weight);
        let mut stood_in = false;
        if found.is_none() {
            if let Some(stand_in) = mapper::stand_in(target.units()) {
                found = self.find(FaceName::ascii(stand_in).units(), process, weight);
                stood_in = found.is_some();
            }
        }
        // A substitute's name, or a stand-in's, is answered as asked, whatever face it reaches.
        let as_asked = substitute.is_some() || stood_in;
        let built_in = Realization::BuiltIn {
            name: if substitute.is_some() {
                FaceName::of(asked.iter().copied())
            } else {
                FaceName::ascii(mapper::BUILT_IN_FACE)
            },
        };
        let found = found.or_else(|| {
            if mapper::asks_fixed_pitch(log_font) {
                return None;
            }
            let default = FaceName::ascii(mapper::DEFAULT_FACE);
            self.find(default.units(), process, weight)
        });
        let Some(id) = found else {
            return built_in;
        };
        let face = self.face(id).expect("a face just found");
        let Some(font) = face.font() else {
            return built_in;
        };
        let height = mapper::height(log_font.height);
        let ppem = if face.raster {
            bitmap::strike_for_height(&font, height).ok().flatten()
        } else {
            glyph::ppem_for_height(&font, height).ok()
        };
        let Some(ppem) = ppem else {
            return built_in;
        };
        let os2 = font.os2().ok().flatten();
        let signature = metrics::signature(&font).unwrap_or_default();
        Realization::TrueType {
            key: Key {
                face: id,
                ppem: ppem.max(1),
                bold: emboldens(&font, os2.as_ref(), weight),
                raster: face.raster,
            },
            char_set: metrics::realised_char_set(&signature, log_font.char_set),
            name: if as_asked {
                FaceName::of(asked.iter().copied())
            } else {
                face.family
            },
        }
    }

    /// The glyph each of `units` maps to in the face of `key` (0, the missing glyph, for a
    /// character it lacks; a symbol font's characters at U+F000 and up, as its codes are), into
    /// `glyphs`; none when the face is gone.
    pub fn glyph_indices(&self, face: FaceId, units: &[u16], glyphs: &mut [u16]) -> Option<()> {
        let font = self.face(face)?.font()?;
        let subtable = font
            .cmap()
            .ok()
            .and_then(|cmap| cmap.unicode().ok().flatten());
        for (unit, glyph) in units.iter().zip(glyphs.iter_mut()) {
            *glyph = match &subtable {
                Some(subtable) => {
                    let symbol = subtable.platform_id == 3 && subtable.encoding_id == 0;
                    let code = if symbol && *unit < 0x100 {
                        0xF000 | *unit as u32
                    } else {
                        *unit as u32
                    };
                    subtable.glyph(code)
                }
                None => 0,
            };
        }
        Some(())
    }

    /// Glyph `glyph` of the realised font `key` rendered into `out` (GGO_BITMAP's layout), or
    /// measured when `out` is empty: its GLYPHMETRICS and its bitmap's size, emboldened as the
    /// key asks. None when the face is gone; the rasteriser's error for a glyph it cannot render
    /// (or an `out` too small).
    pub fn render(
        &mut self,
        key: Key,
        glyph: u16,
        out: &mut [u8],
    ) -> Option<Result<Rendered, Error>> {
        let FontTable {
            faces,
            generations,
            buffers,
            ..
        } = self;
        let slot = key.face.slot as usize;
        if generations[slot] != key.face.generation {
            return None;
        }
        let font = faces[slot].as_ref()?.font()?;
        Some(render(&font, key, glyph, &mut buffers.workspace(), out))
    }

    /// Run `f` on glyph `glyph` of the realised font `key`: its GLYPHMETRICS (emboldened as the
    /// key asks) and its GGO_BITMAP rows, from the font's cache (rendered into it first when it
    /// is not there). None when the face is gone, or the glyph cannot be rendered (a blank glyph
    /// then, its advance its hmtx width).
    pub fn with_glyph<R>(
        &mut self,
        key: Key,
        glyph: u16,
        f: impl FnOnce(&GlyphMetrics, &[u8]) -> R,
    ) -> Option<R> {
        self.clock = self.clock.wrapping_add(1);
        let clock = self.clock;
        let FontTable {
            faces,
            generations,
            realized,
            buffers,
            ..
        } = self;
        let slot = key.face.slot as usize;
        if generations[slot] != key.face.generation {
            return None;
        }
        let font = faces[slot].as_ref()?.font()?;
        let realized = realize(realized, key, clock)?;
        let cache = realized.cache.as_mut()?.as_mut();
        let index = glyph as usize % CACHE_SLOTS;
        let entry = &mut cache[index * SLOT_BYTES..(index + 1) * SLOT_BYTES];
        let (header, bits) = entry.split_at_mut(SLOT_HEADER);
        if realized.glyphs[index] != glyph as u32 {
            realized.glyphs[index] = EMPTY_SLOT;
            let sized = render(&font, key, glyph, &mut buffers.workspace(), &mut []).ok()?;
            if sized.size > SLOT_BITS {
                // Too large for a slot: rendered into a block of its own, uncached.
                let mut block = B::allocate(sized.size)?;
                let done =
                    render(&font, key, glyph, &mut buffers.workspace(), block.as_mut()).ok()?;
                return Some(f(&done.metrics, &block.as_ref()[..done.size]));
            }
            let done = render(&font, key, glyph, &mut buffers.workspace(), bits).ok()?;
            header[..SLOT_HEADER - 4].copy_from_slice(done.metrics.as_bytes());
            header[SLOT_HEADER - 4..].copy_from_slice(&(done.size as u32).to_le_bytes());
            realized.glyphs[index] = glyph as u32;
        }
        let metrics = GlyphMetrics::from_bytes(header)?;
        let size = u32::from_le_bytes(header[SLOT_HEADER - 4..].try_into().ok()?) as usize;
        Some(f(&metrics, &bits[..size]))
    }

    /// Glyph `glyph`'s advance in the realised font `key`, in whole pixels; 0 when the face is
    /// gone.
    pub fn advance(&mut self, key: Key, glyph: u16) -> i32 {
        self.with_glyph(key, glyph, |metrics, _| metrics.cell_inc_x as i32)
            .unwrap_or(0)
    }
}

/// The realised font for `key` among `realized`: its own when it is there, else the least
/// recently used one made it (its cache emptied, and made when it has none); used at `clock`.
/// None when a cache cannot be had.
fn realize<B: Storage>(
    realized: &mut [Realized<B>; REALIZED],
    key: Key,
    clock: u32,
) -> Option<&mut Realized<B>> {
    let index = match realized.iter().position(|each| each.key == Some(key)) {
        Some(index) => index,
        None => {
            let index = realized
                .iter()
                .enumerate()
                .min_by_key(|(_, each)| (each.key.is_some(), each.used))
                .map(|(index, _)| index)?;
            let chosen = &mut realized[index];
            if chosen.cache.is_none() {
                chosen.cache = Some(B::allocate(CACHE_SLOTS * SLOT_BYTES)?);
            }
            chosen.key = Some(key);
            chosen.glyphs = [EMPTY_SLOT; CACHE_SLOTS];
            index
        }
    };
    let chosen = &mut realized[index];
    chosen.used = clock;
    Some(chosen)
}

/// Glyph `glyph` of `font` as the realised font `key` draws it, into `out` (empty: measured).
fn render(
    font: &Font,
    key: Key,
    glyph: u16,
    workspace: &mut Workspace,
    out: &mut [u8],
) -> Result<Rendered, Error> {
    let glyph = if glyph >= font.glyph_count() {
        0
    } else {
        glyph
    };
    let options = Options::new(key.ppem);
    // A raster-style face draws its strike alone: a glyph the strike lacks is its missing glyph.
    let missing = key.raster && !matches!(glyph::strike_glyph(font, glyph, key.ppem), Ok(Some(_)));
    let glyph = if missing { 0 } else { glyph };
    if !key.bold {
        return glyph::render(font, glyph, &options, workspace, out);
    }
    let plain = glyph::render(font, glyph, &options, workspace, &mut [])?;
    let wider = metrics::embolden(plain, None).ok_or(Error::BufferTooSmall)?;
    if out.is_empty() {
        return Ok(wider);
    }
    let room = out
        .get_mut(..wider.size.max(plain.size))
        .ok_or(Error::BufferTooSmall)?;
    let drawn = glyph::render(font, glyph, &options, workspace, room)?;
    metrics::embolden(drawn, Some(room)).ok_or(Error::BufferTooSmall)
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use rtl::gdi::{LogFontW, DEFAULT_CHARSET};

    use super::*;

    impl Storage for Vec<u8> {
        fn allocate(bytes: usize) -> Option<Self> {
            Some(std::vec![0; bytes])
        }
    }

    type Table = FontTable<Vec<u8>>;

    fn fixture_font() -> Vec<u8> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tests/gdi32/ttfont/f2ktahom.ttf"
        );
        std::fs::read(path).unwrap()
    }

    fn wine_font() -> Vec<u8> {
        std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../fonts/tahoma.ttf")).unwrap()
    }

    fn table() -> std::boxed::Box<Table> {
        std::boxed::Box::new(Table::new())
    }

    const FILE: FileIdentity = FileIdentity {
        parent_cluster: 7,
        index: 3,
    };
    const OTHER: FileIdentity = FileIdentity {
        parent_cluster: 7,
        index: 4,
    };

    fn log_font(face: &str, height: i32, weight: i32) -> LogFontW {
        let mut font = LogFontW::zeroed();
        font.height = height;
        font.weight = weight;
        font.char_set = DEFAULT_CHARSET;
        for (unit, byte) in font.face_name.iter_mut().zip(face.encode_utf16()) {
            *unit = byte;
        }
        font
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    /// The capture's load section: a private load twice, two removals, a third refused; a
    /// public load and its removal; the face found by its family name, without regard to case.
    #[test]
    fn loads_count_and_removals_take_them() {
        let mut table = table();
        assert_eq!(table.add(fixture_font(), FILE, Owner::Private(5)), Ok(1));
        assert!(table.load_again(FILE, Owner::Private(5)));
        assert!(table.find(&wide("f2k tahoma"), 5, FW_NORMAL).is_some());
        assert!(
            table.find(&wide("F2K Tahoma"), 6, FW_NORMAL).is_none(),
            "another process's"
        );
        assert!(table.remove(FILE, Owner::Private(5)));
        assert!(
            table.find(&wide("F2K Tahoma"), 5, FW_NORMAL).is_some(),
            "one load left"
        );
        assert!(table.remove(FILE, Owner::Private(5)));
        assert!(!table.remove(FILE, Owner::Private(5)), "gone");
        assert!(table.find(&wide("F2K Tahoma"), 5, FW_NORMAL).is_none());
        assert!(!table.remove(FILE, Owner::Public), "never loaded publicly");

        assert_eq!(table.add(fixture_font(), FILE, Owner::Public), Ok(1));
        let id = table.find(&wide("F2K Tahoma"), 9, FW_NORMAL).unwrap();
        let face = table.face(id).unwrap();
        assert_eq!(face.style.units(), wide("Regular"));
        assert_eq!(face.full.units(), wide("F2K Tahoma"));
        assert_eq!(face.bytes().len(), 143_612);
        assert!(table.remove(FILE, Owner::Public));
        assert!(table.face(id).is_none(), "the id is stale");
        assert_eq!(
            table.add(std::vec![0; 100], OTHER, Owner::Public),
            Err(AddError::NotAFont)
        );
    }

    /// A process's private faces go with it; another's and the public ones stay.
    #[test]
    fn a_private_face_goes_with_its_process() {
        let mut table = table();
        table.add(fixture_font(), FILE, Owner::Private(5)).unwrap();
        table.add(wine_font(), OTHER, Owner::Public).unwrap();
        let Realization::TrueType { key, .. } = table.map(&log_font("Tahoma", -11, 400), 6) else {
            panic!("Tahoma");
        };
        assert!(table.advance(key, 36) > 0);
        assert!(table
            .realized
            .iter()
            .any(|realized| realized.cache.is_some()));
        table.end_process(6);
        assert!(
            table
                .realized
                .iter()
                .all(|realized| realized.cache.is_none()),
            "the caches go with a process's end"
        );
        assert!(table.find(&wide("F2K Tahoma"), 5, FW_NORMAL).is_some());
        table.end_process(5);
        assert!(table.find(&wide("F2K Tahoma"), 5, FW_NORMAL).is_none());
        assert!(table.find(&wide("Tahoma"), 5, FW_NORMAL).is_some());
    }

    /// The mapper: the face's own name at its em, a bold request emboldened; the dialog face's
    /// substitute through Tahoma, answering the name asked for; an unknown name and an empty one
    /// the built-in font; a positive height a cell, 0 the default cell.
    #[test]
    fn the_mapper_chooses_a_face_and_a_size() {
        let mut table = table();
        table.add(fixture_font(), FILE, Owner::Private(5)).unwrap();
        let Realization::TrueType {
            key,
            char_set,
            name,
        } = table.map(&log_font("F2K Tahoma", -11, 400), 5)
        else {
            panic!("a TrueType face");
        };
        assert_eq!((key.ppem, key.bold, char_set), (11, false, 0));
        assert_eq!(name.units(), wide("F2K Tahoma"));
        let Realization::TrueType { key, .. } = table.map(&log_font("F2K Tahoma", 16, 700), 5)
        else {
            panic!("a TrueType face");
        };
        assert_eq!((key.ppem, key.bold), (13, true));
        let Realization::TrueType { key, .. } = table.map(&log_font("F2K Tahoma", 0, 0), 5) else {
            panic!("a TrueType face");
        };
        assert_eq!(key.ppem, 13, "the default cell of 16");
        for unknown in ["F2K No Such Face", ""] {
            assert_eq!(
                table.map(&log_font(unknown, -11, 400), 5),
                Realization::BuiltIn {
                    name: FaceName::ascii("System")
                }
            );
        }
        let dialog = table.map(&log_font("MS Shell Dlg 2", -11, 400), 5);
        let Realization::BuiltIn { name } = dialog else {
            panic!("no Tahoma yet: {dialog:?}");
        };
        assert_eq!(name.units(), wide("MS Shell Dlg 2"), "the name as asked");
        table.add(wine_font(), OTHER, Owner::Public).unwrap();
        let dialog = table.map(&log_font("MS Shell Dlg 2", -11, 400), 5);
        let Realization::TrueType { key, name, .. } = dialog else {
            panic!("Tahoma");
        };
        assert_eq!(name.units(), wide("MS Shell Dlg 2"));
        assert_eq!(table.face(key.face).unwrap().family.units(), wide("Tahoma"));
    }

    /// Glyphs come from the cache once rendered: the same metrics and rows each time, and as the
    /// rasteriser renders them; an emboldened glyph is a pixel wider; a character the face lacks
    /// is the missing glyph.
    #[test]
    fn glyphs_come_through_the_cache() {
        let mut table = table();
        table.add(fixture_font(), FILE, Owner::Public).unwrap();
        let Realization::TrueType { key, .. } = table.map(&log_font("F2K Tahoma", -11, 400), 1)
        else {
            panic!("a TrueType face");
        };
        let mut glyphs = [0u16; 3];
        table
            .glyph_indices(key.face, &wide("A\u{4E00}Z"), &mut glyphs)
            .unwrap();
        assert_ne!(glyphs[0], 0);
        assert_eq!(glyphs[1], 0, "the missing glyph");
        let first = table
            .with_glyph(key, glyphs[0], |metrics, bits| (*metrics, bits.to_vec()))
            .unwrap();
        assert_eq!(
            (first.0.black_box_x, first.0.black_box_y, first.0.cell_inc_x),
            (6, 8, 7)
        );
        assert_eq!(first.1[..4], [0x30, 0, 0, 0], "the strike's 'A', row 0");
        let again = table
            .with_glyph(key, glyphs[0], |metrics, bits| (*metrics, bits.to_vec()))
            .unwrap();
        assert_eq!(first, again);
        assert_eq!(table.advance(key, glyphs[1]), 11, "the missing glyph's em");
        let bold = Key { bold: true, ..key };
        assert_eq!(table.advance(bold, glyphs[0]), 8);
        let wide_a = table
            .with_glyph(bold, glyphs[0], |metrics, bits| (*metrics, bits.to_vec()))
            .unwrap();
        assert_eq!(wide_a.0.black_box_x, 7);
        assert_eq!(wide_a.1[0], 0x38, "row 0's two pixels a pixel wider");
        let mut out = std::vec![0u8; 64];
        let rendered = table.render(key, glyphs[0], &mut out).unwrap().unwrap();
        assert_eq!(rendered.size, 32);
        assert_eq!(&out[..32], &first.1[..32]);
        // The face gone, its realised fonts go.
        assert!(table.remove(FILE, Owner::Public));
        assert!(table.with_glyph(key, glyphs[0], |_, _| ()).is_none());
    }

    /// More realised fonts than the table keeps: the least recently used one makes way, and a
    /// large glyph is drawn without the cache.
    #[test]
    fn realised_fonts_make_way() {
        let mut table = table();
        table.add(fixture_font(), FILE, Owner::Public).unwrap();
        let Realization::TrueType { key, .. } = table.map(&log_font("F2K Tahoma", -11, 400), 1)
        else {
            panic!("a TrueType face");
        };
        let mut glyphs = [0u16; 1];
        table
            .glyph_indices(key.face, &wide("W"), &mut glyphs)
            .unwrap();
        for ppem in 10..30 {
            let key = Key { ppem, ..key };
            assert!(table.advance(key, glyphs[0]) > 0);
        }
        let big = Key { ppem: 120, ..key };
        let size = table
            .with_glyph(big, glyphs[0], |_, bits| bits.len())
            .unwrap();
        assert!(size > SLOT_BITS, "{size}");
    }
}
