//! The bodies the directory holds for sections, image segments, window stations, desktops
//! and the named objects' directory, and what a view maps.

use super::*;

/// A section object's body: the mapping itself. A data section is its own segment: its frames are
/// its own, and a view names it by its object, so its frames outlive the handle that made it while
/// a view references it. An image section is a section of its file's one [`ImageSegment`]: it
/// holds the segment, and its views hold the segment, not the section.
#[derive(Clone, Copy)]
pub struct SectionObject {
    /// The mapped file, as its open found it (a file-backed section).
    pub file: crate::fs::fat32::lookup::File,
    /// Whether it is the paging file's (its pages start zeroed) rather than a file's.
    pub paging_file: bool,
    /// Whether a paging-file section was created SEC_RESERVE rather than SEC_COMMIT, as
    /// NtQuerySection reports it (its views' pages are made as they are touched all the same).
    pub reserve: bool,
    /// Its frames, page by page, made as views first need them.
    pub frames: crate::mem::vm::SectionFrames,
    /// The section's size in bytes.
    pub size: u32,
    /// Whether views may be writable (a read-write mapping).
    pub writable: bool,
    /// A file's section: the file object it holds (the file stays open while it is mapped).
    pub file_object: Option<ObjectId>,
    /// An image section's preferred base, where its one view maps (zero: a data section).
    pub image_base: u32,
    /// An image section's segment, which it holds a reference on (none: a data section).
    pub segment: Option<SegmentId>,
}

impl SectionObject {
    /// A record holding no mapping (a pool's fresh record).
    pub const fn none() -> Self {
        SectionObject {
            file: crate::fs::fat32::lookup::File::plain(0, 0, false),
            paging_file: true,
            reserve: false,
            frames: crate::mem::vm::SectionFrames::empty(),
            size: 0,
            writable: false,
            file_object: None,
            image_base: 0,
            segment: None,
        }
    }
}

/// An image segment: an image file's pages as mapped, shared by every image section of the file
/// and every view of them (NT's image control area and segment). A file has at most one, reached
/// from its record ([`crate::fs::file::FileRecord::image`], NT's section object pointers): the
/// first image section of the file makes it, and later ones share it, so every process's view of a
/// DLL maps the same frames (its writable pages copy-on-write). It holds the file object it was
/// made from — the file stays open, counted as mapped, while it lives.
///
/// It is active while an image section or a view references it. Its last reference leaves it
/// cached, as Windows 2000 keeps an image's control area once its last view goes: still its file's,
/// its frames parked on Standby ([`Followup::Park`]) where the allocator may take them, so the
/// file's next image section revives it and takes back the frames still its own without reading
/// the file. A cached segment is purged — its frames and its file given back — when its file is
/// cut, overwritten, written or deleted ([`Directory::purge_segment`]), when the table needs its
/// record for another image ([`Directory::make_room_for_segment`], the least recently cached
/// first), and at shutdown; it outlives quiescence, its file object and record the cache's, not
/// leaks ([`Directory::image_cache_settled`]). An active segment's file cannot be opened for
/// writing (`nt::section::flush_image_for_write`); a segment whose file changed all the same (a
/// write through a handle opened before the image was mapped) while it was active is
/// detached: no longer its file's, its last reference deletes it.
#[derive(Clone, Copy)]
pub struct ImageSegment {
    /// Its frames, page by page, made as views first need them.
    pub frames: crate::mem::vm::SectionFrames,
    /// The file object it holds.
    pub file_object: ObjectId,
    /// The image's preferred base, where every view maps it.
    pub image_base: u32,
    /// The image's size as mapped.
    pub size: u32,
    /// Whether it is no longer its file's (the file changed while it was active): its last
    /// reference deletes it instead of caching it.
    pub detached: bool,
    /// Whether its frames are parked on Standby (a cached segment's, once its caching finished).
    pub parked: bool,
    /// Its place in the order the cached segments were cached in: the least recent is the first
    /// to give its record up.
    pub(super) cached_at: u32,
}

impl ImageSegment {
    /// A record holding no segment (a pool's fresh record).
    pub(super) const fn none() -> Self {
        ImageSegment {
            frames: crate::mem::vm::SectionFrames::empty(),
            file_object: ObjectId {
                kind: ObjectType::File,
                index: 0,
                generation: 0,
            },
            image_base: 0,
            size: 0,
            detached: false,
            parked: false,
            cached_at: 0,
        }
    }

    /// An active segment of `file_object`'s image, its frames not made yet.
    pub const fn new(file_object: ObjectId, image_base: u32, size: u32) -> Self {
        ImageSegment {
            file_object,
            image_base,
            size,
            ..ImageSegment::none()
        }
    }

    /// How many pages the image spans as mapped.
    pub fn pages(&self) -> u32 {
        self.size.div_ceil(crate::mem::vm::PAGE)
    }
}

/// An image segment's name: its pool index and the generation of that record, so a name that
/// outlived its segment (a file record's, once the segment went) resolves to nothing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SegmentId {
    pub index: u16,
    pub generation: u16,
}

/// What a mapped view maps, and holds a reference on for as long as it is mapped: a data section,
/// or an image segment (the image section that made the view may be closed at once).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mapping {
    Section(ObjectId),
    Image(SegmentId),
}

/// A window station's body: its name (the window station's own, as GetUserObjectInformation's
/// UOI_NAME reports it; not bound in the namespace) and its flags (UOI_FLAGS' dwFlags:
/// WSF_VISIBLE for the interactive one).
#[derive(Clone, Copy)]
pub struct WindowStationObject {
    pub name: &'static str,
    pub flags: u32,
}

impl WindowStationObject {
    /// A record holding no window station (a pool's fresh record).
    pub const fn none() -> Self {
        WindowStationObject { name: "", flags: 0 }
    }
}

/// A desktop's body: its name (as UOI_NAME reports it) and its flags (UOI_FLAGS' dwFlags:
/// DF_ALLOWOTHERACCOUNTHOOK or none). There is one window station, so a desktop's is WinSta0.
#[derive(Clone, Copy)]
pub struct DesktopObject {
    pub name: &'static str,
    pub flags: u32,
}

impl DesktopObject {
    /// A record holding no desktop (a pool's fresh record).
    pub const fn none() -> Self {
        DesktopObject { name: "", flags: 0 }
    }
}

/// The named objects' directory's body: none (`\BaseNamedObjects` is the one there is).
#[derive(Clone, Copy)]
pub struct DirectoryObject;
