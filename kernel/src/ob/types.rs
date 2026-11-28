//! What a handle names: the object kinds, object ids, handle-table entries, and the
//! object manager's constants.

use crate::sched::thread::ThreadId;
use crate::sched::wait::WaitableId;

/// The kinds of objects a handle can name.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ObjectType {
    Event,
    Semaphore,
    Mutex,
    Timer,
    Thread,
    Process,
    Section,
    /// A file object: one open of a file or directory (see [`crate::fs::file`]).
    File,
    /// An object directory: `\BaseNamedObjects`, the one there is (permanent).
    Directory,
    /// A window station: win32k's, WinSta0 the one there is (permanent: made at boot; see
    /// [`crate::win32k`]).
    WindowStation,
    /// A desktop of a window station: WinSta0's Default, the one there is (permanent: made at
    /// boot).
    Desktop,
    /// A key object: one open of a registry key (see [`crate::cm`]).
    Key,
    /// A device context: win32k's, a screen DC (see [`crate::win32k::dc`]).
    Dc,
    /// A brush: win32k's, a logical brush a DC selects (see [`crate::win32k::brush`]).
    Brush,
    /// A pen: win32k's, a logical pen a DC selects (see [`crate::win32k::pen`]).
    Pen,
    /// A bitmap: win32k's, a device-dependent bitmap or a DIB section a memory DC selects (see
    /// [`crate::win32k::bitmap`]).
    Bitmap,
    /// A font object: win32k's, a LOGFONT (see [`crate::win32k::fonts`]).
    Font,
    /// A region: win32k's, its rectangles (see [`crate::win32k::region`]).
    Region,
    /// A token: a process's, made at its first open (see [`crate::se`]).
    Token,
}

/// An object's identity: its kind, its record in that kind's pool, and the record's generation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ObjectId {
    pub kind: ObjectType,
    pub index: u16,
    pub generation: u16,
}

impl ObjectId {
    /// The waitable name of a dispatcher object's body, as the wait entries take it: the dispatcher
    /// database's record at the object's own index. None for every other kind (a wait on a file
    /// object waits on its embedded event: [`crate::fs::file::FileObject::completion`]). The id's
    /// liveness is the caller's to know (a reference it holds).
    pub fn waitable(self) -> Option<WaitableId> {
        let index = self.index;
        match self.kind {
            ObjectType::Event => Some(WaitableId::Event(index)),
            ObjectType::Semaphore => Some(WaitableId::Semaphore(index)),
            ObjectType::Mutex => Some(WaitableId::Mutex(index)),
            ObjectType::Timer => Some(WaitableId::Timer(index)),
            ObjectType::Thread => Some(WaitableId::Thread(ThreadId(index))),
            ObjectType::Process => Some(WaitableId::Process(index)),
            ObjectType::Section
            | ObjectType::File
            | ObjectType::Directory
            | ObjectType::WindowStation
            | ObjectType::Desktop
            | ObjectType::Key
            | ObjectType::Dc
            | ObjectType::Brush
            | ObjectType::Pen
            | ObjectType::Bitmap
            | ObjectType::Font
            | ObjectType::Region
            | ObjectType::Token => None,
        }
    }

    /// The body index of a dispatcher object of `kind`; none for an id of another kind.
    pub(super) fn body_of(self, kind: ObjectType) -> Option<u16> {
        (self.kind == kind).then_some(self.index)
    }
}

/// What a handle-table entry names: an object (a directory search is kernel32's structure on the
/// process heap, as on Windows 2000, not a kernel handle).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Target {
    Object(ObjectId),
}

/// One handle-table entry: what the handle names, the access it was granted, whether a child
/// process would inherit it, and whether it is protected from close (NtSetInformationObject's
/// ObjectHandleFlagInformation: NtClose refuses it).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Entry {
    pub target: Target,
    pub access: u32,
    pub inherit: bool,
    pub protect_from_close: bool,
}

impl Entry {
    /// An entry naming an object (not protected from close: a handle is made closable).
    pub fn object(id: ObjectId, access: u32, inherit: bool) -> Self {
        Entry {
            target: Target::Object(id),
            access,
            inherit,
            protect_from_close: false,
        }
    }

    /// The object the entry names, if it names one.
    pub fn object_id(&self) -> Option<ObjectId> {
        let Target::Object(id) = self.target;
        Some(id)
    }
}

/// GetExitCodeProcess's and GetExitCodeThread's answer for one still running.
pub const STILL_ACTIVE: u32 = 259;

/// How many image segments may be live before a new one makes room by purging the least recently
/// cached ([`Directory::make_room_for_segment`]): the bound on the image cache. Not a cap: while
/// every segment is active, a new one is made all the same.
pub const SEGMENTS: usize = 128;
/// The process index of the System process, which no process object takes: the kernel's own
/// process, as Windows 2000's System process (PsInitialSystemProcess) is a process of its own
/// beside the programs'. The tables keyed by process index keep the System process's record there
/// (the window manager's own class lists, the drivers' stand-in for it).
pub const SYSTEM_PROCESS_INDEX: u16 = 0;
/// The longest object name: MAX_PATH.
pub const MAX_NAME: usize = 260;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ob::EVENT_ALL_ACCESS;

    /// Ids name their dispatcher bodies by their own index, whatever their liveness; the kinds
    /// whose bodies the directory holds name none.
    #[test]
    fn ids_name_their_dispatcher_bodies() {
        let id = |kind| ObjectId {
            kind,
            index: 5,
            generation: 2,
        };
        assert_eq!(id(ObjectType::Event).waitable(), Some(WaitableId::Event(5)));
        assert_eq!(
            id(ObjectType::Thread).waitable(),
            Some(WaitableId::Thread(ThreadId(5)))
        );
        assert_eq!(
            id(ObjectType::Process).waitable(),
            Some(WaitableId::Process(5))
        );
        for kind in [
            ObjectType::Section,
            ObjectType::File,
            ObjectType::Key,
            ObjectType::Token,
        ] {
            assert_eq!(id(kind).waitable(), None);
        }
    }

    /// A handle-table entry names an object by its id (an open file's is its file object).
    #[test]
    fn entries_name_objects() {
        let id = ObjectId {
            kind: ObjectType::Event,
            index: 3,
            generation: 7,
        };
        let entry = Entry::object(id, EVENT_ALL_ACCESS, true);
        assert_eq!(entry.object_id(), Some(id));
        assert!(entry.inherit);
        let file = ObjectId {
            kind: ObjectType::File,
            index: 2,
            generation: 0,
        };
        assert_eq!(
            Entry::object(file, 0x0012_0089, false).object_id(),
            Some(file)
        );
    }
}
