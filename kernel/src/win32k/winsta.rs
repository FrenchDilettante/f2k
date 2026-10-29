//! Window stations and desktops: win32k's objects, and the services user32's window station and
//! desktop calls come through.
//!
//! The boot makes the interactive window station, WinSta0 (WSF_VISIBLE), and its Default desktop
//! ([`init`]): object manager objects ([`crate::ob`]'s WindowStation and Desktop types), permanent
//! (the boot keeps their creator's references). There is one session and one logon, so there is
//! no other window station.
//!
//! A process connects at its first win32k service, as on Windows 2000, where a thread's first call
//! into win32k makes it a GUI thread and its process connects to a window station and a desktop:
//! [`connect`] opens a handle to each in the process's handle table, kept as its [`Connection`].
//! Which ones follows Windows 2000's documented rules for an interactive console process: a process
//! inherits its parent's window station and desktop, and the first one gets WinSta0\Default. No
//! process creates another yet, so every process gets WinSta0\Default. Every thread of a process
//! is on its desktop (SetThreadDesktop does not exist).
//!
//! The services, user32's calls (F2K's argument lists, see [`crate::win32k`]):
//!
//! - NtUserGetProcessWindowStation(ptr<u32> WindowStation): the process's window station handle;
//! - NtUserGetThreadDesktop(u32 ThreadId, ptr<u32> Desktop): a thread's desktop handle;
//! - NtUserGetObjectInformation(handle Object, u32 Index, ptr Information, u32 Length, ptr<u32>
//!   LengthNeeded): GetUserObjectInformationW's answer.

use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
use crate::status::*;

/// GetUserObjectInformation's indexes (winuser.h).
pub const UOI_FLAGS: u32 = 1;
pub const UOI_NAME: u32 = 2;
pub const UOI_TYPE: u32 = 3;

/// USEROBJECTFLAGS' dwFlags for a window station: it is the interactive one, shown on the screen.
pub const WSF_VISIBLE: u32 = 1;

/// The documented all-access masks the connection's handles carry: WINSTA_ALL_ACCESS and
/// DESKTOP_ALL_ACCESS's specific rights with STANDARD_RIGHTS_REQUIRED.
pub const WINSTA_ALL_ACCESS: u32 = 0x000F_037F;
pub const DESKTOP_ALL_ACCESS: u32 = 0x000F_01FF;

/// A process's connection to win32k: the handles, in its own handle table, of its window station
/// and of its threads' desktop. Made at its first win32k service ([`connect`]); the handles close
/// with the process's others at its end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Connection {
    pub window_station: u32,
    pub desktop: u32,
}

/// One window station or desktop, as GetUserObjectInformation describes it through a handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserObject {
    /// Its object type's name: "WindowStation" or "Desktop".
    pub type_name: &'static str,
    pub name: &'static str,
    /// USEROBJECTFLAGS' dwFlags.
    pub flags: u32,
    /// Whether the handle is inheritable (USEROBJECTFLAGS' fInherit).
    pub inherit: bool,
}

/// The longest answer: a name or a type name of up to 31 characters, its terminator, in UTF-16.
const MAX_INFORMATION: usize = 64;

/// What GetUserObjectInformation answers for one index: its bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Information {
    bytes: [u8; MAX_INFORMATION],
    length: usize,
}

impl Information {
    /// The answer's bytes: what the caller's buffer must hold.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }

    /// `text` in UTF-16 with its terminator (the names are ASCII).
    fn text(text: &str) -> Self {
        let mut bytes = [0u8; MAX_INFORMATION];
        let length = (text.len() + 1) * 2;
        assert!(length <= MAX_INFORMATION, "a user object's name fits");
        for (at, unit) in text.bytes().enumerate() {
            bytes[at * 2] = unit;
        }
        Information { bytes, length }
    }
}

/// `object`'s answer for `index`: UOI_FLAGS a USEROBJECTFLAGS (fInherit, fReserved, dwFlags),
/// UOI_NAME its name, UOI_TYPE its type's name, each text in UTF-16 with its terminator; none for
/// another index (UOI_USER_SID among them: there is no security).
pub fn information(object: &UserObject, index: u32) -> Option<Information> {
    Some(match index {
        UOI_FLAGS => {
            let mut bytes = [0u8; MAX_INFORMATION];
            bytes[0..4].copy_from_slice(&u32::from(object.inherit).to_le_bytes());
            bytes[8..12].copy_from_slice(&object.flags.to_le_bytes());
            Information { bytes, length: 12 }
        }
        UOI_NAME => Information::text(object.name),
        UOI_TYPE => Information::text(object.type_name),
        _ => return None,
    })
}

/// NtUserGetObjectInformation over the object the handle names (none: no window station or
/// desktop): the answer for `index` into `buffer` when `length` holds it, its length into `needed`
/// in every case, as the capture shows Windows 2000's: an invalid handle is STATUS_INVALID_HANDLE
/// with a length of 0xFFFFFFFF, an index without an answer STATUS_INVALID_PARAMETER with 0, a
/// buffer too short STATUS_BUFFER_TOO_SMALL with the answer's length, the buffer untouched.
pub fn answer(
    object: Option<UserObject>,
    index: u32,
    buffer: UserAddr,
    length: u32,
    needed: UserPtr<u32>,
) -> NtResult {
    let Some(object) = object else {
        needed.write(u32::MAX)?;
        return Err(STATUS_INVALID_HANDLE);
    };
    let Some(information) = information(&object, index) else {
        needed.write(0)?;
        return Err(STATUS_INVALID_PARAMETER);
    };
    let bytes = information.bytes();
    needed.write(bytes.len() as u32)?;
    if (length as usize) < bytes.len() {
        return Err(STATUS_BUFFER_TOO_SMALL);
    }
    buffer.write(bytes)?;
    Ok(STATUS_SUCCESS)
}

/// NtUserGetObjectInformation(Object, Index, Information, Length, LengthNeeded): see [`answer`].
pub fn get_object_information(
    call: &mut NtCall,
    object: Handle,
    index: u32,
    buffer: UserAddr,
    length: u32,
    needed: UserPtr<u32>,
) -> NtResult {
    answer(user_object(call, object), index, buffer, length, needed)
}

/// NtUserGetProcessWindowStation(WindowStation): the calling process's window station handle.
pub fn get_process_window_station(call: &mut NtCall, out: UserPtr<u32>) -> NtResult {
    let connection = connection(call)?;
    out.write(connection.window_station)?;
    Ok(STATUS_SUCCESS)
}

/// NtUserGetThreadDesktop(ThreadId, Desktop): the desktop handle of the calling process's thread
/// `thread_id` (its desktop is the process's); STATUS_INVALID_PARAMETER for an id no running thread
/// has.
pub fn get_thread_desktop(call: &mut NtCall, thread_id: u32, out: UserPtr<u32>) -> NtResult {
    if !is_thread(call, thread_id) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let connection = connection(call)?;
    out.write(connection.desktop)?;
    Ok(STATUS_SUCCESS)
}

// --- The target's side: the objects, the connection ------------------------------------------

/// The interactive window station and its desktop: the objects every process connects to.
#[cfg(target_arch = "x86")]
struct Interactive {
    station: crate::ob::ObjectId,
    desktop: crate::ob::ObjectId,
}

/// WinSta0 and its Default desktop, made at boot (Windows 2000's win32k keeps the interactive
/// window station as gpwinstaInteractive).
#[cfg(target_arch = "x86")]
static INTERACTIVE: crate::sync::InitOnce<Interactive> = crate::sync::InitOnce::new();

/// The boot's step: the interactive window station, WinSta0, and its Default desktop. Their
/// creator's references are never dropped: they outlive every process.
#[cfg(target_arch = "x86")]
pub fn init() {
    let (station, desktop) = crate::ob::locked(|directory| {
        let station = directory
            .create_window_station("WinSta0", WSF_VISIBLE)
            .expect("the boot makes the one window station");
        let desktop = directory
            .create_desktop("Default", 0)
            .expect("the boot makes the one desktop");
        (station, desktop)
    });
    INTERACTIVE.set(Interactive { station, desktop });
}

/// Connect the calling process to its window station and desktop, if its first win32k service has
/// not already: a handle to each, not inheritable, in its handle table (see the module notes for
/// which ones). STATUS_INSUFFICIENT_RESOURCES when the handle table is full.
#[cfg(target_arch = "x86")]
pub fn connect(process: &crate::process::Process) -> Result<Connection, NtStatus> {
    if let Some(connection) = process.win32k() {
        return Ok(connection);
    }
    let interactive = INTERACTIVE.get();
    let window_station = insert(process, interactive.station, WINSTA_ALL_ACCESS)?;
    let desktop = match insert(process, interactive.desktop, DESKTOP_ALL_ACCESS) {
        Ok(desktop) => desktop,
        Err(status) => {
            process.close_handle(window_station);
            return Err(status);
        }
    };
    let connection = Connection {
        window_station,
        desktop,
    };
    process.set_win32k(connection);
    Ok(connection)
}

/// A handle to `id` in `process`'s handle table, not inheritable; STATUS_INSUFFICIENT_RESOURCES
/// when the table refuses it.
#[cfg(target_arch = "x86")]
fn insert(
    process: &crate::process::Process,
    id: crate::ob::ObjectId,
    access: u32,
) -> Result<u32, NtStatus> {
    process
        .insert_object(id, access, false)
        .map(core::num::NonZeroU32::get)
        .ok_or(STATUS_INSUFFICIENT_RESOURCES)
}

/// The calling process's connection (its first win32k service made it).
#[cfg(target_arch = "x86")]
fn connection(call: &mut NtCall) -> Result<Connection, NtStatus> {
    connect(call.process())
}

/// Whether a thread of the calling process that has not ended has client id `thread_id` (another
/// process's thread is not one).
#[cfg(target_arch = "x86")]
fn is_thread(call: &mut NtCall, thread_id: u32) -> bool {
    let owner = call.process().sched_ptr().cast_const();
    crate::ob::lock(call.passive())
        .thread_by_client_id(owner, thread_id)
        .is_some()
}

/// The window station or desktop the calling process's `handle` names, as it describes itself.
#[cfg(target_arch = "x86")]
fn user_object(call: &mut NtCall, handle: Handle) -> Option<UserObject> {
    use crate::ob::ObjectType;
    let entry = call.process().lookup_handle(handle.raw())?;
    let id = entry.object_id()?;
    let mut directory = crate::ob::lock(call.passive());
    match id.kind {
        ObjectType::WindowStation => directory.window_station(id).map(|station| UserObject {
            type_name: "WindowStation",
            name: station.name,
            flags: station.flags,
            inherit: entry.inherit,
        }),
        ObjectType::Desktop => directory.desktop(id).map(|desktop| UserObject {
            type_name: "Desktop",
            name: desktop.name,
            flags: desktop.flags,
            inherit: entry.inherit,
        }),
        _ => None,
    }
}

// The host builds have no processes: no connection, no thread, no handle names a user object (the
// host tests exercise [`information`] and [`answer`]).

#[cfg(not(target_arch = "x86"))]
fn connection(_: &mut NtCall) -> Result<Connection, NtStatus> {
    Err(STATUS_NOT_IMPLEMENTED)
}

#[cfg(not(target_arch = "x86"))]
fn is_thread(_: &mut NtCall, _: u32) -> bool {
    false
}

#[cfg(not(target_arch = "x86"))]
fn user_object(_: &mut NtCall, _: Handle) -> Option<UserObject> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::syscall::host::{install, UserMemory};

    const WINSTA0: UserObject = UserObject {
        type_name: "WindowStation",
        name: "WinSta0",
        flags: WSF_VISIBLE,
        inherit: false,
    };

    const DEFAULT: UserObject = UserObject {
        type_name: "Desktop",
        name: "Default",
        flags: 0,
        inherit: false,
    };

    fn utf16(text: &str) -> std::vec::Vec<u8> {
        text.encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    /// The answers, as the capture shows them: the names and the types' names with their
    /// terminators (WinSta0 16 bytes, WindowStation 28, Default and Desktop 16), the flags a
    /// 12-byte USEROBJECTFLAGS; nothing for another index.
    #[test]
    fn the_answers_are_the_captures() {
        let answer = |object: &UserObject, index| information(object, index).unwrap();
        assert_eq!(answer(&WINSTA0, UOI_NAME).bytes(), &utf16("WinSta0")[..]);
        assert_eq!(answer(&WINSTA0, UOI_NAME).bytes().len(), 16);
        assert_eq!(answer(&WINSTA0, UOI_TYPE).bytes().len(), 28);
        assert_eq!(answer(&DEFAULT, UOI_NAME).bytes(), &utf16("Default")[..]);
        assert_eq!(answer(&DEFAULT, UOI_TYPE).bytes(), &utf16("Desktop")[..]);
        assert_eq!(
            answer(&WINSTA0, UOI_FLAGS).bytes(),
            &[0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]
        );
        let inheritable = UserObject {
            inherit: true,
            ..DEFAULT
        };
        assert_eq!(
            answer(&inheritable, UOI_FLAGS).bytes(),
            &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(information(&WINSTA0, 4), None, "UOI_USER_SID");
        assert_eq!(information(&WINSTA0, 99), None);
    }

    /// The caller's memory: a page at 0x1000, anything else faults.
    struct Page(std::vec::Vec<u8>);

    impl UserMemory for Page {
        fn read(&self, pointer: u32, bytes: &mut [u8]) -> Result<(), NtStatus> {
            let at = (pointer as usize)
                .checked_sub(0x1000)
                .ok_or(STATUS_ACCESS_VIOLATION)?;
            let source = self
                .0
                .get(at..at + bytes.len())
                .ok_or(STATUS_ACCESS_VIOLATION)?;
            bytes.copy_from_slice(source);
            Ok(())
        }

        fn write(&mut self, pointer: u32, bytes: &[u8]) -> Result<(), NtStatus> {
            let at = (pointer as usize)
                .checked_sub(0x1000)
                .ok_or(STATUS_ACCESS_VIOLATION)?;
            let target = self
                .0
                .get_mut(at..at + bytes.len())
                .ok_or(STATUS_ACCESS_VIOLATION)?;
            target.copy_from_slice(bytes);
            Ok(())
        }
    }

    /// The service's answers into the caller's memory: the length needed in every case, the
    /// buffer written only when it holds the answer whole.
    #[test]
    fn the_service_reports_the_length_in_every_case() {
        let page = std::rc::Rc::new(core::cell::RefCell::new(Page(std::vec![0xCC; 0x100])));
        let _installed = install(page.clone());
        let (buffer, needed) = (UserAddr(0x1000), UserPtr::<u32>::at(0x10F0));
        let read_needed = || needed.read().unwrap();
        let untouched = |page: &Page| page.0[..0x40].iter().all(|&b| b == 0xCC);

        assert_eq!(
            answer(None, UOI_NAME, buffer, 0x40, needed),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(read_needed(), u32::MAX);
        assert_eq!(
            answer(Some(WINSTA0), 99, buffer, 0x40, needed),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(read_needed(), 0);
        assert_eq!(
            answer(Some(WINSTA0), UOI_NAME, UserAddr(0), 0, needed),
            Err(STATUS_BUFFER_TOO_SMALL)
        );
        assert_eq!(read_needed(), 16);
        assert_eq!(
            answer(Some(WINSTA0), UOI_NAME, buffer, 14, needed),
            Err(STATUS_BUFFER_TOO_SMALL)
        );
        assert!(untouched(&page.borrow()));
        assert_eq!(
            answer(Some(WINSTA0), UOI_FLAGS, buffer, 11, needed),
            Err(STATUS_BUFFER_TOO_SMALL)
        );
        assert_eq!(read_needed(), 12);
        assert!(untouched(&page.borrow()));
        assert_eq!(
            answer(Some(WINSTA0), UOI_NAME, buffer, 16, needed),
            Ok(STATUS_SUCCESS)
        );
        assert_eq!(read_needed(), 16);
        assert_eq!(&page.borrow().0[..16], &utf16("WinSta0")[..]);
        assert_eq!(page.borrow().0[16], 0xCC, "the answer alone");
        assert_eq!(
            answer(Some(DEFAULT), UOI_TYPE, UserAddr(0x2000), 16, needed),
            Err(STATUS_ACCESS_VIOLATION)
        );
    }
}
