//! File positioning on the console's handles: the kernel's transitional SetFilePointer, whose
//! handles name no open file when they are the console's. (The console's own calls are kernel32's,
//! over the console server: userland/kernel32/src/scenarios/console.rs.)

use crate::compat::harness::surface::Fixture;

const STDIN: u32 = 0x3;
const STDOUT: u32 = 0x7;
const INVALID_HANDLE_VALUE: u32 = 0xFFFF_FFFF;
const INVALID_SET_FILE_POINTER: u32 = 0xFFFF_FFFF;
const FILE_BEGIN: u32 = 0;

/// SetFilePointer on a handle that names no open file — a standard handle, a closed or foreign
/// value — is INVALID_SET_FILE_POINTER.
#[test]
fn set_file_pointer_refuses_non_file_handles() {
    let mut fixture = Fixture::new();
    for handle in [STDIN, STDOUT, 0x40, INVALID_HANDLE_VALUE, 0] {
        assert_eq!(
            fixture.call("SetFilePointer", &[handle, 0, 0, FILE_BEGIN]),
            INVALID_SET_FILE_POINTER,
            "{handle:#x}"
        );
    }
}
