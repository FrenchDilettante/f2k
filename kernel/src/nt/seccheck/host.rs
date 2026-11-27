//! The host builds' access-check and privilege-check services (see `nt`'s `unserved`).

use super::super::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};

unserved! {
    access_check(UserAddr, Handle, u32, UserAddr, UserAddr, UserPtr<u32>, UserPtr<u32>, UserPtr<u32>);
    access_check_by_type(UserAddr, UserAddr, Handle, u32, UserAddr, u32, UserAddr, UserAddr, UserPtr<u32>, UserPtr<u32>, UserPtr<u32>);
    access_check_by_type_result_list(UserAddr, UserAddr, Handle, u32, UserAddr, u32, UserAddr, UserAddr, UserPtr<u32>, UserPtr<u32>, UserPtr<u32>);
    privilege_check(Handle, UserAddr, UserPtr<u32>);
}
