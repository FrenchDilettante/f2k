//! The security tests' builders: the SID, ACE, ACL and descriptor bytes from rtl's shared
//! `testing::sec` (the kernel's and advapi32's tests lay them out the same way), plus what only
//! the kernel's tests use: the kernel's [`Guid`] in an object ACE, the test subject's SIDs, and a
//! cached descriptor's bytes.

use std::vec::Vec;

pub use rtl::testing::sec::{acl, allowed, compound, denied, descriptor, plain_ace, sd, sid};

use crate::ob::sdcache::SdRef;
use crate::sec::Guid;

/// A GUID, named by its first field.
pub fn guid(data1: u32) -> Guid {
    Guid {
        data1,
        data2: 0,
        data3: 0,
        data4: [0; 8],
    }
}

/// A GUID's bytes: the first three fields little-endian, the last eight as they are.
fn guid_bytes(g: &Guid) -> [u8; 16] {
    let mut v = [0u8; 16];
    v[0..4].copy_from_slice(&g.data1.to_le_bytes());
    v[4..6].copy_from_slice(&g.data2.to_le_bytes());
    v[6..8].copy_from_slice(&g.data3.to_le_bytes());
    v[8..16].copy_from_slice(&g.data4);
    v
}

/// An object ACE of `mask` to `sid`, naming `object_type` when given.
pub fn object_ace(ace_type: u8, mask: u32, object_type: Option<Guid>, sid: &[u8]) -> Vec<u8> {
    rtl::testing::sec::object_ace(ace_type, mask, object_type.as_ref().map(guid_bytes), sid)
}

/// The test user's SID, S-1-5-21-111-222-333-1000.
pub fn user_sid() -> Vec<u8> {
    sid(5, &[21, 111, 222, 333, 1000])
}

/// Another account's SID, S-1-5-21-111-222-333-1001: an owner the subject is not.
pub fn other_sid() -> Vec<u8> {
    sid(5, &[21, 111, 222, 333, 1001])
}

/// A handle's descriptor bytes, copied out of its cache entry.
pub fn sd_bytes(handle: &SdRef) -> Vec<u8> {
    handle.with_bytes(|bytes| bytes.to_vec()).unwrap()
}
