//! The security reference monitor: SIDs, ACLs, security descriptors, privileges,
//! and the access check over them, all sharing one module tree.
//! The submodules are re-exported here, so consumers use `crate::sec::Item`,
//! not `crate::sec::sid::Item`.

pub mod acl;
pub mod check;
pub mod check_aces;
pub mod privileges;
pub mod sd;
pub mod sid;

pub use acl::*;
pub use check::*;
pub use check_aces::*;
pub use privileges::*;
pub use sd::*;
pub use sid::*;
