//! The FAT32 volume: the boot sector's decode and gate list, the mount state, the File Allocation
//! Table's entries, and file lookup and reads, all through a block device.
//!
//! The logic is pure over `&dyn BlockDevice`, so the host tests run it against in-memory volumes;
//! the boot mounts the first registered partition and keeps it for later users (`volume`). The
//! boot sector and its gates are [`boot_sector`], the mount state and cluster math [`layout`],
//! the entry decode and the FAT sector cache [`fat`], the mount and the boot volume [`volume`],
//! directory records [`dirent`], path folding [`path`], the directory walk and path lookup
//! [`lookup`], the chain read [`read`], and the host tests' shared volumes, devices, and captured
//! sectors [`fixtures`].

pub mod boot_sector;
pub mod dirent;
pub mod fat;
#[cfg(test)]
pub(crate) mod fixtures;
pub mod layout;
pub mod lookup;
pub mod path;
pub mod read;
pub mod volume;
