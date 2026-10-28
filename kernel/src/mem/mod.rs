//! Memory management: the physical frame database, paging, kernel stacks, virtual memory, and the
//! block heap the registry's arena runs on.

pub mod frame;
pub mod heap;
pub mod kstacks;
pub mod layout;
pub mod multiboot;
pub mod paging;
pub mod vm;

/// Boot-time frame database, built from the Multiboot memory map. Host builds run the modules' unit
/// tests instead; there is no boot loader to ask for memory there.
#[cfg(target_arch = "x86")]
pub mod bootmem;

#[cfg(target_arch = "x86")]
use frame::FrameDb;
#[cfg(target_arch = "x86")]
use kstacks::KernelStacks;
#[cfg(target_arch = "x86")]
use paging::ScratchWindow;

#[cfg(target_arch = "x86")]
use crate::level::{self, High, LevelCell};

/// The memory manager's database: the frame database, the kernel stacks and the scratch window.
///
/// They are one database because their operations nest. A kernel stack's creation takes a slot,
/// allocates the stack's frames, zeroes each through the scratch window and maps it, as one step;
/// its release unmaps the frames and gives them back. Windows 2000 does the same under one lock,
/// the PFN lock, which covers the frame database and is held while a kernel stack is made. A step
/// borrows the whole database once ([`with_database`]) and lends its parts ([`Database::parts`])
/// to the code it calls, which never reaches the database again from inside the borrow.
#[cfg(target_arch = "x86")]
struct Database {
    /// The frame database, from the boot's [`bootmem::boot_init`] on.
    frames: Option<FrameDb>,
    /// The kernel stacks' slot ledger and parked stack.
    stacks: KernelStacks,
    /// The system's one scratch window.
    scratch: ScratchWindow,
}

/// The database's parts, borrowed apart.
#[cfg(target_arch = "x86")]
struct Parts<'a> {
    frames: &'a mut FrameDb,
    stacks: &'a mut KernelStacks,
    scratch: &'a mut ScratchWindow,
}

#[cfg(target_arch = "x86")]
impl Database {
    /// The database before the boot builds the frame database: every stack slot free, nothing
    /// parked.
    const fn new() -> Self {
        Database {
            frames: None,
            stacks: KernelStacks::empty(),
            scratch: ScratchWindow::new(),
        }
    }

    /// The frame database.
    ///
    /// # Panics
    ///
    /// The boot has not built it yet.
    fn frames(&mut self) -> &mut FrameDb {
        self.frames
            .as_mut()
            .expect("frame database not initialized")
    }

    /// Every part at once, for a step that needs more than one.
    ///
    /// # Panics
    ///
    /// The boot has not built the frame database yet.
    fn parts(&mut self) -> Parts<'_> {
        Parts {
            frames: self
                .frames
                .as_mut()
                .expect("frame database not initialized"),
            stacks: &mut self.stacks,
            scratch: &mut self.scratch,
        }
    }
}

/// The memory manager's database.
// Note: Windows 2000 keeps this at DISPATCH_LEVEL, under the PFN lock, and it moves there once its
// callers hold tokens. Until then the bridge reaches it at the high level, masking interrupts for
// each step (as the system services and the idle thread's reap, its main callers, run already),
// and refuses a step that reaches it again from inside its own borrow.
#[cfg(target_arch = "x86")]
static DATABASE: LevelCell<High, Database> = LevelCell::new(Database::new());

/// Run `step` on the memory manager's database, through the bridge to the high level.
///
/// # Panics
///
/// The processor is already at the high level: `step`, or code it calls, reaching the database
/// again from inside its own borrow.
#[cfg(target_arch = "x86")]
fn with_database<R>(step: impl FnOnce(&mut Database) -> R) -> R {
    level::raised::<High, _>(|high| step(DATABASE.get(high)))
}
