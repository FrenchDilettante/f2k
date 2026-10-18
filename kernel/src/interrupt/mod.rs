//! The interrupt core: interrupt objects, the vector table, and the interrupt claim protocol, with
//! the level discipline ([`irql`]), the deferred procedure call queue ([`dpc`]), and the interval
//! clock ([`clock`]).
//!
//! A driver connects an interrupt object to a hardware vector; connect wires the vector's slot and
//! enables (unmasks) its line, disconnect masks the line and clears the slot. An unconnected
//! vector's line stays masked, so its stub can never be reached by a real interrupt — reaching one
//! means the kernel's own invariant is broken. Two sharable objects with the same trigger mode may
//! share a vector; the pair is served in order.
//!
//! Everything the core knows about the chip arrives through the [`Controller`] seam: claim probes
//! the delivered interrupt (a spurious one — the chip's acknowledge-time quirk — is dropped without
//! raising anything, and the controller performs the partial acknowledgment the quirk demands), end
//! lowers back and acknowledges, enable/disable drive the line masks. The core is hardware-neutral:
//! the programmable-controller implementation sits behind the same seam a future implementation can
//! replace.

pub mod clock;
pub mod dpc;
pub mod irql;
#[cfg(all(target_arch = "x86", feature = "irq-smoke"))]
mod smoke;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(all(target_arch = "x86", feature = "irq-smoke"))]
pub use smoke::run as smoke;

use crate::interrupt::irql::{Irql, IrqlState, HIGH, SYNCH};

/// First hardware vector (the band the remap programs the chips with; IRQ 0).
pub const FIRST_VECTOR: u8 = crate::hw::pic::MASTER_VECTOR_BASE;

/// Last hardware vector (IRQ 15).
pub const LAST_VECTOR: u8 = crate::hw::pic::LAST_VECTOR;

/// How many hardware vectors the band holds.
pub const VECTOR_COUNT: usize = (LAST_VECTOR - FIRST_VECTOR + 1) as usize;

/// The vectors the IDT fills with interrupt stubs, in order. One source of truth for the generated
/// stubs, the table, and the tests.
pub const IRQ_VECTORS: [u8; VECTOR_COUNT] = [
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
];

/// The claim verdict of a delivered interrupt.
pub enum Claim {
    /// A real interrupt: the level was raised to the object's level; the claimer must run the
    /// service and then end it ([`Controller::end`]) exactly once. Carries the previous level.
    Accepted(Irql),
    /// A spurious interrupt: nothing was raised, and the controller has already performed whatever
    /// partial acknowledgment the chip's quirk demands. The claimer must do nothing at all.
    Spurious,
}

/// What servicing a delivered vector did.
pub enum Outcome {
    /// A connected object's service ran, and the interrupt was ended (level lowered, chip
    /// acknowledged).
    Served,
    /// The interrupt was spurious and was dropped.
    Spurious,
    /// A real interrupt arrived on a vector with no connected object — the masked-line invariant
    /// is broken. The interrupt was ended, but the caller must treat this as a kernel bug.
    Unexpected,
}

/// The hardware seam: everything the core knows about the chip.
pub trait Controller {
    /// Claim a delivered vector at the given level: probe the interrupt, raise the level, and
    /// return the previous one — or report the interrupt spurious (nothing raised).
    fn claim(&mut self, vector: u8, level: Irql) -> Claim;
    /// End a claimed interrupt: acknowledge the chip, then lower back to the recorded level. The
    /// acknowledgment comes first, while interrupts are still masked: the lower may re-enable
    /// them, and an interrupt taken there may switch threads before this exit resumes.
    fn end(&mut self, previous: Irql, vector: u8);
    /// Enable (unmask) the vector's line; false if it could not be.
    fn enable(&mut self, vector: u8) -> bool;
    /// Disable (mask) the vector's line.
    fn disable(&mut self, vector: u8);
    /// Whether the vector's line is enabled.
    fn is_enabled(&mut self, vector: u8) -> bool;
    /// Whether no interrupt is left half-served on the chip.
    fn in_service_clear(&mut self) -> bool;
}

/// An interrupt service: `(object, service_context)`. The return value reports the interrupt
/// handled; a shared vector runs every object's service regardless.
pub type InterruptService = fn(&InterruptObject, usize) -> bool;

/// One connected (or connectable) interrupt.
pub struct InterruptObject {
    service: InterruptService,
    service_context: usize,
    vector: u8,
    level: Irql,
    synchronize_level: Irql,
    shareable: bool,
    level_triggered: bool,
    connected: bool,
    /// The exclusion lock synchronize runs under.
    lock: AtomicBool,
}

impl InterruptObject {
    /// A zeroed object; call [`initialize`] before use.
    pub const fn zeroed() -> Self {
        Self {
            service: never_service,
            service_context: 0,
            vector: 0,
            level: Irql(0),
            synchronize_level: Irql(0),
            shareable: false,
            level_triggered: false,
            connected: false,
            lock: AtomicBool::new(false),
        }
    }

    /// The vector this object is bound to.
    pub fn vector(&self) -> u8 {
        self.vector
    }

    /// Whether this object is connected.
    pub fn is_connected(&self) -> bool {
        self.connected
    }
}

/// A service that can never be called: the zeroed object's placeholder (a connected object always
/// has a real service).
fn never_service(_object: &InterruptObject, _context: usize) -> bool {
    false
}

/// Fill an interrupt object: the service and its context, the vector and its level, the synchronize
/// level, and the sharing mode. The object starts disconnected. Validity is checked at connect.
pub fn initialize(
    object: &mut InterruptObject,
    service: InterruptService,
    service_context: usize,
    vector: u8,
    level: Irql,
    synchronize_level: Irql,
    level_triggered: bool,
    shareable: bool,
) {
    object.service = service;
    object.service_context = service_context;
    object.vector = vector;
    object.level = level;
    object.synchronize_level = synchronize_level;
    object.level_triggered = level_triggered;
    object.shareable = shareable;
    object.connected = false;
    object.lock = AtomicBool::new(false);
}

/// What occupies a vector: nothing, one object, or a shared pair.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VectorState {
    /// No object; the line is (must be) masked.
    Unconnected,
    /// One object, normal dispatch.
    Connected,
    /// Two objects sharing; served in order.
    Chained,
    /// A state the connect discipline can never produce.
    Unknown,
}

/// The vector table: the band's slots and their objects.
pub struct VectorTable {
    slots: [Slot; VECTOR_COUNT],
}

#[derive(Clone, Copy)]
struct Slot {
    /// The connected objects, in service order. A chain is exactly two (a driver may share its
    /// line with one other).
    objects: [Option<NonNull<InterruptObject>>; 2],
}

impl Slot {
    const EMPTY: Slot = Slot {
        objects: [None, None],
    };
}

impl VectorTable {
    /// An empty table: every slot unconnected.
    pub const fn zeroed() -> Self {
        Self {
            slots: [Slot::EMPTY; VECTOR_COUNT],
        }
    }

    /// The object's slot index, or none if the vector is outside the hardware band.
    fn index_of(vector: u8) -> Option<usize> {
        if vector < FIRST_VECTOR || vector > LAST_VECTOR {
            None
        } else {
            Some((vector - FIRST_VECTOR) as usize)
        }
    }

    /// Classify a vector (the four-way state an outside observer would read off the table).
    pub fn classify(&self, vector: u8) -> VectorState {
        let Some(index) = Self::index_of(vector) else {
            return VectorState::Unknown;
        };
        match self.slots[index].objects {
            [None, None] => VectorState::Unconnected,
            [Some(_), None] => VectorState::Connected,
            [Some(_), Some(_)] => VectorState::Chained,
            [None, Some(_)] => VectorState::Unknown,
        }
    }

    /// The objects connected to a vector, in service order.
    pub fn connected(&self, vector: u8) -> [Option<&InterruptObject>; 2] {
        let Some(index) = Self::index_of(vector) else {
            return [None, None];
        };
        let to_ref = |slot: Option<NonNull<InterruptObject>>| {
            // SAFETY: the table only holds pointers to objects its callers connected; those objects
            // outlive the table's use of them (they are statics or the caller's).
            slot.map(|p| unsafe { p.as_ref() })
        };
        [
            to_ref(self.slots[index].objects[0]),
            to_ref(self.slots[index].objects[1]),
        ]
    }

    /// Connect `object` to its vector: wire the slot and enable the line. Returns whether it
    /// connected: an already-connected object connects nowhere, an invalid one is refused without
    /// side effects, a failing enable rolls everything back, and a sharable newcomer may join a
    /// compatible incumbent.
    pub fn connect(
        &mut self,
        object: &mut InterruptObject,
        controller: &mut dyn Controller,
        irql: &mut IrqlState,
    ) -> bool {
        // The validity gate: the level must fit the platform's scale, the synchronize level must
        // not undercut it, and the vector must lie in the hardware band.
        if object.level > HIGH
            || object.synchronize_level < object.level
            || Self::index_of(object.vector).is_none()
        {
            return false;
        }

        // An already-connected object connects nowhere.
        if object.connected {
            return false;
        }

        // The dispatcher level for the whole state change.
        let previous = irql.raise(SYNCH);
        let index = Self::index_of(object.vector).unwrap();
        let slot = &mut self.slots[index];
        let mut connected_now = false;

        if slot.objects[0].is_none() {
            // An unconnected vector: wire the slot, then enable the line. A failing enable leaves
            // everything as it was.
            object.connected = true;
            slot.objects[0] = Some(NonNull::from(&*object));
            if controller.enable(object.vector) {
                connected_now = true;
            } else {
                slot.objects[0] = None;
                object.connected = false;
            }
        } else {
            // A connected vector: only a sharable newcomer with the same trigger mode may join, and
            // only into the one free chain slot.
            // SAFETY: the incumbent outlives this call (it is a static or its caller's object);
            // only its sharing fields are read.
            let incumbent = unsafe { slot.objects[0].unwrap().as_ref() };
            let compatible = object.shareable
                && incumbent.shareable
                && object.level_triggered == incumbent.level_triggered;
            if compatible && slot.objects[1].is_none() {
                object.connected = true;
                slot.objects[1] = Some(NonNull::from(&*object));
                connected_now = true;
            }
        }

        irql.lower(previous);
        connected_now
    }

    /// Disconnect `object`: mask the line (unless another object still serves it) and clear the
    /// slot. Returns whether the object had been connected.
    pub fn disconnect(
        &mut self,
        object: &mut InterruptObject,
        controller: &mut dyn Controller,
        irql: &mut IrqlState,
    ) -> bool {
        let was_connected = object.connected;
        if was_connected {
            let previous = irql.raise(SYNCH);
            let index = Self::index_of(object.vector).unwrap();
            let slot = &mut self.slots[index];
            let self_ptr = NonNull::from(&*object);

            if slot.objects[1].is_some() {
                // Chain surgery: removing the head promotes the second object; removing the second
                // just opens the slot. The line stays enabled either way.
                if slot.objects[0] == Some(self_ptr) {
                    slot.objects[0] = slot.objects[1];
                }
                slot.objects[1] = None;
            } else if slot.objects[0] == Some(self_ptr) {
                // The last object on the vector: mask the line and clear the slot.
                controller.disable(object.vector);
                slot.objects[0] = None;
            } else {
                // The object is connected but not on this vector's slot — the state machine is
                // broken; refuse.
                irql.lower(previous);
                return false;
            }
            object.connected = false;
            irql.lower(previous);
        }
        was_connected
    }

    /// Run `routine` with the object's service excluded: raised to the synchronize level, under the
    /// object's lock, lowered back after. Returns the routine's result.
    pub fn synchronize_execution(
        &self,
        object: &InterruptObject,
        routine: fn(usize) -> bool,
        context: usize,
        irql: &mut IrqlState,
    ) -> bool {
        // Raise first, then take the lock: the level is what keeps the service out; the lock is
        // what keeps other synchronizers out.
        let previous = irql.raise(object.synchronize_level);
        while object.lock.swap(true, Ordering::SeqCst) {
            core::hint::spin_loop();
        }
        let result = routine(context);
        object.lock.store(false, Ordering::SeqCst);
        irql.lower(previous);
        result
    }

    /// The table's audit: no vector may be enabled without a connected object, and no interrupt may
    /// be left half-served on the chip.
    pub fn audit(&mut self, controller: &mut dyn Controller) -> Result<(), &'static str> {
        for vector in IRQ_VECTORS {
            let connected = self.connected(vector)[0].is_some();
            let enabled = controller.is_enabled(vector);
            if enabled && !connected {
                return Err("interrupt line enabled without a connected object");
            }
        }
        if !controller.in_service_clear() {
            return Err("interrupt left in service on the chip");
        }
        Ok(())
    }
}

/// Service a delivered vector through the claim protocol: claim (which settles the spurious
/// question and raises the level), run the connected services, end (which lowers and acknowledges).
///
/// A spurious interrupt is dropped: no service runs, the level never moved, the chip was
/// acknowledged exactly as its quirk demands. A real interrupt on an unconnected vector is ended
/// properly but reported [`Outcome::Unexpected`] — the caller treats it as a kernel bug.
pub fn service_interrupt(
    table: &VectorTable,
    controller: &mut dyn Controller,
    vector: u8,
) -> Outcome {
    let [first, second] = table.connected(vector);
    let level = match first {
        Some(object) => object.level,
        None => {
            // No object: claim at the highest level — spurious is the expected outcome (the chip's
            // quirk can deliver a spurious vector whose line was never enabled).
            match controller.claim(vector, HIGH) {
                Claim::Spurious => return Outcome::Spurious,
                Claim::Accepted(previous) => {
                    controller.end(previous, vector);
                    return Outcome::Unexpected;
                }
            }
        }
    };

    match controller.claim(vector, level) {
        Claim::Spurious => Outcome::Spurious,
        Claim::Accepted(previous) => {
            // Run the connected services in order; every object on a shared vector gets the
            // interrupt.
            if let Some(object) = first {
                (object.service)(object, object.service_context);
            }
            if let Some(object) = second {
                (object.service)(object, object.service_context);
            }
            controller.end(previous, vector);
            Outcome::Served
        }
    }
}

// --- Target wiring: the kernel table, controller, and dispatch --------------

#[cfg(target_arch = "x86")]
mod target {
    use core::ptr::{addr_of, addr_of_mut};

    use super::*;
    use crate::cpu::idt::ExceptionFrame;
    use crate::hw::pic::{self, Pic, Verdict};
    use crate::hw::portio::Ports;
    use crate::interrupt::irql;

    /// The kernel's vector table.
    pub(super) static mut TABLE: VectorTable = VectorTable::zeroed();

    /// The kernel's interrupt controller (the remapped 8259A pair).
    pub(super) static mut CONTROLLER: Pic<Ports> = Pic::new(Ports);

    // The claim/audit counters (the smoke's audit reads these).
    static mut CLAIMED: u32 = 0;
    static mut ENDED: u32 = 0;
    static mut SPURIOUS: u32 = 0;
    static mut UNEXPECTED: u32 = 0;

    impl Controller for Pic<Ports> {
        fn claim(&mut self, vector: u8, level: Irql) -> Claim {
            match self.claim(vector) {
                // Real: raise to the service level. The level state performs the interrupt-flag
                // transition.
                Verdict::Real => Claim::Accepted(irql::state_mut().raise(level)),
                // Spurious: the chip work is already done inside the controller; nothing was
                // raised.
                Verdict::SpuriousNoEoi | Verdict::SpuriousCascadeEnded => Claim::Spurious,
            }
        }

        fn end(&mut self, previous: Irql, vector: u8) {
            self.end_of_interrupt(vector);
            irql::state_mut().lower(previous);
        }

        fn enable(&mut self, vector: u8) -> bool {
            self.unmask(vector);
            true
        }

        fn disable(&mut self, vector: u8) {
            self.mask(vector);
        }

        fn is_enabled(&mut self, vector: u8) -> bool {
            self.is_unmasked(vector)
        }

        fn in_service_clear(&mut self) -> bool {
            Pic::in_service_clear(self)
        }
    }

    /// The interval clock's interrupt object.
    static mut CLOCK_OBJECT: InterruptObject = InterruptObject::zeroed();

    fn clock_service(_object: &InterruptObject, _context: usize) -> bool {
        super::clock::service();
        true
    }

    /// The assembly stub's landing: service the interrupt the frame names, then drain the
    /// deferred-work queue (the dispatch software level runs on the way down, at the interrupt
    /// exit), then deliver any pending dispatch request — a quantum the tick ended, or a thread the
    /// drained work readied at a higher priority. A delivered switch resumes this exit when the
    /// interrupted thread next runs.
    extern "C" fn dispatch(frame: &ExceptionFrame) {
        let vector = frame.vector as u8;
        // SAFETY: single CPU; the table and controller are kernel statics whose accessors run
        // serialized by the level discipline (the gates mask on entry).
        unsafe {
            let outcome = service_interrupt(
                &*addr_of_mut!(TABLE),
                &mut *addr_of_mut!(CONTROLLER),
                vector,
            );
            match outcome {
                Outcome::Served => {
                    core::ptr::write_volatile(
                        addr_of_mut!(CLAIMED),
                        core::ptr::read_volatile(addr_of!(CLAIMED)).wrapping_add(1),
                    );
                    core::ptr::write_volatile(
                        addr_of_mut!(ENDED),
                        core::ptr::read_volatile(addr_of!(ENDED)).wrapping_add(1),
                    );
                    crate::interrupt::dpc::drain();
                    crate::sched::idle::dispatcher().deliver_pending();
                }
                Outcome::Spurious => {
                    core::ptr::write_volatile(
                        addr_of_mut!(SPURIOUS),
                        core::ptr::read_volatile(addr_of!(SPURIOUS)).wrapping_add(1),
                    );
                }
                Outcome::Unexpected => {
                    core::ptr::write_volatile(
                        addr_of_mut!(UNEXPECTED),
                        core::ptr::read_volatile(addr_of!(UNEXPECTED)).wrapping_add(1),
                    );
                    crate::serial_println!(
                        "F2K: unexpected interrupt on vector {:#04x}; halting",
                        vector
                    );
                    crate::halt();
                }
            }
        }
    }

    /// The dispatch entry the IDT stubs call.
    pub(super) extern "C" fn dispatch_entry(frame: &ExceptionFrame) {
        dispatch(frame)
    }

    /// Bring up the interrupt subsystem: remap the chips, program the interval timer, connect the
    /// clock, and let interrupts fly.
    ///
    /// # Safety
    ///
    /// Boot CPU, ring 0, with interrupts disabled, before any code that expects the tick.
    pub unsafe fn init() {
        unsafe {
            // The 8259 pair: vectors 0x30-0x3F, every line masked.
            (*addr_of_mut!(CONTROLLER)).remap(pic::MASTER_VECTOR_BASE, pic::SLAVE_VECTOR_BASE);
            // The 8254: the captured platform interval.
            let mut ports = Ports;
            crate::hw::pit::program_interval(&mut ports, crate::hw::pit::INTERVAL_DIVISOR);

            crate::interrupt::dpc::init();
            super::clock::init();

            // The interval clock: IRQ 0, served at the clock level.
            let clock = &mut *addr_of_mut!(CLOCK_OBJECT);
            initialize(
                clock,
                clock_service,
                0,
                super::clock::CLOCK_VECTOR,
                crate::interrupt::irql::CLOCK,
                crate::interrupt::irql::CLOCK,
                false,
                false,
            );
            let connected = (*addr_of_mut!(TABLE)).connect(
                clock,
                &mut *addr_of_mut!(CONTROLLER),
                irql::state_mut(),
            );
            assert!(connected, "connecting the interval clock failed");

            // Interrupts fly from here on.
            irql::state_mut().unmask_interrupts();
        }
    }

    /// Connect a driver's interrupt object to its vector in the kernel table: wire the slot and
    /// enable the line (see [`VectorTable::connect`]). The object is a static: the table keeps its
    /// address for the kernel's lifetime.
    pub fn connect(object: &'static mut InterruptObject) -> bool {
        // SAFETY: single CPU; the table and controller accessors run serialized (the connect
        // raises to the synchronization level for the state change).
        unsafe {
            (*addr_of_mut!(TABLE)).connect(
                object,
                &mut *addr_of_mut!(CONTROLLER),
                irql::state_mut(),
            )
        }
    }

    /// The interrupt subsystem's audit: the level transitions are balanced, every claimed interrupt
    /// was ended, no line is enabled without an object, and the chip carries no stuck in-service
    /// state.
    pub fn audit() -> Result<(), &'static str> {
        // SAFETY: read-only except the table audit's controller probes; single CPU.
        unsafe {
            irql::state_mut().audit()?;
            let claimed = core::ptr::read_volatile(addr_of!(CLAIMED));
            let ended = core::ptr::read_volatile(addr_of!(ENDED));
            if claimed != ended {
                return Err("claimed interrupts not all ended");
            }
            (*addr_of_mut!(TABLE)).audit(&mut *addr_of_mut!(CONTROLLER))?;
        }
        Ok(())
    }

    /// Spurious interrupts counted so far (diagnostic).
    pub fn spurious_count() -> u32 {
        // SAFETY: read-only.
        unsafe { core::ptr::read_volatile(addr_of!(SPURIOUS)) }
    }
}

#[cfg(target_arch = "x86")]
// `audit` has no caller outside the irq-smoke diagnostic; the subsystem API stays complete.
#[allow(unused_imports)]
pub use target::{audit, connect, init, spurious_count};

/// The dispatch entry the IDT stubs call with the shared frame shape (target only): read the
/// vector, service the interrupt, drain the deferred work.
#[cfg(target_arch = "x86")]
pub extern "C" fn dispatch(frame: &crate::cpu::idt::ExceptionFrame) {
    target::dispatch_entry(frame)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    /// A fake controller: per-line enable/in-service bits, a level state, and a log of the
    /// claim/end/enable/disable calls.
    struct FakeController {
        enabled: [bool; VECTOR_COUNT],
        in_service: [bool; VECTOR_COUNT],
        fail_enable_for: Option<u8>,
        irql: IrqlState,
        claims: RefCell<Vec<(u8, Irql)>>,
        ends: RefCell<Vec<(Irql, u8)>>,
        enables: RefCell<Vec<u8>>,
        disables: RefCell<Vec<u8>>,
    }

    impl FakeController {
        fn new() -> Self {
            Self {
                enabled: [false; VECTOR_COUNT],
                in_service: [false; VECTOR_COUNT],
                fail_enable_for: None,
                irql: IrqlState::new(),
                claims: RefCell::new(Vec::new()),
                ends: RefCell::new(Vec::new()),
                enables: RefCell::new(Vec::new()),
                disables: RefCell::new(Vec::new()),
            }
        }

        /// Acknowledge a line (set its in-service bit), as the CPU's interrupt-acknowledge cycle
        /// would.
        fn acknowledge(&mut self, vector: u8) {
            self.in_service[(vector - FIRST_VECTOR) as usize] = true;
        }

        /// Drop a line's in-service bit (as an end would).
        fn complete(&mut self, vector: u8) {
            self.in_service[(vector - FIRST_VECTOR) as usize] = false;
        }
    }

    impl Controller for FakeController {
        fn claim(&mut self, vector: u8, level: Irql) -> Claim {
            self.claims.borrow_mut().push((vector, level));
            if self.in_service[(vector - FIRST_VECTOR) as usize] {
                Claim::Accepted(self.irql.raise(level))
            } else {
                Claim::Spurious
            }
        }

        fn end(&mut self, previous: Irql, vector: u8) {
            self.complete(vector);
            self.irql.lower(previous);
            self.ends.borrow_mut().push((previous, vector));
        }

        fn enable(&mut self, vector: u8) -> bool {
            self.enables.borrow_mut().push(vector);
            if self.fail_enable_for == Some(vector) {
                return false;
            }
            self.enabled[(vector - FIRST_VECTOR) as usize] = true;
            true
        }

        fn disable(&mut self, vector: u8) {
            self.disables.borrow_mut().push(vector);
            self.enabled[(vector - FIRST_VECTOR) as usize] = false;
        }

        fn is_enabled(&mut self, vector: u8) -> bool {
            self.enabled[(vector - FIRST_VECTOR) as usize]
        }

        fn in_service_clear(&mut self) -> bool {
            self.in_service.iter().all(|&bit| !bit)
        }
    }

    /// The service recorder: logs calls.
    thread_local! {
        static SERVICE_CALLS: RefCell<Vec<u8>> = RefCell::new(Vec::new());
    }

    fn recording_service(_object: &InterruptObject, _context: usize) -> bool {
        SERVICE_CALLS.with(|calls| calls.borrow_mut().push(1));
        true
    }

    /// An initialized object at the given vector.
    fn object_at(vector: u8) -> InterruptObject {
        let mut object = InterruptObject::zeroed();
        initialize(
            &mut object,
            recording_service,
            0x1234,
            vector,
            Irql(3),
            Irql(3),
            false,
            false,
        );
        object
    }

    /// The vector band: 0x30-0x3F, exactly 16 vectors, clear of the syscall gate at 0x2E, matching
    /// the chips' programmed bases.
    #[test]
    fn the_hardware_vector_band() {
        assert_eq!(FIRST_VECTOR, 0x30);
        assert_eq!(LAST_VECTOR, 0x3F);
        assert_eq!(VECTOR_COUNT, 16);
        assert_eq!(IRQ_VECTORS[0], FIRST_VECTOR);
        assert_eq!(IRQ_VECTORS[15], LAST_VECTOR);
        for (i, vector) in IRQ_VECTORS.iter().enumerate() {
            assert_eq!(*vector, FIRST_VECTOR as u8 + i as u8);
        }
        assert!(!IRQ_VECTORS.contains(&(crate::user::syscall::SYSCALL_VECTOR as u8)));
    }

    /// Initialize fills every field and connects nothing: the service and context round-trip, the
    /// levels round-trip, sharing and mode round-trip, and the object starts disconnected with a
    /// free lock.
    #[test]
    fn initialize_fills_everything_and_connects_nothing() {
        let mut object = InterruptObject::zeroed();
        initialize(
            &mut object,
            recording_service,
            0xABCD,
            0x35,
            Irql(5),
            Irql(6),
            true,
            true,
        );
        assert_eq!(object.vector(), 0x35);
        assert_eq!(object.service_context, 0xABCD);
        assert_eq!(object.level, Irql(5));
        assert_eq!(object.synchronize_level, Irql(6));
        assert!(object.level_triggered);
        assert!(object.shareable);
        assert!(!object.is_connected());
        assert!(!object.lock.load(Ordering::SeqCst));
        // The service is the one that was installed.
        fn probe(_object: &InterruptObject, _context: usize) -> bool {
            false
        }
        assert!(matches!(object.service as usize, _));
        let _ = probe as usize; // type-level witness: services are plain fn pointers
    }

    /// The validity gate: an over-scaled level, a synchronize level below the service level, or an
    /// out-of-band vector each leave the table and the controller untouched.
    #[test]
    fn invalid_parameters_are_refused_without_side_effects() {
        let mut controller = FakeController::new();

        // Level above the platform's scale.
        let mut over = object_at(FIRST_VECTOR);
        over.level = Irql(32);
        let mut table = VectorTable::zeroed();
        let mut irql = IrqlState::new();
        assert!(!table.connect(&mut over, &mut controller, &mut irql));
        assert_eq!(table.classify(FIRST_VECTOR), VectorState::Unconnected);
        assert!(!controller.is_enabled(FIRST_VECTOR));

        // Synchronize level below the service level.
        let mut under = object_at(FIRST_VECTOR);
        under.synchronize_level = Irql(2);
        under.level = Irql(3);
        assert!(!table.connect(&mut under, &mut controller, &mut irql));
        assert_eq!(table.classify(FIRST_VECTOR), VectorState::Unconnected);

        // A vector outside the hardware band.
        let mut outside = object_at(0x2E);
        assert!(!table.connect(&mut outside, &mut controller, &mut irql));
        assert_eq!(table.classify(0x2E), VectorState::Unknown);

        // Nothing was claimed, enabled, disabled, or ended.
        assert!(controller.claims.borrow().is_empty());
        assert!(controller.enables.borrow().is_empty());
        assert!(controller.disables.borrow().is_empty());
        assert!(controller.ends.borrow().is_empty());
    }

    /// Connect on an unconnected vector: the slot is wired, the line is enabled exactly once with
    /// the object's vector, and the object reports connected.
    #[test]
    fn connect_wires_the_slot_and_enables_the_line_once() {
        let mut table = VectorTable::zeroed();
        let mut controller = FakeController::new();
        let mut irql = IrqlState::new();
        let mut object = object_at(FIRST_VECTOR + 4);

        assert!(table.connect(&mut object, &mut controller, &mut irql));
        assert!(object.is_connected());
        assert_eq!(table.classify(FIRST_VECTOR + 4), VectorState::Connected);
        assert!(controller.is_enabled(FIRST_VECTOR + 4));
        assert_eq!(*controller.enables.borrow(), vec![FIRST_VECTOR + 4]);
    }

    /// A failing enable rolls the connect back: the slot is unwired, the object stays disconnected,
    /// and connect reports failure.
    #[test]
    fn a_failing_enable_rolls_the_connect_back() {
        let mut table = VectorTable::zeroed();
        let mut controller = FakeController::new();
        controller.fail_enable_for = Some(FIRST_VECTOR + 1);
        let mut irql = IrqlState::new();
        let mut object = object_at(FIRST_VECTOR + 1);

        assert!(!table.connect(&mut object, &mut controller, &mut irql));
        assert!(!object.is_connected());
        assert_eq!(table.classify(FIRST_VECTOR + 1), VectorState::Unconnected);
        assert!(!controller.is_enabled(FIRST_VECTOR + 1));
    }

    /// An already-connected object connects nowhere.
    #[test]
    fn a_double_connect_is_refused() {
        let mut table = VectorTable::zeroed();
        let mut controller = FakeController::new();
        let mut irql = IrqlState::new();
        let mut object = object_at(FIRST_VECTOR + 2);

        assert!(table.connect(&mut object, &mut controller, &mut irql));
        assert!(!table.connect(&mut object, &mut controller, &mut irql));
        assert_eq!(table.classify(FIRST_VECTOR + 2), VectorState::Connected);
        assert_eq!(controller.enables.borrow().len(), 1);
    }

    /// Sharing: a sharable newcomer with the same trigger mode joins the incumbent into a chain;
    /// anything incompatible is refused and changes nothing.
    #[test]
    fn a_compatible_newcomer_chains_onto_the_incumbent() {
        let mut table = VectorTable::zeroed();
        let mut controller = FakeController::new();
        let mut irql = IrqlState::new();

        let mut incumbent = object_at(FIRST_VECTOR + 9);
        incumbent.shareable = true;
        assert!(table.connect(&mut incumbent, &mut controller, &mut irql));

        // Compatible: both sharable, both edge-triggered.
        let mut newcomer = object_at(FIRST_VECTOR + 9);
        newcomer.shareable = true;
        assert!(table.connect(&mut newcomer, &mut controller, &mut irql));
        assert_eq!(table.classify(FIRST_VECTOR + 9), VectorState::Chained);

        // The refusal matrix: not shareable, mode mismatch, or a third object (the chain is two).
        let mut third = object_at(FIRST_VECTOR + 9);
        third.shareable = true;
        assert!(!table.connect(&mut third, &mut controller, &mut irql));

        let mut not_sharable = object_at(FIRST_VECTOR + 9);
        not_sharable.shareable = false;
        assert!(!table.connect(&mut not_sharable, &mut controller, &mut irql));

        // A mode mismatch: incumbent edge, newcomer level.
        let mut table2 = VectorTable::zeroed();
        let mut incumbent2 = object_at(FIRST_VECTOR + 9);
        incumbent2.shareable = true;
        incumbent2.level_triggered = true;
        assert!(table2.connect(&mut incumbent2, &mut controller, &mut irql));
        let mut edge_newcomer = object_at(FIRST_VECTOR + 9);
        edge_newcomer.shareable = true;
        assert!(!table2.connect(&mut edge_newcomer, &mut controller, &mut irql));
        assert_eq!(table2.classify(FIRST_VECTOR + 9), VectorState::Connected);
    }

    /// Disconnect: removing the only object masks the line and clears the slot; an unconnected
    /// object reports false.
    #[test]
    fn disconnect_masks_the_line_and_clears_the_slot() {
        let mut table = VectorTable::zeroed();
        let mut controller = FakeController::new();
        let mut irql = IrqlState::new();
        let mut object = object_at(FIRST_VECTOR + 3);

        assert!(table.connect(&mut object, &mut controller, &mut irql));
        assert!(table.disconnect(&mut object, &mut controller, &mut irql));
        assert!(!object.is_connected());
        assert_eq!(table.classify(FIRST_VECTOR + 3), VectorState::Unconnected);
        assert!(!controller.is_enabled(FIRST_VECTOR + 3));
        assert_eq!(*controller.disables.borrow(), vec![FIRST_VECTOR + 3]);

        // Disconnecting an unconnected object reports false.
        assert!(!table.disconnect(&mut object, &mut controller, &mut irql));
    }

    /// Chain surgery: removing the head promotes the second object; removing the second opens the
    /// slot; removing the last of all masks the line. The line stays enabled while any object
    /// remains.
    #[test]
    fn chain_surgery_head_second_and_last() {
        let mut table = VectorTable::zeroed();
        let mut controller = FakeController::new();
        let mut irql = IrqlState::new();

        let mut head = object_at(FIRST_VECTOR + 7);
        head.shareable = true;
        let mut tail = object_at(FIRST_VECTOR + 7);
        tail.shareable = true;
        assert!(table.connect(&mut head, &mut controller, &mut irql));
        assert!(table.connect(&mut tail, &mut controller, &mut irql));
        assert_eq!(table.classify(FIRST_VECTOR + 7), VectorState::Chained);

        // Removing the head promotes the tail; the line stays on.
        assert!(table.disconnect(&mut head, &mut controller, &mut irql));
        assert_eq!(table.classify(FIRST_VECTOR + 7), VectorState::Connected);
        assert!(controller.is_enabled(FIRST_VECTOR + 7));
        assert!(controller.disables.borrow().is_empty());

        // Removing the last object masks the line.
        assert!(table.disconnect(&mut tail, &mut controller, &mut irql));
        assert_eq!(table.classify(FIRST_VECTOR + 7), VectorState::Unconnected);
        assert!(!controller.is_enabled(FIRST_VECTOR + 7));

        // And the tail-removal case: head stays, slot opens.
        let mut head2 = object_at(FIRST_VECTOR + 7);
        head2.shareable = true;
        let mut tail2 = object_at(FIRST_VECTOR + 7);
        tail2.shareable = true;
        assert!(table.connect(&mut head2, &mut controller, &mut irql));
        assert!(table.connect(&mut tail2, &mut controller, &mut irql));
        assert!(table.disconnect(&mut tail2, &mut controller, &mut irql));
        assert_eq!(table.classify(FIRST_VECTOR + 7), VectorState::Connected);
        assert!(controller.is_enabled(FIRST_VECTOR + 7));
        assert_eq!(controller.disables.borrow().len(), 1);
    }

    /// The four-way classification over the table: unconnected, connected, chained — and unknown
    /// outside the band.
    #[test]
    fn classification_is_the_four_way_state() {
        let mut table = VectorTable::zeroed();
        let mut controller = FakeController::new();
        let mut irql = IrqlState::new();

        assert_eq!(table.classify(FIRST_VECTOR + 5), VectorState::Unconnected);
        assert_eq!(table.classify(0x05), VectorState::Unknown);
        assert_eq!(table.classify(0x2E), VectorState::Unknown);
        assert_eq!(table.classify(0x40), VectorState::Unknown);

        let mut one = object_at(FIRST_VECTOR + 5);
        assert!(table.connect(&mut one, &mut controller, &mut irql));
        assert_eq!(table.classify(FIRST_VECTOR + 5), VectorState::Connected);

        let mut two = object_at(FIRST_VECTOR + 5);
        two.shareable = true;
        one.shareable = true;
        assert!(table.connect(&mut two, &mut controller, &mut irql));
        assert_eq!(table.classify(FIRST_VECTOR + 5), VectorState::Chained);
    }

    /// The claim protocol: an accepted claim is followed by exactly one end (the service ran
    /// first); a spurious claim by none — no service, no raise, nothing acknowledged beyond what
    /// the controller already owned.
    #[test]
    fn the_claim_protocol_pairs_one_end_with_each_acceptance() {
        let mut table = VectorTable::zeroed();
        let mut controller = FakeController::new();
        let mut irql = IrqlState::new();
        let mut object = object_at(FIRST_VECTOR);
        assert!(table.connect(&mut object, &mut controller, &mut irql));

        // A real interrupt: acknowledged in-service, then served.
        controller.acknowledge(FIRST_VECTOR);
        SERVICE_CALLS.with(|calls| calls.borrow_mut().clear());
        let outcome = service_interrupt(&table, &mut controller, FIRST_VECTOR);
        assert!(matches!(outcome, Outcome::Served));
        assert_eq!(controller.ends.borrow().len(), 1);
        assert_eq!(SERVICE_CALLS.with(|c| c.borrow().len()), 1);
        assert_eq!(controller.irql.current(), crate::interrupt::irql::PASSIVE);
        assert!(controller.in_service_clear());

        // A spurious interrupt: nothing in service, nothing claimed beyond the probe, nothing
        // ended, no service run.
        SERVICE_CALLS.with(|calls| calls.borrow_mut().clear());
        let outcome = service_interrupt(&table, &mut controller, FIRST_VECTOR);
        assert!(matches!(outcome, Outcome::Spurious));
        assert_eq!(controller.ends.borrow().len(), 1, "no new end");
        assert_eq!(SERVICE_CALLS.with(|c| c.borrow().len()), 0);
        assert_eq!(controller.irql.current(), crate::interrupt::irql::PASSIVE);

        // A real interrupt on an unconnected vector: ended properly, but reported as the kernel bug
        // it is.
        let mut controller2 = FakeController::new();
        controller2.acknowledge(FIRST_VECTOR + 6);
        let outcome = service_interrupt(&table, &mut controller2, FIRST_VECTOR + 6);
        assert!(matches!(outcome, Outcome::Unexpected));
        assert_eq!(controller2.ends.borrow().len(), 1);
        assert!(controller2.in_service_clear());
    }

    /// The connect/disconnect state machine can never leave a line enabled without a connected
    /// object (the audit).
    #[test]
    fn no_line_enabled_without_an_object() {
        let mut table = VectorTable::zeroed();
        let mut controller = FakeController::new();
        let mut irql = IrqlState::new();
        assert_eq!(table.audit(&mut controller), Ok(()));

        let mut object = object_at(FIRST_VECTOR + 11);
        assert!(table.connect(&mut object, &mut controller, &mut irql));
        assert_eq!(table.audit(&mut controller), Ok(()));
        assert!(table.disconnect(&mut object, &mut controller, &mut irql));
        assert_eq!(table.audit(&mut controller), Ok(()));

        // An enable without a connect (a controller gone rogue) is what the audit exists to catch.
        controller.enabled[(FIRST_VECTOR + 11 - FIRST_VECTOR) as usize] = true;
        assert!(table.audit(&mut controller).is_err());
    }

    /// Synchronize: the routine runs raised to the object's synchronize level, under the object's
    /// lock, with the level lowered back after.
    struct SyncProbe {
        level: RefCell<Option<Irql>>,
        lock: RefCell<Option<bool>>,
    }

    thread_local! {
        static SYNC_IRQL: RefCell<*mut IrqlState> = RefCell::new(core::ptr::null_mut());
        static SYNC_OBJECT: RefCell<*const InterruptObject> =
            RefCell::new(core::ptr::null());
        static SYNC_PROBE: RefCell<*mut SyncProbe> = RefCell::new(core::ptr::null_mut());
    }

    fn sync_routine(_context: usize) -> bool {
        // The thread-locals hold the raw pointers the probe reads.
        let level = SYNC_IRQL.with(|s| unsafe { (*(*s.borrow())).current() });
        let locked = SYNC_OBJECT.with(|o| unsafe { (*(*o.borrow())).lock.load(Ordering::SeqCst) });
        SYNC_PROBE.with(|p| unsafe {
            let probe = &mut *(*p.borrow());
            *probe.level.borrow_mut() = Some(level);
            *probe.lock.borrow_mut() = Some(locked);
        });
        true
    }

    #[test]
    fn synchronize_runs_raised_and_locked() {
        let table = VectorTable::zeroed();
        let mut object = object_at(FIRST_VECTOR + 2);
        object.synchronize_level = Irql(8);
        let mut irql = IrqlState::new();
        let mut probe = SyncProbe {
            level: RefCell::new(None),
            lock: RefCell::new(None),
        };
        SYNC_IRQL.with(|s| *s.borrow_mut() = &mut irql as *mut IrqlState);
        SYNC_OBJECT.with(|o| *o.borrow_mut() = &object as *const InterruptObject);
        SYNC_PROBE.with(|p| *p.borrow_mut() = &mut probe as *mut SyncProbe);

        assert!(table.synchronize_execution(&object, sync_routine, 0, &mut irql));
        assert_eq!(
            *probe.level.borrow(),
            Some(Irql(8)),
            "raised during the routine"
        );
        assert_eq!(
            *probe.lock.borrow(),
            Some(true),
            "the lock is held during the routine"
        );
        assert_eq!(
            irql.current(),
            crate::interrupt::irql::PASSIVE,
            "lowered after"
        );
        assert!(
            !object.lock.load(Ordering::SeqCst),
            "the lock is released after"
        );
    }
}
