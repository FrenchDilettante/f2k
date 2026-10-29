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
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

#[cfg(all(target_arch = "x86", feature = "irq-smoke"))]
pub use smoke::run as smoke;
#[cfg(all(target_arch = "x86", feature = "nest-smoke"))]
mod nest_smoke;
#[cfg(all(target_arch = "x86", feature = "nest-smoke"))]
pub use nest_smoke::run as nest_smoke;

use crate::interrupt::irql::{Irql, OldIrql, HIGH, SYNCH};
use crate::level::{At, Clock, Ide, Keyboard, Level};
use crate::pcr::pcr;

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
    /// service and then end it ([`Controller::end`]) exactly once. Carries what the raise found.
    Accepted(OldIrql),
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
    /// return what the raise found — or report the interrupt spurious (nothing raised).
    fn claim(&mut self, vector: u8, level: Irql) -> Claim;
    /// End a claimed interrupt: acknowledge the chip, then lower back to the recorded level. The
    /// acknowledgment comes first, while interrupts are still masked: the lower may re-enable
    /// them, and an interrupt taken there may switch threads before this exit resumes.
    fn end(&mut self, previous: OldIrql, vector: u8);
    /// Enable (unmask) the vector's line; false if it could not be.
    fn enable(&mut self, vector: u8) -> bool;
    /// Disable (mask) the vector's line.
    fn disable(&mut self, vector: u8);
    /// Whether the vector's line is enabled.
    fn is_enabled(&mut self, vector: u8) -> bool;
    /// Whether no interrupt is left half-served on the chip.
    fn in_service_clear(&mut self) -> bool;
}

/// An interrupt service that takes no level token: `(object, service_context)`. The return value
/// reports the interrupt handled; a shared vector runs every object's service regardless. The
/// kernel's own interrupts are all typed; the host tests' objects, at levels of their own, use
/// this.
pub type InterruptService = fn(&InterruptObject, usize) -> bool;

/// An interrupt service at level `L`, handed that level's token: `(at, service_context)`.
pub type TypedService<L> = fn(&mut At<L>, usize) -> bool;

/// An interrupt service at the clock level.
pub type ClockService = TypedService<Clock>;

/// An interrupt service at the keyboard's level.
pub type KeyboardService = TypedService<Keyboard>;

/// An interrupt service at the IDE disk's level.
pub type IdeService = TypedService<Ide>;

/// What an object's claim runs. A service that takes a level token is typed by its level, so the
/// token it is handed is the one the claim raised to.
#[derive(Clone, Copy)]
enum Service {
    /// A service that takes no token.
    Untyped(InterruptService),
    /// A clock-level service.
    Clock(ClockService),
    /// A keyboard-level service.
    Keyboard(KeyboardService),
    /// An IDE-level service.
    Ide(IdeService),
}

/// One connected (or connectable) interrupt.
pub struct InterruptObject {
    service: Service,
    service_context: usize,
    vector: u8,
    level: Irql,
    synchronize_level: Irql,
    shareable: bool,
    level_triggered: bool,
    /// Set and cleared by connect and disconnect, raised to the synchronize level.
    connected: AtomicBool,
    /// The exclusion lock synchronize runs under.
    lock: AtomicBool,
}

impl InterruptObject {
    /// A zeroed object; call [`initialize`] before use.
    #[cfg_attr(not(test), allow(dead_code))]
    pub const fn zeroed() -> Self {
        Self {
            service: Service::Untyped(never_service),
            service_context: 0,
            vector: 0,
            level: Irql(0),
            synchronize_level: Irql(0),
            shareable: false,
            level_triggered: false,
            connected: AtomicBool::new(false),
            lock: AtomicBool::new(false),
        }
    }

    /// An object whose service runs at the clock level and is handed its token: the service and
    /// its context, the vector, and the sharing mode. The level and the synchronize level are the
    /// clock's. The object starts disconnected; validity is checked at connect.
    pub const fn at_clock(
        service: ClockService,
        service_context: usize,
        vector: u8,
        level_triggered: bool,
        shareable: bool,
    ) -> Self {
        Self::typed::<Clock>(
            Service::Clock(service),
            service_context,
            vector,
            level_triggered,
            shareable,
        )
    }

    /// An object whose service runs at the keyboard's level and is handed its token (see
    /// [`InterruptObject::at_clock`]).
    pub const fn at_keyboard(
        service: KeyboardService,
        service_context: usize,
        vector: u8,
        level_triggered: bool,
        shareable: bool,
    ) -> Self {
        Self::typed::<Keyboard>(
            Service::Keyboard(service),
            service_context,
            vector,
            level_triggered,
            shareable,
        )
    }

    /// An object whose service runs at the IDE disk's level and is handed its token (see
    /// [`InterruptObject::at_clock`]).
    pub const fn at_ide(
        service: IdeService,
        service_context: usize,
        vector: u8,
        level_triggered: bool,
        shareable: bool,
    ) -> Self {
        Self::typed::<Ide>(
            Service::Ide(service),
            service_context,
            vector,
            level_triggered,
            shareable,
        )
    }

    /// An object served at level `L`, which is both its level and its synchronize level.
    const fn typed<L: Level>(
        service: Service,
        service_context: usize,
        vector: u8,
        level_triggered: bool,
        shareable: bool,
    ) -> Self {
        Self {
            service,
            service_context,
            vector,
            level: L::IRQL,
            synchronize_level: L::IRQL,
            shareable,
            level_triggered,
            connected: AtomicBool::new(false),
            lock: AtomicBool::new(false),
        }
    }

    /// The vector this object is bound to.
    pub fn vector(&self) -> u8 {
        self.vector
    }

    /// Whether this object is connected.
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    /// Run the service, once the claim has raised the processor from `previous` to `claimed`, the
    /// level of the vector's first object. A typed service is handed its level's token.
    fn serve(&self, previous: OldIrql, claimed: Irql) {
        match self.service {
            Service::Untyped(service) => {
                service(self, self.service_context);
            }
            Service::Clock(service) => serve_at(service, self.service_context, previous, claimed),
            Service::Keyboard(service) => {
                serve_at(service, self.service_context, previous, claimed)
            }
            Service::Ide(service) => serve_at(service, self.service_context, previous, claimed),
        }
    }
}

/// Run a service typed by its level `L`, handing it the token the claim proves: the claim raised
/// the processor from `previous` to `claimed`.
fn serve_at<L: Level>(service: TypedService<L>, context: usize, previous: OldIrql, claimed: Irql) {
    // A typed service is handed the token the claim proves, so it must have been claimed at its
    // own level (a shared vector's second object could differ), from below it.
    assert!(
        claimed == L::IRQL && previous.level() < claimed,
        "a typed interrupt service claimed at another level"
    );
    // SAFETY: an entry: the claim raised the processor to `L` from below it (both checked just
    // above), so no other token for `L` is live; the token dies with the call, before the claim's
    // end lowers.
    let mut at = unsafe { At::<L>::enter() };
    service(&mut at, context);
}

/// A service that can never be called: the zeroed object's placeholder (a connected object always
/// has a real service).
fn never_service(_object: &InterruptObject, _context: usize) -> bool {
    false
}

/// Fill an interrupt object: the service and its context, the vector and its level, the synchronize
/// level, and the sharing mode. The object starts disconnected. Validity is checked at connect.
#[cfg_attr(not(test), allow(dead_code))]
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
    object.service = Service::Untyped(service);
    object.service_context = service_context;
    object.vector = vector;
    object.level = level;
    object.synchronize_level = synchronize_level;
    object.level_triggered = level_triggered;
    object.shareable = shareable;
    object.connected = AtomicBool::new(false);
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
///
/// The slots are atomics, so the table is a plain static: the interrupt dispatch reads them with
/// no lock, and connect and disconnect change them raised to the synchronize level (interrupts
/// masked), so no claim reads a slot halfway through a change.
pub struct VectorTable {
    slots: [Slot; VECTOR_COUNT],
}

struct Slot {
    /// The connected objects, in service order; null for none. A chain is exactly two (a driver
    /// may share its line with one other). Only `&'static` objects are stored:
    /// [`VectorTable::connect`] takes nothing else.
    objects: [AtomicPtr<InterruptObject>; 2],
}

impl Slot {
    const EMPTY: Slot = Slot {
        objects: [
            AtomicPtr::new(core::ptr::null_mut()),
            AtomicPtr::new(core::ptr::null_mut()),
        ],
    };

    /// The object in position `at`, if any.
    fn object(&self, at: usize) -> Option<&'static InterruptObject> {
        let object = self.objects[at].load(Ordering::SeqCst);
        // SAFETY: a slot holds null or an object `connect` stored, which took it as
        // `&'static InterruptObject`: valid and shared for the kernel's lifetime.
        unsafe { object.cast_const().as_ref() }
    }

    /// Store `object` (or none) in position `at`.
    fn store(&self, at: usize, object: Option<&'static InterruptObject>) {
        let pointer = object.map_or(core::ptr::null_mut(), |object| {
            core::ptr::from_ref(object).cast_mut()
        });
        self.objects[at].store(pointer, Ordering::SeqCst);
    }

    /// Whether position `at` holds `object`.
    fn holds(&self, at: usize, object: &InterruptObject) -> bool {
        self.object(at)
            .is_some_and(|held| core::ptr::eq(held, object))
    }
}

impl VectorTable {
    /// An empty table: every slot unconnected.
    pub const fn zeroed() -> Self {
        Self {
            slots: [const { Slot::EMPTY }; VECTOR_COUNT],
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
        match self.connected(vector) {
            _ if Self::index_of(vector).is_none() => VectorState::Unknown,
            [None, None] => VectorState::Unconnected,
            [Some(_), None] => VectorState::Connected,
            [Some(_), Some(_)] => VectorState::Chained,
            [None, Some(_)] => VectorState::Unknown,
        }
    }

    /// The objects connected to a vector, in service order.
    pub fn connected(&self, vector: u8) -> [Option<&'static InterruptObject>; 2] {
        let Some(index) = Self::index_of(vector) else {
            return [None, None];
        };
        let slot = &self.slots[index];
        [slot.object(0), slot.object(1)]
    }

    /// Connect `object` to its vector: wire the slot and enable the line. Returns whether it
    /// connected: an already-connected object connects nowhere, an invalid one is refused without
    /// side effects, a failing enable rolls everything back, and a sharable newcomer may join a
    /// compatible incumbent. The object is a static (or leaked): the table keeps it for the
    /// kernel's lifetime.
    pub fn connect(
        &self,
        object: &'static InterruptObject,
        controller: &mut dyn Controller,
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
        if object.is_connected() {
            return false;
        }

        // The synchronize level (interrupts masked) for the whole state change.
        let previous = pcr().raise(SYNCH);
        let index = Self::index_of(object.vector).unwrap();
        let slot = &self.slots[index];
        let mut connected_now = false;

        match slot.object(0) {
            None => {
                // An unconnected vector: wire the slot, then enable the line. A failing enable
                // leaves everything as it was.
                object.connected.store(true, Ordering::SeqCst);
                slot.store(0, Some(object));
                if controller.enable(object.vector) {
                    connected_now = true;
                } else {
                    slot.store(0, None);
                    object.connected.store(false, Ordering::SeqCst);
                }
            }
            Some(incumbent) => {
                // A connected vector: only a sharable newcomer with the same trigger mode may
                // join, and only into the one free chain slot.
                let compatible = object.shareable
                    && incumbent.shareable
                    && object.level_triggered == incumbent.level_triggered;
                if compatible && slot.object(1).is_none() {
                    object.connected.store(true, Ordering::SeqCst);
                    slot.store(1, Some(object));
                    connected_now = true;
                }
            }
        }

        pcr().lower(previous);
        connected_now
    }

    /// Disconnect `object`: mask the line (unless another object still serves it) and clear the
    /// slot. Returns whether the object had been connected.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn disconnect(&self, object: &InterruptObject, controller: &mut dyn Controller) -> bool {
        let was_connected = object.is_connected();
        if was_connected {
            let previous = pcr().raise(SYNCH);
            let index = Self::index_of(object.vector).unwrap();
            let slot = &self.slots[index];

            if slot.object(1).is_some() {
                // Chain surgery: removing the head promotes the second object; removing the second
                // just opens the slot. The line stays enabled either way.
                if slot.holds(0, object) {
                    slot.store(0, slot.object(1));
                }
                slot.store(1, None);
            } else if slot.holds(0, object) {
                // The last object on the vector: mask the line and clear the slot.
                controller.disable(object.vector);
                slot.store(0, None);
            } else {
                // The object is connected but not on this vector's slot — the state machine is
                // broken; refuse.
                pcr().lower(previous);
                return false;
            }
            object.connected.store(false, Ordering::SeqCst);
            pcr().lower(previous);
        }
        was_connected
    }

    /// Run `routine` with the object's service excluded: raised to the synchronize level, under the
    /// object's lock, lowered back after. Returns the routine's result.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn synchronize_execution(
        &self,
        object: &InterruptObject,
        routine: fn(usize) -> bool,
        context: usize,
    ) -> bool {
        // Raise first, then take the lock: the level is what keeps the service out; the lock is
        // what keeps other synchronizers out.
        let previous = pcr().raise(object.synchronize_level);
        while object.lock.swap(true, Ordering::SeqCst) {
            core::hint::spin_loop();
        }
        let result = routine(context);
        object.lock.store(false, Ordering::SeqCst);
        pcr().lower(previous);
        result
    }

    /// The table's audit: no vector may be enabled without a connected object, and no interrupt may
    /// be left half-served on the chip.
    pub fn audit(&self, controller: &mut dyn Controller) -> Result<(), &'static str> {
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
            for object in [first, second].into_iter().flatten() {
                object.serve(previous, level);
            }
            controller.end(previous, vector);
            Outcome::Served
        }
    }
}

// --- Target wiring: the kernel table, controller, and dispatch --------------

#[cfg(target_arch = "x86")]
mod target {
    use core::sync::atomic::AtomicU32;

    use super::*;
    use crate::cpu::idt::ExceptionFrame;
    use crate::hw::pic::{self, Pic, Verdict};
    use crate::hw::portio::Ports;

    /// The kernel's vector table.
    static TABLE: VectorTable = VectorTable::zeroed();

    /// The kernel's interrupt controller (the 8259A pair, remapped to the hardware band).
    pub(super) static CONTROLLER: Pic<Ports> =
        Pic::new(Ports, pic::MASTER_VECTOR_BASE, pic::SLAVE_VECTOR_BASE);

    /// Spurious interrupts counted so far (see [`spurious_count`]).
    static SPURIOUS: AtomicU32 = AtomicU32::new(0);

    /// The kernel's controller as the core's seam reaches it: the static pair.
    struct Chip;

    impl Controller for Chip {
        fn claim(&mut self, vector: u8, level: Irql) -> Claim {
            match CONTROLLER.claim(vector) {
                // Real: raise to the service level. The ledger performs the interrupt-flag
                // transition.
                Verdict::Real => Claim::Accepted(pcr().raise(level)),
                // Spurious: the chip work is already done inside the controller; nothing was
                // raised.
                Verdict::SpuriousNoEoi | Verdict::SpuriousCascadeEnded => Claim::Spurious,
            }
        }

        fn end(&mut self, previous: OldIrql, vector: u8) {
            // Acknowledged with interrupts masked: a line the claim held off waits for the lower
            // (see `IrqlState::end_claim`).
            pcr().end_claim(previous, || CONTROLLER.end_of_interrupt(vector));
        }

        fn enable(&mut self, vector: u8) -> bool {
            CONTROLLER.unmask(vector);
            true
        }

        fn disable(&mut self, vector: u8) {
            CONTROLLER.mask(vector);
        }

        fn is_enabled(&mut self, vector: u8) -> bool {
            CONTROLLER.is_unmasked(vector)
        }

        fn in_service_clear(&mut self) -> bool {
            CONTROLLER.in_service_clear()
        }
    }

    /// The interval clock's interrupt object: IRQ 0, served at the clock level.
    static CLOCK_OBJECT: InterruptObject =
        InterruptObject::at_clock(clock_service, 0, super::clock::CLOCK_VECTOR, false, false);

    fn clock_service(at_clock: &mut At<Clock>, _context: usize) -> bool {
        super::clock::service(at_clock);
        true
    }

    /// The assembly stub's landing: service the interrupt the frame names, then drain the
    /// deferred-work queue (the dispatch software level runs on the way down, at the interrupt
    /// exit), then deliver any pending dispatch request — a quantum the tick ended, or a thread the
    /// drained work readied at a higher priority. A delivered switch resumes this exit when the
    /// interrupted thread next runs.
    extern "C" fn dispatch(frame: &ExceptionFrame) {
        let vector = frame.vector as u8;
        // The performance trace samples on the clock's vector: the tick is its clock. The gate
        // masked interrupts and the ledger does not know yet (the claim tells it): the sample's
        // clock read raises and lowers through the ledger, and must not enable them on its way
        // out, so the ledger is told for the sample's length.
        #[cfg(feature = "perf-trace")]
        if vector == super::clock::CLOCK_VECTOR {
            let enabled = pcr().interrupts_enabled();
            pcr().enter_gate();
            crate::perf::sample(frame);
            pcr().leave_gate(enabled);
        }
        match service_interrupt(&TABLE, &mut Chip, vector) {
            Outcome::Served => {
                crate::interrupt::dpc::drain();
                crate::sched::dispatcher::deliver_pending();
            }
            Outcome::Spurious => {
                SPURIOUS.fetch_add(1, Ordering::Relaxed);
            }
            Outcome::Unexpected => {
                crate::serial_println!(
                    "F2K: unexpected interrupt on vector {:#04x}; halting",
                    vector
                );
                crate::halt();
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
        // The 8259 pair: vectors 0x30-0x3F, every line masked.
        CONTROLLER.remap();
        // The 8254: the captured platform interval.
        let mut ports = Ports;
        crate::hw::pit::program_interval(&mut ports, crate::hw::pit::INTERVAL_DIVISOR);
        // The wall clock's origin, read while the kernel clock still reads zero.
        crate::time::init(&mut ports);
        // The shared data page, its system time that reading, before the first tick updates it.
        crate::user::shared::init(crate::time::boot_filetime());

        super::clock::init();
        // The performance trace's sampling rate, if the kernel command line asks for one.
        #[cfg(feature = "perf-trace")]
        crate::perf::init();

        // The interval clock.
        let connected = TABLE.connect(&CLOCK_OBJECT, &mut Chip);
        assert!(connected, "connecting the interval clock failed");

        // Interrupts fly from here on.
        pcr().unmask_interrupts();
    }

    /// Connect a driver's interrupt object to its vector in the kernel table: wire the slot and
    /// enable the line (see [`VectorTable::connect`]). The object is a static: the table keeps its
    /// address for the kernel's lifetime.
    pub fn connect(object: &'static InterruptObject) -> bool {
        TABLE.connect(object, &mut Chip)
    }

    /// The interrupt subsystem's audit: the level transitions are balanced, no line is enabled
    /// without an object, and the chip carries no stuck in-service state.
    pub fn audit() -> Result<(), &'static str> {
        pcr().audit()?;
        TABLE.audit(&mut Chip)
    }

    /// Spurious interrupts counted so far (diagnostic).
    pub fn spurious_count() -> u32 {
        SPURIOUS.load(Ordering::Relaxed)
    }

    /// Whether the clock's line has a request the processor has not taken yet: a tick the
    /// performance counter's reader must count, interrupts masked around it (no claim runs between
    /// the select and the read).
    pub fn clock_requested() -> bool {
        CONTROLLER.requested(super::clock::CLOCK_VECTOR)
    }
}

#[cfg(target_arch = "x86")]
// `audit` has no caller outside the irq-smoke diagnostic; the subsystem API stays complete.
#[allow(unused_imports)]
pub use target::{audit, clock_requested, connect, init, spurious_count};

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
    use crate::interrupt::irql::IrqlState;

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

        fn end(&mut self, previous: OldIrql, vector: u8) {
            self.complete(vector);
            self.irql.lower(previous);
            self.ends.borrow_mut().push((previous.level(), vector));
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

    /// An object the table can keep: leaked, as the kernel's are statics.
    fn leak(object: InterruptObject) -> &'static InterruptObject {
        Box::leak(Box::new(object))
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
        // The service is the one that was installed, untyped (it takes no level token).
        assert!(
            matches!(object.service, Service::Untyped(service) if core::ptr::fn_addr_eq(service, recording_service as InterruptService))
        );
    }

    /// The validity gate: an over-scaled level, a synchronize level below the service level, or an
    /// out-of-band vector each leave the table and the controller untouched.
    #[test]
    fn invalid_parameters_are_refused_without_side_effects() {
        let mut controller = FakeController::new();

        // Level above the platform's scale.
        let mut over = object_at(FIRST_VECTOR);
        over.level = Irql(32);
        let table = VectorTable::zeroed();
        assert!(!table.connect(leak(over), &mut controller));
        assert_eq!(table.classify(FIRST_VECTOR), VectorState::Unconnected);
        assert!(!controller.is_enabled(FIRST_VECTOR));

        // Synchronize level below the service level.
        let mut under = object_at(FIRST_VECTOR);
        under.synchronize_level = Irql(2);
        under.level = Irql(3);
        assert!(!table.connect(leak(under), &mut controller));
        assert_eq!(table.classify(FIRST_VECTOR), VectorState::Unconnected);

        // A vector outside the hardware band.
        let outside = leak(object_at(0x2E));
        assert!(!table.connect(outside, &mut controller));
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
        let table = VectorTable::zeroed();
        let mut controller = FakeController::new();
        let object = leak(object_at(FIRST_VECTOR + 4));

        assert!(table.connect(object, &mut controller));
        assert!(object.is_connected());
        assert_eq!(table.classify(FIRST_VECTOR + 4), VectorState::Connected);
        assert!(controller.is_enabled(FIRST_VECTOR + 4));
        assert_eq!(*controller.enables.borrow(), vec![FIRST_VECTOR + 4]);
    }

    /// A failing enable rolls the connect back: the slot is unwired, the object stays disconnected,
    /// and connect reports failure.
    #[test]
    fn a_failing_enable_rolls_the_connect_back() {
        let table = VectorTable::zeroed();
        let mut controller = FakeController::new();
        controller.fail_enable_for = Some(FIRST_VECTOR + 1);
        let object = leak(object_at(FIRST_VECTOR + 1));

        assert!(!table.connect(object, &mut controller));
        assert!(!object.is_connected());
        assert_eq!(table.classify(FIRST_VECTOR + 1), VectorState::Unconnected);
        assert!(!controller.is_enabled(FIRST_VECTOR + 1));
    }

    /// An already-connected object connects nowhere.
    #[test]
    fn a_double_connect_is_refused() {
        let table = VectorTable::zeroed();
        let mut controller = FakeController::new();
        let object = leak(object_at(FIRST_VECTOR + 2));

        assert!(table.connect(object, &mut controller));
        assert!(!table.connect(object, &mut controller));
        assert_eq!(table.classify(FIRST_VECTOR + 2), VectorState::Connected);
        assert_eq!(controller.enables.borrow().len(), 1);
    }

    /// An object on the vector, sharable or not.
    fn sharable_at(vector: u8, shareable: bool) -> &'static InterruptObject {
        let mut object = object_at(vector);
        object.shareable = shareable;
        leak(object)
    }

    /// Sharing: a sharable newcomer with the same trigger mode joins the incumbent into a chain;
    /// anything incompatible is refused and changes nothing.
    #[test]
    fn a_compatible_newcomer_chains_onto_the_incumbent() {
        let table = VectorTable::zeroed();
        let mut controller = FakeController::new();

        let incumbent = sharable_at(FIRST_VECTOR + 9, true);
        assert!(table.connect(incumbent, &mut controller));

        // Compatible: both sharable, both edge-triggered.
        let newcomer = sharable_at(FIRST_VECTOR + 9, true);
        assert!(table.connect(newcomer, &mut controller));
        assert_eq!(table.classify(FIRST_VECTOR + 9), VectorState::Chained);

        // The refusal matrix: not shareable, mode mismatch, or a third object (the chain is two).
        let third = sharable_at(FIRST_VECTOR + 9, true);
        assert!(!table.connect(third, &mut controller));

        let not_sharable = sharable_at(FIRST_VECTOR + 9, false);
        assert!(!table.connect(not_sharable, &mut controller));

        // A mode mismatch: incumbent edge, newcomer level.
        let table2 = VectorTable::zeroed();
        let mut incumbent2 = object_at(FIRST_VECTOR + 9);
        incumbent2.shareable = true;
        incumbent2.level_triggered = true;
        assert!(table2.connect(leak(incumbent2), &mut controller));
        let edge_newcomer = sharable_at(FIRST_VECTOR + 9, true);
        assert!(!table2.connect(edge_newcomer, &mut controller));
        assert_eq!(table2.classify(FIRST_VECTOR + 9), VectorState::Connected);
    }

    /// Disconnect: removing the only object masks the line and clears the slot; an unconnected
    /// object reports false.
    #[test]
    fn disconnect_masks_the_line_and_clears_the_slot() {
        let table = VectorTable::zeroed();
        let mut controller = FakeController::new();
        let object = leak(object_at(FIRST_VECTOR + 3));

        assert!(table.connect(object, &mut controller));
        assert!(table.disconnect(object, &mut controller));
        assert!(!object.is_connected());
        assert_eq!(table.classify(FIRST_VECTOR + 3), VectorState::Unconnected);
        assert!(!controller.is_enabled(FIRST_VECTOR + 3));
        assert_eq!(*controller.disables.borrow(), vec![FIRST_VECTOR + 3]);

        // Disconnecting an unconnected object reports false.
        assert!(!table.disconnect(object, &mut controller));
    }

    /// Chain surgery: removing the head promotes the second object; removing the second opens the
    /// slot; removing the last of all masks the line. The line stays enabled while any object
    /// remains.
    #[test]
    fn chain_surgery_head_second_and_last() {
        let table = VectorTable::zeroed();
        let mut controller = FakeController::new();

        let head = sharable_at(FIRST_VECTOR + 7, true);
        let tail = sharable_at(FIRST_VECTOR + 7, true);
        assert!(table.connect(head, &mut controller));
        assert!(table.connect(tail, &mut controller));
        assert_eq!(table.classify(FIRST_VECTOR + 7), VectorState::Chained);

        // Removing the head promotes the tail; the line stays on.
        assert!(table.disconnect(head, &mut controller));
        assert_eq!(table.classify(FIRST_VECTOR + 7), VectorState::Connected);
        assert!(controller.is_enabled(FIRST_VECTOR + 7));
        assert!(controller.disables.borrow().is_empty());

        // Removing the last object masks the line.
        assert!(table.disconnect(tail, &mut controller));
        assert_eq!(table.classify(FIRST_VECTOR + 7), VectorState::Unconnected);
        assert!(!controller.is_enabled(FIRST_VECTOR + 7));

        // And the tail-removal case: head stays, slot opens.
        let head2 = sharable_at(FIRST_VECTOR + 7, true);
        let tail2 = sharable_at(FIRST_VECTOR + 7, true);
        assert!(table.connect(head2, &mut controller));
        assert!(table.connect(tail2, &mut controller));
        assert!(table.disconnect(tail2, &mut controller));
        assert_eq!(table.classify(FIRST_VECTOR + 7), VectorState::Connected);
        assert!(controller.is_enabled(FIRST_VECTOR + 7));
        assert_eq!(controller.disables.borrow().len(), 1);
    }

    /// The four-way classification over the table: unconnected, connected, chained — and unknown
    /// outside the band.
    #[test]
    fn classification_is_the_four_way_state() {
        let table = VectorTable::zeroed();
        let mut controller = FakeController::new();

        assert_eq!(table.classify(FIRST_VECTOR + 5), VectorState::Unconnected);
        assert_eq!(table.classify(0x05), VectorState::Unknown);
        assert_eq!(table.classify(0x2E), VectorState::Unknown);
        assert_eq!(table.classify(0x40), VectorState::Unknown);

        let one = sharable_at(FIRST_VECTOR + 5, true);
        assert!(table.connect(one, &mut controller));
        assert_eq!(table.classify(FIRST_VECTOR + 5), VectorState::Connected);

        let two = sharable_at(FIRST_VECTOR + 5, true);
        assert!(table.connect(two, &mut controller));
        assert_eq!(table.classify(FIRST_VECTOR + 5), VectorState::Chained);
    }

    /// The claim protocol: an accepted claim is followed by exactly one end (the service ran
    /// first); a spurious claim by none — no service, no raise, nothing acknowledged beyond what
    /// the controller already owned.
    #[test]
    fn the_claim_protocol_pairs_one_end_with_each_acceptance() {
        let table = VectorTable::zeroed();
        let mut controller = FakeController::new();
        let object = leak(object_at(FIRST_VECTOR));
        assert!(table.connect(object, &mut controller));

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
        let table = VectorTable::zeroed();
        let mut controller = FakeController::new();
        assert_eq!(table.audit(&mut controller), Ok(()));

        let object = leak(object_at(FIRST_VECTOR + 11));
        assert!(table.connect(object, &mut controller));
        assert_eq!(table.audit(&mut controller), Ok(()));
        assert!(table.disconnect(object, &mut controller));
        assert_eq!(table.audit(&mut controller), Ok(()));

        // An enable without a connect (a controller gone rogue) is what the audit exists to catch.
        controller.enabled[(FIRST_VECTOR + 11 - FIRST_VECTOR) as usize] = true;
        assert!(table.audit(&mut controller).is_err());
    }

    /// Connect and disconnect run raised to the synchronize level, masked, and lower back: the
    /// processor's ledger balances, and interrupts are enabled again after.
    #[test]
    fn connect_and_disconnect_raise_to_the_synchronize_level_and_back() {
        let table = VectorTable::zeroed();
        let mut controller = FakeController::new();
        let object = leak(object_at(FIRST_VECTOR + 12));
        assert!(table.connect(object, &mut controller));
        assert!(table.disconnect(object, &mut controller));
        let pcr = crate::pcr::pcr();
        assert_eq!(pcr.current(), crate::interrupt::irql::PASSIVE);
        assert!(pcr.interrupts_enabled());
        assert_eq!(pcr.audit(), Ok(()));
    }

    /// Synchronize: the routine runs raised to the object's synchronize level, under the object's
    /// lock, with the level lowered back after.
    struct SyncProbe {
        level: RefCell<Option<Irql>>,
        lock: RefCell<Option<bool>>,
    }

    thread_local! {
        static SYNC_OBJECT: RefCell<*const InterruptObject> =
            RefCell::new(core::ptr::null());
        static SYNC_PROBE: RefCell<*mut SyncProbe> = RefCell::new(core::ptr::null_mut());
    }

    fn sync_routine(_context: usize) -> bool {
        // The thread-locals hold the raw pointers the probe reads.
        let level = crate::pcr::pcr().current();
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
        let mut probe = SyncProbe {
            level: RefCell::new(None),
            lock: RefCell::new(None),
        };
        SYNC_OBJECT.with(|o| *o.borrow_mut() = &object as *const InterruptObject);
        SYNC_PROBE.with(|p| *p.borrow_mut() = &mut probe as *mut SyncProbe);

        assert!(table.synchronize_execution(&object, sync_routine, 0));
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
            crate::pcr::pcr().current(),
            crate::interrupt::irql::PASSIVE,
            "lowered after"
        );
        assert!(
            !object.lock.load(Ordering::SeqCst),
            "the lock is released after"
        );
    }

    /// A controller that claims through the processor's own ledger, as the kernel's does.
    struct LedgerLine {
        in_service: bool,
    }

    impl Controller for LedgerLine {
        fn claim(&mut self, _vector: u8, level: Irql) -> Claim {
            if self.in_service {
                Claim::Accepted(crate::pcr::pcr().raise(level))
            } else {
                Claim::Spurious
            }
        }

        fn end(&mut self, previous: OldIrql, _vector: u8) {
            crate::pcr::pcr().end_claim(previous, || self.in_service = false);
        }

        fn enable(&mut self, _vector: u8) -> bool {
            true
        }

        fn disable(&mut self, _vector: u8) {}

        fn is_enabled(&mut self, _vector: u8) -> bool {
            true
        }

        fn in_service_clear(&mut self) -> bool {
            !self.in_service
        }
    }

    thread_local! {
        /// The level the clock service saw, and its count of ticks.
        static CLOCK_SEEN: std::cell::Cell<Option<Irql>> = const { std::cell::Cell::new(None) };
        static TICKS: &'static crate::level::LevelCell<Clock, u32> =
            Box::leak(Box::new(crate::level::LevelCell::new(0)));
    }

    fn counting_clock_service(at_clock: &mut At<Clock>, _context: usize) -> bool {
        CLOCK_SEEN.with(|seen| seen.set(Some(crate::pcr::pcr().current())));
        TICKS.with(|ticks| *ticks.get(at_clock) += 1);
        true
    }

    /// A clock-level object's service is handed the clock token once the claim has raised the
    /// processor to the clock level, and reaches clock-level state with it; the end lowers back.
    #[test]
    fn a_clock_service_is_handed_its_token_after_the_claim() {
        let object = leak(InterruptObject::at_clock(
            counting_clock_service,
            0,
            FIRST_VECTOR,
            false,
            false,
        ));
        let table = VectorTable::zeroed();
        let mut line = LedgerLine { in_service: false };
        assert!(table.connect(object, &mut line));

        for _ in 0..2 {
            line.in_service = true;
            assert!(matches!(
                service_interrupt(&table, &mut line, FIRST_VECTOR),
                Outcome::Served
            ));
        }
        assert_eq!(CLOCK_SEEN.with(|seen| seen.get()), Some(Clock::IRQL));
        assert_eq!(crate::pcr::pcr().current(), crate::interrupt::irql::PASSIVE);
        let ticks =
            crate::level::raised::<Clock, _>(|at_clock| TICKS.with(|ticks| *ticks.get(at_clock)));
        assert_eq!(ticks, 2);
    }

    thread_local! {
        /// The levels the device services saw.
        static DEVICE_SEEN: RefCell<Vec<Irql>> = const { RefCell::new(Vec::new()) };
    }

    fn keyboard_service(_: &mut At<Keyboard>, _context: usize) -> bool {
        DEVICE_SEEN.with(|seen| seen.borrow_mut().push(crate::pcr::pcr().current()));
        true
    }

    fn ide_service(_: &mut At<Ide>, _context: usize) -> bool {
        DEVICE_SEEN.with(|seen| seen.borrow_mut().push(crate::pcr::pcr().current()));
        true
    }

    /// The device objects are served at their own levels, the keyboard's and the disk's, and
    /// handed those levels' tokens.
    #[test]
    fn device_services_are_handed_their_levels_tokens() {
        let keyboard = leak(InterruptObject::at_keyboard(
            keyboard_service,
            0,
            FIRST_VECTOR + 1,
            false,
            false,
        ));
        let disk = leak(InterruptObject::at_ide(
            ide_service,
            0,
            FIRST_VECTOR + 14,
            false,
            false,
        ));
        assert_eq!(keyboard.level, Keyboard::IRQL);
        assert_eq!(disk.synchronize_level, Ide::IRQL);
        let table = VectorTable::zeroed();
        let mut line = LedgerLine { in_service: false };
        assert!(table.connect(keyboard, &mut line));
        assert!(table.connect(disk, &mut line));
        for vector in [FIRST_VECTOR + 1, FIRST_VECTOR + 14] {
            line.in_service = true;
            assert!(matches!(
                service_interrupt(&table, &mut line, vector),
                Outcome::Served
            ));
        }
        assert_eq!(
            DEVICE_SEEN.with(|seen| seen.take()),
            vec![Keyboard::IRQL, Ide::IRQL]
        );
        assert_eq!(crate::pcr::pcr().current(), crate::interrupt::irql::PASSIVE);
    }

    /// A typed service claimed at a level other than its own is refused: its token would be a lie.
    #[test]
    #[should_panic(expected = "claimed at another level")]
    fn a_typed_service_claimed_at_another_level_is_refused() {
        // The keyboard's object shares a vector behind an object at another level, which sets the
        // claim's level.
        let mut first = object_at(FIRST_VECTOR + 1);
        first.shareable = true;
        let mut keyboard =
            InterruptObject::at_keyboard(keyboard_service, 0, FIRST_VECTOR + 1, false, true);
        keyboard.shareable = true;
        let table = VectorTable::zeroed();
        let mut line = LedgerLine { in_service: false };
        assert!(table.connect(leak(first), &mut line));
        assert!(table.connect(leak(keyboard), &mut line));
        line.in_service = true;
        service_interrupt(&table, &mut line, FIRST_VECTOR + 1);
    }
}
