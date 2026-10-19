//! The CPU tables: the GDT (segments, TEB, TSS) and the IDT (exception handlers, the syscall gate,
//! the hardware-vector stubs), plus the diagnostic dump the exception stubs print; and the
//! floating-point unit's setup (`fxsave` and the SSE state).

pub mod fpu;
pub mod gdt;
pub mod idt;
