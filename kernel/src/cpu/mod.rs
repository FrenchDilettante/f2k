//! The CPU tables: the GDT (segments, TEB, TSS) and the IDT
//! (exception handlers, the syscall gate, the hardware-vector
//! stubs), plus the diagnostic dump the exception stubs print.

pub mod gdt;
pub mod idt;
