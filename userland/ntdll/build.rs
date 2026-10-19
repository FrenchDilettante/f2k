//! ntdll.dll's build: its stubs and .def from the export specs (see build-support/stubs.rs).
include!("../build-support/stubs.rs");

fn main() {
    build_dll(
        "ntdll",
        0x77F8_0000,
        &[
            "src/ldr.s",
            "src/except.s",
            "src/csr.s",
            "src/critsec.s",
            "src/heap.s",
        ],
    );
}
