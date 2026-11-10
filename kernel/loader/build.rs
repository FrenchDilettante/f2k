//! Emits the kernel's image, ntoskrnl.exe, from the kernel's link, and the object the loader
//! carries it in.
//!
//! The kernel builds first (`make kernel` builds it, then this crate, under the same profile): its
//! link, `ntoskrnl` (an ELF, its relocations kept by `--emit-relocs`), lies in the profile's output
//! directory, beside where this crate's binary lands. From it and the kernel's export spec
//! (`kernel/exports.toml`), tools/exportgen emits the PE32 image and checks it against both; the
//! image is written beside the link (`ntoskrnl.exe`, which the disk carries), and wrapped in a
//! relocatable object that the loader's linker script (`scripts/loader.x86`) places: the image's
//! bytes, the reservation of the rest of its memory, and the kernel's function and data symbols at
//! their addresses in it, so the loader's own symbol table names the code it carries.
//!
//! Without the kernel's link (a check of this crate before the kernel is built) nothing is emitted:
//! the linker script refuses a loader without its image.

use std::path::{Path, PathBuf};

use exportgen::elf::{self, Elf, ObjectSymbol};
use exportgen::pe;

/// The image's module name, which its export directory carries.
const MODULE: &str = "ntoskrnl.exe";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // The library's host tests need none of this: only the target's binary carries the image.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("none") {
        return;
    }
    let manifest =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"));
    let repo = manifest.join("../..");
    let script = repo.join("scripts/loader.x86");
    println!("cargo:rerun-if-changed={}", script.display());
    println!("cargo:rustc-link-arg-bins=-T{}", script.display());

    let out = PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets OUT_DIR"));
    // OUT_DIR lies under <target>/<triple>/<profile>/build/: the profile's directory, where the
    // kernel's link lands, is the one holding `build`.
    let built = out
        .ancestors()
        .find(|dir| dir.file_name().is_some_and(|name| name == "build"))
        .and_then(Path::parent)
        .expect("OUT_DIR lies in the profile's build directory");
    let link = built.join("ntoskrnl");
    let spec_path = repo.join("kernel/exports.toml");
    println!("cargo:rerun-if-changed={}", link.display());
    // The link's modification time alone can miss a new link: cargo going back to a feature set it
    // built before puts that build's cached link back with its old time, older than this script's
    // last run. `make kernel` passes the link's checksum, so a different link reruns the script.
    println!("cargo:rerun-if-env-changed=F2K_KERNEL_LINK_CHECKSUM");
    println!("cargo:rerun-if-changed={}", spec_path.display());
    if !link.exists() {
        println!(
            "cargo:warning={} is missing: build the kernel first (`make kernel`)",
            link.display()
        );
        return;
    }

    let bytes = read(&link);
    let elf = Elf::parse(&bytes).unwrap_or_else(|error| panic!("{}: {error}", link.display()));
    let linked =
        pe::Linked::from_elf(&elf).unwrap_or_else(|error| panic!("{}: {error}", link.display()));
    let spec = exportgen::load(&spec_path).unwrap_or_else(|error| panic!("{error}"));
    exportgen::check_kernel(&spec).unwrap_or_else(|error| panic!("{error}"));
    let image = pe::emit(&linked, &spec, MODULE).unwrap_or_else(|error| panic!("{error}"));
    pe::check(&image, &linked, &spec, MODULE).unwrap_or_else(|error| panic!("{error}"));
    write(&built.join(MODULE), &image);

    let size_of_image = pe::read(&image)
        .expect("an emitted image reads")
        .size_of_image;
    let symbols: Vec<ObjectSymbol> = linked
        .symbols
        .iter()
        .filter(|s| s.kind == elf::STT_FUNC || s.kind == elf::STT_OBJECT)
        .map(|s| ObjectSymbol {
            name: s.name.clone(),
            offset: s.rva,
            size: s.size,
            kind: s.kind,
        })
        .collect();
    let object = elf::image_object(&image, size_of_image - image.len() as u32, &symbols);
    let object_path = out.join("image.o");
    write(&object_path, &object);
    println!("cargo:rustc-link-arg-bins={}", object_path.display());
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn write(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
}
