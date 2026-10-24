#!/usr/bin/env python3
"""
A VirtualBox disk (VDI) of F2K's boot disk, with extra files added and, optionally, the program
the boot runs.

  vbox_image.py <disk image> <extras directory> <vdi> [--cmdline "<program> [arguments]"]

- The disk image is the Makefile's (`make disk`): it is copied, never changed.
- Every file under the extras directory goes into the copy's FAT32 volume at the same path,
  directories merged with the volume's own (`WINNT/system32/cmd.exe` lands in \\WINNT\\system32 beside
  the system DLLs); a file the volume already has is replaced. `.gitkeep` files are left out.
- With --cmdline, Limine's entry hands the kernel that command line, as the on-target tests do
  (`-- <cmdline>`): the program's root-relative volume path and its arguments. Without it, the
  boot runs what the kernel runs by default.
- The VDI is written by qemu-img, then given a fixed UUID: VirtualBox registers a disk by its UUID
  and refuses one whose UUID changed, so a VM keeps its disk attached across rebuilds (rebuild
  with the VM powered off).
"""
import argparse
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

# The disk's FAT32 partition, as mtools addresses it (the Makefile's disk target puts it at 1 MiB).
PARTITION = "@@1M"
LIMINE_CONF = Path(__file__).resolve().parent.parent / "boot" / "limine.conf"
# The kernel's path line in Limine's entry: the command line goes after it.
KERNEL_PATH_LINE = "    path: boot():/f2k-kernel\n"
# A VDI's header (VirtualBox's documented format): its signature, and the image's UUID.
VDI_SIGNATURE_AT, VDI_SIGNATURE = 0x40, (0xBEDA107F).to_bytes(4, "little")
VDI_UUID_AT = 0x188
# F2K's VDI, the same in every build.
IMAGE_UUID = uuid.UUID("0f2b0000-2000-4000-8000-00000000f2b0")


def mtools(*command: str) -> None:
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if result.returncode != 0:
        sys.exit(f"vbox_image.py: {' '.join(command)} failed:\n{result.stdout}")


def add_extras(volume: str, extras: Path) -> list[str]:
    """Copy every file under `extras` into the volume at the same path; the paths added."""
    added = []
    for path in sorted(extras.rglob("*")):
        relative = path.relative_to(extras).as_posix()
        if path.name == ".gitkeep":
            continue
        if path.is_dir():
            # A directory the volume already has (WINNT, system32) is kept, its files merged.
            exists = subprocess.run(["mdir", "-b", "-i", volume, f"::/{relative}"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if exists.returncode != 0:
                mtools("mmd", "-i", volume, f"::/{relative}")
        else:
            mtools("mcopy", "-o", "-i", volume, str(path), f"::/{relative}")
            added.append(relative)
    return added


def set_cmdline(volume: str, cmdline: str, scratch: Path) -> None:
    """Limine's entry with `-- <cmdline>` after the kernel's path, into the volume."""
    if "\n" in cmdline:
        sys.exit("vbox_image.py: a command line is one line")
    entry = LIMINE_CONF.read_text()
    if KERNEL_PATH_LINE not in entry:
        sys.exit(f"vbox_image.py: {LIMINE_CONF} has no kernel path line to add the command line after")
    scratch.write_text(entry.replace(KERNEL_PATH_LINE, f"{KERNEL_PATH_LINE}    cmdline: -- {cmdline}\n"))
    try:
        mtools("mcopy", "-o", "-i", volume, str(scratch), "::/boot/limine/limine.conf")
    finally:
        scratch.unlink(missing_ok=True)


def write_vdi(image: Path, vdi: Path) -> None:
    """`image` as a VDI at `vdi`, with F2K's fixed UUID."""
    vdi.unlink(missing_ok=True)
    result = subprocess.run(["qemu-img", "convert", "-f", "raw", "-O", "vdi", str(image), str(vdi)],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if result.returncode != 0:
        sys.exit(f"vbox_image.py: qemu-img convert failed:\n{result.stdout}")
    with open(vdi, "r+b") as file:
        file.seek(VDI_SIGNATURE_AT)
        if file.read(4) != VDI_SIGNATURE:
            sys.exit(f"vbox_image.py: {vdi} has no VDI signature: not setting its UUID")
        file.seek(VDI_UUID_AT)
        file.write(IMAGE_UUID.bytes_le)


def main() -> None:
    parser = argparse.ArgumentParser(description="F2K's boot disk as a VirtualBox VDI")
    parser.add_argument("disk", type=Path, help="the boot disk image (make disk)")
    parser.add_argument("extras", type=Path, help="the files to add, at their paths in the volume")
    parser.add_argument("vdi", type=Path, help="the VDI to write")
    parser.add_argument("--cmdline", default="", help="the program the boot runs, and its arguments")
    args = parser.parse_args()

    raw = args.vdi.with_suffix(".img")
    shutil.copyfile(args.disk, raw)
    volume = f"{raw}{PARTITION}"
    added = add_extras(volume, args.extras) if args.extras.is_dir() else []
    if args.cmdline:
        set_cmdline(volume, args.cmdline, args.vdi.with_suffix(".conf"))
    write_vdi(raw, args.vdi)
    raw.unlink()

    print(f"VirtualBox disk: {args.vdi} (UUID {IMAGE_UUID})")
    print(f"Added from {args.extras}: {', '.join(added) if added else 'nothing'}")
    print(f"The boot runs: {args.cmdline or 'the kernel default'}")


if __name__ == "__main__":
    main()
