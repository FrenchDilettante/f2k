#!/usr/bin/env python3
"""
A VirtualBox disk (VDI) of F2K's boot disk, with extra files laid over its volume.

  vbox_image.py <disk image> <extras directory> <vdi>

- The disk image is the Makefile's cmd disk (`make cmd-disk`): the disk with cmd.exe added, its
  Limine entry already carrying the command line the boot runs (CMDLINE). It is copied, never
  changed.
- Every file under the extras directory goes into the copy's FAT32 volume at the same path,
  directories merged with the volume's own; a file the volume already has is replaced
  (`WINNT/system32/cmd.exe` replaces F2K's cmd.exe in \\WINNT\\system32). `.gitkeep` files are
  left out.
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
# Limine's configuration on the volume, and its entry's command line.
LIMINE_CONF = "::/boot/limine/limine.conf"
CMDLINE_KEY = "cmdline:"
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


def boot_command_line(volume: str) -> str:
    """The command line the volume's Limine entry hands the kernel, as its configuration reads."""
    result = subprocess.run(["mtype", "-i", volume, LIMINE_CONF],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if result.returncode != 0:
        return f"unknown ({LIMINE_CONF} unreadable)"
    lines = (line.strip() for line in result.stdout.splitlines())
    return next((line.removeprefix(CMDLINE_KEY).strip() for line in lines
                 if line.startswith(CMDLINE_KEY)), "none: the kernel's default")


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
    parser.add_argument("disk", type=Path, help="the boot disk image (make cmd-disk)")
    parser.add_argument("extras", type=Path, help="the files to lay over the volume, at their paths")
    parser.add_argument("vdi", type=Path, help="the VDI to write")
    args = parser.parse_args()

    raw = args.vdi.with_suffix(".img")
    shutil.copyfile(args.disk, raw)
    volume = f"{raw}{PARTITION}"
    added = add_extras(volume, args.extras) if args.extras.is_dir() else []
    command_line = boot_command_line(volume)
    write_vdi(raw, args.vdi)
    raw.unlink()

    print(f"VirtualBox disk: {args.vdi} (UUID {IMAGE_UUID})")
    print(f"Added from {args.extras}: {', '.join(added) if added else 'nothing'}")
    print(f"The boot runs: {command_line}")


if __name__ == "__main__":
    main()
