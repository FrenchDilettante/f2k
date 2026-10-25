# F2K Makefile
# Windows 2000-compatible OS in Rust

# Architecture
ARCH ?= x86
TARGET ?= x86-f2k
# Host triple for unit tests: .cargo/config.toml defaults cargo to the
# kernel target, so host tests (run-tests) override it back to the host
# (detected from the toolchain; override on the command line if needed).
RUST_HOST_TARGET ?= $(shell rustc -vV | sed -n 's/^host: //p')
# Build options (target spec, build-std, linker) live in .cargo/config.toml,
# so cargo and rust-analyzer use the same settings as make.
# The cargo profile the kernel builds with: dev (unoptimized, the default), or dev-opt (optimized,
# the debug assertions and overflow checks kept; Cargo.toml). Each builds in its own directory.
KERNEL_PROFILE ?= dev
PROFILE_DIR = $(if $(filter dev,$(KERNEL_PROFILE)),debug,$(KERNEL_PROFILE))
OUT_DIR = $(BUILD_DIR)/$(TARGET)/$(PROFILE_DIR)
KERNEL_ELF ?= $(OUT_DIR)/f2k-kernel
# Cargo features for kernel builds (comma-separated, no spaces). The
# on-target suite passes them per case; manual builds accept them too
# (e.g. `make disk CARGO_FEATURES=run-ret0`).
CARGO_FEATURES ?=
FEATURE_FLAGS = $(if $(CARGO_FEATURES),--features $(CARGO_FEATURES),)
# The build stamps: what the kernel ELF and the disk image were built with, beside each (the
# suite's --no-build refuses a build whose stamps differ from what a test needs). Removed before a
# build, written once it succeeded.
KERNEL_STAMP = $(KERNEL_ELF).build
DISK_STAMP = $(DISK_IMG).build
BUILD_STAMP = features=$(CARGO_FEATURES)\nprofile=$(KERNEL_PROFILE)

# The perf-trace build forces frame pointers for its stack walk. Cargo's RUSTFLAGS replaces the
# target's rustflags in .cargo/config.toml, so the whole set is spelled out here — keep them in
# sync.
KERNEL_RUSTFLAGS = -Z unstable-options -C relocation-model=static -C code-model=kernel \
                   -C link-arg=-nostdlib -C link-arg=-static
ifneq (,$(findstring perf-trace,$(CARGO_FEATURES)))
export RUSTFLAGS := $(KERNEL_RUSTFLAGS) -C force-frame-pointers=yes
endif

# Directories
BOOT_DIR ?= boot
KERNEL_DIR ?= kernel
BUILD_DIR ?= target
SCRIPTS_DIR ?= scripts
# make vbox-image: the files to add to the VirtualBox disk (at their paths in the volume), the VDI,
# and the program its boot runs (empty: the kernel's default), e.g. CMDLINE='WINNT\system32\cmd.exe'.
VBOX_EXTRAS ?= vbox-image
VBOX_VDI ?= $(BUILD_DIR)/f2k.vdi
CMDLINE ?=
EXPORTGEN_DIR ?= tools/exportgen
USERLAND_DIR ?= userland

# Tools
OBJCOPY ?= x86_64-elf-objcopy
NASM ?= nasm
DD ?= dd

# QEMU settings
QEMU ?= qemu-system-i386
QEMU_FLAGS ?= -m 256M -nographic -no-reboot -no-shutdown -net none

# Disk image settings
DISK_IMG ?= $(OUT_DIR)/f2k-disk.img
ISO_IMG ?= $(OUT_DIR)/f2k.iso
# 64MB disk image (131072 * 512 bytes): large enough for a spec-compliant FAT32 partition
DISK_SIZE ?= 131072
# A fixture's directory, tests/<dll>/<name>: the fixtures are grouped by the DLL they exercise, and
# their names are unique across the groups (the disk carries them flat, by name).
fixture_dir = $(patsubst %/fixture.toml,%,$(wildcard tests/*/$(1)/fixture.toml))
# The corpus fixtures the disk carries in its root directory (tests/<dll>/<name>/<name>.exe, stored
# as NAME.EXE), after HELLO.EXE: the boots load their images from the volume by these paths.
DISK_FIXTURES ?= exit0 ret0
# The sectioned fixtures (tests/README.md), in their own directory, \CORPUS, the way each runs from
# its own directory on the real machine: the root keeps its one cluster (the disk-smoke pins it).
# They are the fixtures whose declaration, tests/<dll>/<name>/fixture.toml, says kind "sectioned",
# less those declared ahead of their real-machine build (no <name>.exe yet). Each one's companion
# DLLs and programs (tests/<dll>/<name>/*.dll, and *.exe but its own) go beside it, as they sit
# beside the program on the real machine, and the DLLs in a subdirectory of its
# (tests/<dll>/<name>/<sub>/*.dll) in that subdirectory.
CORPUS_FIXTURES ?= $(sort $(foreach fixture,$(notdir $(patsubst %/fixture.toml,%,$(shell grep -l '^kind = "sectioned"' tests/*/*/fixture.toml))),$(if $(wildcard $(call fixture_dir,$(fixture))/$(fixture).exe),$(fixture))))
# The system DLLs the userland workspace builds, which the disk carries in its system directory
# (\WINNT\system32, under the kernel's NtSystemRoot).
SYSTEM_DLLS = $(BUILD_DIR)/userland/i686-f2k-pe/release/ntdll.dll \
              $(BUILD_DIR)/userland/i686-f2k-pe/release/kernel32.dll \
              $(BUILD_DIR)/userland/i686-f2k-pe/release/msvcrt.dll \
              $(BUILD_DIR)/userland/i686-f2k-pe/release/advapi32.dll \
              $(BUILD_DIR)/userland/i686-f2k-pe/release/user32.dll

# Limine bootloader settings
LIMINE_DIR ?= $(BOOT_DIR)/limine
LIMINE_BIN ?= $(LIMINE_DIR)/limine
LIMINE_CD_BIN ?= $(LIMINE_DIR)/limine-bios-cd.bin
LIMINE_SYS ?= $(LIMINE_DIR)/limine-bios.sys
LIMINE_CONF ?= $(BOOT_DIR)/limine.conf

.PHONY: help
help:
	@echo "F2K Build System"
	@echo "================"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all           - Build everything and create bootable disk"
	@echo "  userland     - Build the system DLLs (ntdll.dll, which the kernel embeds, kernel32.dll,"
	@echo "                 msvcrt.dll, advapi32.dll and user32.dll)"
	@echo "  kernel       - Build the kernel (the system DLLs first)"
	@echo "  qemu         - Build the disk and boot the kernel directly in QEMU (Multiboot, disk attached)"
	@echo "  test         - Run every on-target QEMU test (kernel boots and the corpus)"
	@echo "  run-tests    - Run host unit tests (cargo test --lib)"
	@echo "  compat       - The tests' pins checked against the export specs, the host scenarios run"
	@echo "  compat-report - The DLL compatibility report from the last test results (target/compat/)"
	@echo "  check-all    - run-tests, then compat, then test"
	@echo "  check        - cargo check + clippy"
	@echo "  fmt          - Format the Rust sources (rustfmt) and the Markdown files (rumdl)"
	@echo "  fmt-check    - Fail if a Rust source or a Markdown file is not formatted"
	@echo "  kernel-bin   - Convert kernel to raw binary"
	@echo "  disk         - Create Limine-bootable hard disk image (needs mtools)"
	@echo "  limine       - Download/setup limine bootloader (if needed)"
	@echo "  iso          - Create bootable ISO with limine"
	@echo "  qemu_iso     - Create ISO and run in QEMU"
	@echo "  run          - Build and run in QEMU (raw disk)"
	@echo "  vbox-image   - The disk as a VirtualBox VDI, with vbox-image/'s files added"
	@echo "                 (CMDLINE='<program> [arguments]': what the boot runs)"
	@echo "  clean        - Clean build artifacts"
	@echo "  clobber      - Remove all build artifacts"
	@echo ""
	@echo "Environment:"
	@echo "  ARCH=x86             - Target architecture (default: x86)"
	@echo "  TARGET=x86-f2k       - Rust target (default: x86-f2k)"
	@echo "  DISK_IMG=...         - Disk image path"
	@echo "  KERNEL_PROFILE=dev   - Kernel cargo profile: dev, or dev-opt (optimized, checks kept)"

.PHONY: all
all: disk

# The system DLLs (userland/, its own Cargo workspace and target): the kernel embeds ntdll (and its
# tests read the others), and the disk carries them all, so they build first. Their generated stubs and .def come from the export specs
# (userland/<dll>/exports.toml, through tools/exportgen), the source the kernel's NT service table
# is generated from too.
.PHONY: userland
userland:
	@echo "Building the system DLLs..."
	cd $(USERLAND_DIR) && cargo build --release

.PHONY: kernel
kernel: userland
	@echo "Building F2K kernel..."
	rm -f $(KERNEL_STAMP)
	cd $(KERNEL_DIR) && cargo build --profile $(KERNEL_PROFILE) $(FEATURE_FLAGS)
	printf '$(BUILD_STAMP)\n' > $(KERNEL_STAMP)
	@echo "Kernel built: $(KERNEL_ELF)"

.PHONY: qemu
qemu: disk
	@echo "Booting F2K in QEMU (Multiboot via -kernel, the disk attached). Exit with Ctrl-A X."
	$(QEMU) $(QEMU_FLAGS) -kernel $(KERNEL_ELF) -drive file=$(DISK_IMG),format=raw,if=ide

.PHONY: kernel-bin
kernel-bin:
	@echo "Converting kernel to raw binary..."
	$(OBJCOPY) -O binary $(KERNEL_ELF) $(KERNEL_ELF).raw
	@echo "Raw kernel: $(KERNEL_ELF).raw"

.PHONY: disk
disk: kernel limine
	@echo "Creating Limine-bootable disk image..."
	rm -f $(DISK_IMG) $(DISK_STAMP)
	$(DD) if=/dev/zero of=$(DISK_IMG) bs=512 count=$(DISK_SIZE)
	# MBR with one active FAT32 partition at 1 MiB; Limine's stage 2 goes in the gap before it
	python3 $(SCRIPTS_DIR)/create_partition_table.py $(DISK_IMG) $(DISK_SIZE)
	mformat -F -i $(DISK_IMG)@@1M -v F2K ::
	# The disk-smoke checksum fixture goes in first: the first file into a
	# fresh volume gets cluster 3 (LBA 4067), the sector the diagnostic
	# reads. It must stay ahead of every other copy and the mmd below (a
	# directory would take the cluster).
	mcopy -i $(DISK_IMG)@@1M $(call fixture_dir,hello)/hello.exe ::/HELLO.EXE
	mmd -i $(DISK_IMG)@@1M ::/boot ::/boot/limine
	mcopy -i $(DISK_IMG)@@1M $(KERNEL_ELF) ::/f2k-kernel
	mcopy -i $(DISK_IMG)@@1M $(LIMINE_SYS) $(LIMINE_CONF) ::/boot/limine/
	# The corpus the boots run, by 8.3 name: the loader reads every image from
	# the volume by path. The root's entries stay within its one sector.
	for exe in $(foreach fixture,$(DISK_FIXTURES),$(call fixture_dir,$(fixture))/$(fixture).exe); do \
		mcopy -i $(DISK_IMG)@@1M $$exe ::/$$(basename $$exe | tr a-z A-Z) || exit 1; \
	done
	# The system directory, under the system root (KUSER_SHARED_DATA's NtSystemRoot, C:\WINNT):
	# the system DLLs the userland workspace builds. ntdll loads kernel32 from here into every
	# process, and msvcrt, advapi32 and user32 into the programs that import them (the kernel maps
	# ntdll itself and reads kernel32's start thunk from here at boot).
	mmd -i $(DISK_IMG)@@1M ::/WINNT ::/WINNT/system32
	mcopy -i $(DISK_IMG)@@1M $(SYSTEM_DLLS) ::/WINNT/system32/
	# The sectioned corpus in \CORPUS, with the files fixture's data tree beside
	# FILES.EXE and the two attributes git cannot carry (tests/kernel32/files/setup.bat
	# sets them on the real machine).
	mmd -i $(DISK_IMG)@@1M ::/CORPUS
	for directory in $(foreach fixture,$(CORPUS_FIXTURES),$(call fixture_dir,$(fixture))); do \
		fixture=$$(basename $$directory); \
		mcopy -i $(DISK_IMG)@@1M $$directory/$$fixture.exe \
			::/CORPUS/$$(echo $$fixture | tr a-z A-Z).EXE || exit 1; \
		for companion in $$directory/*.dll $$directory/*.exe $$directory/*/*.dll; do \
			[ -f "$$companion" ] || continue; \
			[ "$$companion" = "$$directory/$$fixture.exe" ] && continue; \
			place=$$(dirname "$${companion#$$directory}" | tr a-z A-Z); \
			[ "$$place" = / ] || mmd -D s -i $(DISK_IMG)@@1M ::/CORPUS$$place 2>/dev/null; \
			mcopy -i $(DISK_IMG)@@1M "$$companion" \
				::/CORPUS$${place%/}/$$(basename "$$companion" | tr a-z A-Z) || exit 1; \
		done; \
	done
	mcopy -s -i $(DISK_IMG)@@1M $(call fixture_dir,files)/DATA ::/CORPUS/
	mattrib -i $(DISK_IMG)@@1M +r ::/CORPUS/DATA/RDONLY.TXT
	mattrib -i $(DISK_IMG)@@1M +h ::/CORPUS/DATA/HIDDEN.TXT
	$(LIMINE_BIN) bios-install $(DISK_IMG)
	cp $(KERNEL_STAMP) $(DISK_STAMP)
	@echo "Disk image created: $(DISK_IMG)"

.PHONY: run
run: disk
	@echo "Booting $(DISK_IMG) in QEMU. Exit with Ctrl-A X."
	$(QEMU) $(QEMU_FLAGS) -drive file=$(DISK_IMG),format=raw,if=ide

.PHONY: vbox-image
vbox-image: disk
	python3 $(SCRIPTS_DIR)/vbox_image.py $(DISK_IMG) $(VBOX_EXTRAS) $(VBOX_VDI) --cmdline '$(CMDLINE)'

.PHONY: release
release: userland
	@echo "Building F2K kernel (release mode)..."
	cd $(KERNEL_DIR) && cargo build --release
	@echo "Kernel built: $(BUILD_DIR)/$(TARGET)/release/f2k-kernel"

.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	cd $(KERNEL_DIR) && cargo clean
	cd $(USERLAND_DIR) && cargo clean

.PHONY: clobber
clobber: clean
	@echo "Removing target directory..."
	-rm -rf $(BUILD_DIR)

# On-target QEMU tests, through pytest (uv drives the environment, pyproject.toml): the kernel's own
# boots are tests/core/kernel/test_kernel.py (kernel features to build with, image to boot,
# expected COM1 strings); the sectioned corpus's tests are tests/<dll>/<name>/test_<name>.py, one per
# fixture, over its real-machine capture (gating fixtures must pass; the rest run as expected failures, a
# progress report). `make test` runs them all; each test builds what it needs, and boots run in
# parallel. New cases are data, not new Makefile targets: narrow a run through pytest instead
# (`make test PYTEST_FLAGS="-n 4 -m disk"`, or the `kernel` and `corpus` markers).
UV ?= uv
PYTEST = $(UV) run pytest
PYTEST_FLAGS ?= -n 4

.PHONY: test
test:
	F2K_KERNEL_PROFILE=$(KERNEL_PROFILE) $(PYTEST) tests $(PYTEST_FLAGS)

# Everything a change is verified with, fastest first, stopping at the first failure: the host unit
# tests, the pins and the host scenarios (every scenario run), and the on-target suite
# (PYTEST_FLAGS passes through, e.g. "-n 2").
.PHONY: check-all
check-all:
	$(MAKE) run-tests
	$(MAKE) compat
	$(MAKE) test

# The system DLLs' compatibility (scripts/compat.py): --check holds the tests' pins against the
# export specs and the captures; --run runs every host scenario, ignored ones included (keeping the
# results under target/test-results/), and fails once a known gap's scenario passes.
.PHONY: compat
compat: userland
	$(UV) run scripts/compat.py --check --run

# The compatibility report, target/compat/report.html: every export of every spec as a square,
# coloured by its pinning tests' results: the host scenarios (run here) and the on-target suite's
# last run (target/test-results/pytest.json, which every `make test` keeps).
.PHONY: compat-report
compat-report: userland
	$(UV) run scripts/compat.py --run --report

.PHONY: run-tests
run-tests: userland
	@echo "Running host unit tests..."
	# CARGO_UNSTABLE_BUILD_STD=std: the workspace config builds core from
	# source for the kernel; for host tests that collides with the host's
	# prebuilt std, so build std (and its deps) from source instead.
	cd $(KERNEL_DIR) && CARGO_UNSTABLE_BUILD_STD=std cargo test --lib --target $(RUST_HOST_TARGET)
	# The export-spec generator the build scripts run (a host crate of its own).
	cd $(EXPORTGEN_DIR) && CARGO_UNSTABLE_BUILD_STD=std cargo test --target $(RUST_HOST_TARGET)
	# The userland runtime's host tests, under the root configuration as the kernel's are (std
	# built from source): the userland workspace's own configuration would hand them a from-source
	# core beside the prebuilt std (its build-std array cannot be emptied from the command line).
	CARGO_UNSTABLE_BUILD_STD=std cargo test --manifest-path $(USERLAND_DIR)/rtl/Cargo.toml --target $(RUST_HOST_TARGET) --target-dir target/userland-host
	# The system DLLs' user-mode code (their libraries).
	for dll in kernel32 msvcrt advapi32 user32; do \
		CARGO_UNSTABLE_BUILD_STD=std cargo test --manifest-path $(USERLAND_DIR)/$$dll/Cargo.toml --lib --target $(RUST_HOST_TARGET) --target-dir target/userland-host || exit 1; \
	done
	# The compiler's helpers, F2K's own programs' runtime, and the programs' libraries.
	for crate in compiler-helpers exe; do \
		CARGO_UNSTABLE_BUILD_STD=std cargo test --manifest-path $(USERLAND_DIR)/$$crate/Cargo.toml --lib --target $(RUST_HOST_TARGET) --target-dir target/userland-host || exit 1; \
	done

.PHONY: check
check: userland
	@echo "Checking code..."
	cd $(USERLAND_DIR) && cargo clippy --release
	cd $(KERNEL_DIR) && cargo check
	cd $(KERNEL_DIR) && cargo clippy

# Formatting: the Rust sources' settings live in rustfmt.toml at the workspace root, the Markdown
# files' (rumdl) in pyproject.toml.
.PHONY: fmt fmt-check
fmt:
	cargo fmt --all
	cd $(EXPORTGEN_DIR) && cargo fmt
	cd $(USERLAND_DIR) && cargo fmt --all
	uv run rumdl fmt .

fmt-check:
	cargo fmt --all -- --check
	cd $(EXPORTGEN_DIR) && cargo fmt -- --check
	cd $(USERLAND_DIR) && cargo fmt --all -- --check
	uv run rumdl check .

# =============================================================================
# Limine Bootloader Targets
# =============================================================================

ISO_DIR ?= $(OUT_DIR)/iso

.PHONY: limine
limine:
	@echo "Setting up limine bootloader..."
	@mkdir -p $(LIMINE_DIR)
	@# A private temporary directory, so parallel checkouts (worktrees) don't race on the download.
	@# The limine binary is copied last: it's what marks the setup as done.
	@if [ ! -f $(LIMINE_BIN) ]; then \
		tmp=$$(mktemp -d "$${TMPDIR:-/tmp}/limine.XXXXXX") && \
		trap 'rm -rf "$$tmp"' EXIT && \
		echo "Downloading limine binary release..." && \
		curl -fsSL -o "$$tmp/limine.tar.xz" https://github.com/Limine-Bootloader/Limine/releases/download/v12.9.3/limine-binary.tar.xz && \
		tar xJf "$$tmp/limine.tar.xz" -C "$$tmp" && \
		$(MAKE) -C "$$tmp/limine-binary" limine && \
		cp "$$tmp/limine-binary/limine-bios.sys" $(LIMINE_DIR)/ && \
		cp "$$tmp/limine-binary/limine-bios-cd.bin" $(LIMINE_DIR)/ && \
		cp "$$tmp/limine-binary/limine" $(LIMINE_DIR)/ && \
		chmod +x $(LIMINE_BIN) ; \
	fi
	@echo "Limine bootloader ready in $(LIMINE_DIR)/"

.PHONY: iso
iso: kernel limine
	@echo "Creating limine bootable ISO..."
	# Create ISO directory structure
	rm -rf $(ISO_DIR)
	mkdir -p $(ISO_DIR)/boot/limine
	cp $(LIMINE_CD_BIN) $(ISO_DIR)/
	cp $(LIMINE_SYS) $(ISO_DIR)/boot/limine/
	# The kernel is a 32-bit Multiboot 1 ELF (Limine's own protocol is 64-bit only)
	cp $(KERNEL_ELF) $(ISO_DIR)/f2k-kernel
	cp $(LIMINE_CONF) $(ISO_DIR)/boot/limine/
	# Create ISO with xorriso
	@echo "Creating ISO image..."
	@if ! command -v xorriso >/dev/null 2>&1; then \
		echo "ERROR: xorriso not found. Install with: brew install xorriso" && \
		false; \
	fi
	xorriso -as mkisofs \
		-R -r -J \
		-b limine-bios-cd.bin \
		-no-emul-boot \
		-boot-load-size 4 \
		-boot-info-table \
		$(ISO_DIR) -o $(ISO_IMG)
	# Install limine bootloader on the ISO image
	@echo "Installing limine bootloader on ISO image..."
	$(LIMINE_BIN) bios-install --force $(ISO_IMG)
	@echo "ISO created: $(ISO_IMG)"

.PHONY: qemu_iso
qemu_iso: iso disk
	@echo "Starting F2K ISO in QEMU (the disk attached for the volume)..."
	$(QEMU) $(QEMU_FLAGS) -cdrom $(ISO_IMG) -boot d -drive file=$(DISK_IMG),format=raw,if=ide
