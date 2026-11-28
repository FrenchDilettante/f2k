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
# The cargo profile the kernel builds with: release (the default), dev-opt (optimized like release,
# the debug assertions and overflow checks kept), or dev (unoptimized; its image no longer fits the
# 16 MiB kernel image window on x86_64 hosts). Each builds in its own directory (dev's is debug/).
# The on-target suite boots its own default profile, TEST_PROFILE below.
KERNEL_PROFILE ?= release
PROFILE_DIR = $(if $(filter dev,$(KERNEL_PROFILE)),debug,$(KERNEL_PROFILE))
OUT_DIR = $(BUILD_DIR)/$(TARGET)/$(PROFILE_DIR)
# What the loaders boot: the boot loader (kernel/loader), a Multiboot ELF carrying the kernel's
# image and naming its symbols. Beside it lie the kernel's link (ntoskrnl, an ELF with its symbols
# and debugging information) and the PE32 image the loader's build emits from it, ntoskrnl.exe.
KERNEL_ELF ?= $(OUT_DIR)/f2k-kernel
NTOSKRNL_EXE = $(OUT_DIR)/ntoskrnl.exe
# Cargo features for kernel builds (comma-separated, no spaces). The
# on-target suite passes them per case; manual builds accept them too
# (e.g. `make disk CARGO_FEATURES=run-ret0`).
CARGO_FEATURES ?=
FEATURE_FLAGS = $(if $(CARGO_FEATURES),--features $(CARGO_FEATURES),)
# The build stamps: what the boot image and the disk image were built with, beside each (the
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
LOADER_DIR ?= kernel/loader
BUILD_DIR ?= target
SCRIPTS_DIR ?= scripts
# What a manual boot (make run, make vbox-image) runs: the program's path on the volume and its
# arguments, the Limine entry's command line after the kernel's "--".
CMDLINE ?= WINNT\system32\cmd.exe
# make vbox-image: the files laid over the VirtualBox disk's volume (at their paths in it), and the
# VDI.
VBOX_EXTRAS ?= vbox-image
VBOX_VDI ?= $(BUILD_DIR)/f2k.vdi
EXPORTGEN_DIR ?= tools/exportgen
USERLAND_DIR ?= userland

# Tools
NASM ?= nasm
DD ?= dd

# QEMU settings: make run's machine is interactive. QEMU's window shows the VGA text screen and
# takes the PS/2 keyboard, and COM1, the kernel's log, goes to the terminal.
QEMU ?= qemu-system-i386
QEMU_FLAGS ?= -m 256M -serial stdio -no-reboot -no-shutdown -net none

# Disk image settings
DISK_IMG ?= $(OUT_DIR)/f2k-disk.img
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
# DLLs, programs and drivers (tests/<dll>/<name>/*.dll, *.exe but its own, and a kernel-mode
# fixture's *.sys) go beside it, as they sit beside the program on the real machine, and the DLLs
# in a subdirectory of its
# (tests/<dll>/<name>/<sub>/*.dll) in that subdirectory.
CORPUS_FIXTURES ?= $(sort $(foreach fixture,$(notdir $(patsubst %/fixture.toml,%,$(shell grep -l '^kind = "sectioned"' tests/*/*/fixture.toml))),$(if $(wildcard $(call fixture_dir,$(fixture))/$(fixture).exe),$(fixture))))
# The system DLLs the userland workspace builds, which the disk carries in its system directory
# (\WINNT\system32, under the kernel's NtSystemRoot).
SYSTEM_DLLS = $(BUILD_DIR)/userland/i686-f2k-pe/release/ntdll.dll \
              $(BUILD_DIR)/userland/i686-f2k-pe/release/kernel32.dll \
              $(BUILD_DIR)/userland/i686-f2k-pe/release/msvcrt.dll \
              $(BUILD_DIR)/userland/i686-f2k-pe/release/advapi32.dll \
              $(BUILD_DIR)/userland/i686-f2k-pe/release/user32.dll \
              $(BUILD_DIR)/userland/i686-f2k-pe/release/gdi32.dll \
              $(BUILD_DIR)/userland/i686-f2k-pe/release/shell32.dll
# F2K's own programs the userland workspace builds (userland/<program>), which the disk carries in
# the system directory beside the DLLs. The target names every image it links <name>.dll (the
# DLLs are its binaries too), so `userland` copies each program to its .exe name beside it.
SYSTEM_PROGRAMS = pwd ps shutdown fish drawdemo
SYSTEM_EXES = $(foreach program,$(SYSTEM_PROGRAMS),$(BUILD_DIR)/userland/i686-f2k-pe/release/$(program).exe)
# F2K's command interpreter (userland/cmd), built and copied to its .exe name as the programs are,
# but kept off the disk the tests boot: it goes on its own disk (`cmd-disk`), a copy of that one
# whose boot runs CMDLINE, the disk make run and make vbox-image boot.
CMD_PROGRAM = cmd
CMD_EXE = $(BUILD_DIR)/userland/i686-f2k-pe/release/$(CMD_PROGRAM).exe
# F2K's own test programs (userland/<program>), built and copied to their .exe names as the
# programs are, but kept off the disk the tests boot: the test that needs one boots a copy of that
# disk with it added (keyshow.exe: tests/core/test_guikeys.py; fontshow.exe:
# tests/core/test_tahoma.py, with the font it draws; dlgshow.exe: tests/core/test_dialogs.py;
# menushow.exe: tests/core/test_nonclient.py; scrollshow.exe: tests/core/test_scrollbars.py;
# nestshow.exe: tests/core/test_nesting.py; shapeshow.exe: tests/core/test_shapeshow.py;
# mapshow.exe: tests/core/test_mapshow.py; textshow.exe: tests/core/test_textshow.py;
# listboxshow.exe: tests/core/test_listboxes.py; comboboxshow.exe: tests/core/test_comboboxes.py;
# clipshow.exe: tests/core/test_childpaint.py).
TEST_PROGRAMS = keyshow fontshow dlgshow menushow scrollshow nestshow shapeshow mapshow textshow listboxshow comboboxshow clipshow
TEST_EXES = $(foreach program,$(TEST_PROGRAMS),$(BUILD_DIR)/userland/i686-f2k-pe/release/$(program).exe)
CMD_DISK_IMG ?= $(OUT_DIR)/f2k-cmd-disk.img
# The system's fonts (fonts/README.md), which the cmd disk carries in \WINNT\Fonts.
SYSTEM_FONTS = $(sort $(wildcard fonts/*.ttf))

# Limine bootloader settings
LIMINE_DIR ?= $(BOOT_DIR)/limine
LIMINE_BIN ?= $(LIMINE_DIR)/limine
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
	@echo "                 msvcrt.dll, advapi32.dll, user32.dll, gdi32.dll and shell32.dll) and F2K's"
	@echo "                 own programs (pwd.exe, ps.exe, shutdown.exe, fish.exe, drawdemo.exe, cmd.exe,"
	@echo "                 keyshow.exe, fontshow.exe, dlgshow.exe, menushow.exe, scrollshow.exe,"
	@echo "                 nestshow.exe, shapeshow.exe, mapshow.exe, textshow.exe, listboxshow.exe,"
	@echo "                 comboboxshow.exe, clipshow.exe)"
	@echo "  kernel       - Build the kernel (the system DLLs first), its image ntoskrnl.exe, and the"
	@echo "                 boot loader that carries it (f2k-kernel, what the loaders boot)"
	@echo "  test        - Run every on-target QEMU test (kernel boots and the corpus)"
	@echo "  run-tests    - Run host unit tests (cargo test --lib, and the kernel's doc tests)"
	@echo "  compat       - The tests' pins checked against the export specs, the host scenarios run,"
	@echo "                 and the DLL compatibility report written (target/compat/report.html)"
	@echo "  check-all    - run-tests, then compat, then test"
	@echo "  check        - cargo check + clippy"
	@echo "  miri         - The kernel's host tests (those MIRI_TESTS names) under Miri, the"
	@echo "                 undefined-behaviour checker (MIRI_TESTS=:: for every test)"
	@echo "  fmt          - Format the Rust sources (rustfmt) and the Markdown files (rumdl)"
	@echo "  fmt-check    - Fail if a Rust source or a Markdown file is not formatted"
	@echo "  disk         - Create Limine-bootable hard disk image (needs mtools), the one the tests boot"
	@echo "  cmd-disk     - The disk with cmd.exe added, its boot running CMDLINE"
	@echo "  limine       - Download/setup limine bootloader (if needed)"
	@echo "  run          - Boot the cmd disk in a QEMU window: cmd.exe, or what CMDLINE names"
	@echo "                 (keyboard and screen in the window, COM1 on the terminal)"
	@echo "  vbox-image   - The cmd disk as a VirtualBox VDI, vbox-image/'s files laid over its volume"
	@echo "  clean        - Clean build artifacts"
	@echo "  clobber      - Remove all build artifacts"
	@echo ""
	@echo "Environment:"
	@echo "  ARCH=x86             - Target architecture (default: x86)"
	@echo "  TARGET=x86-f2k       - Rust target (default: x86-f2k)"
	@echo "  DISK_IMG=...         - Disk image path"
	@echo "  CMDLINE='...'        - What make run and make vbox-image boot into: the program's path"
	@echo "                         on the volume and its arguments (default: F2K's cmd.exe)"
	@echo "  KERNEL_PROFILE=release - Kernel cargo profile: release (the default), dev-opt (optimized, checks kept), or dev"
	@echo "  TEST_PROFILE=dev-opt   - Profile make test builds and boots: dev-opt (the default), release, or dev"

.PHONY: all
all: disk

# The system DLLs (userland/, its own Cargo workspace and target): the kernel embeds ntdll (and its
# tests read the others), and the disk carries them all, so they build first. Their generated stubs and .def come from the export specs
# (userland/<dll>/exports.toml, through tools/exportgen), the source the kernel's NT service table
# is generated from too.
.PHONY: userland
# Each .exe is replaced whole, by a rename, and only when its .dll changed: a test copying one onto
# its disk while another worker's build runs this (tests/f2kboot.py's disk_with_programs holds no
# build lock) reads the old file or the new one, never one cp has just truncated.
userland:
	@echo "Building the system DLLs and programs..."
	@cd $(USERLAND_DIR) && cargo build --release
	@for exe in $(SYSTEM_EXES) $(CMD_EXE) $(TEST_EXES); do \
		cmp -s $${exe%.exe}.dll $$exe && continue; \
		cp $${exe%.exe}.dll $$exe.tmp && mv -f $$exe.tmp $$exe || exit 1; \
	done

# The kernel's link first, then the boot loader, whose build emits the kernel's image from it. The
# loader's build is handed the link's checksum (F2K_KERNEL_LINK_CHECKSUM): cargo going back to a
# feature set it built before puts that build's cached link back with its old modification time,
# which cargo's own check of the link (newer than the image's last emission) would miss.
.PHONY: kernel
kernel: userland
	@echo "Building F2K kernel..."
	rm -f $(KERNEL_STAMP)
	cd $(KERNEL_DIR) && cargo build --profile $(KERNEL_PROFILE) $(FEATURE_FLAGS)
	cd $(LOADER_DIR) && F2K_KERNEL_LINK_CHECKSUM="$$(cksum < $(abspath $(OUT_DIR))/ntoskrnl)" \
		cargo build --profile $(KERNEL_PROFILE)
	printf '$(BUILD_STAMP)\n' > $(KERNEL_STAMP)
	@echo "Kernel built: $(NTOSKRNL_EXE), booted as $(KERNEL_ELF)"

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
	# process, and msvcrt, advapi32, user32, gdi32 and shell32 into the programs that import them
	# (the kernel maps ntdll itself and reads kernel32's start thunk from here at boot). F2K's own
	# programs go beside them, on the PATH every process starts with. The kernel's image,
	# ntoskrnl.exe, sits there too, where Windows 2000 keeps its kernel; the boot itself never
	# reads it (the boot loader carries the image it maps).
	mmd -i $(DISK_IMG)@@1M ::/WINNT ::/WINNT/system32
	mcopy -i $(DISK_IMG)@@1M $(SYSTEM_DLLS) $(SYSTEM_EXES) $(NTOSKRNL_EXE) ::/WINNT/system32/
	# The sectioned corpus in \CORPUS, with the files fixture's data tree beside
	# FILES.EXE and the two attributes git cannot carry (tests/kernel32/files/setup.bat
	# sets them on the real machine).
	mmd -i $(DISK_IMG)@@1M ::/CORPUS
	for directory in $(foreach fixture,$(CORPUS_FIXTURES),$(call fixture_dir,$(fixture))); do \
		fixture=$$(basename $$directory); \
		mcopy -i $(DISK_IMG)@@1M $$directory/$$fixture.exe \
			::/CORPUS/$$(echo $$fixture | tr a-z A-Z).EXE || exit 1; \
		for companion in $$directory/*.dll $$directory/*.exe $$directory/*.sys $$directory/*/*.dll; do \
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
	# The paging file, as Windows 2000's setup leaves one: hidden and system, at the boot's 8 MiB
	# (kernel/src/mem/pagingfile.rs's BOOT_MAX_PAGES). The boot takes it over as it is, contents
	# and all, rather than allocating its 16384 clusters at every boot; a boot that finds it
	# missing, or of another size, makes it or sizes it itself.
	$(DD) if=/dev/zero of=$(OUT_DIR)/pagefile.sys bs=4096 count=2048 2>/dev/null
	mcopy -i $(DISK_IMG)@@1M $(OUT_DIR)/pagefile.sys ::/pagefile.sys
	mattrib -i $(DISK_IMG)@@1M -a +h +s ::/pagefile.sys
	rm -f $(OUT_DIR)/pagefile.sys
	$(LIMINE_BIN) bios-install $(DISK_IMG)
	cp $(KERNEL_STAMP) $(DISK_STAMP)
	@echo "Disk image created: $(DISK_IMG)"

# The cmd disk: the disk with cmd.exe beside the system's programs, the system's fonts (fonts/*.ttf)
# in \WINNT\Fonts, where win32k loads them at its start, and its Limine entry's command line, after
# the kernel's path, `-- $(CMDLINE)`. The disk the tests boot carries no fonts.
.PHONY: cmd-disk
cmd-disk: disk
	@printf 'Creating the disk that boots into %s...\n' '$(CMDLINE)'
	rm -f $(CMD_DISK_IMG)
	cp $(DISK_IMG) $(CMD_DISK_IMG)
	mcopy -i $(CMD_DISK_IMG)@@1M $(CMD_EXE) ::/WINNT/system32/
	mmd -i $(CMD_DISK_IMG)@@1M ::/WINNT/Fonts
	mcopy -i $(CMD_DISK_IMG)@@1M $(SYSTEM_FONTS) ::/WINNT/Fonts/
	grep -q '^    path: boot():/f2k-kernel$$' $(LIMINE_CONF)
	{ sed '/^    path: boot():\/f2k-kernel$$/q' $(LIMINE_CONF); \
	  printf '    cmdline: -- %s\n' '$(CMDLINE)'; \
	  sed '1,/^    path: boot():\/f2k-kernel$$/d' $(LIMINE_CONF); } > $(CMD_DISK_IMG).conf
	mcopy -o -i $(CMD_DISK_IMG)@@1M $(CMD_DISK_IMG).conf ::/boot/limine/limine.conf
	rm -f $(CMD_DISK_IMG).conf
	@echo "Disk image created: $(CMD_DISK_IMG)"

# The cmd disk booted through Limine, in a QEMU window.
.PHONY: run
run: cmd-disk
	@printf 'Booting %s in QEMU: %s\n' '$(CMD_DISK_IMG)' '$(CMDLINE)'
	$(QEMU) $(QEMU_FLAGS) -drive file=$(CMD_DISK_IMG),format=raw,if=ide

# The cmd disk as a VirtualBox VDI, vbox-image/'s files laid over its volume after cmd.exe (so
# `vbox-image/WINNT/system32/cmd.exe` replaces F2K's).
.PHONY: vbox-image
vbox-image: cmd-disk
	python3 $(SCRIPTS_DIR)/vbox_image.py $(CMD_DISK_IMG) $(VBOX_EXTRAS) $(VBOX_VDI)

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
# The profile the on-target suite builds and boots by default: dev-opt, optimized as release is but
# with the debug assertions and overflow checks kept (the dev-profile kernel image outgrows the
# 16 MiB kernel image window on x86_64 hosts). The host cargo tests (run-tests) and `make check`
# are unaffected: they run under cargo's own default profile, dev.
TEST_PROFILE ?= dev-opt

.PHONY: test
test:
	F2K_KERNEL_PROFILE=$(TEST_PROFILE) $(PYTEST) tests $(PYTEST_FLAGS)

# Miri, the interpreter that checks for undefined behaviour, over the kernel's host tests: each of
# MIRI_TESTS (libtest filters, matching any part of a test's path) runs as its own Miri process,
# MIRI_JOBS at a time, its output in target/miri/logs/; a failing one's tail is shown. Cargo runs
# from a directory outside the repository, naming the kernel's manifest: the repository's
# .cargo/config.toml (build-std, the kernel target) breaks Miri, and cargo reads its configuration
# from the working directory up. The build lives in its own target directory; the toolchain is the
# repository's (rust-toolchain), with the miri component. The rig leaks its dispatchers and records
# on purpose, hence -Zmiri-ignore-leaks; some tests read the repository's files (the export specs),
# hence -Zmiri-disable-isolation.
#
# The default set is the code with the most unsafe aliasing to check (the dispatcher and its
# records, the level cells and locks, the processor's slots, the heap and the pool, the frame and
# page tables, the I/O manager, the object directory, the wait discipline and its objects) and
# takes minutes. Left out: hal::tests (its fake platform reads the level from inside
# the ledger's own change) and interrupt::tests (a test compares function addresses, which Miri
# does not keep equal); and the modules too slow to interpret (whole DLL images, file systems: an
# hour and more). `make miri MIRI_TESTS=::` runs every test.
MIRI_TOOLCHAIN = $(shell sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain)
MIRI_DIR ?= $(patsubst %/,%,$(or $(TMPDIR),/tmp))/f2k-miri
MIRI_TARGET_DIR ?= $(CURDIR)/$(BUILD_DIR)/miri
MIRI_MANIFEST = $(CURDIR)/$(KERNEL_DIR)/Cargo.toml
MIRIFLAGS ?= -Zmiri-ignore-leaks -Zmiri-disable-isolation
MIRI_JOBS ?= 6
MIRI_TESTS ?= sched::dispatcher sched::thread sched::switch sched::semaphore sched::process \
	sched::idle sched::object sched::tests sched::census sched::database sched::list \
	sched::startup \
	level:: sync:: pcr:: slots:: mem::heap mem::dma mem::pool mem::frame mem::paging:: mem::pte \
	dev::io hal::exports csr:: win32k::text ob:: process:: fs::file interrupt::clock user::apc \
	sched::wait:: sched::apc sched::timer sched::waitable_timer sched::mutex sched::event \
	block::lock nt::signal nt::wait nt::tests
MIRI_ENV = cd $(MIRI_DIR) && CARGO_TARGET_DIR=$(MIRI_TARGET_DIR) MIRIFLAGS="$(MIRIFLAGS)"
MIRI_TEST = cargo +$(MIRI_TOOLCHAIN) miri test --manifest-path $(MIRI_MANIFEST) --lib
# A group still running after MIRI_GROUP_TIMEOUT seconds fails, naming the test it was running
# (scripts/test_timeout.py): the default groups take a few minutes each on a loaded machine.
MIRI_GROUP_TIMEOUT ?= 900
MIRI_RUN = python3 $(CURDIR)/$(SCRIPTS_DIR)/test_timeout.py --test-timeout 0 \
	--run-timeout $(MIRI_GROUP_TIMEOUT) --

.PHONY: miri
miri: userland
	@mkdir -p $(MIRI_DIR) $(MIRI_TARGET_DIR)/logs
	$(MIRI_ENV) $(MIRI_TEST) --no-run
	@printf '%s\n' $(MIRI_TESTS) | xargs -P $(MIRI_JOBS) -n 1 sh -c '\
		log="$(MIRI_TARGET_DIR)/logs/$$1.log"; \
		if ($(MIRI_ENV) $(MIRI_RUN) $(MIRI_TEST) -q -- "$$1") > "$$log" 2>&1; then \
			echo "miri ok: $$1 ($$(grep -o "[0-9]* passed" "$$log"))"; \
		else \
			echo "miri FAILED: $$1 (see $$log)"; tail -40 "$$log"; exit 1; \
		fi' sh

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
# results under target/test-results/), and fails once a known gap's scenario passes; --report writes
# the compatibility report, target/compat/report.html: every export of every spec as a square in one
# treemap, then one section per tests/compat/*.toml (pe_deps.py's dependency sets) with each
# executable's imports as squares in the same representation. Squares are coloured by the pinning
# tests' results: the host scenarios (run here) and the on-target suite's last run
# (target/test-results/pytest.json, which every `make test` keeps). A DLL among tests/compat/*.toml
# is a compatibility target (F2K runs the real one): a section, not part of the treemap.
.PHONY: compat
compat: userland
	@$(UV) run scripts/compat.py --check --run --report

# Each host test runs under scripts/test_timeout.py: a test still running after HOST_TEST_TIMEOUT
# seconds (the slowest takes about 10 s on a loaded machine) is named and the run fails, instead of
# a looping test holding the run forever. `make run-tests HOST_TEST_TIMEOUT=0` turns it off.
HOST_TEST_TIMEOUT ?= 120
HOST_TEST = python3 $(CURDIR)/$(SCRIPTS_DIR)/test_timeout.py --test-timeout $(HOST_TEST_TIMEOUT) --

.PHONY: run-tests
run-tests: userland
	@echo "Running host unit tests..."
	# CARGO_UNSTABLE_BUILD_STD=std: the workspace config builds core from
	# source for the kernel; for host tests that collides with the host's
	# prebuilt std, so build std (and its deps) from source instead.
	cd $(KERNEL_DIR) && CARGO_UNSTABLE_BUILD_STD=std $(HOST_TEST) cargo test --lib --target $(RUST_HOST_TARGET)
	# The kernel's documentation tests: the compile-fail examples of the level tokens and the
	# locks, each checked for the error code it names (against the library's plain host build).
	cd $(KERNEL_DIR) && CARGO_UNSTABLE_BUILD_STD=std $(HOST_TEST) cargo test --doc --target $(RUST_HOST_TARGET)
	# The boot loader's work on the kernel's image (its library).
	cd $(LOADER_DIR) && CARGO_UNSTABLE_BUILD_STD=std $(HOST_TEST) cargo test --lib --target $(RUST_HOST_TARGET)
	# The export-spec generator the build scripts run (a host crate of its own).
	cd $(EXPORTGEN_DIR) && CARGO_UNSTABLE_BUILD_STD=std $(HOST_TEST) cargo test --target $(RUST_HOST_TARGET)
	# The userland runtime's host tests, under the root configuration as the kernel's are (std
	# built from source): the userland workspace's own configuration would hand them a from-source
	# core beside the prebuilt std (its build-std array cannot be emptied from the command line).
	CARGO_UNSTABLE_BUILD_STD=std $(HOST_TEST) cargo test --manifest-path $(USERLAND_DIR)/rtl/Cargo.toml --target $(RUST_HOST_TARGET) --target-dir target/userland-host
	# The system DLLs' user-mode code (their libraries).
	for dll in kernel32 msvcrt advapi32 user32 gdi32 shell32; do \
		CARGO_UNSTABLE_BUILD_STD=std $(HOST_TEST) cargo test --manifest-path $(USERLAND_DIR)/$$dll/Cargo.toml --lib --target $(RUST_HOST_TARGET) --target-dir target/userland-host || exit 1; \
	done
	# The compiler's helpers, F2K's own programs' runtime, and the programs' libraries (a program
	# without one, fontshow, is passed over).
	for crate in compiler-helpers exe $(SYSTEM_PROGRAMS) $(CMD_PROGRAM) $(TEST_PROGRAMS); do \
		[ -f $(USERLAND_DIR)/$$crate/src/lib.rs ] || continue; \
		CARGO_UNSTABLE_BUILD_STD=std $(HOST_TEST) cargo test --manifest-path $(USERLAND_DIR)/$$crate/Cargo.toml --lib --target $(RUST_HOST_TARGET) --target-dir target/userland-host || exit 1; \
	done

.PHONY: check
check: userland
	@echo "Checking code..."
	cd $(USERLAND_DIR) && cargo clippy --release
	cd $(KERNEL_DIR) && cargo check
	cd $(KERNEL_DIR) && cargo clippy
	cd $(LOADER_DIR) && cargo clippy

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
		cp "$$tmp/limine-binary/limine" $(LIMINE_DIR)/ && \
		chmod +x $(LIMINE_BIN) ; \
	fi
	@echo "Limine bootloader ready in $(LIMINE_DIR)/"
