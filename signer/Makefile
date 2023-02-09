
GCC = gcc
ARM_GCC = arm-none-eabi-gcc
BUILD_DIR = ./build
RUST_LIB = $(BUILD_DIR)/lib
CARGO = cargo
CBINDGEN = cbindgen
CARGO_ARM_TARGET = thumbv7em-none-eabihf

.DEFAULT_GOAL := no-arm

BINDGEN_ALLOWLIST_FUNCTIONS = --allowlist-function println_str
BINDGEN_ALLOWLIST_FUNCTIONS += --allowlist-function println_int

no-arm: main.out

arm: arm-build-rust

main.out: build/lib/libsigner.a build/lib/println.o unit_tests/main.c
	cp clib/println.h build/lib
	$(GCC) -std=c99 -pipe unit_tests/main.c -o build/main.out -L build/lib -lsigner -Ibuild/lib build/lib/println.o

build/lib/println.o:
	$(GCC) -std=c99 -c clib/println.c -o build/lib/println.o

build/lib/libsigner.a: build/rust/bindings.rs src/lib.rs
	mkdir -p "build/lib"
	mkdir -p "build/rust-builds"
	$(CARGO) build --target-dir build/rust-builds --features use-std --release
	cp build/rust-builds/release/libsigner.a build/lib/
	$(CBINDGEN) --output build/lib/libsigner.h --lang c

build/rust/bindings.rs: clib/println.h
	mkdir -p "build/rust"
	bindgen --output build/rust/bindings.rs --use-core --with-derive-default $(BINDGEN_ALLOWLIST_FUNCTIONS) src/wrapper.h --ctypes-prefix cty -- -DPB_NO_PACKED_STRUCTS=1 -DPB_FIELD_16BIT=1 -fshort-enums -DTESTING=1 -Iclib

clean:
	rm -rf build

arm-build-rust: build/rust/bindings.rs src/lib.rs
	mkdir -p "build/lib"
	mkdir -p "build/rust-builds"
	$(CARGO) build --target-dir build/rust-builds --release --target $(CARGO_ARM_TARGET)
	cp build/rust-builds/$(CARGO_ARM_TARGET)/release/libsigner.a build/lib/
	$(CBINDGEN) --output build/lib/libsigner.h --lang c
