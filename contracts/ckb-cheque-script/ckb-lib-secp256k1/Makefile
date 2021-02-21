TARGET := riscv64-unknown-elf
CC := $(TARGET)-gcc
LD := $(TARGET)-gcc
AR := $(TARGET)-ar
OBJCOPY := $(TARGET)-objcopy
CFLAGS := -fPIC -O3 -fno-builtin-printf -fno-builtin-memcmp -nostdinc -nostdlib -nostartfiles -fvisibility=hidden -fdata-sections -ffunction-sections -I deps/secp256k1/src -I deps/secp256k1 -I deps/ckb-c-std-lib -I deps/ckb-c-std-lib/libc -I deps/ckb-c-std-lib/molecule -I c -I build -Wall -Werror -Wno-nonnull -Wno-nonnull-compare -Wno-unused-function -g
LDFLAGS := -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections
SECP256K1_SRC := deps/secp256k1/src/ecmult_static_pre_context.h

SCRIPT_CFLAGS := -I ckb-production-scripts/c -I ckb-production-scripts/deps/ckb-c-std-lib -I ckb-production-scripts/deps/ckb-c-std-lib/libc -I ckb-production-scripts/deps/ckb-c-std-lib/molecule

CKB_SCRIPT_SECP256K1 := ckb-production-scripts/deps/secp256k1
PATCH_PATH := build/secp256k1_blake2b_sighash_all

CC2 := gcc
LD2 := gcc
AR2 := ar

BUILDER_DOCKER := jjy0/ckb-capsule-recipe-rust:2020-9-28

all: build/libckb-lib-secp256k1.a build/secp256k1_blake2b_sighash_all

all-via-docker: ${PROTOCOL_HEADER}
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make all"

build/secp256k1_blake2b_sighash_all: secp256k1_blake2b.c ${PROTOCOL_HEADER} ckb-production-scripts/c/secp256k1_lock.h build/secp256k1_data_info.h $(SECP256K1_SRC)
	$(CC) $(CFLAGS) ${SCRIPT_CFLAGS} -I ${CKB_SCRIPT_SECP256K1} -I ${CKB_SCRIPT_SECP256K1}/src -D __SHARED_LIBRARY__ -c -o $@ $<
	$(OBJCOPY) --only-keep-debug $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@

build/libckb-lib-secp256k1.a: build/secp256k1_blake2b.o
	$(AR) rcs $@ $^

build/secp256k1_blake2b.o: secp256k1_blake2b.c ${PROTOCOL_HEADER} ckb-production-scripts/c/secp256k1_lock.h build/secp256k1_data_info.h $(SECP256K1_SRC)
	$(CC) $(CFLAGS) ${SCRIPT_CFLAGS} -I ${CKB_SCRIPT_SECP256K1} -I ${CKB_SCRIPT_SECP256K1}/src -D __SHARED_LIBRARY__ -c -o $@ $<

build/secp256k1_data_info.h: build/dump_secp256k1_data
	$<

build/dump_secp256k1_data: ckb-production-scripts/c/dump_secp256k1_data.c $(SECP256K1_SRC)
	mkdir -p build
	gcc -I ${CKB_SCRIPT_SECP256K1}/src -I ${CKB_SCRIPT_SECP256K1} -o $@ $<

$(SECP256K1_SRC):
	cd ckb-production-scripts/deps/secp256k1 && \
		./autogen.sh && \
		CC=$(CC) LD=$(LD) ./configure --with-bignum=no --enable-ecmult-static-precomputation --enable-endomorphism --enable-module-recovery --host=$(TARGET) && \
		make src/ecmult_static_pre_context.h src/ecmult_static_context.h

build-x86/libckb-lib-secp256k1.a: build-x86/secp256k1_blake2b.o
	$(AR2) rcs $@ $^

CFLAGS2:=$(filter-out -Werror,$(CFLAGS))
CFLAGS2:=$(filter-out -Wno-nonnull,$(CFLAGS2))
CFLAGS2:=$(filter-out -Wno-nonnull-compare,$(CFLAGS2))
CFLAGS2:=$(filter-out -Wno-unused-function,$(CFLAGS2))
CFLAGS2:=$(filter-out -Wall,$(CFLAGS2))
CFLAGS2:=$(filter-out -nostartfiles,$(CFLAGS2))
CFLAGS2+=-D CKB_STDLIB_NO_SYSCALL_IMPL

build-x86/secp256k1_blake2b.o: secp256k1_blake2b.c ${PROTOCOL_HEADER} ckb-production-scripts/c/secp256k1_lock.h build/secp256k1_data_info.h $(SECP256K1_SRC)
	$(CC2) $(CFLAGS2) ${SCRIPT_CFLAGS} -I ${CKB_SCRIPT_SECP256K1} -I ${CKB_SCRIPT_SECP256K1}/src -D __SHARED_LIBRARY__ -c -o $@ $<

clean:
	rm -f build/*.o build/*.a
	rm -rf build/secp256k1_data_info.h build/dump_secp256k1_data
	rm -rf build/secp256k1_data
	rm -rf build/ckb-lib-secp256k1
	rm -rf build/*.debug
