TARGET := riscv64-unknown-linux-gnu
CC := $(TARGET)-gcc
LD := $(TARGET)-gcc
AR := $(TARGET)-ar
OBJCOPY := $(TARGET)-objcopy
CFLAGS := -fPIC -O3 -fno-builtin-printf -fno-builtin-memcmp -nostdinc -nostdlib -nostartfiles -fvisibility=hidden -fdata-sections -ffunction-sections -I deps/secp256k1/src -I deps/secp256k1 -I deps/ckb-c-std-lib -I deps/ckb-c-std-lib/libc -I deps/ckb-c-std-lib/molecule -I c -I build -Wall -Werror -Wno-nonnull -Wno-nonnull-compare -Wno-unused-function -g
LDFLAGS := -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections
SECP256K1_SRC := deps/secp256k1/src/ecmult_static_pre_context.h

CKB_SCRIPT_C := ckb-production-scripts/c
CKB_SCRIPT_LIB := ckb-production-scripts/deps/ckb-c-std-lib/
CKB_SCRIPT_LIBC := ckb-production-scripts/deps/ckb-c-std-lib/libc
CKB_SCRIPT_MOLECULE := ckb-production-scripts/deps/ckb-c-std-lib/molecule

CKB_SCRIPT_SECP256K1 := ckb-production-scripts/deps/secp256k1

# docker pull nervos/ckb-riscv-gnu-toolchain:gnu-bionic-20191012
BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:aae8a3f79705f67d505d1f1d5ddc694a4fd537ed1c7e9622420a470d59ba2ec3

all: build/libckb-lib-secp256k1.a

all-via-docker: ${PROTOCOL_HEADER}
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make all"

build/libckb-lib-secp256k1.a: build/lib.o
	$(AR) rcs $@ $^

build/lib.o: lib.c ${PROTOCOL_HEADER} ckb-production-scripts/c/secp256k1_lock.h build/secp256k1_data_info.h $(SECP256K1_SRC)
	$(CC) $(CFLAGS) -I ${CKB_SCRIPT_C} -I ${CKB_SCRIPT_LIB} -I ${CKB_SCRIPT_LIBC} -I ${CKB_SCRIPT_MOLECULE} -I ${CKB_SCRIPT_SECP256K1} -I ${CKB_SCRIPT_SECP256K1}/src -c -o $@ $<

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

clean:
	rm -f build/*.o build/*.a
	rm -rf build/secp256k1_data_info.h build/dump_secp256k1_data
	rm -rf build/secp256k1_data
	rm -rf build/*.debug
