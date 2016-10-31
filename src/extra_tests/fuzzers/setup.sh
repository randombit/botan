#!/bin/sh

mkdir bin
mkdir output
mkdir corpus

CFG_FLAGS="--with-debug-info --unsafe-fuzzer-mode --minimized-build --enable-modules=tls,chacha20poly1305,ocb,ccm,system_rng,auto_rng"

# Just need the static lib, not CLI or tests

../../../configure.py $CFG_FLAGS --with-build-dir=afl --cc=clang --cc-bin='afl-clang-fast++'
make -f afl/Makefile afl/libbotan-1.11.a -j2

CLANG_COV_FLAGS="-fsanitize=address,undefined -fsanitize-coverage=edge,indirect-calls,8bit-counters -fno-sanitize-recover=undefined"
../../../configure.py $CFG_FLAGS --with-build-dir=llvm --cc=clang "--cc-abi-flags=$CLANG_COV_FLAGS"
make -f llvm/Makefile llvm/libbotan-1.11.a -j2
