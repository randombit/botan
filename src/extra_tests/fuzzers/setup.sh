#!/bin/sh

mkdir bin
mkdir output
mkdir corpus

CFG_FLAGS="--with-debug-info --unsafe-fuzzer-mode --minimized-build --enable-modules=tls,chacha20poly1305,ocb,ccm,system_rng,auto_rng"

if [ ! -d libFuzzer ]; then
    svn co http://llvm.org/svn/llvm-project/llvm/trunk/lib/Fuzzer libFuzzer
fi

exit

# Just need the static lib, not CLI or tests

../../../configure.py $CFG_FLAGS --with-build-dir=afl-build --cc=clang --cc-bin='afl-clang-fast++'
make -f afl-build/Makefile afl-build/libbotan-1.11.a -j8

CLANG_COV_FLAGS="-fsanitize=address,undefined -fsanitize-coverage=edge,indirect-calls,8bit-counters -fno-sanitize-recover=undefined"
../../../configure.py $CFG_FLAGS --with-build-dir=llvm-build --cc=clang "--cc-abi-flags=$CLANG_COV_FLAGS"
make -f llvm-build/Makefile llvm-build/libbotan-1.11.a -j8
