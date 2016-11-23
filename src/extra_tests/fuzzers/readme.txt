
The code in this directory is for testing various message decoders and
math functions using the fuzzers AFL (http://lcamtuf.coredump.cx/afl/)
and libFuzzer (http://llvm.org/docs/LibFuzzer.html).

To build for AFL, run

  make afl

For libFuzzer

  make llvm

To add a new fuzzer, create a new file in jigs/, include "driver.h",
and implement the function with the signature

void fuzz(const uint8_t buf[], size_t len);

This function should abort or crash if something is incorrect.

Run it with

make run_{llvm,afl}_{what}

like in

make run_llvm_crl
make run_afl_tls_client

You can pass args to the fuzzer process using args=

make args=-max_len=4000 run_llvm_tls_client

The fuzzer entry point assumes no more than 4K of input. The base
libFuzzer default max len is 64 bytes, the makefile sets it to 140 as
default.

Use

make cmin_redc_p384

to run afl-cmin to minimize and merge the LLVM and AFL outputs back to
the corpus directory.

TODO:

- KLEE (https://klee.github.io)
- DFSan (http://clang.llvm.org/docs/DataFlowSanitizer.html)
- More jigs
