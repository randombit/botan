Fuzzing The Library
============================

Botan comes with a set of fuzzing endpoints which can be used to test
the library.

.. highlight:: shell

Fuzzing with libFuzzer
------------------------

To fuzz with libFuzzer (https://llvm.org/docs/LibFuzzer.html), you'll first
need to compile libFuzzer::

  $ svn co https://llvm.org/svn/llvm-project/compiler-rt/trunk/lib/fuzzer libFuzzer
  $ cd libFuzzer && clang -c -g -O2 -std=c++11 *.cpp
  $ ar cr libFuzzer.a libFuzzer/*.o

Then build the fuzzers::

  $ ./configure.py --cc=clang --build-fuzzer=libfuzzer --unsafe-fuzzer-mode \
        --enable-sanitizers=coverage,address,undefined
  $ make fuzzers

Enabling 'coverage' sanitizer flags is required for libFuzzer to work.
Address sanitizer and undefined sanitizer are optional.

The fuzzer binaries will be in `build/fuzzer`. Simply pick one and run it, optionally
also passing a directory containing corpus inputs.

Using `libfuzzer` build mode implicitly assumes the fuzzers need to
link with `libFuzzer`; if another library is needed (for example in
OSS-Fuzz, which uses `libFuzzingEngine`), use the flag
`--with-fuzzer-lib` to specify the desired name.

Fuzzing with AFL
--------------------

To fuzz with AFL (http://lcamtuf.coredump.cx/afl/)::

  $ ./configure.py --with-sanitizers --build-fuzzer=afl --unsafe-fuzzer-mode --cc-bin=afl-g++
  $ make fuzzers

For AFL sanitizers are optional. You can also use `afl-clang-fast++`
or `afl-clang++`, be sure to set `--cc=clang` also.

The fuzzer binaries will be in `build/fuzzer`. To run them you need to
run under `afl-fuzz`::

  $ afl-fuzz -i corpus_path -o output_path ./build/fuzzer/binary

Fuzzing with TLS-Attacker
--------------------------

TLS-Attacker (https://github.com/RUB-NDS/TLS-Attacker) includes a mode for fuzzing
TLS servers. A prebuilt copy of TLS-Attacker is available in a git repository::

  $ git clone --depth 1 https://github.com/randombit/botan-ci-tools.git

To run it against Botan's server::

  $ ./configure.py --with-sanitizers
  $ make botan
  $ ./src/scripts/run_tls_attacker.py ./botan ./botan-ci-tools

Output and logs from the fuzzer are placed into `/tmp`. See the
TLS-Attacker documentation for more information about how to use this
tool.

Input Corpus
-----------------------

AFL requires an input corpus, and libFuzzer can certainly make good
use of it.

Some crypto corpus repositories include

* https://github.com/randombit/crypto-corpus
* https://github.com/mozilla/nss-fuzzing-corpus
* https://github.com/google/boringssl/tree/master/fuzz
* https://github.com/openssl/openssl/tree/master/fuzz/corpora

Adding new fuzzers
---------------------

New fuzzers are created by adding a source file to `src/fuzzers` which
have the signature:

``void fuzz(const uint8_t in[], size_t len)``

After adding your fuzzer, rerun ``./configure.py`` and build.
