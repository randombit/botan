Fuzzing The Library
============================

Botan comes with a set of fuzzing endpoints which can be used to test
the library.

.. highlight:: shell

Fuzzing with libFuzzer
------------------------

As of Clang Version 6.0 libFuzzer is automatically included in the compiler. Therefore you don't need to install any new software.
You can build the fuzzers by running ::

  $ ./configure.py --cc=clang --build-fuzzer=libfuzzer --enable-sanitizers=fuzzer
  $ make fuzzers

The option `--enable-sanitizers=fuzzer` compiles the library for coverage-guided fuzzing.
You can add additional sanitizers like `address`, `undefined` and `memory` or with/without
additional information during building by either adding `--unsafe-fuzzer-mode` or `--with-debug-info`.
The `coverage` sanitizer is not compatible with this configuration.

If you want to link additional libraries you can use the `--with-fuzzer-lib` option
while configuring the build with configure.py.
The fuzzer binaries will be in `build/fuzzer`. Simply pick one and run it, optionally
also passing a directory containing corpus inputs. Running

  $ make fuzzer_corpus

downloads a specific corpus from https://github.com/randombit/crypto-corpus.git. Together
with

  $ ./src/scripts/test_fuzzers.py fuzzer_corpus build/fuzzer

you can test the Fuzzers.

Fuzzing with AFL++
--------------------

Please make sure that you have installed AFL++ according to https://aflplus.plus/building/.
The version of Clang should match the version of `afl-clang-fast++`/ `afl-clang-fast`.
You can fuzz with AFL++ in LLVM mode (https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md) by running ::

  $ ./configure.py --cc=clang --with-sanitizers --build-fuzzer=afl --unsafe-fuzzer-mode --cc-bin=afl-clang-fast++
  $ make fuzzers

For AFL++ in GCC mode make sure that you have `afl-g++-fast` installed.
Otherwise follow https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.gcc_plugin.md to build and install it.
You can configure the build by running ::

  $ ./configure.py --cc=gcc --with-sanitizers --build-fuzzer=afl --unsafe-fuzzer-mode --cc-bin=afl-g++-fast
  $ make fuzzers

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

Some other crypto corpus repositories include

* https://github.com/randombit/crypto-corpus
* https://github.com/mozilla/nss-fuzzing-corpus
* https://github.com/google/boringssl/tree/master/fuzz
* https://github.com/openssl/openssl/tree/master/fuzz/corpora

Adding new fuzzers
---------------------

New fuzzers are created by adding a source file to `src/fuzzers` which
have the signature:

``void fuzz(std::span<const uint8_t> in)``

After adding your fuzzer, rerun ``./configure.py`` and build.
