Fuzzing The Library
============================

Botan comes with a set of fuzzing endpoints which can be used to test
the library.

.. highlight:: shell

Fuzzing with libFuzzer
------------------------

libFuzzer is provided by Clang's sanitizer runtime. You do not need a separate
libFuzzer checkout; link the fuzz targets with ``-fsanitize=fuzzer``.
You can build the fuzzers by running ::

  $ ./configure.py --cc=clang --build-fuzzer=libfuzzer --enable-sanitizers=fuzzer
  $ make fuzzers

The option ``--enable-sanitizers=fuzzer`` adds the required compile and link
flags for coverage-guided fuzzing. You can add additional sanitizers like
``address``, ``undefined`` and ``memory`` or with/without additional
information during building by either adding ``--unsafe-fuzzer-mode`` or
``--with-debug-info``. The ``coverage`` sanitizer is not compatible with this
configuration.

If you want to link additional libraries you can use the `--with-fuzzer-lib` option
while configuring the build with configure.py.
The fuzzer binaries will be in `build/fuzzer`. Simply pick one and run it, optionally
also passing a directory containing corpus inputs. Running

  $ make fuzzer_corpus

downloads a specific corpus from https://github.com/randombit/crypto-corpus.git. Together
with

  $ ./src/scripts/test_fuzzers.py fuzzer_corpus build/fuzzer

you can test the Fuzzers.

Legacy AFL++ support remains available through ``--build-fuzzer=afl``, but it
is not actively tested. If you use it, configure Botan with a matching AFL++
compiler wrapper and run the resulting binary under ``afl-fuzz``.

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

Adding new fuzzers
---------------------

New fuzzers are created by adding a source file to `src/fuzzers` which
have the signature:

``void fuzz(std::span<const uint8_t> in)``

After adding your fuzzer, rerun ``./configure.py`` and build.
