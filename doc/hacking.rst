
Source Code Layout
=================================================

Under `src` there are directories

* `lib` is the library itself, more on that below
* `cmd` is the implementation of the command line application.
  It is structed as a multicall binary so each program is relatively
  independent.
* `tests` contain what you would expect. Input files go under `tests/data`.
* `build-data` contains files read by the configure script. For
  example `build-data/cc/gcc.txt` describes various gcc options.
* `scripts` contains various scripts: install, distribution, various
  codegen things. Scripts controlling CI go under `scripts/ci`.
* `python` and `ocaml` are the FFI bindings for those languages

Library Layout
========================================

* `base` defines some high level types
* `utils` contains various utility functions and types
* `codec` has hex, base64
* `block` contains the block cipher implementations
* `modes` contains block cipher modes
* `stream` contains the stream ciphers
* `hash` contains the hash function implementations
* `passhash` contains password hashing algorithms for authentication
* `kdf` contains the key derivation functions
* `mac` contains the message authentication codes
* `pbkdf` contains password hashing algorithms for key derivation
* `math` is the math library for public key operations. It is divided into
  four parts: `mp` which are the low level algorithms; `bigint` which is
  a C++ wrapper around `mp`; `numbertheory` which contains algorithms like
  primality testing and exponentiation; and `ec_gfp` which defines elliptic
  curves over prime fields.
* `pubkey` contains the public key implementations
* `pk_pad` contains padding schemes for public key algorithms
* `rng` contains the random number generators
* `entropy` has various entropy sources
* `asn1` is the DER encoder/decoder
* `cert` has `x509` (X.509 PKI OCSP is also here) and `cvc` (Card Verifiable Ceritifcates,
  for ePassports)
* `tls` contains the TLS implementation
* `filters` has a filter/pipe API for data transforms
* `misc` contains odds and ends: format preserving encryption, SRP, threshold
  secret sharing, all or nothing transform, and others
* `compression` has the compression wrappers (zlib, bzip2, lzma)
* `ffi` is the C99 API
* `vendor` contains bindings to external libraries like OpenSSL and Sqlite3

Style Conventions
========================================

When writing your code remember the need for it to be easily
understood by reviewers/auditors, both at the time of the patch
submission and in the future.

Avoid complicated template metaprogramming where possible. It has its
places but should be used judiciously.

A formatting setup for emacs is included in `scripts/indent.el` but
the basic formatting style should be obvious. No tabs, and remove
trailing whitespace.

Use m_ prefix on all member variables. The current code is not
consistent but all new code should use it.

Prefer using braces on both sides of if/else blocks, even if only
using a single statement. Again the current code doesn't always do
this.

Sending patches
========================================

All contributions should be submitted as pull requests via the github page.
If you are planning a large change email the mailing list or open a
discussion ticket on github before starting out.

If you are interested in contributing but don't know where to start
check out todo.rst for some ideas - these are projects we would almost
certainly accept if the code quality was high.

Also, try building and testing it on whatever hardware you have handy,
especially non-x86 platforms, or especially C++11 compilers other
than the regularly tested GCC, Clang, and Visual Studio compilers.
