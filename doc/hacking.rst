
Source Code Layout
=================================================

Under `src` there are directories

* `lib` is the library itself, more on that below
* `cli` (command line interface) is the implementation of the command line application.
  It is structed as a multicall binary so each program is relatively
  independent.
* `tests` contain what you would expect. Input files go under `tests/data`.
* `build-data` contains files read by the configure script. For
  example `build-data/cc/gcc.txt` describes various gcc options.
* `scripts` contains various scripts: install, distribution, various
  codegen things. Scripts controlling CI go under `scripts/ci`.
* `python/botan.py` is the Python ctypes wrapper

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

Copyright Notice
========================================

At the top of any new file add a comment with a copyright and
a reference to the license, for examplee::

  /*
  * (C) 2015,2016 Copyright Holder
  * Botan is released under the Simplified BSD License (see license.txt)
  */

If you are making a substantial or non-trivial change to an existing
file, add or update your own copyright statement at the top of the
file.  If you are making a change in a new year not covered by your
existing statement, add the year. Even if the years you are making the
change are consecutive, avoid year ranges: specify each year separated
by a comma.

Also if you are a new contributor or making an addition in a new year,
include an update to `doc/license.txt` in your PR.

Style Conventions
========================================

When writing your code remember the need for it to be easily
understood by reviewers and auditors, both at the time of the patch
submission and in the future.

Avoid complicated template metaprogramming where possible. It has its
places but should be used judiciously.

When designing a new API (for use either by library users or just
internally) try writing out the calling code first. That is, write out
some code calling your idealized API, then just implement that. This
can often help avoid cut-and-paste by creating the correct abstractions
needed to solve the problem at hand.

The C++11 `auto` keyword is very convenient but only use it when the
type truly is obvious (considering also the potential for unexpected
integer conversions and the like, such as an apparent uint8_t being
promoted to an int).

Use `override` annotations whenever possible.

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

All contributions should be submitted as pull requests via GitHub
(https://github.com/randombit/botan). If you are planning a large
change email the mailing list or open a discussion ticket on github
before starting out to make sure you are on the right path to
something which we'll be able to accept.

Depending on what your change is, your PR should probably also include
an update to `doc/news.rst` with a note explaining the change. If your
change is a simple bug fix, a one sentence description is perhaps
sufficient. If there is an existing ticket on GitHub with discussion
or other information, reference it in your change note as 'GH #000'.

Update `doc/credits.txt` with your information so people know what
you did! (This is optional)

If you are interested in contributing but don't know where to start
check out `doc/todo.rst` for some ideas - these are changes we would
almost certainly accept once they've passed code review.

Also, try building and testing it on whatever hardware you have handy,
especially non-x86 platforms, or especially C++11 compilers other
than the regularly tested GCC, Clang, and Visual Studio compilers.

Build Tools and Hints
========================================

If you don't already use it for all your C/C++ development, install
`ccache` now and configure a large cache on a fast disk. It allows for
very quick rebuilds by caching the compiler output.

Use `--with-sanitizers` to enable ASan. UBSan has to be added separately
with --cc-abi-flags at the moment as GCC 4.8 does not have UBSan.

Other Ways You Can Help
========================================

Convince your employer that the software your company uses and relies on is
worth the time and cost of serious audit. The code may be free, but you are
still using it - so make sure it is any good. Fund code and design reviews
whenever you can of the free software your company relies on, including Botan,
then share the results with the developers to improve the ecosystem for everyone.

Funding Development
========================================

If there is a change you'd like implemented in the library but you'd rather not,
or can't, write it yourself, you can contact Jack Lloyd who in addition to being
the primary author also works as a freelance contractor and security consultant.
