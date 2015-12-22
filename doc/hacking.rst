Source Code Layout
=================================================

Under ``src`` there are directories

* ``lib`` is the library itself, more on that below
* ``cli`` is the command line application ``botan``
* ``tests`` contain what you would expect. Input files go under ``tests/data``.
* ``build-data`` contains files read by the configure script. For
  example ``build-data/cc/gcc.txt`` describes various gcc options.
* ``scripts`` contains misc scripts: install, distribution, various
  codegen things. Scripts controlling CI go under ``scripts/ci``.
* ``python/botan.py`` is the Python ctypes wrapper

Library Layout
========================================

* ``base`` defines some high level types
* ``utils`` contains various utility functions and types
* ``codec`` has hex, base64
* ``block`` contains the block cipher implementations
* ``modes`` contains block cipher modes (CBC, GCM, etc)
* ``stream`` contains the stream ciphers
* ``hash`` contains the hash function implementations
* ``passhash`` contains password hashing algorithms for authentication
* ``kdf`` contains the key derivation functions
* ``mac`` contains the message authentication codes
* ``pbkdf`` contains password hashing algorithms for key derivation
* ``math`` is the math library for public key operations. It is divided into
  four parts: ``mp`` which are the low level algorithms; ``bigint`` which is
  a C++ wrapper around ``mp``; ``numbertheory`` which contains algorithms like
  primality testing and exponentiation; and ``ec_gfp`` which defines elliptic
  curves over prime fields.
* ``pubkey`` contains the public key implementations
* ``pk_pad`` contains padding schemes for public key algorithms
* ``rng`` contains the random number generators
* ``entropy`` has various entropy sources
* ``asn1`` is the DER encoder/decoder
* ``cert`` has ``x509`` (X.509 PKI OCSP is also here) and ``cvc`` (Card Verifiable Ceritifcates,
  for ePassports)
* ``tls`` contains the TLS implementation
* ``filters`` is a filter/pipe API for data transforms
* ``compression`` has the compression wrappers (zlib, bzip2, lzma)
* ``ffi`` is the C99 API
* ``prov`` contains bindings to external libraries like OpenSSL
* ``misc`` contains odds and ends: format preserving encryption, SRP, threshold
  secret sharing, all or nothing transform, and others

Copyright Notice
========================================

At the top of any new file add a comment with a copyright and
a reference to the license, for example::

  /*
  * (C) 2015,2016 Copyright Holder
  * Botan is released under the Simplified BSD License (see license.txt)
  */

If you are making a substantial or non-trivial change to an existing
file, add or update your own copyright statement at the top of the
file. If you are making a change in a new year not covered by your
existing statement, add the year. Even if the years you are making the
change are consecutive, avoid year ranges: specify each year separated
by a comma.

Also if you are a new contributor or making an addition in a new year,
include an update to ``doc/license.txt`` in your PR.

Style Conventions
========================================

When writing your code remember the need for it to be easily
understood by reviewers and auditors, both at the time of the patch
submission and in the future.

Avoid complicated template metaprogramming where possible. It has its
places but should be used judiciously.

When designing a new API (for use either by library users or just
internally) try writing out the calling code first. That is, write out
some code calling your idealized API, then just implement that API.
This can often help avoid cut-and-paste by creating the correct
abstractions needed to solve the problem at hand.

The C++11 ``auto`` keyword is very convenient but only use it when the
type truly is obvious (considering also the potential for unexpected
integer conversions and the like, such as an apparent uint8_t being
promoted to an int).

If a variable is defined and not modified, declare it ``const``

Use ``override`` annotations whenever overriding a virtual function.

A formatting setup for emacs is included in `scripts/indent.el` but
the basic formatting style should be obvious. No tabs, and remove
trailing whitespace.

Use ``m_`` prefix on all member variables. The current code is not
consistent but all new code should use it.

Prefer using braces on both sides of if/else blocks, even if only
using a single statement. Again the current code doesn't always do
this.

Avoid ``using namespace`` declarations, even inside of single functions.
One allowed exception is ``using namespace std::placeholders`` in
functions which use ``std::bind``.

Use ``::`` to explicitly refer to the global namespace (eg, when calling
an OS or library function like ``::select`` or ``::sqlite3_open``).

Sending patches
========================================

All contributions should be submitted as pull requests via GitHub
(https://github.com/randombit/botan). If you are planning a large
change email the mailing list or open a discussion ticket on github
before starting out to make sure you are on the right path.

Depending on what your change is, your PR should probably also include
an update to ``doc/news.rst`` with a note explaining the change. If your
change is a simple bug fix, a one sentence description is perhaps
sufficient. If there is an existing ticket on GitHub with discussion
or other information, reference it in your change note as 'GH #000'.

Update ``doc/credits.txt`` with your information so people know what
you did! (This is optional)

If you are interested in contributing but don't know where to start
check out ``doc/todo.rst`` for some ideas - these are changes we would
almost certainly accept once they've passed code review.

Also, try building and testing it on whatever hardware you have handy,
especially non-x86 platforms, or especially C++11 compilers other
than the regularly tested GCC, Clang, and Visual Studio compilers.

External Dependencies
========================================

Compiler Dependencies
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The library should always be as functional as possible when compiled with just
C++11. However, feel free to use the C++11 language. Little mercy is given to
sub-par C++11 compilers that don't actually implement the language (some
temporary concessions are made for MSVC 2013).

Use of compiler extensions is fine whenever appropriate; this is typically
restricted to a single file or an internal header. Compiler extensions used
currently include native uint128_t, SIMD intrinsics, inline asm syntax and so
on, so there are some existing examples of appropriate use.

Generally intrinsics or inline asm is preferred over bare assembly to avoid
calling convention issues among different platforms; the improvement in
maintainability is seen as worth any potentially performance tradeoff. One risk
with intrinsics is that the compiler might rewrite your clever const-time SIMD
into something with a conditional jump, but code intended to be const-time
should in any case be annotated so it can be checked at runtime with tools.

Operating System Dependencies
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you're adding a small OS dependency in some larger piece of code, try to
contain the actual non-portable operations to utils/os_utils.* and then call
them from there.

Old and obsolete systems are supported where convenient but generally speaking
SunOS 5, IRIX 9, Windows 2000 and company are not secure platforms to build
anything on so no special contortions are necessary. Patches that complicate the
code in order to support any OS not supported by its vendor will likely be
rejected. In writing OS specific code, feel free to assume roughly POSIX 2008,
or for Windows Vista/2008 Server (the oldest versions still supported by
Microsoft).

Library Dependencies
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Any external library dependency - even optional ones - is met with as one PR
submitter put it "great skepticism".

At every API boundary there is potential for confusion that does not exist when
the call stack is all contained within the boundary.  So the additional API
really needs to pull its weight. For example a simple text parser or such which
can be trivially implemented is not really for consideration. As a rough idea of
the bar, equate the viewed cost of an external dependency as at least 1000
additional lines of code in the library. That is, if the library really does
need this functionality, and it can be done in the library for less than that,
then it makes sense to just write the code. Yup.

Given the entire library is (accoriding to SLOCcount) 62K lines of code, that
may give some estimate of the bar - you can do pretty much anything in 1000
lines of well written C++11 (the implementations of *all* of the message
authentication codes is much less than 1K SLOC).

Current (all optional) external dependencies of the library are OpenSSL (for
accessing their fast RSA and ECDSA impls, not the handshake code!), zlib, bzip2,
lzma, sqlite3, plus various operating system utilities like basic filesystem
operations. These are hugely useful libraries that provide serious value, and
are worth the trouble of maintaining an integration with. And importantly their
API contract doesn't change often: code calling zlib doesn't bitrot much.

Examples of external dependencies that would be appropriate include integration
with system crypto (PKCS #11, TPM, CommonCrypto, CryptoAPI algorithms),
potentially a parallelism framework such as Cilk (as part of a larger design for
parallel message processing, say), or hypothentically use of a safe ASN.1 parser
(that is, one written in Rust or OCaml providing a C API).

Test Tools
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Integration to better leverage specialized test or verification tools such as
valgrind, ASan/UBSan, AFL, LLVM libFuzzer, KLEE, Coq, etc is fine. Typically
these are not enabled or used during normal builds but are specially set up by
developers or auditors.

Python
========================================

The house language for scripts is Python. The aim is to support 2.7 and latest
3.x with the minimum possible number of explicit version checks (ideally zero).
Support for CPython 2.6, PyPy, etc is a bonus but not required.

Build Tools and Hints
========================================

If you don't already use it for all your C/C++ development, install
``ccache`` now and configure a large cache on a fast disk. It allows for
very quick rebuilds by caching the compiler output.

Use ``--with-sanitizers`` to enable ASan. UBSan has to be added separately
with ``--cc-abi-flags`` at the moment as GCC 4.8 does not have UBSan.

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
