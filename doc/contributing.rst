
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
* ``configs`` contains configuration files for emacs, astyle, pylint, etc
* ``python/botan2.py`` is the Python ctypes wrapper

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
* ``cert/x509`` is X.509 certificates, PKCS #10 requests, OCSP
* ``tls`` contains the TLS implementation
* ``filters`` is a filter/pipe API for data transforms
* ``compression`` has the compression wrappers (zlib, bzip2, lzma)
* ``ffi`` is the C99 API
* ``prov`` contains bindings to external libraries like OpenSSL
* ``misc`` contains odds and ends: format preserving encryption, SRP, threshold
  secret sharing, all or nothing transform, and others

Sending patches
========================================

All contributions should be submitted as pull requests via GitHub
(https://github.com/randombit/botan). If you are planning a large
change email the mailing list or open a discussion ticket on github
before starting out to make sure you are on the right path. And once
you have something written, free to open a [WIP] PR for early review
and comment.

If possible please sign your git commits using a PGP key.
See https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work for
instructions on how to set this up.

Depending on what your change is, your PR should probably also include an update
to ``news.rst`` with a note explaining the change. If your change is a
simple bug fix, a one sentence description is perhaps sufficient. If there is an
existing ticket on GitHub with discussion or other information, reference it in
your change note as 'GH #000'.

Update ``doc/credits.txt`` with your information so people know what you did!

If you are interested in contributing but don't know where to start check out
``doc/todo.rst`` for some ideas - these are changes we would almost certainly
accept once they've passed code review.

Also, try building and testing it on whatever hardware you have handy,
especially non-x86 platforms, or especially C++11 compilers other than the
regularly tested GCC, Clang, and Visual Studio compilers.

Git Usage
========================================

Do *NOT* merge ``master`` into your topic branch, this creates
needless commits and noise in history. Instead, as needed, rebase your
branch against master (``git rebase -i master``) and force push the
branch to update the PR. If the GitHub PR page does not report any
merge conflicts and nobody asks you to rebase, you don't need to
rebase.

Try to keep your history clean and use rebase to squash your commits
as needed. If your diff is less than roughly 100 lines, it should
probably be a single commit. Only split commits as needed to help with
review/understanding of the change.

Python
========================================

Scripts should be in Python whenever possible.

For configure.py (and install.py) the target is stock (no modules outside the
standard library) CPython 2.7 plus latest CPython 3.x. Support for CPython 2.6,
PyPy, etc is great when viable (in the sense of not causing problems for 2.7 or
3.x, and not requiring huge blocks of version dependent code). As running this
program succesfully is required for a working build making it as portable as
possible is considered key.

The python wrapper botan2.py targets CPython 2.7, 3.x, and latest PyPy. Note that
a single file is used to avoid dealing with any of Python's various crazy module
distribution issues.

For random scripts not typically run by an end-user (codegen, visualization, and
so on) there isn't any need to worry about 2.6 and even just running under
Python2 xor Python3 is acceptable if needed. Here it's fine to depend on any
useful modules such as graphviz or matplotlib, regardless if it is available
from a stock CPython install.

Build Tools and Hints
========================================

If you don't already use it for all your C/C++ development, install
``ccache`` now and configure a large cache on a fast disk. It allows for
very quick rebuilds by caching the compiler output.

Use ``--with-sanitizers`` to enable ASan. UBSan has to be added separately
with ``--cc-abi-flags`` at the moment as GCC 4.8 does not have UBSan.

Copyright Notice
========================================

At the top of any new file add a comment with a copyright and a reference to the
license, for example::

  /*
  * (C) 2015,2016 Copyright Holder
  * Botan is released under the Simplified BSD License (see license.txt)
  */

If you are making a substantial or non-trivial change to an existing file, add
or update your own copyright statement at the top of the file. If you are making
a change in a new year not covered by your existing statement, add the
year. Even if the years you are making the change are consecutive, avoid year
ranges: specify each year separated by a comma.

Style Conventions
========================================

When writing your code remember the need for it to be easily understood by
reviewers and auditors, both at the time of the patch submission and in the
future.

Avoid complicated template metaprogramming where possible. It has its places but
should be used judiciously.

When designing a new API (for use either by library users or just internally)
try writing out the calling code first. That is, write out some code calling
your idealized API, then just implement that API.  This can often help avoid
cut-and-paste by creating the correct abstractions needed to solve the problem
at hand.

The C++11 ``auto`` keyword is very convenient but only use it when the type
truly is obvious (considering also the potential for unexpected integer
conversions and the like, such as an apparent uint8_t being promoted to an int).

If a variable is defined and not modified, declare it ``const``.  Some exception
for very short-lived variables, but generally speaking being able to read the
declaration and know it will not be modified is useful.

Use ``override`` annotations whenever overriding a virtual function.  If
introducing a new type that is not intended for derivation, mark it ``final``.

Avoid explicit ``delete`` - use RAII.

Use ``m_`` prefix on all member variables.

For formatting, there are configs for emacs and astyle in ``src/configs``.
No tabs, and remove trailing whitespace.

Prefer using braces on both sides of if/else blocks, even if only using a single
statement. The current code doesn't always do this.

Avoid ``using namespace`` declarations, even inside of single functions.  One
allowed exception is ``using namespace std::placeholders`` in functions which
use ``std::bind``. (But, don't use ``std::bind`` - use a lambda instead).

Use ``::`` to explicitly refer to the global namespace (eg, when calling an OS
or external library function like ``::select`` or ``::sqlite3_open``).

Use of External Dependencies
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

Current the (optional) external dependencies of the library are OpenSSL (for
access to fast and side channel hardened RSA, ECDSA, AES), zlib, bzip2, lzma,
sqlite3, Trousers (TPM integration), plus various operating system utilities
like basic filesystem operations. These provide major pieces of functionality
which seem worth the trouble of maintaining an integration with.

Examples of other external dependencies that would be appropriate include
integration with system crypto (PKCS #11, TPM, CommonCrypto, CryptoAPI
algorithms), potentially a parallelism framework such as Cilk (as part of a
larger design for parallel message processing, say), or hypothentically use of a
safe ASN.1 parser (that is, one written in a safe language like Rust or OCaml
providing a C API).
