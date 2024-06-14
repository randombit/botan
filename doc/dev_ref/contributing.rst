
Notes for New Contributors
===================================

Source Code Layout
-------------------------------------------------

Under ``src`` there are directories

* ``lib`` is the library itself, more on that below
* ``cli`` is the command line application ``botan``
* ``tests`` contain what you would expect. Input files go under ``tests/data``.
* ``python/botan3.py`` is the Python ctypes wrapper
* ``bogo_shim`` contains the shim binary and configuration for
  `BoringSSL's TLS test suite <https://github.com/google/boringssl/tree/master/ssl/test>`_
* ``fuzzer`` contains fuzz targets for various modules of the library
* ``build-data`` contains files read by the configure script. For
  example ``build-data/cc/gcc.txt`` describes various gcc options.
* ``examples`` contains usage examples used in the documentation.
* ``scripts`` contains misc scripts: install, distribution, various
  codegen things. Scripts controlling CI go under ``scripts/ci``.
* ``configs`` contains configuration files tools like pylint
* ``editors`` contains configuration files for editors like vscode and emacs

Under ``doc`` one finds the sources of this documentation

Library Layout
----------------------------------------

Under ``src/lib`` are several directories

* ``asn1`` is the DER encoder/decoder
* ``base`` defines some high level types
* ``block`` contains the block cipher implementations
* ``codec`` has hex, base64, base32, base58
* ``compat`` a (partial) compatibility layer for the libsodium API
* ``compression`` has the compression wrappers (zlib, bzip2, lzma)
* ``entropy`` has various entropy sources used by some of the RNGs
* ``ffi`` is the C99 API
* ``filters`` is a filter/pipe API for data transforms
* ``hash`` contains the hash function implementations
* ``kdf`` contains the key derivation functions
* ``mac`` contains the message authentication codes
* ``math`` is the big integer math library. It is divided into three parts:
  ``mp`` which are the low level algorithms; ``bigint`` which is a C++ wrapper
  around ``mp``, and ``numbertheory`` which contains higher level algorithms like
  primality testing and exponentiation
* ``misc`` contains odds and ends: format preserving encryption, SRP, threshold
  secret sharing, all or nothing transform, and others
* ``modes`` contains block cipher modes (CBC, GCM, etc)
* ``passhash`` contains password hashing algorithms for authentication
* ``pbkdf`` contains password hashing algorithms for key derivation
* ``pk_pad`` contains padding schemes for public key algorithms
* ``prov`` contains bindings to external libraries such as PKCS #11
* ``psk_db`` contains a generic interface for a Pre-Shared-Key database
* ``pubkey`` contains the public key algorithms
* ``rng`` contains the random number generators
* ``stream`` contains the stream ciphers
* ``tls`` contains the TLS implementation
* ``utils`` contains various utility functions and types
* ``x509`` is X.509 certificates, PKCS #10 requests, OCSP

Each of these folders can contain subfolders which are treated as modules if they
contain an ``info.txt`` file. These submodules have an implicit dependency on their
parent module. The chapter :ref:`configure_script` contains more information on
Botan's module architecture.

Sending patches
----------------------------------------

All contributions should be submitted as pull requests via GitHub
(https://github.com/randombit/botan). If you are planning a large
change, open a discussion ticket on github before starting out to make
sure you are on the right path. And once you have something written,
even if it is not complete/ready to go, feel free to open a draft PR
for early review and comment.

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
``doc/dev_ref/todo.rst`` for some ideas - these are changes we would almost
certainly accept once they've passed code review.

Also, try building and testing it on whatever hardware you have handy,
especially unusual platforms, or using C++ compilers other than the regularly
tested GCC, Clang, and Visual Studio.

FFI Additions
----------------

If adding a new function declaration to ``ffi.h``, the same PR must also add the
same declaration in the Python binding ``botan3.py``, in addition the new API
functionality must be exposed to Python and a test written in Python.

Git Usage
----------------------------------------

Do *NOT* merge ``master`` into your topic branch, this creates needless commits
and noise in history. Instead, as needed, rebase your branch against master
(``git rebase -i master``) and force push the branch to update the PR. If the
GitHub PR page does not report any merge conflicts and nobody asks you to
rebase, you don't need to rebase.

Try to keep your history clean and use rebase to squash your commits as
needed. If your diff is less than roughly 100 lines, it should probably be a
single commit. Only split commits as needed to help with review/understanding of
the change.

Python
----------------------------------------

Scripts should be in Python 3 whenever possible.

For configure.py (and helper scripts install.py, cleanup.py and build_docs.py)
the target is stock (no modules outside the standard library) CPython 3.x.
Support for PyPy, etc is great when viable (in the sense of not causing problems
for 3.x, and not requiring huge blocks of version dependent code). As running
this program successfully is required for a working build, making it as portable
as possible is considered key.

The python wrapper botan3.py targets CPython 3.x, and latest PyPy. Note that
a single file is used to avoid dealing with any of Python's various crazy module
distribution issues.

For random scripts not typically run by an end-user (codegen, visualization, and
so on) there isn't any need to worry about platform independence. Here it's fine
to depend on any useful modules such as graphviz or matplotlib, regardless if it
is available from a stock CPython install.

Build Tools and Hints
----------------------------------------

If you don't already use it for all your C/C++ development, install ``ccache``
(or on Windows, ``sccache``) right now, and configure a large cache on a fast
disk. It allows for very quick rebuilds by caching the compiler output.

Use ``--enable-sanitizers=`` flag to enable various sanitizer checks.  Supported
values including "address" and "undefined" for GCC and Clang. GCC also supports
"iterator" (checked iterators), and Clang supports "memory" (MSan) and
"coverage" (for fuzzing).

On Linux if you have the ``lcov`` and ``gcov`` tools installed, then running
``./src/scripts/ci_build.py coverage`` will produce a coverage enabled build,
run the tests, test the fuzzers against a corpus, and produce an HTML report
of total coverage. This coverage build requires the development headers for
zlib, bzip2, liblzma, TrouSerS (libtspi), and Sqlite3.

Copyright Notice
----------------------------------------

At the top of any new file add a comment with a copyright and a reference to the
license, for example::

  /*
  * (C) 202x <You>
  *
  * Botan is released under the Simplified BSD License (see license.txt)
  */

If you are making a substantial or non-trivial change to an existing file, add
or update your own copyright statement at the top of each file.

Style Conventions
----------------------------------------

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

Unless there is a specific reason otherwise (eg due to calling some C API which
requires exactly a ``long*`` be provided) integer types should be either
``(u)intXX_t`` or ``size_t``. If the variable is used for integer values of "no
particular size", as in the loop ``for(some_type i = 0; i != 100; ++i)`` then
the type should be ``size_t``. Use one of the specific size integer types only
when there is a algorithmic/protocol reason to use an integer of that size. For
example if a parsing a protocol that uses 16-bit integer fields to encode a
length, naturally one would use ``uint16_t`` there.

If a variable is defined and not modified, declare it ``const``.  Some exception
for very short-lived variables, but generally speaking being able to read the
declaration and know it will not be modified is useful.

Use ``override`` annotations whenever overriding a virtual function.  If
introducing a new type that is not intended for further derivation, mark it ``final``.

Avoid explicit ``new`` or (especially) explicit ``delete``: use RAII,
``make_unique``, etc.

Use ``m_`` prefix on all member variables.

``clang-format`` is used for all C++ formatting. The configuration is
in ``.clang-format`` in the root directory. You can rerun the
formatter using ``make fmt`` or by invoking the script
``src/scripts/dev_tools/run_clang_format.py``. If the output would be
truly horrible, it is allowed to disable formatting for a specific
area using ``// clang-format off`` annotations.

.. note::

   Since the output of clang-format varies from version to version, we
   currently require using exactly ``clang-format 17``.

Use braces on both sides of if/else blocks, even if only using a single
statement.

Avoid ``using namespace`` declarations, even inside of single functions.  One
allowed exception is ``using namespace std::placeholders`` in functions which
use ``std::bind``. (But, don't use ``std::bind`` - use a lambda instead).

Use ``::`` to explicitly refer to the global namespace (eg, when calling an OS
or external library function like ``::select`` or ``::sqlite3_open``).

Use of External Dependencies
----------------------------------------

Compiler Dependencies
~~~~~~~~~~~~~~~~~~~~~~~

The library should always be as functional as possible when compiled with just
Standard C++20. However, feel free to use the full language.

Use of compiler extensions is fine whenever appropriate; this is typically
restricted to a single file or an internal header. Compiler extensions used
currently include native uint128_t, SIMD intrinsics, inline asm syntax and so
on, so there are some existing examples of appropriate use.

Generally intrinsics or inline asm is preferred over bare assembly to avoid
calling convention issues among different platforms; the improvement in
maintainability is seen as worth any potential performance tradeoff. One risk
with intrinsics is that the compiler might rewrite your clever const-time SIMD
into something with a conditional jump, but code intended to be const-time
should in any case be annotated (using ``CT::poison``) so it can be checked at
runtime with tools.

Operating System Dependencies
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you're adding a small OS dependency in some larger piece of code, try to
contain the actual non-portable operations to utils/os_utils.* and then call
them from there.

As a policy, operating systems which are not supported by their original vendor
are not supported by Botan either. Patches that complicate the code in order to
support obsolete operating systems will likely be rejected. In writing OS
specific code, feel free to assume roughly POSIX 2008, or for Windows, Windows 8
/Server 2012 (which are as of this writing the oldest versions still supported
by Microsoft).

Some operating systems, such as OpenBSD, only support the latest release. For
such cases, it's acceptable to add code that requires APIs added in the most
recent release of that OS as soon as the release is available.

Library Dependencies
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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

Currently the (optional) external dependencies of the library are several
compression libraries (zlib, bzip2, lzma), sqlite3 database, Trousers (TPM
integration), plus various operating system utilities like basic filesystem
operations. These provide major pieces of functionality which seem worth the
trouble of maintaining an integration with.

At this point the most plausible examples of an appropriate new external
dependency are all deeper integrations with system level cryptographic
interfaces (CommonCrypto, CryptoAPI, /dev/crypto, iOS keychain, TPM 2.0, etc)
