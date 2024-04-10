.. _building:

Building The Library
=================================

This document describes how to build Botan on Unix/POSIX and Windows
systems. The POSIX oriented descriptions should apply to most common Unix
systems (including Apple macOS/Darwin), along with POSIX-ish systems like QNX.

.. note::
   Botan is available already in nearly all
   `packaging systems <https://repology.org/project/botan/versions>`_ so you
   probably only need to build from source if you need unusual options
   or are building for an old system which has out of date packages.

Currently systems such as VMS, OS/390, and OS/400 are not supported by the build
system, primarily due to lack of access and interest.  Please contact the
maintainer if you would like to build Botan on such a system.

Botan's build is controlled by configure.py, which is a `Python
<https://www.python.org>`_ script. Python 3.x or later is required.

.. highlight:: none

For the impatient, this works for most systems::

  $ ./configure.py [--prefix=/some/directory]
  $ make
  $ make install

Or using ``nmake``, if you're compiling on Windows with Visual C++. On
platforms that do not understand the '#!' convention for beginning
script files, or that have Python installed in an unusual spot, you
might need to prefix the ``configure.py`` command with ``python3`` or
``/path/to/python3``::

  $ python3 ./configure.py [arguments]

Configuring the Build
---------------------------------

The first step is to run ``configure.py``, which is a Python script
that creates various directories, config files, and a Makefile for
building everything. This script should run under a vanilla install of
Python 3.x.

The script will attempt to guess what kind of system you are trying to
compile for (and will print messages telling you what it guessed).
You can override this process by passing the options ``--cc``,
``--os``, and ``--cpu``.

You can pass basically anything reasonable with ``--cpu``: the script
knows about a large number of different architectures, their
sub-models, and common aliases for them. You should only select the
64-bit version of a CPU (such as "sparc64" or "mips64") if your
operating system knows how to handle 64-bit object code - a 32-bit
kernel on a 64-bit CPU will generally not like 64-bit code.

By default the script tries to figure out what will work on your
system, and use that. It will print a display at the end showing which
modules have and have not been enabled. For instance on one system
we might see lines like::

   INFO: Skipping (dependency failure): certstor_sqlite3 sessions_sqlite3
   INFO: Skipping (incompatible CPU): aes_power8
   INFO: Skipping (incompatible OS): darwin_secrandom getentropy win32_stats
   INFO: Skipping (incompatible compiler): aes_armv8 pmull sha1_armv8 sha2_32_armv8
   INFO: Skipping (no enabled compression schemes): compression
   INFO: Skipping (requires external dependency): boost bzip2 lzma sqlite3 tpm zlib

The ones that are skipped because they are require an external
dependency have to be explicitly asked for, because they rely on third
party libraries which your system might not have or that you might not
want the resulting binary to depend on. For instance to enable zlib
support, add ``--with-zlib`` to your invocation of ``configure.py``.
All available modules can be listed with ``--list-modules``.

Some modules may be marked as 'deprecated' or 'experimental'. Deprecated
modules are available and built by default, but they will be removed in a
future release of the library. Use ``--disable-deprecated-features`` to
disable all of these modules or ``--disable-modules=MODS`` for finer grained
control. Experimental modules are under active development and not built
by default. Their API may change in future minor releases. Applications may
still enable and use such modules using ``--enable-modules=MODS`` or using
``--enable-experimental-features`` to enable all experimental features.

You can control which algorithms and modules are built using the
options ``--enable-modules=MODS`` and ``--disable-modules=MODS``, for
instance ``--enable-modules=zlib`` and ``--disable-modules=xtea,idea``.
Modules not listed on the command line will simply be loaded if needed
or if configured to load by default. If you use ``--minimized-build``,
only the most core modules will be included; you can then explicitly
enable things that you want to use with ``--enable-modules``. This is
useful for creating a minimal build targeting to a specific
application, especially in conjunction with the amalgamation option;
see :ref:`amalgamation` and :ref:`minimized_builds`.

For instance::

 $ ./configure.py --minimized-build --enable-modules=rsa,eme_oaep,emsa_pssr

will set up a build that only includes RSA, OAEP, PSS along with any
required dependencies. Note that a minimized build does not by default
include any random number generator, which is needed for example to
generate keys, nonces and IVs. See :doc:`api_ref/rng` on which random number
generators are available.

Common Build Targets
--------------------

Build everthing that is configured::

 $ make all

Build the unit test binary (``./botan-test`` to run)::

 $ make tests

Build and run the tests::

 $ make check

Build the documentation (Doxygen API reference and Sphinx handbook)::

 $ make docs

Install the library::

 $ make install

Remove all generated artefacts::

 $ make clean

Cross Compiling
---------------------

Cross compiling refers to building software on one type of host (say Linux
x86-64) but creating a binary for some other type (say MinGW x86-32). This is
completely supported by the build system. To extend the example, we must tell
`configure.py` to use the MinGW tools::

 $ ./configure.py --os=mingw --cpu=x86_32 --cc-bin=i686-w64-mingw32-g++ --ar-command=i686-w64-mingw32-ar
 ...
 $ make
 ...
 $ file botan.exe
 botan.exe: PE32 executable (console) Intel 80386, for MS Windows

.. note::
   For whatever reason, some distributions of MinGW lack support for
   threading or mutexes in the C++ standard library. You can work around
   this by disabling thread support using ``--without-os-feature=threads``

You can also specify the alternate tools by setting the `CXX` and `AR`
environment variables (instead of the `--cc-bin` and `--ar-command` options), as
is commonly done with autoconf builds.

On Unix
----------------

The basic build procedure on Unix and Unix-like systems is::

   $ ./configure.py [various options]
   $ make
   $ make check

If the tests look OK, install::

   $ make install

On Unix systems the script will default to using GCC; use ``--cc`` if
you want something else. For instance use ``--cc=clang`` for Clang.

The ``make install`` target has a default directory in which it will
install Botan (typically ``/usr/local``). You can override this by
using the ``--prefix`` argument to ``configure.py``, like so::

   $ ./configure.py --prefix=/opt <other arguments>

On some systems shared libraries might not be immediately visible to
the runtime linker. For example, on Linux you may have to edit
``/etc/ld.so.conf`` and run ``ldconfig`` (as root) in order for new
shared libraries to be picked up by the linker. An alternative is to
set your ``LD_LIBRARY_PATH`` shell variable to include the directory
that the Botan libraries were installed into.

On macOS
--------------

A build on macOS works much like that on any other Unix-like system.

To build a universal binary for macOS, for older macOs releases,
you need to set some additional build flags.
Do this with the `configure.py` flag `--cc-abi-flags`::

  --cc-abi-flags="-force_cpusubtype_ALL -mmacosx-version-min=10.4 -arch i386 -arch ppc"


for mac M1 on arm64, you can build the x86_64 arch version via Rosetta separately.
Do this with with `arch -x86_64 configure.py --library-suffix=-x86_64`
Then using lipo to create a fat binary.
`lipo -create libbotan-arm64.dylib libbotan-x86_64.dylib -o libbotan.dylib`

On Windows
--------------

.. note::

   The earliest versions of Windows supported are Windows 7 and Windows 2008 R2

You need to have a copy of Python installed, and have both Python and
your chosen compiler in your path. Open a command shell (or the SDK
shell), and run::

   $ python3 configure.py --cc=msvc --os=windows
   $ nmake
   $ nmake check
   $ nmake install

Micosoft's ``nmake`` does not support building multiple jobs in parallel, which
is unfortunate when building on modern multicore machines. It is possible to use
the (somewhat unmaintained) `Jom <https://wiki.qt.io/Jom>`_ build tool, which is
a ``nmake`` compatible build system that supports parallel builds. Alternately,
starting in Botan 3.2, there is additionally support for using the ``ninja``
build tool as an alternative to ``nmake``::

   $ python3 configure.py --cc=msvc --os=windows --build-tool=ninja
   $ ninja
   $ ninja check
   $ ninja install

For MinGW, use::

   $ python3 configure.py --cc=gcc --os=mingw
   $ make

By default the install target will be ``C:\botan``; you can modify
this with the ``--prefix`` option.

When building your applications, all you have to do is tell the
compiler to look for both include files and library files in
``C:\botan``, and it will find both. Or you can move them to a
place where they will be in the default compiler search paths (consult
your documentation and/or local expert for details).

Ninja Support
---------------

Starting in Botan 3.2, there is additionally support for the
`ninja <https://ninja-build.org>`_ build system.

This is particularly useful on Windows as there the default build tool ``nmake``
does not support parallel jobs. The ``ninja`` based build also works on Unix and
macOs systems.

Support for ``ninja`` is still new and there are probably some rough edges.

For iOS using XCode
-------------------------

For iOS, you typically build for 3 architectures: armv7 (32 bit, older
iOS devices), armv8-a (64 bit, recent iOS devices) and x86_64 for
the iPhone simulator. You can build for these 3 architectures and then
create a universal binary containing code for all of these
architectures, so you can link to Botan for the simulator as well as
for an iOS device.

To cross compile for armv7, configure and make with::

  $ ./configure.py --os=ios --prefix="iphone-32" --cpu=armv7 --cc=clang \
                   --cc-abi-flags="-arch armv7"
  $ xcrun --sdk iphoneos make install

To cross compile for armv8-a, configure and make with::

  $ ./configure.py --os=ios --prefix="iphone-64" --cpu=armv8-a --cc=clang \
                   --cc-abi-flags="-arch arm64"
  $ xcrun --sdk iphoneos make install

To compile for the iPhone Simulator, configure and make with::

  $ ./configure.py --os=ios --prefix="iphone-simulator" --cpu=x86_64 --cc=clang \
                   --cc-abi-flags="-arch x86_64"
  $ xcrun --sdk iphonesimulator make install

Now create the universal binary and confirm the library is compiled
for all three architectures::

   $ xcrun --sdk iphoneos lipo -create -output libbotan-2.a \
                  iphone-32/lib/libbotan-2.a \
                  iphone-64/lib/libbotan-2.a \
                  iphone-simulator/lib/libbotan-2.a
   $ xcrun --sdk iphoneos lipo -info libbotan-2.a
   Architectures in the fat file: libbotan-2.a are: armv7 x86_64 armv64

The resulting static library can be linked to your app in Xcode.

For Android
---------------------

Modern versions of Android NDK use Clang and support C++20. Simply
configure using the appropriate NDK compiler and ``ar`` (``ar`` only
needed if building the static library). Here we build for Aarch64
targeting Android API 28::

  $ export AR=/opt/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar
  $ export CXX=/opt/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android28-clang++
  $ ./configure.py --os=android --cc=clang --cpu=arm64
  $ make

If you are building for mobile development consider restricting the build
to only what you need (see :ref:`minimized_builds`)

Docker
^^^^^^^^^^^

To build android version, there is the possibility to use
the docker way::

  sudo ANDROID_SDK_VER=29 ANDROID_ARCH=aarch64 src/scripts/docker-android.sh

This will produce the docker-builds/android folder containing
each architecture compiled.

Emscripten (WebAssembly)
---------------------------

To build for WebAssembly using Emscripten, try::

  ./configure.py --cpu=wasm --os=emscripten
  make

This will produce HTML files ``botan-test.html`` and ``botan.html``
along with a static archive ``libbotan-3.a`` which can be linked with
other modules.

Supporting Older Distros
--------------------------

Some "stable" distributions, notably RHEL/CentOS, ship very obsolete
versions of binutils, which do not support more recent CPU instructions.
As a result when building you may receive errors like::

   Error: no such instruction: `sha256rnds2 %xmm0,%xmm4,%xmm3'

Depending on how old your binutils is, you may need to disable BMI2,
AVX2, SHA-NI, and/or RDSEED. These can be disabled by passing the
flags ``--disable-bmi2``, ``--disable-avx2``, ``--disable-sha-ni``,
and ``--disable-rdseed`` to ``configure.py``.

Other Build-Related Tasks
----------------------------------------

.. _building_docs:

Building The Documentation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

There are two documentation options available, Sphinx and Doxygen.
Sphinx will be used if ``sphinx-build`` is detected in the PATH, or if
``--with-sphinx`` is used at configure time. Doxygen is only enabled
if ``--with-doxygen`` is used. Both are generated by the makefile
target ``docs``.


.. _amalgamation:

The Amalgamation Build
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You can also configure Botan to be built using only a single source file; this
is quite convenient if you plan to embed the library into another application.

To generate the amalgamation, run ``configure.py`` with whatever options you
would ordinarily use, along with the option ``--amalgamation``. This will create
two (rather large) files, ``botan_all.h`` and ``botan_all.cpp``.

.. note::

   The library will as usual be configured to target some specific operating
   system and CPU architecture. You can use the CPU target "generic" if you need
   to target multiple CPU architectures, but this has the effect of disabling
   *all* CPU specific features such as SIMD, AES instruction sets, or inline
   assembly. If you need to ship amalgamations for multiple targets, it would be
   better to create different amalgamation files for each individual target.

Whenever you would have included a botan header, you can then include
``botan_all.h``, and include ``botan_all.cpp`` along with the rest of the source
files in your build. If you want to be able to easily switch between amalgamated
and non-amalgamated versions (for instance to take advantage of prepackaged
versions of botan on operating systems that support it), you can instead ignore
``botan_all.h`` and use the headers from ``build/include`` as normal.

You can also build the library using Botan's build system (as normal) but
utilizing the amalgamation instead of the individual source files by running
something like ``./configure.py --amalgamation && make``. This is essentially a
very simple form of link time optimization; because the entire library source is
visible to the compiler, it has more opportunities for interprocedural
optimizations.  Additionally (assuming you are not making use of a compiler
cache such as ``ccache`` or ``sccache``) amalgamation builds usually have
significantly shorter compile times for full rebuilds.

Modules Relying on Third Party Libraries
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Currently ``configure.py`` cannot detect if external libraries are
available, so using them is controlled explicitly at build time
by the user using

 - ``--with-bzip2`` enables the filters providing bzip2 compression and
   decompression. Requires the bzip2 development libraries to be installed.

 - ``--with-zlib`` enables the filters providing zlib compression and
   decompression. Requires the zlib development libraries to be installed.

 - ``--with-lzma`` enables the filters providing lzma compression and
   decompression. Requires the lzma development libraries to be installed.

 - ``--with-sqlite3`` enables using sqlite3 databases in various contexts
   (TLS session cache, PSK database, etc).

 - ``--with-tpm`` adds support for using TPM hardware via the TrouSerS library.

 - ``--with-boost`` enables using some Boost libraries. In particular
   Boost.Filesystem is used for a few operations (but on most platforms, a
   native API equivalent is available), and Boost.Asio is used to provide a few
   extra TLS related command line utilities.

Multiple Builds
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

It may be useful to run multiple builds with different configurations.
Specify ``--with-build-dir=<dir>`` to set up a build environment in a
different directory.

Setting Distribution Info
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The build allows you to set some information about what distribution
this build of the library comes from.  It is particularly relevant to
people packaging the library for wider distribution, to signify what
distribution this build is from. Applications can test this value by
checking the string value of the macro ``BOTAN_DISTRIBUTION_INFO``. It
can be set using the ``--distribution-info`` flag to ``configure.py``,
and otherwise defaults to "unspecified". For instance, a `Gentoo
<https://www.gentoo.org>`_ ebuild might set it with
``--distribution-info="Gentoo ${PVR}"`` where ``${PVR}`` is an ebuild
variable automatically set to a combination of the library and ebuild
versions.

Local Configuration Settings
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You may want to do something peculiar with the configuration; to
support this there is a flag to ``configure.py`` called
``--with-local-config=<file>``. The contents of the file are
inserted into ``build/build.h`` which is (indirectly) included
into every Botan header and source file.

Enabling or Disabling Use of Certain OS Features
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Botan uses compile-time flags to enable or disable use of certain operating
specific functions. You can also override these at build time if desired.

The default feature flags are given in the files in ``src/build-data/os`` in the
``target_features`` block. For example Linux defines flags like ``getrandom``,
``getauxval``, and ``sockets``.  The ``configure.py`` option
``--list-os-features`` will display all the feature flags for all operating
system targets.

To disable a default-enabled flag, use ``--without-os-feature=feat1,feat2,...``

To enable a flag that isn't otherwise enabled, use ``--with-os-feature=feat``.
For example, modern Linux systems support the ``getentropy`` call, but it is not
enabled by default because many older systems lack it. However if you know you
will only deploy to recently updated systems you can use
``--with-os-feature=getentropy`` to enable it.

A special case if dynamic loading, which applications for certain environments
will want to disable. There is no specific feature flag for this, but
``--disable-modules=dyn_load`` will prevent it from being used.

.. note:: Disabling ``dyn_load`` module will also disable the PKCS #11
          wrapper, which relies on dynamic loading.

Configuration Parameters
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

There are some configuration parameters which you may want to tweak
before building the library. These can be found in ``build.h``. This
file is overwritten every time the configure script is run (and does
not exist until after you run the script for the first time).

Also included in ``build/build.h`` are macros which let applications
check which features are included in the current version of the
library. All of them begin with ``BOTAN_HAS_``. For example, if
``BOTAN_HAS_RSA`` is defined, then an application knows that this
version of the library has RSA available.

``BOTAN_MP_WORD_BITS``: This macro controls the size of the words used for
calculations with the MPI implementation in Botan.  It must be set to either 32
or 64 bits. The default is chosen based on the target processor. There is
normally no reason to change this.

``BOTAN_DEFAULT_BUFFER_SIZE``: This constant is used as the size of
buffers throughout Botan. The default should be fine for most
purposes, reduce if you are very concerned about runtime memory usage.

Building Applications
----------------------------------------

Unix
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Botan usually links in several different system libraries (such as
``librt`` or ``libz``), depending on which modules are configured at
compile time. In many environments, particularly ones using static
libraries, an application has to link against the same libraries as
Botan for the linking step to succeed. But how does it figure out what
libraries it *is* linked against?

The answer is to ask the ``botan`` command line tool using
the ``config`` and ``version`` commands.

``botan version``: Print the Botan version number.

``botan config prefix``: If no argument, print the prefix where Botan is
installed (such as ``/opt`` or ``/usr/local``).

``botan config cflags``: Print options that should be passed to the
compiler whenever a C++ file is compiled. Typically this is used for
setting include paths.

``botan config libs``: Print options for which libraries to link to
(this will include a reference to the botan library itself).

Your ``Makefile`` can run ``botan config`` and get the options
necessary for getting your application to compile and link, regardless
of whatever crazy libraries Botan might be linked against.

Windows
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

No special help exists for building applications on Windows. However,
given that typically Windows software is distributed as binaries, this
is less of a problem - only the developer needs to worry about it. As
long as they can remember where they installed Botan, they just have
to set the appropriate flags in their Makefile/project file.

CMake
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Starting in Botan 3.3.0 we provide a ``botan-config.cmake`` module to
discover the installed library binaries and headers. This hooks into
CMake's ``find_package()`` and comes with common features like version
detection. Also, library consumers may specify which botan modules they
require in ``find_package()``.

Examples::

   find_package(Botan 3.3.0)
   find_package(Botan 3.3.0 COMPONENTS rsa ecdsa tls13)
   find_package(Botan 3.3.0 OPTIONAL_COMPONENTS tls13_pqc)

Language Wrappers
----------------------------------------

Building the Python wrappers
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The Python wrappers for Botan use ctypes and the C89 API so no special
build step is required, just import botan3.py

See :doc:`Python Bindings <api_ref/python>` for more information about
the Python bindings.

.. _minimized_builds:

Minimized Builds
--------------------

Many developers wish to configure a minimized build which contains only the
specific features their application will use. In general this is straighforward:
use ``--minimized-build`` plus ``--enable-modules=`` to enable the specific modules
you wish to use. Any such configurations should build and pass the tests; if you
encounter a case where it doesn't please file an issue.

The only trick is knowing which features you want to enable. The most common
difficulty comes with entropy sources. By default, none are enabled, which means
if you attempt to use ``AutoSeeded_RNG``, it will fail. The easiest resolution
is to also enable ``system_rng`` which can act as either an entropy source or
used directly as the RNG.

If you are building for x86, ARM, or POWER, it can be beneficial to enable
hardware support for the relevant instruction sets with modules such as
``aes_ni`` and ``clmul`` for x86, or ``aes_armv8``, ``pmull``, and
``sha2_32_armv8`` on ARMv8. SIMD optimizations such as ``chacha_avx2`` also can
provide substantial performance improvements.

.. note::
   In a future release, hardware specific modules will be enabled by default if
   the underlying "base" module is enabled.

If you are building a TLS application, you may (or may not) want to include
``tls_cbc`` which enables support for CBC ciphersuites. If ``tls_cbc`` is
disabled, then it will not be possible to negotiate TLS v1.0/v1.1. In general
this should be considered a feature; only enable this if you need backward
compatability with obsolete clients or servers.

For TLS another useful feature which is not enabled by default is the
ChaCha20Poly1305 ciphersuites. To enable these, add ``chacha20poly1305``.


Configure Script Options
---------------------------

``--cpu=CPU``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Set the target CPU architecture. If not used, the arch of the current
system is detected (using Python's platform module) and used.

``--os=OS``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Set the target operating system.

``--cc=COMPILER``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Set the desired build compiler

``--cc-min-version=MAJOR.MINOR``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Set the minimal version of the target
compiler. Use --cc-min-version=0.0 to support all compiler
versions. Default is auto detection.

``--cc-bin=BINARY``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Set path to compiler binary

If not provided, the value of the ``CXX`` environment variable is used if set.

``--cc-abi-flags=FLAGS``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Set ABI flags, which for the purposes of this option mean options
which should be passed to both the compiler and linker.

``--cxxflags=FLAGS``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Override all compiler flags. This is equivalent to setting ``CXXFLAGS``
in the environment.

``--extra-cxxflags=FLAGS``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Set extra compiler flags, which are appended to the default set.  This
is useful if you want to set just one or two additional options but
leave the normal logic for selecting flags alone.

``--ldflags=FLAGS``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Set flags to pass to the linker. This is equivalent to setting ``LDFLAGS``

``--ar-command=AR``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Set the path to the tool to use to create static archives (``ar``).
This is normally only used for cross-compilation.

If not provided, the value of the ``AR`` environment variable is used if set.

``--ar-options=AR_OPTIONS``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Specify the options to pass to ``ar``.

If not provided, the value of the ``AR_OPTIONS`` environment variable is used if set.

``--msvc-runtime=RT``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Specify the MSVC runtime to use (MT, MD, MTd, or MDd). If not specified,
picks either MD or MDd depending on if debug mode is set.

``--compiler-cache``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Specify a compiler cache (like ccache) to use for each compiler invocation.

``--with-endian=ORDER``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The parameter should be either "little" or "big". If not used then if
the target architecture has a default, that is used. Otherwise left
unspecified, which causes less optimal codepaths to be used but will
work on either little or big endian.

``--with-os-features=FEAT``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Specify an OS feature to enable. See ``src/build-data/os`` and
``doc/os.rst`` for more information.

``--without-os-features=FEAT``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Specify an OS feature to disable.

``--enable-experimental-features``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Enable all experimental modules and features. Note that these are unstable and
may change or even be removed in future releases. Also note that individual
experimental modules can be explicitly enabled using ``--enable-modules=MODS``.

``--disable-experimental-features``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Disable all experimental modules and features. This is the default.

``--enable-deprecated-features``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Enable all deprecated modules and features. Note that these are scheduled for
removal in future releases. This is the default.

``--disable-deprecated-features``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Disable all deprecated modules and features. Note that individual deprecated
modules can be explicitly disabled using ``--disable-modules=MODS``.

``--disable-sse2``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Disable use of SSE2 intrinsics

``--disable-ssse3``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Disable use of SSSE3 intrinsics

``--disable-sse4.1``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Disable use of SSE4.1 intrinsics

``--disable-sse4.2``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Disable use of SSE4.2 intrinsics

``--disable-avx2``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Disable use of AVX2 intrinsics

``--disable-bmi2``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Disable use of BMI2 intrinsics

``--disable-rdrand``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Disable use of RDRAND intrinsics

``--disable-rdseed``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Disable use of RDSEED intrinsics

``--disable-aes-ni``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Disable use of AES-NI intrinsics

``--disable-sha-ni``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Disable use of SHA-NI intrinsics

``--disable-altivec``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Disable use of AltiVec intrinsics

``--disable-neon``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Disable use of NEON intrinsics

``--disable-armv8crypto``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Disable use of ARMv8 Crypto intrinsics

``--disable-powercrypto``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Disable use of POWER Crypto intrinsics

``--system-cert-bundle=PATH``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Set a path to a file containing one or more trusted CA certificates in
PEM format. If not given, some default locations are checked.

``--with-debug-info``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Include debug symbols.

``--with-sanitizers``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Enable some default set of sanitizer checks. What exactly is enabled
depends on the compiler.

``--enable-sanitizers=SAN``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Enable specific sanitizers. See ``src/build-data/cc`` for more information.

``--without-stack-protector``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Disable stack smashing protections. **not recommended**

``--with-coverage-info``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Add coverage info

``--disable-shared-library``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Disable building a shared library

``--disable-static-library``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Disable building static library

``--optimize-for-size``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Optimize for code size.

``--no-optimizations``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Disable all optimizations for debugging.

``--debug-mode``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Enable debug info and disable optimizations

``--amalgamation``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Use amalgamation to build

``--name-amalgamation``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Specify an alternative amalgamation file name. By default we use `botan_all`.


``--with-build-dir=DIR``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Setup the build in a specified directory instead of ``./build``

``--with-external-includedir=DIR``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Search for includes in this directory. Provide this parameter multiple times to
define multiple additional include directories.

``--with-external-libdir=DIR``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Add DIR to the link path. Provide this parameter multiple times to define
multiple additional library link directories.

``--define-build-macro``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Set a compile-time pre-processor definition (i.e. add a -D... to the compiler
invocations). Provide this parameter multiple times to add multiple compile-time
definitions. Both KEY=VALUE and KEY (without specific value) are supported.

``--with-sysroot-dir=DIR``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Use specified dir for system root while cross-compiling

``--link-method=METHOD``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

During build setup a directory linking to each header file is created.
Choose how the links are performed (options are "symlink", "hardlink",
or "copy").

``--with-local-config=FILE``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Include the contents of FILE into the generated build.h

``--distribution-info=STRING``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Set distribution specific version information

``--maintainer-mode``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A build configuration used by library developers, which enables extra
warnings and turns most warnings into errors.

.. warning::

   When this option is used, all relevant warnings available in the
   most recent release of GCC/Clang are enabled, so it may fail to
   build if your compiler is not sufficiently recent. In addition
   there may be non-default configurations or unusual platforms which
   cause warnings which are converted to errors. Patches addressing
   such warnings are welcome, but otherwise no support is available
   when using this option.

``--werror-mode``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Turns most warnings into errors.

``--no-install-python-module``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Skip installing Python module.

``--with-python-versions=N.M``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Where to install botan3.py. By default this is chosen to be the
version of Python that is running ``configure.py``.

``--with-valgrind``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Use valgrind API to perform additional checks. Not needed by end users.

``--unsafe-fuzzer-mode``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Disable essential checks for testing. **UNSAFE FOR PRODUCTION**

``--build-fuzzers=TYPE``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Select which interface the fuzzer uses. Options are "afl",
"libfuzzer", "klee", or "test". The "test" mode builds fuzzers that
read one input from stdin and then exit.

``--with-fuzzer-lib=LIB``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Specify an additional library that fuzzer binaries must link with.

``--build-targets=BUILD_TARGETS``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Build only the specific targets and tools
(``static``, ``shared``, ``cli``, ``tests``, ``bogo_shim``).


``--without-documentation``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Skip building/installing documentation

``--with-sphinx``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Use Sphinx to generate the handbook

``--with-pdf``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Use Sphinx to generate PDF doc

``--with-rst2man``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Use rst2man to generate a man page for the CLI

``--with-doxygen``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Use Doxygen to generate API reference

``--module-policy=POL``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The option ``--module-policy=POL`` enables modules required by and
disables modules prohibited by a text policy in ``src/build-data/policy``.
Additional modules can be enabled if not prohibited by the policy.
Currently available policies include ``bsi``, ``nist`` and ``modern``::

 $ ./configure.py --module-policy=bsi --enable-modules=tls,xts

``--enable-modules=MODS``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Enable some specific modules

``--disable-modules=MODS``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Disable some specific modules

``--minimized-build``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Start with the bare minimum. This is mostly useful in conjuction with
``--enable-modules`` to get a build that has just the features a
particular application requires.

``--with-boost``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Use Boost.Asio for networking support. This primarily affects the
command line utils.

``--with-bzip2``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Enable bzip2 compression

``--with-lzma``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Enable lzma compression

``--with-zlib``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Enable using zlib compression

``--with-commoncrypto``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Enable using CommonCrypto for certain operations

``--with-sqlite3``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Enable using sqlite3 for data storage

``--with-tpm``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Enable support for TPM

``--program-suffix=SUFFIX``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A string to append to all program binaries.

``--library-suffix=SUFFIX``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A string to append to all library names.

``--prefix=DIR``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Set the install prefix.

``--docdir=DIR``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Set the documentation installation dir.

``--bindir=DIR``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Set the binary installation dir.

``--libdir=DIR``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Set the library installation dir.

``--mandir=DIR``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Set the man page installation dir.

``--includedir=DIR``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Set the include file installation dir.

``--list-modules``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

List all modules that could be enabled or disabled using `--enable-modules` or
`--disable-modules`.
