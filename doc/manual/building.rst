
Building The Library
=================================

This document describes how to build Botan on Unix/POSIX and MS
Windows systems. The POSIX oriented descriptions should apply to most
common Unix systems (including MacOS X), along with POSIX-ish systems
like BeOS, QNX, and Plan 9. Currently, systems other than Windows and
POSIX (such as VMS, MacOS 9, OS/390, OS/400, ...) are not supported by
the build system, primarily due to lack of access. Please contact the
maintainer if you would like to build Botan on such a system.

Botan's build is controlled by configure.py, which is a `Python
<http://www.python.org>`_ script. Python 2.6 or later is required.

For the impatient, this works for most systems::

  $ ./configure.py [--prefix=/some/directory]
  $ make
  $ make install

Or using ``nmake``, if you're compiling on Windows with Visual C++. On
platforms that do not understand the '#!' convention for beginning
script files, or that have Python installed in an unusual spot, you
might need to prefix the ``configure.py`` command with ``python`` or
``/path/to/python``::

  $ python ./configure.py [arguments]

Configuring the Build
---------------------------------

The first step is to run ``configure.py``, which is a Python script
that creates various directories, config files, and a Makefile for
building everything. This script should run under a vanilla install of
Python 2.6, 2.7, or 3.x.

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
algorithms have and have not been enabled. For instance on one system
we might see lines like::

   INFO: Skipping, by request only - bzip2 cvc gnump lzma openssl sqlite3 zlib
   INFO: Skipping, dependency failure - sessions_sqlite
   INFO: Skipping, incompatible CPU - asm_x86_32 md4_x86_32 md5_x86_32 mp_x86_32 serpent_x86_32 sha1_x86_32
   INFO: Skipping, incompatible OS - beos_stats cryptoapi_rng win32_stats
   INFO: Skipping, incompatible compiler - mp_x86_32_msvc

The ones that are skipped because they are 'by request only' have to
be explicitly asked for, because they rely on third party libraries
which your system might not have or that you might not want the
resulting binary to depend on. For instance to enable zlib support,
add ``--with-zlib`` to your invocation of ``configure.py``.

You can control which algorithms and modules are built using the
options ``--enable-modules=MODS`` and ``--disable-modules=MODS``, for
instance ``--enable-modules=zlib`` and ``--disable-modules=rc5,idea``.
Modules not listed on the command line will simply be loaded if needed
or if configured to load by default. If you use ``--no-autoload``,
only the most core modules will be included; you can then explicitly
enable things that you want to use with ``--enable-modules``. This is
useful for creating a minimal build targeting to a specific
application, especially in conjunction with the amalgamation option;
see :ref:`amalgamation`.

For instance::

 $ ./configure.py --no-autoload --enable-modules=rsa,ecdsa,eme1,emsa1,emsa4

will set up a build that only includes RSA, ECDSA, and some padding
modes, along with their dependencies. A small subset of core features,
including AES, SHA-2, HMAC, and the multiple precision integer
library, are always loaded.

The script tries to guess what kind of makefile to generate, and it
almost always guesses correctly (basically, Visual C++ uses NMAKE with
Windows commands, and everything else uses Unix make with POSIX
commands). Just in case, you can override it with
``--make-style=X``. The styles Botan currently knows about are 'gmake'
(GNU make and possibly some other Unix makes), and 'nmake', the make
variant commonly used by Microsoft compilers. To add a new variant
(eg, a build script for VMS), you will need to create a new template
file in ``src/build-data/makefile``.

On Unix
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The basic build procedure on Unix and Unix-like systems is::

   $ ./configure.py [--enable-modules=<list>] [--cc=CC]
   $ make
   $ ./botan test

If that fails with an error about not being able to find libbotan.so,
you may need to set ``LD_LIBRARY_PATH``:

   $ LD_LIBRARY_PATH=. ./botan test

If the tests look OK, install:

   $ make install

On Unix systems the script will default to using GCC; use ``--cc`` if
you want something else. For instance use ``--cc=icc`` for Intel C++
and ``--cc=clang`` for Clang.

The ``make install`` target has a default directory in which it will
install Botan (typically ``/usr/local``). You can override this by
using the ``--prefix`` argument to ``configure.py``, like so:

``./configure.py --prefix=/opt <other arguments>``

On some systems shared libraries might not be immediately visible to
the runtime linker. For example, on Linux you may have to edit
``/etc/ld.so.conf`` and run ``ldconfig`` (as root) in order for new
shared libraries to be picked up by the linker. An alternative is to
set your ``LD_LIBRARY_PATH`` shell variable to include the directory
that the Botan libraries were installed into.

On Mac OS X
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In general the Unix instructions above should apply, however OS X does
not support ``LD_LIBRARY_PATH``. Thomas Keller suggests instead
running ``install_name_tool`` between building and running the
self-test program::

  $ VERSION=1.11.11 # or whatever the current version is
  $ install_name_tool -change $(otool -X -D libbotan-$VERSION.dylib) \
       $PWD/libbotan-$VERSION.dylib botan-test

Building Universal Binaries
&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&

To build a universal binary for OS X, you need to set some additional
build flags. Do this with the --cc-abi-flags option::

  $ ./configure.py [other arguments] --cc-abi-flags="-force_cpusubtype_ALL -mmacosx-version-min=10.4 -arch i386 -arch ppc"

On MS Windows
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you don't want to deal with building botan on Windows, check the
website; commonly prebuilt Windows binaries with installers are
available, especially for stable versions.

You need to have a copy of Python installed, and have both Python and
your chosen compiler in your path. Open a command shell (or the SDK
shell), and run::

   > python configure.py --cc=msvc (or --cc=gcc for MinGW) [--cpu=CPU]
   > nmake
   > botan.exe test
   > nmake install

For Win95 pre OSR2, the ``cryptoapi_rng`` module will not work,
because CryptoAPI didn't exist. And all versions of NT4 lack the
ToolHelp32 interface, which is how ``win32_stats`` does its slow
polls, so a version of the library built with that module will not
load under NT4. Later versions of Windows support both methods, so
this shouldn't be much of an issue anymore.

By default the install target will be ``C:\botan``; you can modify
this with the ``--prefix`` option.

When building your applications, all you have to do is tell the
compiler to look for both include files and library files in
``C:\botan``, and it will find both. Or you can move them to a
place where they will be in the default compiler search paths (consult
your documentation and/or local expert for details).


For iOS using XCode
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To cross compile for iOS, configure with::

  $ ./configure.py --cpu=armv7 --cc=clang --cc-abi-flags="-arch armv7 -arch armv7s --sysroot=$(IOS_SYSROOT)"

Along with any additional configuration arguments. Using ``--no-autoload``
might be helpful as can substantially reduce code size.

Edit the makefile and change AR (around line 30) to::

  AR = libtool -static -o

You may also want to edit LIB_OPT to use -Os to optimize for size.

Now build as normal with ``make``. Confirm the binaries are compiled
for both architectures with::

  $ xcrun -sdk iphoneos lipo -info botan
  Architectures in the fat file: botan are: armv7 armv7s

Now sign the test application with::

  $ codesign -fs "Your Name" botan-test

which should allow you to run the library self tests on a jailbroken
device.

For Android
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Instructions for building the library on Android can be found
`here <http://www.tiwoc.de/blog/2013/03/building-the-botan-library-for-android/>`_.

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

You can also configure Botan to be built using only a single source
file; this is quite convenient if you plan to embed the library into
another application. To do so, run ``configure.py`` with whatever
arguments you would ordinarily use, along with the option
``--gen-amalgamation``. This will create two (rather large) files,
``botan_all.h`` and ``botan_all.cpp``.

Whenever you would have included a botan header, you can then include
``botan_all.h``, and include ``botan_all.cpp`` along with the rest of
the source files in your build. If you want to be able to easily
switch between amalgamated and non-amalgamated versions (for instance
to take advantage of prepackaged versions of botan on operating
systems that support it), you can instead ignore ``botan_all.h`` and
use the headers from ``build/include`` as normal.

You can also build the library as normal but using the amalgamation
instead of the individual source files using ``--via-amalgamation``.
This is essentially a very simple form of link time optimization;
because the entire library source is visible to the compiler, it has
more opportunities for interprocedural optimizations.

Modules Relying on Third Party Libraries
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Currently ``configure.py`` cannot detect if external libraries are
available, so using them is controlled explicitly at build time
by the user using

 - ``--with-bzip2`` enables the filters providing bzip2 compression
   and decompression. Requires the bzip2 development libraries to be
   installed.

 - ``--with-zlib`` enables the filters providing zlib compression
   and decompression. Requires the zlib development libraries to be
   installed.

 - ``--with-lzma`` enables the filters providing lzma compression and
   decompression. Requires the lzma development libraries to be
   installed.

 - ``--with-sqlite3`` enables storing TLS session information to an
   encrypted SQLite database.

 - ``--with-gnump`` adds an alternative engine for public key
   cryptography that uses the GNU MP library. GNU MP 4.1 or later is
   required.

 - ``--with-openssl`` adds an engine that uses OpenSSL for some public
   key operations and ciphers/hashes. OpenSSL 0.9.7 or later is
   required.

Multiple Builds
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

It may be useful to run multiple builds with different configurations.
Specify ``--build-dir=<dir>`` to set up a build environment in a
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
<http://www.gentoo.org>`_ ebuild might set it with
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

Configuration Parameters
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

There are some configuration parameters which you may want to tweak
before building the library. These can be found in ``build.h``. This
file is overwritten every time the configure script is run (and does
not exist until after you run the script for the first time).

Also included in ``build/build.h`` are macros which let applications
check which features are included in the current version of the
library. All of them begin with ``BOTAN_HAS_``. For example, if
``BOTAN_HAS_BLOWFISH`` is defined, then an application can include
``<botan/blowfish.h>`` and use the Blowfish class.

``BOTAN_MP_WORD_BITS``: This macro controls the size of the words used
for calculations with the MPI implementation in Botan. You can choose
8, 16, 32, or 64. Normally this defaults to either 32 or 64, depending
on the processor. Unless you are building for a 8 or 16-bit CPU, this
isn't worth messing with.

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
(this will include a reference to the botan library iself).

Your ``Makefile`` can run ``botan config`` and get the options
necessary for getting your application to compile and link, regardless
of whatever crazy libraries Botan might be linked against.

MS Windows
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

No special help exists for building applications on Windows. However,
given that typically Windows software is distributed as binaries, this
is less of a problem - only the developer needs to worry about it. As
long as they can remember where they installed Botan, they just have
to set the appropriate flags in their Makefile/project file.

Language Wrappers
----------------------------------------

Building the Python wrappers
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The Python wrappers for Botan use Boost.Python, so you must have Boost
installed. To build the wrappers, pass the flag
``--with-boost-python`` to ``configure.py`` and build the ``python``
target with ``make``.

To install the module, use the ``install_python`` target.

See :doc:`Python Bindings <python>` for more information about the
binding.

Building the Perl XS wrappers
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To build the Perl XS wrappers, after building the main library change
your directory to ``src/contrib/perl-xs`` and run ``perl Makefile.PL``,
then run ``make`` to build the module and ``make test`` to run the
test suite::

  $ perl Makefile.PL
  Checking if your kit is complete...
  Looks good
  Writing Makefile for Botan
  $ make
  cp Botan.pm blib/lib/Botan.pm
  AutoSplitting blib/lib/Botan.pm (blib/lib/auto/Botan)
  /usr/bin/perl5.8.8 /usr/lib64/perl5/5.8.8/ExtUtils/xsubpp  [...]
  g++ -c   -Wno-write-strings -fexceptions  -g   [...]
  Running Mkbootstrap for Botan ()
  chmod 644 Botan.bs
  rm -f blib/arch/auto/Botan/Botan.so
  g++  -shared Botan.o  -o blib/arch/auto/Botan/Botan.so  \
             -lbotan -lbz2 -lpthread -lrt -lz     \

  chmod 755 blib/arch/auto/Botan/Botan.so
  cp Botan.bs blib/arch/auto/Botan/Botan.bs
  chmod 644 blib/arch/auto/Botan/Botan.bs
  Manifying blib/man3/Botan.3pm
  $ make test
  PERL_DL_NONLAZY=1 /usr/bin/perl5.8.8 [...]
  t/base64......ok
  t/filt........ok
  t/hex.........ok
  t/oid.........ok
  t/pipe........ok
  t/x509cert....ok
  All tests successful.
  Files=6, Tests=83,  0 wallclock secs ( 0.08 cusr +  0.02 csys =  0.10 CPU)
