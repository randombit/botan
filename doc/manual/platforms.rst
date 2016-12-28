Supported Platforms
==============================

For Botan 2, the tier-1 supported platforms are

* Linux x86-64, GCC 4.8 or higher
* Linux x86-64, Clang 3.5 or higher
* Linux aarch64, GCC 4.8+
* Linux ppc64le, GCC 4.8+
* Windows x86-64, Visual C++ 2013 and 2015

These platforms are all tested by continuous integration, and the developers
have access to hardware in order to test patches. Problems affecting these
platforms are considered release blockers.

For Botan 2, the tier-2 supported platforms are

* Linux x86-32, GCC 4.8+
* Linux arm32, GCC 4.8+
* Windows x86-64, MinGW GCC
* Apple OS X x86-64, XCode Clang
* iOS arm32/arm64, XCode Clang
* Android arm32, NDK Clang
* FreeBSD x86-64, Clang 3.8+
* IncludeOS x86-32, Clang 3.8+

Some (but not all) of the tier-2 platforms are tested by CI. Things should
mostly work, and if problems are encountered, the Botan devs will probably be
able to help. But they are not as well tested as tier-1.

Of course many other modern OSes such as OpenBSD, NetBSD, AIX, Solaris or QNX
are also probably fine (Botan has been tested on all of them successfully in the
past), but none of the core developers run these OSes and may not be able to
help so much in debugging problems. Patches to improve the build for these
platforms are welcome. Note that as a policy Botan does not support any OS which
is not supported by its original vendor; any such EOLed systems that are still
running are unpatched and insecure.

In theory any working C++11 compiler is fine but in practice, we only test with
GCC, Clang, and Visual C++.  There is support in the build system for several
commercial C++ compilers (Intel, PGI, Sun Studio, Ekopath, etc) all of which
worked with older (C++98) versions of both the code and the compilers, but it is
not known if the latest versions of these compilers can compile the library
properly.
