Support Information
=======================

Supported Platforms
------------------------

For Botan 3, the tier-1 supported platforms are

* Linux x86-64, GCC 11 or later
* Linux x86-64, Clang 14 or later
* Linux aarch64, GCC 11 or later
* Linux ppc64le, GCC 11 or later
* Windows x86-64, Visual C++ 2022 or later

These platforms are all tested by continuous integration, and the developers
have access to hardware in order to test patches. Problems affecting these
platforms are considered release blockers.

For Botan 3, the tier-2 supported platforms are

* macOS x86-64, latest XCode Clang
* iOS aarch64, latest XCode Clang
* Windows x86-64, latest MinGW GCC
* Android aarch64, latest NDK Clang
* Linux arm32, GCC 11 or later
* Linux x86-32, GCC 11 or later
* FreeBSD x86-64, Clang 14 or later

Some (but not all) of the tier-2 platforms are tested by CI. Everything should
work, and if problems are encountered, the developers will probably be able to
help. But they are not as carefully tested as tier-1.

Of course most other modern OSes such as QNX, AIX, OpenBSD, NetBSD, and Solaris
also work just fine. Some are tested occasionally, usually just before a new
release. But very little code specific to these platforms is written by the
primary developers. For example, any functionality in the library which
utilizes OpenBSD specific APIs was likely contributed by someone interested in
that platform.

In theory any working C++20 compiler is fine but in practice, we only regularly
test with GCC, Clang, and Visual C++. Several other compilers (such as Intel and
Sun Studio) are supported by the build system but are not tested by the
developers and may have build or codegen problems. Patches to improve support
for these compilers is welcome.

Branch Support Status
-------------------------

Following table provides the support status for Botan branches as of
February 2023. Any branch not listed here is no longer supported.
Dates in the future are approximate.

============== ============== ========================== ============
Branch         First Release  End of Active Development  End of Life
============== ============== ========================== ============
1.8            2008-12-08     2010-08-31                 2016-02-13
1.10           2011-06-20     2012-07-10                 2018-12-31
2.x            2017-01-06     2020-11-05                 2024-12-31 or later
3.x            2023?          ?                          ?
============== ============== ========================== ============

"Active development" refers to adding new features and optimizations. At the
conclusion of the active development phase, only bugfixes are applied.

Getting Help
------------------

To get help with Botan, open an issue on
`GitHub <https://github.com/randombit/botan/issues>`_
