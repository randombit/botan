
Botan Development Roadmap
========================================

Branch Structure
----------------------------------------

Stability of branches is indicated by even or odd minor version numbers. The
minor number of master is always odd, and devel releases come from it. Every
once in a while a new even-numbered branch is forked. All development continues
on the main trunk, with fixes and API compatible features backported to the
stable branch. Stability of API and ABI is very important in the stable
branches, whereas in master ABI changes happen with no warning, and API changes
are made whenever it would serve the ends of justice.

Current Status
----------------------------------------

Currently (as of 2016-11-03) git master is approaching feature freeze for a
stable 2.0 branch by the end of December 2016.

At some point between the final release candidate and the 2.0.0 release, a new
release-2.0 branch will be created off of master. Development will continue on
master (renumbered as 2.1.0), with chosen changes backported to release-2.0
branch.

Theoretically a new development release could be created at any time after this.
But it is likely that for at least several months after branching, most
development will be oriented towards being applied also to 2.0, and so there
will not be any interesting diff between 2.1 and 2.0. At some point when the
divergence grows enough to be 'interesting' a new development release will be
created. These early development releases would only be for experimenters, with
2.0 recommended for general use.

Support Lifetimes
----------------------------------------

Botan 2.0.x will be supported for at least 24 months from the date of 2.0.0
(probably longer)

Botan 1.10.x is supported (for security patches only) through 2017-12-31

All prior versions are no longer supported in any way.

Supported Targets
----------------------------------------

The primary supported targets, which are tested with every commit by
continuous integration, are GCC and Clang on Linux/x86-64, Clang on
OSX/x86-64, and MSVC 2015 on Windows/x86-64. We also test arm, arm64,
and ppc64 builds via GCC cross compilation and qemu emulation, and for
iOS cross-compilation is checked (but the tests are not run).

Other processors and OSes, like MIPS and OpenBSD, are occasionally
tested on an ad-hoc basis, but breakage is somewhat more likely.

As a policy we do not support any OS which is not supported by its
original vendor. So for example no consideration whatsoever is given
to supporting such EOLed systems as Windows 2000 or Solaris 2.6.

Ongoing Issues
----------------------------------------

Documentation could always use help. Many things are completely undocumented,
few things are documented well.
