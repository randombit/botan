
Botan Development Roadmap
========================================

Branch Stucture
----------------------------------------

Stability of branches is indicated by even or odd minor version numbers. The
minor number of the primary trunk is always odd and devel releases and
snapshots are made directly from it. Every once in a while a new even-numbered
branch is forked. All development continues on the main trunk, with fixes and
occasionally small features backported to the stable branch. Stability of API
and ABI is very important in the stable branches, whereas in trunk ABI changes
happen with no warning and API changes are made whenever it would serve the
ends of justice.

Current Status
----------------------------------------

Currently (as of 2015-01-08) trunk is numbered 1.11 and is written in C++11,
unlike earlier versions which used C++98. In due time a new stable 2.0 branch
will be made off of trunk and afterwards trunk will be renumbered as 2.1. The
2.0 releases will be maintained with security and bug fixes at least until a
new 2.2 stable branch is created and likely for some time afterwards. In the
last decade the length of time between new stable trees being created has been
between 23 and 41 months, suggesting a support lifetime of 2-4 years for 2.0.x.

The 1.10 stable tree is, well, stable. There isn't enough project time to
backport all of the nice features from 1.11 (eg TLS v1.2, GCM, OCB, or
McEliece) to 1.10, even where it could be done while maintaining API/ABI
compat. The C++11 transition makes it especially hard for the 1.10/1.11
split. So if 1.10 does what you want now it probably will next week, but it
won't ever do much beyond that. If you want any feature or optimization or side
channel resistance added in the last 4 years you have to use 1.11. 1.10 will
continue to be maintained at the current level for at least a year after 2.0 is
released.

1.8 and all older versions are no longer maintained.

Supported Targets
----------------------------------------

The primary supported target (ie, what the main developer uses and tests with
regularly) is a recent GCC or Clang on Linux with an x86-64 CPU. Occasionally
Linux systems using POWER, MIPS, and ARM processors are also checked. Testing
and fixes for Windows, MinGW, OS X, OpenBSD, Visual C++, iOS, etc comes
primarily from users.

Ongoing Issues
----------------------------------------

Currently sources are kept in :doc:`Monotone <vcs>`, which likely discourages
some would-be developers. The github mirror may be helping somewhat here.

Some infrastructure, scripts and such still exists only on the machines of the
primary developer.

Documentation could always use help. Many things are completely undocumented,
few things are documented well.
