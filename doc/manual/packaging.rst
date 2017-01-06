Info for Packagers
========================

This document has information for anyone who is packaging copies of Botan for
use by downstream developers, such as through a Linux distribution or other
package management system.

Set Distribution Info
------------------------

If your distribution of Botan involves creating library binaries, use the
configure.py flag ``--distribution-info=`` to set the version of your
packaging. For example Foonix OS might distribute its 4th revision of the
package for Botan 2.1.3 using ``--distribution-info='Foonix 2.1.3-4'``. The
string is completely free-form, since it depends on how the distribution numbers
releases and packages.

Any value set with ``--distribution-info`` flag will be included in the version
string, and can read through the ``BOTAN_DISTRIBUTION_INFO`` macro.

Minimize Distribution Patches
------------------------------

We (Botan upstream) *strongly* prefer that downstream distributions maintain no
long-term patches against Botan. Even if it is a build problem which probably
only affects your environment, please open an issue on github and include the
patch you are using. Perhaps the issue does affect other users, and even if not
it would be better for everyone if the library were improved so it were not
necessary for the patch to be created in the first place. For example, having to
modify or remove a build data file, or edit the makefile after generation,
suggests an area where the build system is insufficiently flexible.

Obviously nothing in the BSD-2 license prevents you from distributing patches or
modified versions of Botan however you please. But long term patches by
downstream distributors have a tendency to bitrot and sometimes even result in
security problems (such as in the Debian OpenSSL RNG fiasco) because the patches
are never reviewed by the library developers. So we try to discourage them, and
work to ensure they are never necessary.
