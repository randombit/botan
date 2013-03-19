
Getting The Latest Sources
========================================

All releases are signed with a :doc:`PGP key <pgpkey>`.

Unsure which release you want? Check the :ref:`FAQ <devel_vs_stable>`.

.. only:: not website

   .. note::

      If you are viewing this documentation offline, a more recent
      release `may be available <https://botan.randombit.net/download.html>`_.

Current Stable Series (1.10)
----------------------------------------

The latest version of the current stable series, from branch
``net.randombit.botan.1_10``, is :doc:`relnotes/1_10_5`:
:tgz:`1.10.5` (:tgz_sig:`sig <1.10.5>`),
:tbz:`1.10.5` (:tbz_sig:`sig <1.10.5>`)

Windows Installer
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Windows installers for use with Visual C++ 2010
:installer_x86_32:`1.10.5` (:installer_sig_x86_32:`sig <1.10.5>`)
and
:installer_x86_64:`1.10.5` (:installer_sig_x86_64:`sig <1.10.5>`)
are also available.

Current Development Series (1.11)
----------------------------------------

The latest version of the current development series, from branch
``net.randombit.botan``, is :doc:`relnotes/1_11_2`:
:tgz:`1.11.2` (:tgz_sig:`sig <1.11.2>`),
:tbz:`1.11.2` (:tbz_sig:`sig <1.11.2>`)

A script also creates daily snapshots of trunk, which are available
`here <https://files.randombit.net/botan/snapshots/>`_.

.. note::

   Versions 1.11.0 and later require a mostly-compliant C++11 compiler
   such as Clang 3.1 or GCC 4.7.

Older Stable Series (1.8)
----------------------------------------

The latest version of the previous stable series, from branch
``net.randombit.botan.1_8`` is :doc:`relnotes/1_8_14`:
:tgz:`1.8.14` (:tgz_sig:`sig <1.8.14>`),
:tbz:`1.8.14` (:tbz_sig:`sig <1.8.14>`)

Accessing Version Control
----------------------------------------

Botan's development occurs using a distributed version control system
called `Monotone <http://www.monotone.ca>`_ (though there is also a
mirror on `github <https://github.com/randombit/botan>`_. The main
branch of development occurs on the branch named
``net.randombit.botan``. To download that branch and set up a new
workspace, run::

   $ mtn db init --db=botan.mtn
   $ mtn pull --db=botan.mtn randombit.net 'net.randombit.botan'
   [...]
   $ mtn checkout --db=botan.mtn --branch=net.randombit.botan
   [...]

By default the ``checkout`` command will place the workspace in a
directory with the same name as the branch you are checking out. If
you want a different directory name, just include it after the
``--branch`` option (you can also rename this directory at any time).

If this is the first time you've connected to the server, Monotone
will print::

  mtn: first time connecting to server randombit.net
  mtn: I'll assume it's really them, but you might want to double-check
  mtn: their key's fingerprint: 8c0b868f2247215c63c96983b1c8ca0f0f0cfd9a

The fingerprint shown above was the correct one as of June 20, 2012.

To pull further changes, from anywhere in the workspace run these
commands::

  $ mtn pull
  [...]
  $ mtn update
  [summary of changes]

The ``mtn update`` command will give you a summary of which files
changed; to view the full changelog, run ``mtn log``.
