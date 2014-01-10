
Accessing Version Control
========================================

Botan's development occurs using a distributed version control system
called `Monotone <http://www.monotone.ca>`_ (though there is also a
mirror on `github <https://github.com/randombit/botan>`_). The main
branch of development occurs on the branch named
``net.randombit.botan``. To download that branch and set up a new
workspace, run::

   $ mtn db init --db=botan.mtn
   $ mtn pull --db=botan.mtn mtn.randombit.net 'net.randombit.botan'
   [...]
   $ mtn checkout --db=botan.mtn --branch=net.randombit.botan
   [...]

By default the ``checkout`` command will place the workspace in a
directory with the same name as the branch you are checking out. If
you want a different directory name, just include it after the
``--branch`` option (you can also rename this directory at any time).

If this is the first time you've connected to the server, Monotone
will print::

  mtn: first time connecting to server mtn.randombit.net
  mtn: I'll assume it's really them, but you might want to double-check
  mtn: their key's fingerprint: 8c0b868f2247215c63c96983b1c8ca0f0f0cfd9a

The fingerprint shown above was the correct one as of March 21, 2013.

To pull further changes, from anywhere in the workspace run these
commands::

  $ mtn pull
  [...]
  $ mtn update
  [summary of changes]

The ``mtn update`` command will give you a summary of which files
changed; to view the full changelog, run ``mtn log``.
