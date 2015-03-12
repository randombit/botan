Botan Crypto Library
========================================

.. image:: https://travis-ci.org/neusdan/botan.svg?branch=net.randombit.botan
    :target: https://travis-ci.org/neusdan/botan

Botan is a C++11 library for crypto and TLS released under the permissive
2-clause BSD license (see ``doc/license.txt`` for the specifics).

For full instructions on building the library, read
``doc/manual/building.rst``, but basically::

  $ configure.py --help
  $ configure.py [probably some options]
  $ make
  $ ./botan-test
  # test output
  $ ./botan
  # shows available commands
  $ make install

You can file bugs in `GitHub Issues
<https://github.com/randombit/botan/issues/>`_ or by sending a
report to the `botan-devel mailing list
<http://lists.randombit.net/mailman/listinfo/botan-devel/>`_

The `github wiki <https://github.com/randombit/botan/wiki>`_
is also available as a resource.
