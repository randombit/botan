Botan Crypto Library
========================================

.. image:: https://ci.appveyor.com/api/projects/status/5t1osr48aq000yri?svg=true
    :target: https://ci.appveyor.com/project/neusdan/botan


Botan is a C++11 library for crypto and TLS released under the permissive
2-clause BSD license (see ``doc/license.txt`` for the specifics).

.. image:: https://travis-ci.org/randombit/botan.svg?branch=net.randombit.botan
    :target: https://travis-ci.org/randombit/botan

In addition to Travis CI, Kullo GmbH hosts a CI building botan on
Linux, OS X, and Windows at https://botan-ci.kullo.net/

For all the details on building the library read ``doc/manual/building.rst``,
but basically::

  $ configure.py --help
  $ configure.py [probably some options]
  $ make
  $ ./botan-test
  # test output
  $ ./botan
  # shows available commands
  $ make install

You can file bugs at https://github.com/randombit/botan/issues/
or by sending a report to the `botan-devel mailing list
<http://lists.randombit.net/mailman/listinfo/botan-devel/>`_

The `github wiki <https://github.com/randombit/botan/wiki>`_
is also available as a resource.
