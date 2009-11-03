Botan 1.8.8 2009-11-03

Botan is a C++ class library for performing a wide variety of
cryptographic operations.

I consider this release the best version available, and recommend all
users upgrade from 1.6 or earlier versions as soon as possible. Some
APIs have changed incompatibly since the 1.6 release series, but most
applications should work as-is or with only simple modifications.

Botan is under a BSD-like license, the details of which can be found
in license.txt. More information about the authors and contributors
can be found in credits.txt and thanks.txt. All of these files are
included in the doc/ directory of the source distribution.

You can file bugs in Bugzilla, which can be accessed at
  http://www.randombit.net/bugzilla/
or by sending a report to the botan-devel mailing list
  http://lists.randombit.net/mailman/listinfo/botan-devel/

In the doc directory, there should be a set of PDFs, including

building.pdf - build instructions
api.pdf - the API reference manual
tutorial.pdf - a set of simple examples and tutorials

A set of example programs can be found in the doc/examples directory.

Some higher level cryptographic protocols are implemented using
Botan in:

- NetSieben SSH Library (SSHv2)
    http://www.netsieben.com/products/ssh/
- Ajisai (SSLv3/TLSv1)
    http://www.randombit.net/code/ajisai/

Check the project's website at http://botan.randombit.net/ for
announcements and new releases. If you'll be developing code using
this library, consider joining the mailing lists to keep up to date
with changes and new releases.

As always, feel free to contact me with any questions or comments.

-Jack Lloyd (lloyd@randombit.net)
