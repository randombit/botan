
This package contains a program to exercise Botan's path validation
algorithm, as contained in the X509_Store object. The data used is
NIST's X.509v3 certificate path validation testing data, as found on
NIST's web site (version 1.0.7 of the testing data is currently
used). The PKCS #7 and PKCS #12 data files have been removed, as they
are not used in this test.

Currently, some tests fail or are not be run for various reasons (in
particular, we don't have support policy extensions yet, so that
excludes running a good number of the tests). Even if all of the tests
DO pass, that does not imply that Botan's path validation and
certificate processing code is bug free, as there are many (*very
many*) possible options in X.509 which this testing data does not make
use of at all. However, it is helpful for implementation testing and
assurance (I have found a good number of bugs using these tests).

Currently, we do not make use of the S/MIME or PKCS #12 testing data
contained in these tests, because Botan does not support either of
these standards.

To use this, compile x509test.cpp, and run the resulting
executable. The results are written to standard output. Your system
must have a POSIX.1 dirent.h, and the code assumes Unix-style paths.

Email me with any questions or comments about these tests.
