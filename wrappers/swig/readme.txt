This is the beginning of an attempt to SWIG-ify Botan so it can be accessed by
other languages. You should use the latest SWIG 1.3 release (I am currently
using SWIG 1.3.19). Currently I am only testing this code with Python 2.2.1,
since that is the language I am mainly interested in at this point. Feel free
to send me patches so this is usable with Perl or whatever.

I'm not attempting to make everything in Botan usable from a script -
basically, I just want the parts that *I* want to use. Most things are not
supported yet, and there are lots of bugs in the stuff that does exist. If
there is something in particular that you would like to be able to use from a
script, let me know (patches are good, too).

Todo:
  * Why does it seg fault if we don't create a LibraryInitializer. It should
    throw an exception, like it does in C++. Maybe have it init Botan when the
    module is loaded? That seems a lot cleaner/nicer, but I don't know how to
    do it yet.
  * Lots of problems with exceptions
  * Use constraints to prevent bad args when possible
  * Pipe/Filter
     - Better argument processing for all filters
     - Support for ciphers, MACs, etc
     - Chain + Fork
     - Support for append/prepend/pop/reset in Pipe?
  * Public Key Crypto
     - RSA
     - DSA
     - DH
     - Generic X.509 and PKCS #8 stuff
  * PKI
     - X.509 certs + CRLs
     - PKCS #10 requests
     - X.509 stores
     - X.509 CA
