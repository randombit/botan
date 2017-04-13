Botan: Crypto and TLS for C++11
========================================

The `German Federal Office for Information Security (BSI) <https://www.bsi.bund.de/EN/>`_
carried out a project "Secure Implementation of a Universal Crypto Library"
in which it analyzed open source cryptographic libraries and developed a secure
cryptographic library based on the `Botan <https://botan.randombit.org>`_ cryptographic library.
Botan 2.0 satisfies the basic requirements of the BSI and
its use is recommended in security products. The library includes all algorithms 
recommended by BSI technical guidelines `02102-1 <https://www.bsi.bund.de/DE/Publikationen/TechnischeRichtlinien/tr02102/index_htm.html>`_,
`02102-2 <https://www.bsi.bund.de/DE/Publikationen/TechnischeRichtlinien/tr02102/index_htm.html>`_ and `03111 <https://www.bsi.bund.de/DE/Publikationen/TechnischeRichtlinien/tr03111/index_htm.html>`_.
Botan is licensed under the Simplified BSD license and can therefore be freely 
used in open source as well as commercial software.

This repository contains versions of Botan that are approved by the BSI. All changes made
to Botan during the project were contributed to the original project. Our goal is to keep 
this fork in sync with the official repository, but we cannot assure this. In case an approved
version differs from an official Botan version, the changes are listed in the `release notes <news.rst>`_.

Versioning
----------------------------------------

The versioning scheme used here is based on that of the
`original project <https://botan.randombit.net/manual/versions.html>`_. In case
there are differences between an official release version and an approved version,
the approved version number will contain the original version it is based on followed by
a `RSCSN` suffix. For example, the version 2.0.1-RSCS1 is based on the official
Botan version 2.0.1, but contains additional changes that are not part of 2.0.1
(but may be part of a to-be-released version 2.1.0).
New Botan releases will be audited every 3-6 months and cryptographically relevant
changes will be checked and documented. Provided that the official version 2.1.0 will be approved
by the BSI, this version will finally be announced here.

Release Downloads
----------------------------------------

All approved releases are signed with a PGP key.

Key will be announced here shortly.

Support & Maintenance
----------------------------------------

If you need help with a problem, please `open an issue <https://github.com/randombit/botan/issues/new>`_
at the offical GitHub repository. In case you want to contribute some changes, please also
`contribute <https://github.com/randombit/botan/compare>`_ them to the official Botan repository.

BSI Compliant Usage of Botan
----------------------------------------

Botan contains a `BSI module policy <src/build-data/policy/bsi.txt>`_ which includes all algorithms recommended by BSI
technical guidelines and prohibits alternative algorithms.
To configure Botan with the BSI policy::

  $ ./configure.py --module-policy=bsi

Additional modules which are not automatically enabled by the BSI policy
can be enabled manually using `--enable-modules`, for example::

  $ ./configure.py --module-policy=bsi --enable-modules=tls,ffi,x509,xts

TLS
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Botan contains a TLS Policy class `BSI_TR_02102_2 <src/lib/tls/tls_policy.h>`_ that only allows the algorithms recommended in
BSI technical guideline `02102-2 <https://www.bsi.bund.de/DE/Publikationen/TechnischeRichtlinien/tr02102/index_htm.html>`_.
This policy can be passed whereever a ``TLS_Policy`` reference is accepted by the API.
For more information, see the `handbook <https://botan.randombit.net/manual/tls.html>`_.


Random Number Generation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Botan contains an implementation of `NIST SP 800-90A <http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf>`_'s `HMAC_DRBG <src/lib/rng/hmac_drbg.h>`_.
The parameters reseed interval, maximum number of bytes per request and the entropy source(s) for
seeding and reseeding can be configured per ``HMAC_DRBG`` instance. For example,
a ``PKCS11_RNG`` can be used as an entropy source::

  Botan::PKCS11::PKCS11_RNG p11_rng(session);
  Botan::HMAC_DRBG drbg(Botan::MessageAuthenticationCode::create("HMAC(SHA-512)"), p11_rng);

``HMAC_DRBG`` will automatically reseed whenever the reseed interval or maximum number
of bytes per request are exceeded. On platforms which support ``fork()``, it will also
automatically reseed after a fork. For more information, see the `handbook <https://botan.randombit.net/manual/rng.html>`_.

