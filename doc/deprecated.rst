Deprecated Features
========================

Certain functionality is deprecated and is likely to be removed in
a future major release.

To help warn users, macros are used to annotate deprecated functions
and headers. These warnings are enabled by default, but can be
disabled by defining the macro ``BOTAN_NO_DEPRECATED_WARNINGS`` prior
to including any Botan headers.

.. warning::
    Not all of the functionality which is currently deprecated has an
    associated warning.

If you are using something which is currently deprecated and there
doesn't seem to be an obvious alternative, contact the developers to
explain your use case if you want to make sure your code continues to
work.

TLS Protocol Deprecations
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following TLS protocol features are deprecated and will be removed
in a future major release:

- Support for TLSv1.0/v1.1 and DTLS v1.0

- All support for DSA ciphersuites/certificates

- Support for point compression in TLS. This is supported in v1.2 but
  removed in v1.3. For simplicity it will be removed in v1.2 also.

- Support for using SHA-1 to sign TLS v1.2 ServerKeyExchange.

- All CBC mode ciphersuites. This includes all available 3DES and SEED
  ciphersuites. This implies also removing Encrypt-then-MAC extension.

- All ciphersuites using DH key exchange (DHE-DSS, DHE-RSA, DHE-PSK, anon DH)

- Support for renegotiation in TLS v1.2

- All ciphersuites using static RSA key exchange

- All anonymous (DH/ECDH) ciphersuites. This does not include PSK and
  ECDHE-PSK, which will be retained.

- SRP ciphersuites. This is implied by the removal of CBC mode, since
  all available SRP ciphersuites use CBC. To avoid use of obsolete
  ciphers, it would be better to instead perform a standard TLS
  negotiation, then a PAKE authentication within (and bound to) the
  TLS channel.

- OCB ciphersuites using 128-bit keys

Deprecated Functionality
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This section lists cryptographic functionality which will be removed
in a future major release.

- Block cipher GOST 28147

- Hash function GOST 34.11-94

- DLIES

- GCM support for 64-bit tags

- Weak or rarely used ECC builtin groups including "secp160k1", "secp160r1",
  "secp160r2", "secp192k1", "secp224k1",
  "brainpool160r1", "brainpool192r1", "brainpool224r1", "brainpool320r1",
  "x962_p192v2", "x962_p192v3", "x962_p239v1", "x962_p239v2", "x962_p239v3".

- All built in MODP groups < 2048 bits

- Support for explicit ECC curve parameters and ImplicitCA encoded parameters in
  EC_Group and all users (including X.509 certificates and PKCS#8 private keys).

- All pre-created DSA groups

- All support for loading, generating or using RSA keys with a public
  exponent larger than 2**64-1

Deprecated Headers
^^^^^^^^^^^^^^^^^^^^^^

  PBKDF headers:
  ``bcrypt_pbkdf.h``,
  ``pbkdf1.h``,
  ``pbkdf2.h``,
  ``pgp_s2k.h``,
  ``scrypt.h``,

  Internal implementation headers - seemingly no reason for applications to use:
  ``curve_gfp.h``,
  ``mdx_hash.h``,
  ``polyn_gf2m.h``,
  ``reducer.h``,
  ``scan_name.h``,
  ``tls_algos.h``,
  ``tls_magic.h``,
  ``xmss_hash.h``,

  Utility headers, nominally useful in applications but not a core part of
  the library API and most are just sufficient for what the library needs
  to implement other functionality.
  ``compiler.h``,
  ``cpuid.h``,
  ``http_util.h``,
  ``uuid.h``,

Other API deprecations
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- Currently, for certain KDFs, if KDF interface is invoked with a
  requested output length larger than supported by the KDF, it returns
  instead a truncated key. In a future major release, instead if KDF
  is called with a length larger than it supports an exception will be
  thrown.

- The TLS constructors taking ``std::function`` for callbacks. Instead
  use the ``TLS::Callbacks`` interface.

- The ``Buffered_Computation`` base class. In a future release the
  class will be removed, and all of member functions instead declared
  directly on ``MessageAuthenticationCode`` and ``HashFunction``. So
  this only affects you if you are directly referencing
  ``Botan::Buffered_Computation`` in some way.

Deprecated Build Targets
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- Configuring a build (with ``configure.py``) using Python2. In a future
  major release, Python3 will be required.
