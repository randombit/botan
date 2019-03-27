Deprecated Features
========================

The following functionality is currently deprecated, and will likely
be removed in a future release. If you think you have a good reason to
be using one of the following, contact the developers to explain your
use case if you want to make sure your code continues to work.

This is in addition to specific API calls marked with BOTAN_DEPRECATED
in the source.

- Directly using an algorithm class like ``AES_128`` or ``SHA_256``. Instead
  create the objects via a ``T::create`` call.

- Directly accessing the member variables of types calendar_point, ASN1_Attribute,
  AlgorithmIdentifier, and BER_Object

- The headers ``botan.h``, ``init.h``, ``lookup.h``, ``threefish.h``, ``sm2_enc.h``

- Using a default output length for "SHAKE-128" and "SHAKE-256". Instead,
  always specify the desired output length.

- All or nothing package transform (``package.h``)

- The TLS constructors taking `std::function` for callbacks. Instead
  use the TLS::Callbacks interface.

- Using ``X509_Certificate::subject_info`` and ``issuer_info`` to access any
  information that is not included in the DN or subject alternative name. Prefer
  using the specific assessor functions for other data, eg instead of
  ``cert.subject_info("X509.Certificate.serial")`` use ``cert.serial_number()``.

- The Buffered_Computation base class. In a future release the class will be
  removed, and all of member functions instead declared directly on
  MessageAuthenticationCode and HashFunction. So this only affects you if you
  are directly referencing `Botan::Buffered_Computation` in some way.

- Platform support for Google Native Client

- Support for PathScale and HP compilers

- Block ciphers CAST-256, Kasumi, MISTY1, and DESX.

- CBC-MAC

- PBKDF1 key derivation

- GCM support for 64-bit tags

- Weak or rarely used ECC builtin groups including "secp160k1", "secp160r1",
  "secp160r2", "secp192k1", "secp192r1", "secp224k1", "secp224r1",
  "brainpool160r1", "brainpool192r1", "brainpool224r1", "brainpool320r1",
  "x962_p192v2", "x962_p192v3", "x962_p239v1", "x962_p239v2", "x962_p239v3".

- All built in MODP groups < 2048 bits

- All pre-created DSA groups

TLS Protocol Deprecations
---------------------------

The following TLS protocol features are deprecated and will be removed
in a future major release:

- Support for TLSv1.0/v1.1 and DTLS v1.0

- All support for DSA ciphersuites/certificates

- All CBC mode ciphersuites. This includes all available 3DES and SEED
  ciphersuites. This implies also removing Encrypt-then-MAC extension.

- All ciphersuites using DH key exchange (DHE-DSS, DHE-RSA, DHE-PSK, anon DH)

- All ciphersuites using static RSA key exchange

- All anonymous (DH/ECDH) ciphersuites. This does not include PSK and
  ECDHE-PSK, which will be retained.

- SRP ciphersuites. This is implied by the removal of CBC mode, since
  all available SRP ciphersuites use CBC. To avoid use of obsolete
  ciphers, it would be better to instead perform a standard TLS
  negotiation, then a PAKE authentication within (and bound to) the
  TLS channel.

- OCB ciphersuites using 128-bit keys
