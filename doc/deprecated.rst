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

- Block ciphers CAST-256, GOST 28147, Kasumi, MISTY1, DESX, XTEA, Noekeon

- Hash functions GOST 34.11-94, Tiger, MD4

- X9.42 KDF

- DLIES

- MCEIES

- CBC-MAC

- PBKDF1 key derivation

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

- All or nothing package transform (``package.h``)


Deprecated Headers
^^^^^^^^^^^^^^^^^^^^^^

* The following headers and all functionality contained within them
  are outright deprecated, and will be removed entirely in a future
  major release. Most are either simply forwarding includes to another
  (still public) header, or contain functionality which is entirely
  deprecated. Consult the relevent file for more information.
  ``basefilt.h``, ``botan.h``, ``buf_filt.h``, ``cipher_filter.h``, ``comp_filter.h``,
  ``compiler.h``, ``init.h``, ``key_filt.h``, ``lookup.h``, ``sm2_enc.h``, ``threefish.h``,
  ``xmss_key_pair.h``

* The following headers have useful functionality but which we wish to
  hide from applications to allow easier library evolution. They will
  be made internal in a future major release, and will only be
  available to the library itself. In most cases, there is an
  alternative available. For example instead of using algorithm
  specific interfaces, use X::create to create the object dynamically.

  Block cipher headers (interact using BlockCipher interface):
  ``aes.h``,
  ``aria.h``,
  ``blowfish.h``,
  ``camellia.h``,
  ``cascade.h``,
  ``cast128.h``,
  ``cast256.h``,
  ``des.h``,
  ``desx.h``,
  ``gost_28147.h``,
  ``idea.h``,
  ``kasumi.h``,
  ``lion.h``,
  ``misty1.h``,
  ``noekeon.h``,
  ``seed.h``,
  ``serpent.h``,
  ``shacal2.h``,
  ``sm4.h``,
  ``threefish_512.h``,
  ``twofish.h``,
  ``xtea.h``,

  Hash function headers (interact using HashFunction interface):
  ``adler32.h``,
  ``blake2b.h``,
  ``comb4p.h``,
  ``crc24.h``,
  ``crc32.h``,
  ``gost_3411.h``,
  ``keccak.h``,
  ``md4.h``,
  ``md5.h``,
  ``par_hash.h``,
  ``rmd160.h``,
  ``sha160.h``,
  ``sha2_32.h``,
  ``sha2_64.h``,
  ``sha3.h``,
  ``shake.h``,
  ``skein_512.h``,
  ``sm3.h``,
  ``streebog.h``,
  ``tiger.h``,
  ``whrlpool.h``,

  MAC headers:
  ``cbc_mac.h``,
  ``cmac.h``,
  ``gmac.h``,
  ``hmac.h``,
  ``poly1305.h``,
  ``siphash.h``,
  ``x919_mac.h``,

  Stream cipher headers:
  ``chacha.h``,
  ``ctr.h``,
  ``ofb.h``,
  ``rc4.h``,
  ``salsa20.h``,

  Cipher mode headers:
  ``cbc.h``,
  ``ccm.h``,
  ``cfb.h``,
  ``chacha20poly1305.h``,
  ``eax.h``,
  ``gcm.h``,
  ``ocb.h``,
  ``shake_cipher.h``,
  ``siv.h``,
  ``xts.h``,

  KDF headers:
  ``hkdf.h``,
  ``kdf1.h``,
  ``kdf1_iso18033.h``,
  ``kdf2.h``,
  ``prf_tls.h``,
  ``prf_x942.h``,
  ``sp800_108.h``,
  ``sp800_56a.h``,
  ``sp800_56c.h``,

  PBKDF headers:
  ``bcrypt_pbkdf.h``,
  ``pbkdf1.h``,
  ``pbkdf2.h``,
  ``pgp_s2k.h``,
  ``scrypt.h``,

  Internal implementation headers - seemingly no reason for applications to use:
  ``blinding.h``,
  ``curve_gfp.h``,
  ``curve_nistp.h``,
  ``datastor.h``,
  ``divide.h``,
  ``eme.h``,
  ``eme_pkcs.h``,
  ``eme_raw.h``,
  ``emsa.h``,
  ``emsa1.h``,
  ``emsa_pkcs1.h``,
  ``emsa_raw.h``,
  ``emsa_x931.h``,
  ``gf2m_small_m.h``,
  ``ghash.h``,
  ``iso9796.h``,
  ``keypair.h``,
  ``mdx_hash.h``,
  ``mode_pad.h``,
  ``mul128.h``,
  ``oaep.h``,
  ``pbes2.h``,
  ``polyn_gf2m.h``,
  ``pow_mod.h``,
  ``pssr.h``,
  ``reducer.h``,
  ``rfc6979.h``,
  ``scan_name.h``,
  ``stream_mode.h``,
  ``tls_algos.h``,
  ``tls_magic.h``,
  ``xmss_common_ops.h``,
  ``xmss_hash.h``,
  ``xmss_index_registry.h``,
  ``xmss_tools.h``,

  Utility headers, nominally useful in applications but not a core part of
  the library API and most are just sufficient for what the library needs
  to implement other functionality.
  ``atomic.h``,
  ``bswap.h``,
  ``charset.h``,
  ``compiler.h``,
  ``cpuid.h``,
  ``http_util.h``,
  ``loadstor.h``,
  ``locking_allocator.h``,
  ``parsing.h``,
  ``rotate.h``,
  ``secqueue.h``,
  ``stl_compatibility.h``,
  ``uuid.h``,

  Merged into other headers:
  ``alg_id.h``, ``asn1_oid.h``, ``asn1_str.h``, and ``asn1_time.h`` - use ``asn1_obj.h``

Other API deprecations
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- Directly accessing the member variables of types ``calendar_point``,
  ``ASN1_Attribute``, ``AlgorithmIdentifier``, and ``BER_Object``

- Using a default output length for "SHAKE-128" and "SHAKE-256". Instead,
  always specify the desired output length.

- Currently, for certain KDFs, if KDF interface is invoked with a
  requested output length larger than supported by the KDF, it returns
  instead a truncated key. In a future major release, instead if KDF
  is called with a length larger than it supports an exception will be
  thrown.

- The TLS constructors taking ``std::function`` for callbacks. Instead
  use the ``TLS::Callbacks`` interface.

- Using ``X509_Certificate::subject_info`` and ``issuer_info`` to access any
  information that is not included in the DN or subject alternative name. Prefer
  using the specific assessor functions for other data, eg instead of
  ``cert.subject_info("X509.Certificate.serial")`` use ``cert.serial_number()``.

- The ``Buffered_Computation`` base class. In a future release the
  class will be removed, and all of member functions instead declared
  directly on ``MessageAuthenticationCode`` and ``HashFunction``. So
  this only affects you if you are directly referencing
  ``Botan::Buffered_Computation`` in some way.

Deprecated Build Targets
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- Configuring a build (with ``configure.py``) using Python2. In a future
  major release, Python3 will be required.

- Platform support for Google Native Client

- Support for PathScale and HP compilers
