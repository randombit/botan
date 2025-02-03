=================================
Public Key Cryptography
=================================

Public key cryptography is a collection of techniques allowing for encryption,
signatures, and key agreement.

Key Objects
----------------------------------------

Public and private keys are represented by classes ``Public_Key`` and
``Private_Key``. Both derive from ``Asymmetric_Key``.

Currently there is an inheritance relationship between ``Private_Key`` and
``Public_Key``, so that a private key can also be used as the corresponding
public key. It is best to avoid relying on this, as this inheritance will be
removed in a future major release.

.. cpp:class:: Asymmetric_Key

  .. cpp:function:: std::string algo_name()

     Return a short string identifying the algorithm of this key,
     eg "RSA" or "ML-DSA".

  .. cpp:function:: size_t estimated_strength() const

     Return an estimate of the strength of this key, in terms of brute force
     key search. For example if this function returns 128, then it is is
     estimated to be roughly as difficult to crack as AES-128.

  .. cpp:function:: OID object_identifier() const

     Return an object identifier which can be used to identify this
     type of key.

  .. cpp:function:: bool supports_operation(PublicKeyOperation op) const

     Check if this key could be used for the queried operation type.

.. cpp:class:: Public_Key

   .. cpp:function:: size_t key_length() const = 0;

      Return an integer value that most accurately captures for the security
      level of the key. For example for RSA this returns the length of the
      public modules, while for ECDSA keys it returns the size of the elliptic
      curve group.

   .. cpp:function:: bool check_key(RandomNumberGenerator& rng, bool strong) const = 0;

      Check if the key seems to be valid. If *strong* is set to true then more
      expensive tests are performed.

   .. cpp:function:: AlgorithmIdentifier algorithm_identifier() const = 0;

      Return an X.509 algorithm identifier that can be used to identify the key.

   .. cpp:function:: std::vector<uint8_t> public_key_bits() const = 0;

      Returns a binary representation of the public key. Typically this is a
      BER encoded structure that includes metadata like the algorithm and
      parameter set used to generate the key.

      Note that pre-standard post-quantum algorithms of the NIST competition
      (e.g. Kyber, Dilithium, FrodoKEM, etc) do not have a standardized BER
      encoding, yet. For the time being, the raw public key bits are returned
      for these algorithms. That might change as the standards evolve.

   .. cpp:function:: std::vector<uint8_t> raw_public_key_bits() const = 0;

      Returns a binary representation of the public key's canonical structure.
      Typically, this does not include any metadata like an algorithm identifier
      or parameter set. Note that some schemes (e.g. RSA) do not know such "raw"
      canonical structure and therefore throw `Not_Implemented`.
      For key agreement algorithms, this is the canonical public value of the
      scheme.

      Decoding the resulting raw bytes typically requires knowledge of the
      algorithm and parameters used to generate the key.

   .. cpp:function:: std::vector<uint8_t> subject_public_key() const;

      Return the X.509 ``SubjectPublicKeyInfo`` encoding of this key. See
      :rfc:`5280` for details.

   .. cpp:function:: std::string fingerprint_public(const std::string& alg = "SHA-256") const;

      Return a hashed fingerprint of this public key.

.. cpp:class:: Private_Key

   .. cpp:function:: std::unique_ptr<Public_Key> public_key() const

      Return an object containing the public key corresponding to this private key.

      Prefer this over the (deprecated) implicit conversion of a private key to
      a public key currently possible due to an inheritence relation.

   .. cpp:function:: secure_vector<uint8_t> private_key_info() const

      Return the key encoded as a PKCS #8 `PrivateKeyInfo` structure. See
      :rfc:`5208` for details.

      Further functions relating to encoding and encrypting PKCS #8 private are
      detailed in :ref:`serializing_private_keys`.

   .. cpp:function:: secure_vector<uint8_t> private_key_bits() const

      Return the serialization of the private key, cooresponding to the
      `PrivateKey` field of a PKCS #8 `PrivateKeyInfo` structure. See
      :rfc:`5208` for details.

   .. cpp:function:: bool stateful_operation() const;

      Returns true if this keys operation is stateful, that is if updating the
      key is required after each private operation. Currently the only stateful
      schemes included are XMSS and LMS.

   .. cpp:function:: std::optional<uint64_t> remaining_operations() const

      If this algorithm is stateful, returns the number of private operations
      remaining before this key is exhausted. Returns `nullopt` if the key is
      not stateful.

Public Key Algorithms
------------------------

Botan includes a number of public key algorithms, some of which are in common
use, others only used in specialized or niche applications.

RSA
~~~~~~

Based on the difficulty of factoring. Usable for encryption, signatures, and key encapsulation.

ECDSA
~~~~~~

Fast signature scheme based on elliptic curves.

ECDH, DH, X25519 and X448
~~~~~~~~~~~~~~~~~~~~~~~~~

Key agreement schemes. DH uses arithmetic over finite fields and is slower and
with larger keys. ECDH, X25519 and X448 use elliptic curves instead.

ML-DSA (FIPS 204)
~~~~~~~~~~~~~~~~~

Post-quantum secure signature scheme based on (structured) lattices.
This algorithm is standardized in FIPS 204. Signing keys are always stored and
expanded from the 32-byte private random seed (`xi`), loading the expanded key
format specified in FIPS 204 is explicitly not supported.

Support for ML-DSA is implemented in the module ``ml_dsa``

Additionally, support for the pre-standardized version "Dilithium" is retained
for the time being. The implemented specification is commonly referred to as
version 3.1 of the CRYSTALS-Dilithium submission to NIST's third round of the
PQC competition. This is not compatible to the "Initial Public Draft" version of
FIPS 204 for which Botan does not offer an implementation.

Currently two flavors of Dilithium are implemented in separate Botan modules:

 * ``dilithium``, that uses Keccak (SHAKE), and that saw some public usage
   by early adopters.
 * ``dilithium_aes``, that uses AES instead of Keccak-based primitives.
   This mode is deprecated and will be removed in a future release.

ML-KEM (FIPS 203)
~~~~~~~~~~~~~~~~~

Post-quantum key encapsulation scheme based on (structured) lattices. This
algorithm is standardized in FIPS 203. Decapsulation keys are always stored and
expanded from the 64-byte private random seeds (``d || z``), loading the
expanded key format specified in FIPS 203 is explicitly not supported.

Support for ML-KEM is implemented in the module ``ml_kem``.

Additionally, support for the pre-standardized version "Kyber" is retained for
the time being. The implemented specification is commonly referred to as version
3.01 of the CRYSTALS-Kyber submission to NIST's third round of the PQC
competition. This is not compatible to the "Initial Public Draft" version of
FIPS 203 for which Botan does not offer an implementation.

Currently two flavors of Kyber are implemented in separate Botan modules:

 * ``kyber``, that uses Keccak (SHAKE and SHA-3), and that saw some public
   usage by early adopters.
 * ``kyber_90s``, that uses AES/SHA-2 instead of Keccak-based primitives.
   This mode is deprecated and will be removed in a future release.

Ed25519 and Ed448
~~~~~~~~~~~~~~~~~

Signature schemes based on a specific elliptic curve.

XMSS
~~~~~~~~~

A post-quantum secure signature scheme whose security is based (only) on the
security of a hash function. Unfortunately XMSS is stateful, meaning the private
key changes with each signature, and only a certain pre-specified number of
signatures can be created. If the same state is ever used to generate two
signatures, then the whole scheme becomes insecure, and signatures can be
forged.

HSS-LMS
~~~~~~~

A post-quantum secure hash-based signature scheme similar to XMSS. Contains
support for multitrees. It is stateful, meaning the private key changes after
each signature. If the same state is ever used to generate two signatures, then
the whole scheme becomes insecure, and signatures can be forged.

SLH-DSA (FIPS 205)
~~~~~~~~~~~~~~~~~~

The Stateless Hash-Based Digital Signature Standard (SLH-DSA)
is the FIPS 205 post-quantum secure signature scheme whose security is solely
based on the security of a hash function. Unlike XMSS, it is a stateless
signature scheme, meaning that the private key does not change with each
signature. It has high security but very long signatures and high runtime.

Support for SLH-DSA is implemented in the modules ``slh_dsa_sha2`` and ``slh_dsa_shake``.

Additionally, support for the pre-standardized version "SPHINCS+" is retained
for the time being. The implemented specification is commonly referred to as
version 3.1 of the SPHINCS+ submission to NIST's third round of the
PQC competition. This is not compatible with the "Initial Public Draft" version of
FIPS 205 for which Botan does not offer an implementation. Also, Botan does not
support the Haraka hash function.

Currently, two flavors of SPHINCS+ are implemented in separate Botan modules:

 * ``sphincsplus_shake``, that uses Keccak (SHAKE) hash functions
 * ``sphincsplus_sha2``, that uses SHA-256

FrodoKEM
~~~~~~~~

A post-quantum secure key encapsulation scheme based on (unstructured) lattices.

McEliece
~~~~~~~~~~

.. deprecated:: 3.0.0

Post-quantum secure key encapsulation scheme based on the hardness of certain
decoding problems. Deprecated; use Classic McEliece

Classic McEliece
~~~~~~~~~~~~~~~~

Post-quantum secure, code-based key encapsulation scheme.

ElGamal
~~~~~~~~

Encryption scheme based on the discrete logarithm problem. Generally unused
except in PGP.

DSA
~~~~

.. deprecated:: 3.7.0

Finite field based signature scheme. A NIST standard but now quite obsolete.

ECGDSA, ECKCDSA, SM2, GOST-34.10
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A set of signature schemes based on elliptic curves. All are national standards
in their respective countries (Germany, South Korea, China, and Russia, resp),
and are completely obscure and unused outside of that context.

GOST-34.10 support is deprecated.

.. _creating_new_private_keys:

Creating New Private Keys
----------------------------------------

Creating a new private key requires two things: a source of random numbers (see
:ref:`random_number_generators`) and potentially some algorithm specific
parameters.

Generic Method
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There is a generic method which can create keys of any algorithm type, defined
in ``pk_algs.h``

.. cpp:function:: std::unique_ptr<Private_Key> create_private_key(std::string_view algo, \
                                                RandomNumberGenerator& rng, \
                                                std::string_view params)

    Examples of algorithm/parameter pairs that can be provided here:

    * "RSA" / "3072"
    * "ECDSA" / "secp256r1"
    * "Ed5519" / ""
    * "ML-KEM" / "ML-KEM-768"
    * "DH" / "modp/ietf/2048"

    If *params* is left empty then a suitable algorithm-specific default
    will be chosen. This default may change from release to release, but
    generally tries to reflect a conservative setting.

Creating A New RSA Private Key
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. cpp:function:: RSA_PrivateKey::RSA_PrivateKey(RandomNumberGenerator& rng, size_t bits)

  A constructor that creates a new random RSA private key with a modulus
  of length *bits*.

  RSA key generation is relatively slow, and can take an unpredictable
  amount of time. Generating a 2048 bit RSA key might take 5 to 10
  seconds on a slow machine like a Raspberry Pi 2. Even on a fast
  desktop it might take up to half a second. In a GUI blocking for
  that long can be a problem. The usual approach is to perform key
  generation in a new thread, with a animated modal UI element so the
  user knows the application is still alive. If you wish to provide a
  progress estimate things get a bit complicated but some library
  users documented their approach in
  `a blog post <https://medium.com/nexenio/indicating-progress-of-rsa-key-pair-generation-the-practical-approach-a049ba829dbe>`_.

Creating A New EC Private Key
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For a few schemes, the curve and signature scheme come as a package, and there
are no extra parameters:

.. cpp:function:: Ed25519_PrivateKey::Ed25519_PrivateKey(RandomNumberGenerator& rng)

   Generate a new Ed25519 private key

.. cpp:function:: Ed448_PrivateKey::Ed448_PrivateKey(RandomNumberGenerator& rng)

   Generate a new Ed448 private key

.. cpp:function:: X25519_PrivateKey::X25519_PrivateKey(RandomNumberGenerator& rng)

   Generate a new X25519 private key

.. cpp:function:: X448_PrivateKey::X448_PrivateKey(RandomNumberGenerator& rng)

   Generate a new X448 private key

Others require additionally specfiying which curve to use. First create a
relevant :cpp:class:`EC_Group` using for example :cpp:func:`EC_Group::from_name`
or :cpp:func:`EC_Group::from_OID`. Then pass it to the private key
constructor. If the choice of group is not otherwise mandated by your
application, use "secp256r1" (aka P-256) or "secp384r1" (aka P-384) as they are
fastest, widely implemented, and considered secure.

.. cpp:function:: ECDH_PrivateKey::ECDH_PrivateKey(RandomNumberGenerator& rng, const EC_Group& group)

   Generate a new ECDH private key

.. cpp:function:: ECDSA_PrivateKey::ECDSA_PrivateKey(RandomNumberGenerator& rng, const EC_Group& group)

   Generate a new ECDSA private key

.. cpp:function:: ECKCDSA_PrivateKey::ECKCDSA_PrivateKey(RandomNumberGenerator& rng, const EC_Group& group)

   Generate a new ECKCDSA private key

.. cpp:function:: ECGDSA_PrivateKey::ECGDSA_PrivateKey(RandomNumberGenerator& rng, const EC_Group& group)

   Generate a new ECGDSA private key

.. cpp:function:: GOST_3410_PrivateKey::GOST_3410_PrivateKey(RandomNumberGenerator& rng, const EC_Group& group)

   Generate a new GOST-34.10 private key

.. cpp:function:: SM2_PrivateKey::SM2_PrivateKey(RandomNumberGenerator& rng, const EC_Group& group)

   Generate a new SM2 private key

Creating A New Finite Field DL Private Key
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Instead of elliptic curves, some older algorithms are based on the security of
discrete logarithms in the group of integers modulo a prime. For security, these
require much larger keys than elliptic curve schemes, and are typically much slower.

.. warning::

   Avoid such algorithms in new code

.. cpp:function:: DH_PrivateKey::DH_PrivateKey(RandomNumberGenerator& rng, const DL_Group& group)

   Create a new Diffie-Hellman private key. In most protocols that still support
   finite field DH, it is used with a set of pre-created and trusted groups. These
   were specified in :rfc:`3526` and are usually called the IETF MODP groups.

   The MODP groups are built into the library and can be accessed by name for
   example ``DL_Group::from_name("modp/ietf/3072")``, where 3072 refers to the
   number of bits in the prime modulus.

.. cpp:function:: DSA_PrivateKey::DSA_PrivateKey(RandomNumberGenerator& rng, const DL_Group& group)

   Create a new DSA private key. DSA requires groups of a special form. The best way to create
   such a group is to create a new ``DL_Group`` at random for each key, using the "DSA kosherizer"
   algorithm. See :ref:`dl_group` for more information.

.. cpp:function:: ElGamal_PrivateKey::ElGamal_PrivateKey(RandomNumberGenerator& rng, const DL_Group& group)

.. _serializing_private_keys:

Serializing Private Keys Using PKCS #8
----------------------------------------

The standard format for serializing a private key is PKCS #8, the operations
for which are defined in ``pkcs8.h``. It supports both unencrypted and
encrypted storage.

.. cpp:function:: secure_vector<uint8_t> PKCS8::BER_encode(const Private_Key& key, \
   RandomNumberGenerator& rng, const std::string& password, const std::string& pbe_algo = "")

  Takes any private key object, serializes it, encrypts it using
  *password*, and returns a binary structure representing the private
  key.

  The final (optional) argument, *pbe_algo*, specifies a particular
  password based encryption (or PBE) algorithm. If you don't specify a
  PBE, a sensible default will be used.

  The currently supported PBE is PBES2 from PKCS5. Format is as follows:
  ``PBE-PKCS5v20(CIPHER,PBKDF)`` or ``PBES2(CIPHER,PBKDF)``.

  Cipher can be any block cipher using CBC or GCM modes, for example
  "AES-128/CBC" or "Camellia-256/GCM". For best interop with other systems, use
  AES in CBC mode. The PBKDF can be either the name of a hash function (in which
  case PBKDF2 is used with that hash) or "Scrypt", which causes the scrypt
  memory hard password hashing function to be used. Scrypt is supported since
  version 2.7.0.

  Use `PBE-PKCS5v20(AES-256/CBC,SHA-256)` if you want to ensure the keys can
  be imported by different software packages. Use
  `PBE-PKCS5v20(AES-256/GCM,Scrypt)` for best security assuming you do not
  care about interop.

  For ciphers you can use anything which has an OID defined for CBC, GCM or SIV
  modes. Currently this includes AES, Camellia, Serpent, Twofish, and SM4. Most
  other libraries only support CBC mode for private key encryption. GCM has
  been supported in PBES2 since 2.0. SIV has been supported since 2.8.

.. cpp:function:: std::string PKCS8::PEM_encode(const Private_Key& key, \
   RandomNumberGenerator& rng, const std::string& pass, const std::string& pbe_algo = "")

  This formats the key in the same manner as ``BER_encode``, but additionally
  encodes it into a text format with identifying headers. Using PEM encoding
  is *highly* recommended for many reasons, including compatibility with other
  software, for transmission over 8-bit unclean channels, because it can be
  identified by a human without special tools, and because it sometimes allows
  more sane behavior of tools that process the data.

Unencrypted serialization is also supported.

.. warning::

  In most situations, using unencrypted private key storage is a bad idea,
  because anyone can come along and grab the private key without having to
  know any passwords or other secrets. Unless you have very particular
  security requirements, always use the versions that encrypt the key based on
  a passphrase, described above.

.. cpp:function:: secure_vector<uint8_t> PKCS8::BER_encode(const Private_Key& key)

  Serializes the private key and returns the result.

.. cpp:function:: std::string PKCS8::PEM_encode(const Private_Key& key)

  Serializes the private key, base64 encodes it, and returns the
  result.

Last but not least, there are some functions that will load (and
decrypt, if necessary) a PKCS #8 private key:

.. cpp:function:: std::unique_ptr<Private_Key> load_key(DataSource& source, \
                                      std::function<std::string ()> get_passphrase)
.. cpp:function:: std::unique_ptr<Private_Key> load_key(DataSource& source, \
                                      const std::string& pass)
.. cpp:function:: std::unique_ptr<Private_Key> load_key(DataSource& source)

These functions will return an object allocated key object based on the data
from whatever source it is using (assuming, of course, the source is in fact
storing a representation of a private key, and the decryption was
successful). The encoding used (PEM or BER) need not be specified; the format
will be detected automatically. The ``DataSource`` is usually a
``DataSource_Stream`` to read from a file or ``DataSource_Memory`` for an
in-memory buffer.

The versions taking a ``std::string`` attempt to decrypt using the password
given (if the key is encrypted; if it is not, the passphase value will be
ignored). If the passphrase does not decrypt the key, an exception will be
thrown.

.. _serializing_public_keys:

Serializing Public Keys
-----------------------------

To import and export public keys, use:

.. cpp:function:: std::vector<uint8_t> X509::BER_encode(const Public_Key& key)

.. cpp:function:: std::string X509::PEM_encode(const Public_Key& key)

.. cpp:function:: std::unique_ptr<Public_Key> X509::load_key(DataSource& in)

.. cpp:function:: std::unique_ptr<Public_Key> X509::load_key(const secure_vector<uint8_t>& buffer)

.. cpp:function:: std::unique_ptr<Public_Key> X509::load_key(const std::string& filename)

  These functions operate in the same way as the ones described in
  :ref:`serializing_private_keys`, except that no encryption option is
  available.

.. note::

   In versions prior to 3.0, these functions returned a raw pointer instead of a
   ``unique_ptr``.

.. _dl_group:

DL_Group
------------------------------

.. cpp:class:: DL_Group

   Represents parameters for finite field discrete logarithm algorithms

.. cpp:function:: static DL_Group DL_Group::from_name(std::string_view name)

  The name here is a (Botan specific) identifier which maps to one of the
  standard discrete logarithm groups.

  For the groups from :rfc:`5208` (often called the MODP groups, the
  IETF groups, or the IPsec groups) use "modp/ietf/N" where N can be
  any of 1024, 1536, 2048, 3072, 4096, 6144, or 8192. This group type
  is used for Diffie-Hellman and ElGamal algorithms, but *cannot*
  be used with DSA.

  For the groups from :rfc:`7919` (often called the TLS FFDHE groups)
  use "ffdhe/ietf/N" where N is any of 2048, 3072, 4096, 6144, or 8192.
  These groups are typically only used in TLS, but can be used with
  Diffie-Hellman more generally. They *cannot* be used with DSA.

  For the groups from :rfc:`5054` (the SRP6 groups) use "modp/srp/N"
  where N can be any of 1024, 1536, 2048, 3072, 4096, 6144, or 8192.
  These groups *should only be used with SRP6*.

  Finally a small number of pre-created groups usable for DSA are available.
  These are "dsa/jce/1024", "dsa/botan/2048", and "dsa/botan/3072". Support for
  these groups is deprecated and they will be removed in a future major release.
  Should DSA be required, create a new random group for each key.

You can generate a new random group using

.. cpp:function:: DL_Group::DL_Group(RandomNumberGenerator& rng, \
   PrimeType type, size_t pbits, size_t qbits = 0)

  The *type* can be

  * ``Strong``: A group where (p-1)/2 is also prime. Best for Diffie-Hellman,
    but very slow to generate.
  * ``Prime_Subgroup``: A group where (p-1) is divided by a large prime q,
    of size ``qbits``. Faster to generate than ``Strong``, suitable for
    Diffie-Hellman.
  * ``DSA_Kosherizer``: Generate a group suitable for DSA using the
    algorithm specified in FIPS 186-3.

  If *qbits* is set to zero then a suitable value is chosen relative to the
  value of *pbits* and the type of group being created.

You can serialize a ``DL_Group`` using

.. cpp:function:: std::vector<uint8_t> DL_Group::DER_Encode(Format format) const

or

.. cpp:function:: std::string DL_Group::PEM_encode(Format format) const

where *format* is any of

* ``ANSI_X9_42`` (or ``DH_PARAMETERS``) for modp groups
* ``ANSI_X9_57`` (or ``DSA_PARAMETERS``) for DSA-style groups
* ``PKCS_3`` is an older format for modp groups; it should only
  be used for backwards compatibility.

You can reload a serialized group from BER or PEM formats using

.. cpp:function:: DL_Group::DL_Group(std::span<const uint8_t> ber, DL_Group_Format format)

.. cpp:function:: static DL_Group DL_Group::from_pem(std::string_view pem, DL_Group_Format format)

Code Example: DL_Group
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The example below creates a new 2048 bit ``DL_Group``, prints the generated
parameters and ANSI_X9_42 encodes the created group for further usage with DH.

.. literalinclude:: /../src/examples/dl_group.cpp
   :language: cpp


Key Checking
---------------------------------

Most public key algorithms have limitations or restrictions on their
parameters. For example RSA requires an odd exponent, and algorithms
based on the discrete logarithm problem need a generator > 1.

Each public key type has a function

.. cpp:function:: bool Public_Key::check_key(RandomNumberGenerator& rng, bool strong)

  This function performs a number of algorithm-specific tests that the key
  seems to be mathematically valid and consistent, and returns true if all of
  the tests pass.

  It does not have anything to do with the validity of the key for any
  particular use, nor does it have anything to do with certificates that link
  a key (which, after all, is just some numbers) with a user or other
  entity. If *strong* is ``true``, then it does "strong" checking, which
  includes expensive operations like primality checking.

As key checks are not automatically performed they must be called manually after
loading keys from untrusted sources. If a key from an untrusted source is not
checked, the implementation might be vulnerable to algorithm specific attacks.

The following example loads the Subject Public Key from the x509
certificate ``cert.pem`` and checks the loaded key. If the key check
fails a respective error is thrown.

.. literalinclude:: /../src/examples/check_key.cpp
   :language: cpp

Public Key Encryption/Decryption
----------------------------------

Safe public key encryption requires the use of a padding scheme which hides
the underlying mathematical properties of the algorithm.  Additionally, they
will add randomness, so encrypting the same plaintext twice produces two
different ciphertexts.

The primary interface for encryption is

.. cpp:class:: PK_Encryptor

   .. cpp:function:: std::vector<uint8_t> encrypt( \
         const uint8_t in[], size_t length, RandomNumberGenerator& rng) const

   .. cpp:function:: std::vector<uint8_t> encrypt( \
      std::span<const uint8_t> in, RandomNumberGenerator& rng) const

      These encrypt a message, returning the ciphertext.

   .. cpp:function::  size_t maximum_input_size() const

      Returns the maximum size of the message that can be processed, in
      bytes. If you call :cpp:func:`PK_Encryptor::encrypt` with a value larger
      than this the operation will fail with an exception.

   .. cpp:function:: size_t ciphertext_length(size_t ctext_len) const

      Return an upper bound on the returned size of a ciphertext, if this
      particular key/padding scheme is used to encrypt a message of the provided
      length.

:cpp:class:`PK_Encryptor` is only an interface - to actually encrypt you have to
create an implementation, of which there are currently three available in the
library, :cpp:class:`PK_Encryptor_EME`, :cpp:class:`DLIES_Encryptor` and
:cpp:class:`ECIES_Encryptor`. DLIES is a hybrid encryption scheme (from
IEEE 1363) that uses Diffie-Hellman key agreement technique in combination with
a KDF, a MAC and a symmetric encryption algorithm to perform message
encryption. ECIES is similar to DLIES, but uses ECDH for the key
agreement. Normally, public key encryption is done using algorithms which
support it directly, such as RSA or ElGamal; these use the EME class:

.. cpp:class:: PK_Encryptor_EME

   .. cpp:function:: PK_Encryptor_EME(const Public_Key& key, std::string padding)

     With *key* being the key you want to encrypt messages to. The padding
     method to use is specified in *padding*.

     If you are not sure what padding to use, use "OAEP(SHA-256)". If you need
     compatibility with protocols using the PKCS #1 v1.5 standard, you can also
     use "PKCS1v15".

     For SM2 encryption, the padding string specifies which hash function to
     use; normally this would be "SM3".

.. cpp:class:: DLIES_Encryptor

   .. deprecated:: 2.13.0

      DLIES should no longer be used

   Available in the header ``dlies.h``

   .. cpp:function:: DLIES_Encryptor(const DH_PrivateKey& own_priv_key, \
         RandomNumberGenerator& rng, \
         std::unique_ptr<KDF> kdf, \
         std::unique_ptr<MessageAuthenticationCode> mac, \
         size_t mac_key_len = 20)

      Where *kdf* is a key derivation function (see
      :ref:`key_derivation_function`) and *mac* is a
      MessageAuthenticationCode. The encryption is performed by XORing the
      message with a stream of bytes provided by the KDF.

   .. cpp:function:: DLIES_Encryptor(const DH_PrivateKey& own_priv_key, \
         RandomNumberGenerator& rng, \
         std::unique_ptr<KDF> kdf, \
         std::unique_ptr<Cipher_Mode> cipher, \
         size_t cipher_key_len, \
         std::unique_ptr<MessageAuthenticationCode> mac, \
         size_t mac_key_len = 20)

      Instead of XORing the message with KDF output, a cipher mode can be used

.. cpp:class:: ECIES_Encryptor

   Available in the header ``ecies.h``.

   .. warning::

      ECIES is standardized by various organizations (including IEEE and ISO)
      but unfortunately has dozens of different options which greatly hinder
      interoperability. ECDH key exchange with a static receiver key is much
      simpler, and provides similar security properties.

   Parameters for encryption and decryption are set by the
   :cpp:class:`ECIES_System_Params` class which stores the EC domain parameters,
   the KDF (see :ref:`key_derivation_function`), the cipher (see
   :ref:`cipher_modes`) and the MAC.

   .. cpp:function:: ECIES_Encryptor(const PK_Key_Agreement_Key& private_key, \
         const ECIES_System_Params& ecies_params, \
         RandomNumberGenerator& rng)

      Where *private_key* is the key to use for the key agreement. The system
      parameters are specified in *ecies_params* and the RNG to use is passed in
      *rng*.

   .. cpp:function:: ECIES_Encryptor(RandomNumberGenerator& rng, \
         const ECIES_System_Params& ecies_params)

      Creates an ephemeral private key which is used for the key agreement.


.. cpp:class:: PK_Decryptor

   Interface for public key decryption.

   .. cpp:function:: secure_vector<uint8_t> decrypt(std::span<const uint8_t> in) const

      Decrypts a message, throwing an exception in the case of failure.

      .. warning::

         If using PKCS1v1.5 encryption padding this function is not safe since
         it exposes via a side channel if the decryption succeeded or not. This
         side channel *is sufficient for an attacker to decrypt arbitrary
         messages and forge arbitrary signatures*. Use
         :cpp:func:`PK_Decryptor::decrypt_or_random` to avoid this situation.

   .. cpp:function:: secure_vector<uint8_t> decrypt_or_random(const uint8_t in[], \
                                               size_t length, \
                                               size_t expected_pt_len, \
                                               RandomNumberGenerator& rng) const

         Similar to `decrypt` except that if the decryption fails, or if the
         decrypted key is not of the expected length, then it returns a random
         string of the expected length. This hides the PKCS1v1.5 oracle.

   .. cpp:function:: secure_vector<uint8_t> decrypt_or_random(const uint8_t in[], \
                                               size_t length, \
                                               size_t expected_pt_len, \
                                               RandomNumberGenerator& rng, \
                                               const uint8_t required_content_bytes[], \
                                               const uint8_t required_content_offsets[], \
                                               size_t required_contents) const

         Similar to `decrypt` except that if the decryption fails, or if the
         decrypted key is not of the expected length, then it returns a random
         string of the expected length. This hides the PKCS1v1.5 oracle.

         This variant of the function is used if there are specific bytes within
         the message which must take on a certain value, rather than the
         encrypted "message" just being a random key, which is the more typical
         usage. If any of the required values are incorrect, then again a
         randomly generated key is returned to hide the PKCS1v1.5 oracle.

Botan implements the following encryption algorithms:

1. RSA. Requires a :ref:`padding scheme <eme>` as parameter.
#. DLIES (deprecated)
#. ECIES
#. SM2. Takes an optional ``HashFunction`` as parameter which defaults to SM3.
#. ElGamal. Requires a :ref:`padding scheme <eme>` as parameter.

.. _rsa_example:

Code Example: RSA Encryption
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following code sample reads a PKCS #8 keypair from the passed location and
subsequently encrypts a fixed plaintext with the included public key, using OAEP
with SHA-256. For the sake of completeness, the ciphertext is then decrypted using
the private key.

.. literalinclude:: /../src/examples/rsa_encrypt.cpp
   :language: cpp

.. _eme:

Available encryption padding schemes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. note::

   Padding schemes in the context of encryption are sometimes also called
   *Encoding Method for Encryption* (EME).

OAEP
""""

OAEP (called EME1 in IEEE 1363 and in earlier versions of the library)
as specified in PKCS#1 v2.0 (RFC 2437) or PKCS#1 v2.1 (RFC 3447).

- Name: ``OAEP``,
- Deprecated aliases: ``EME-OAEP``, ``EME1``
- Parameters specification:

  - ``(<HashFunction>)``
  - ``(<HashFunction>,MGF1)``
  - ``(<HashFunction>,MGF1(<HashFunction>))``
  - ``(<HashFunction>,MGF1(<HashFunction>),<optional label>)``

- The only Mask generation function available is MGF1, which is also the default.
- By default the same hash function will be used for the label and MGF1.
- By default the OAEP label is the empty string
- Examples:
  ``OAEP(SHA-256)``,
  ``OAEP(SHA-256,MGF1)``,
  ``OAEP(SHA-256,MGF1(SHA-512))``,
  ``OAEP(SHA-512,MGF1(SHA-512),TCPA)``

PKCS #1 v1.5 Type 2 (encryption)
""""""""""""""""""""""""""""""""

PKCS #1 v1.5 Type 2 (encryption) padding.

Name: ``PKCS1v15``
Deprecated alias: ``EME-PKCS1-v1_5``

.. warning::

   PKCS v1.5 encryption padding is prone to oracle attacks (the Bleichenbacher
   attack, and the many variations thereof). Avoid it if at all possible. If you
   must use it, use :cpp:func:`PK_Decryptor::decrypt_or_random` function which
   can hide the decryption failures.

Raw EME
"""""""

Does not change the input during padding. Unpadding will strip leading zero bytes.

.. warning::

   This is extremely unsafe and only necessary in specialized situations. Don't
   use this unless you know what you are doing.

Name: ``Raw``

Public Key Signature Schemes
---------------------------------

Signature generation is performed using

.. cpp:class:: PK_Signer

   .. cpp:function:: PK_Signer(const Private_Key& key, \
      const std::string& padding, \
      Signature_Format format = Siganture_Format::Standard)

     Constructs a new signer object for the private key *key* using the
     hash/padding specified in *padding*. The key must support signature operations. In
     the current version of the library, this includes RSA, ECDSA, ML-DSA, ECKCDSA,
     ECGDSA, SM2, and others.

     .. note::

       Botan both supports non-deterministic and deterministic (as per RFC
       6979) DSA and ECDSA signatures. Either type of signature can be verified
       by any other (EC)DSA library, regardless of which mode it prefers. If the
       ``rfc6979`` module is enabled at build time, deterministic DSA and ECDSA
       signatures will be created.

     The proper value of *padding* depends on the algorithm. For many signature
     schemes including ECDSA and DSA, simply naming a hash function like "SHA-256"
     is all that is required.

     For RSA, more complicated padding is required. The two most common schemes
     for RSA signature padding are PSS and PKCS1v1.5, so you must specify both
     the padding mechanism as well as a hash, for example "PSS(SHA-256)"
     or "PKCS1v15(SHA-256)".

     Certain newer signature schemes, especially post-quantum based ones, hardcode the
     hash function associated with their signatures, and no configuration is
     possible. In this case *padding* should be left blank, or may possibly be used to identify
     some algorithm-specific option. For instance ML-DSA may be parameterized with
     "Randomized" or "Deterministic" to choose if the generated signature is randomized or
     not. If left blank, a default is chosen.

     Another available option, usable in certain specialized scenarios, is using
     padding scheme "Raw", where the provided input is treated as if it was
     already hashed, and directly signed with no other processing.

     The *format* defaults to ``Standard`` which is either the usual, or the
     only, available formatting method, depending on the algorithm. For certain
     signature schemes including ECDSA, DSA, ECGDSA and ECKCDSA you can also use
     ``DerSequence``, which will format the signature as an ASN.1 SEQUENCE
     value. This formatting is used in protocols such as TLS and Bitcoin.

   .. cpp:function:: void update(const uint8_t* in, size_t length)
   .. cpp:function:: void update(std::span<const uint8_t> in)
   .. cpp:function:: void update(uint8_t in)

      These add more data to be included in the signature computation. Typically, the
      input will be provided directly to a hash function.

   .. cpp:function:: std::vector<uint8_t> signature(RandomNumberGenerator& rng)

      Creates the signature and returns it. The rng may or may not be used,
      depending on the scheme.

   .. cpp:function:: std::vector<uint8_t> sign_message( \
      const uint8_t* in, size_t length, RandomNumberGenerator& rng)

   .. cpp:function:: std::vector<uint8_t> sign_message( \
       std::span<const uint8_t> in, RandomNumberGenerator& rng)

      These functions are equivalent to calling :cpp:func:`PK_Signer::update` and then
      :cpp:func:`PK_Signer::signature`. Any data previously provided using ``update`` will
      also be included in the signature.

   .. cpp:function:: size_t signature_length() const

      Return an upper bound on the length of the signatures returned by this object.

   .. cpp:function:: AlgorithmIdentifier algorithm_identifier() const

      Return an algorithm identifier appropriate to identify signatures generated
      by this object in an X.509 structure.

   .. cpp:function:: std::string hash_function() const

      Return the hash function which is being used

Signatures are verified using

.. cpp:class:: PK_Verifier

   .. cpp:function:: PK_Verifier(const Public_Key& pub_key, \
          const std::string& padding, Signature_Format format = Signature_Format::Standard)

      Construct a new verifier for signatures associated with public key *pub_key*. The
      *padding* and *format* should be the same as that used by the signer.

   .. cpp:function:: void update(const uint8_t* in, size_t length)
   .. cpp:function:: void update(std::span<const uint8_t> in)
   .. cpp:function:: void update(uint8_t in)

      Add further message data that is purportedly associated with the
      signature that will be checked.

   .. cpp:function:: bool check_signature(const uint8_t* sig, size_t length)
   .. cpp:function:: bool check_signature(std::span<const uint8_t> sig)

      Check to see if *sig* is a valid signature for the message data that was written
      in. Return true if so. This function clears the internal message state, so after
      this call you can call :cpp:func:`PK_Verifier::update` to start verifying another
      message.

   .. cpp:function:: bool verify_message(const uint8_t* msg, size_t msg_length, \
                                         const uint8_t* sig, size_t sig_length)

   .. cpp:function:: bool verify_message(std::span<const uint8_t> msg, \
                                         std::span<const uint8_t> sig)

      These are equivalent to calling :cpp:func:`PK_Verifier::update` on *msg* and then
      calling :cpp:func:`PK_Verifier::check_signature` on *sig*. Any data previously
      provided to :cpp:func:`PK_Verifier::update` will also be included.

Botan implements the following signature algorithms:

1. RSA. Requires a :ref:`padding scheme <emsa>` as parameter.
#. DSA. Requires a :ref:`hash function <sig_with_hash>` as parameter.
#. ECDSA. Requires a :ref:`hash function <sig_with_hash>` as parameter.
#. ECGDSA. Requires a :ref:`hash function <sig_with_hash>` as parameter.
#. ECKDSA.
   Requires a :ref:`hash function <sig_with_hash>` as parameter,
   not supporting ``Raw``.
#. GOST 34.10-2001.
   Requires a :ref:`hash function <sig_with_hash>` as parameter.
#. Ed25519 and Ed448. See :ref:`Ed25519_Ed448_variants` for parameters.
#. SM2.
   Takes one of the following as parameter:

   - ``<user ID>`` (uses ``SM3``)
   - ``<user ID>,<HashFunction>``

#. ML-DSA (Dilithium).
   Takes the optional parameter ``Deterministic`` (default) or ``Randomized``.
#. SLH-DSA.
   Takes the optional parameter ``Deterministic`` (default) or ``Randomized``.
#. XMSS. Takes no parameter.
#. HSS-LMS. Takes no parameter.

.. _ecdsa_example:

Code Example: ECDSA Signature
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following sample program below demonstrates the generation of a new ECDSA keypair over
the curve secp512r1 and a ECDSA signature using SHA-256. Subsequently the computed
signature is validated.

.. literalinclude:: /../src/examples/ecdsa.cpp
   :language: cpp

.. _emsa:

RSA signature padding schemes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

These signature padding mechanisms are specific to RSA; no other public
key algorithms included in Botan make use of then. For historical reasons,
many different padding schemes have been defined for RSA over the years.
The most common are PSS and the (now obsolete) PKCS1v15.

.. note::

   Padding schemes in the context of signatures are sometimes also called
   *Encoding methods for signatures with appendix* (EMSA).

PKCS #1 v1.5 Type 1 (signature)
"""""""""""""""""""""""""""""""

PKCS #1 v1.5 Type 1 (signature) padding, aka EMSA3 in IEEE 1363.

.. note::

   While not as actively unsafe as PKCS1v15 encryption padding is,
   PKCS1 signature padding is considered quite obsolete.

- Name: ``PKCS1v15``
- Deprecated aliases: ``EMSA_PKCS1``, ``EMSA-PKCS1-v1_5``, ``EMSA3``
- Parameters specification:

  - ``(<HashFunction>)``
  - ``(Raw,<optional HashFunction>)``

- The raw variant encodes a precomputed hash,
  optionally with the digest ID of the given hash.
- Examples:
  ``PKCS1v15(SHA-256)``,
  ``PKCS1v15(Raw)``,
  ``PKCS1v15(Raw,MD5)``,

EMSA-PSS
""""""""

Probabilistic signature scheme (PSS) (called EMSA4 in IEEE 1363).

- Name: ``PSS``
- Deprecated aliases: ``EMSA-PSS``, ``PSSR``, ``PSS-MGF1``, ``EMSA4``
- Parameters specification:

  - ``(<HashFunction>)``
  - ``(<HashFunction>,MGF1,<optional salt size>)``

- Examples:
  ``PSS(SHA-256)``,
  ``PSS(SHA-256,MGF1,32)``,

There also exists a raw version,
which accepts a pre-hashed buffer instead of the message.
Don't use this unless you know what you are doing.

- Name: ``PSS_Raw``
- Deprecated alias: ``PSSR_Raw``
- Parameters specification:

  - ``(<HashFunction>)``
  - ``(<HashFunction>,MGF1,<optional salt size>)``

ISO-9796-2
""""""""""

The ISO-9796-2 padding schemes are used for signatures in the EMV contactless
payment card system. There is likely no reason to use it in other contexts.

ISO-9796-2 - Digital signature scheme 2 (probabilistic).

- Name: ``ISO_9796_DS2``
- Parameters specification:

  - ``(<HashFunction>)``
  - ``(<HashFunction>,<exp|imp>,<optional salt size>)``

- Defaults to the explicit mode.
- Examples:
  ``ISO_9796_DS2(RIPEMD-160)``,
  ``ISO_9796_DS2(RIPEMD-160,imp)``

ISO-9796-2 - Digital signature scheme 3 (deterministic),
i.e. DS2 without a salt.

- Name: ``ISO_9796_DS3``
- Parameters specification:

  - ``(<HashFunction>)``
  - ``(<HashFunction>,<exp|imp>``

- Defaults to the explicit mode.
- Examples:
  ``ISO_9796_DS3(RIPEMD-160)``,
  ``ISO_9796_DS3(RIPEMD-160,imp)``,

X9.31
"""""

.. deprecated:: 3.7.0

   X9.31 signatures are obsolete, and support for it is deprecated

EMSA from X9.31 (EMSA2 in IEEE 1363).

- Name: ``X9.31``
- Deprecated aliases: ``EMSA2``, ``EMSA_X931``
- Parameters specification:
  ``(<HashFunction>)``
- Example: ``X9.31(SHA-256)``

Raw EMSA
""""""""

Sign inputs directly with no hashing or padding

.. warning::

   This exists as an escape hatch allowing an application to define
   some protocol-specific padding scheme. Don't use this unless you
   know what you are doing.

- Name: ``Raw``
- Parameters specification:
  ``(<optional HashFunction>)``
- Examples:
  ``Raw``,
  ``Raw(SHA-256)``

.. _sig_with_hash:

Signature with Hash
~~~~~~~~~~~~~~~~~~~

For many signature schemes including ECDSA and DSA,
simply naming a hash function like ``SHA-256`` is all that is required.

Previous versions of Botan required using a hash specifier
like ``EMSA1(SHA-256)`` when generating or verifying ECDSA/DSA signatures,
with the specified hash.
The ``EMSA1`` was a reference to a now obsolete IEEE standard.

Parameters specification:

- ``<HashFunction>``
- ``EMSA1(<HashFunction>)`` [deprecated]

There also exists a raw mode, which accepts a pre-hashed buffer
instead of the message.

.. warning::

   This is used for situations where somehow the hash is computed by another
   module and then signed. Many ways of doing this are insecure. Don't use this
   unless you know what you are doing.

Parameters specification:

- ``Raw``
- ``Raw(<HashFunction>)``

.. _Ed25519_Ed448_variants:

Ed25519 and Ed448 Variants
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. warning::

   Ed25519 and Ed448 have different verification criteria, depending
   on the implementation. This can be problematic in systems which rely on
   consensus - see `It’s 255:19AM. Do you know what your validation criteria
   are? <https://hdevalence.ca/blog/2020-10-04-its-25519am>`_ for details.

Most signature schemes in Botan follow a hash-then-sign paradigm. That is, the
entire message is digested to a fixed length representative using a collision
resistant hash function, and then the digest is signed. Ed25519 and Ed448 instead sign
the message directly. This is beneficial, in that the design should
remain secure even in the (extremely unlikely) event that a collision attack on
SHA-512 is found. However it means the entire message must be buffered in
memory, which can be a problem for many applications which might need to sign
large inputs. To use this variety of Ed25519/Ed448, use a padding name of "Pure".

This is the default mode if no padding name is given.

Parameter specification:
``Pure`` / ``Identity``

Ed25519ph (or Ed448) (pre-hashed) instead hashes the message with SHA-512 (or SHAKE256(512))
and then signs the digest plus a special prefix specified in RFC 8032. To use it, specify
padding name "Ed25519ph" (or "Ed448ph").

Parameter specification:
``Ed25519ph``

Another variant of pre-hashing is used by GnuPG. There the message is digested
with any hash function, then the digest is signed. To use it, specify any valid
hash function. Even if SHA-512 is used, this variant is not compatible with
Ed25519ph.

Parameter specification:
``<HashFunction>``

For best interop with other systems, prefer "Ed25519ph".

Key Agreement
---------------------------------

Key agreement is a scheme where two parties exchange public keys, after which it is
possible for them to derive a secret key which is known only to the two of them.

There are different approaches possible for key agreement. In many protocols, both parties
generate a new key, exchange public keys, and derive a secret, after which they throw away
their private keys, using them only the once. However this requires the parties to both be
online and able to communicate with each other.

In other protocols, one of the parties publishes their public key online in some way, and
then it is possible for someone to send encrypted messages to that recipient by generating
a new keypair, performing key exchange with the published public key, and then sending
both the message along with their ephemeral public key. Then the recipient uses the
provided public key along with their private key to complete the key exchange, recover the
shared secret, and decrypt the message.

Typically the raw output of the key agreement function is not uniformly distributed,
and may not be of an appropriate length to use as a key. To resolve these problems,
key agreement will use a :ref:`key_derivation_function` on the shared secret to
produce an output of the desired length.

1. ECDH over GF(p) Weierstrass curves
#. ECDH over x25519 or x448
#. DH over prime fields

.. cpp:class:: PK_Key_Agreement

  .. cpp:function:: PK_Key_Agreement(const Private_Key& key, \
                    RandomNumberGenerator& rng, \
                    const std::string& kdf, \
                    const std::string& provider = "")

      Set up to perform key derivation using the given private key and specified KDF.

  .. size_t agreed_value_size() const

      Return the byte length of what the underlying key agreement outputs.
      For example ECDH with secp256r1 will return 32, while finite field
      Diffie-Hellman with a 2048 bit modulus will return 256.

  .. cpp:function:: SymmetricKey derive_key(size_t key_len, \
                    const uint8_t peer_key[], \
                    size_t peer_key_len, \
                    const uint8_t salt[], \
                    size_t salt_len) const

  .. cpp:function:: SymmetricKey derive_key(size_t key_len, \
                    std::span<const uint8_t> peer_key, \
                    const uint8_t salt[], size_t salt_len) const

  .. cpp:function:: SymmetricKey derive_key(size_t key_len, \
                    const uint8_t peer_key[], size_t peer_key_len, \
                    const std::string& salt = "") const

  .. cpp:function:: SymmetricKey derive_key(size_t key_len, \
                    std::span<const uint8_t> peer_key, \
                    const std::string& salt = "") const

     Return a shared secret key.

     The *peer_key* parameter must be the public key associated with the other party.

     The shared key will be of length *key_len*. If the KDF cannot accomodate
     outputs of this size (only likely for very large values, or if using KDF1),
     an exception will be thrown. If a KDF is not in use ("Raw" KDF), *key_len*
     is ignored and this function will always return directly what the agreement
     scheme output, of length equal to :cpp:func:`agreed_value_size`.

     The *salt* will be hashed along with the shared secret by the KDF; this can
     be useful to bind the shared secret to a specific usage. If a KDF is not
     being used ("Raw" KDF) then any non-empty salt will be rejected.

.. _ecdh_example:

Code Example: ECDH Key Agreement
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The code below performs an unauthenticated ECDH key agreement using the secp521r1 elliptic
curve and applies the key derivation function KDF2(SHA-256) with 256 bit output length to
the computed shared secret.

.. literalinclude:: /../src/examples/ecdh.cpp
   :language: cpp

Key Encapsulation
-------------------

Key encapsulation (KEM) is a variation on public key encryption which is commonly used by
post-quantum secure schemes. Instead of choosing a random secret and encrypting it, as in
typical public key encryption, a KEM encryption takes no inputs and produces two values,
the shared secret and the encapsulated key. The decryption operation takes in the
encapsulated key and returns the shared secret.

.. cpp:class:: PK_KEM_Encryptor

  .. cpp:function:: PK_KEM_Encryptor(const Public_Key& key, \
                       const std::string& kdf = "", \
                       const std::string& provider = "")

     Create a KEM encryptor

  .. cpp:function:: size_t shared_key_length(size_t desired_shared_key_len) const

     Size in bytes of the shared key being produced by this PK_KEM_Encryptor.

  .. cpp:function:: size_t encapsulated_key_length() const

     Size in bytes of the encapsulated key being produced by this PK_KEM_Encryptor.

  .. cpp:function:: KEM_Encapsulation encrypt(RandomNumberGenerator& rng, \
                                size_t desired_shared_key_len = 32, \
                                std::span<const uint8_t> salt = {})

     Perform a key encapsulation operation with the result being returned
     as a convenient struct.

  .. cpp:function:: void encrypt(std::span<uint8_t> out_encapsulated_key, \
                   std::span<uint8_t> out_shared_key, \
                   RandomNumberGenerator& rng, \
                   size_t desired_shared_key_len = 32, \
                   std::span<const uint8_t> salt = {})

     Perform a key encapsulation operation by passing in out-buffers of
     the correct output length. Use encapsulated_key_length() and
     shared_key_length() to pre-allocate the output buffers.

  .. cpp:function:: void encrypt(secure_vector<uint8_t>& out_encapsulated_key, \
                   secure_vector<uint8_t>& out_shared_key, \
                   size_t desired_shared_key_len, \
                   RandomNumberGenerator& rng, \
                   std::span<const uint8_t> salt)

      Perform a key encapsulation operation by passing in out-vectors
      that will be re-allocated to the correct output size.

.. cpp:class:: KEM_Encapsulation

  .. cpp:function::  std::vector<uint8_t> encapsulated_shared_key() const

  .. cpp:function:: secure_vector<uint8_t> shared_key() const

.. cpp:class:: PK_KEM_Decryptor

  .. cpp:function:: PK_KEM_Decryptor(const Public_Key& key, \
                       const std::string& kdf = "", \
                       const std::string& provider = "")

     Create a KEM decryptor

  .. cpp:function:: size_t encapsulated_key_length() const

     Size in bytes of the encapsulated key expected by this PK_KEM_Decryptor.

  .. cpp:function:: size_t shared_key_length(size_t desired_shared_key_len) const

     Size in bytes of the shared key being produced by this PK_KEM_Encryptor.

  .. cpp:function:: secure_vector<uint8> decrypt(std::span<const uint8> encapsulated_key, \
                    size_t desired_shared_key_len, \
                    std::span<const uint8_t> salt)

      Perform a key decapsulation operation

  .. cpp:function:: void decrypt(std::span<uint8_t> out_shared_key, \
                   std::span<const uint8_t> encap_key, \
                   size_t desired_shared_key_len = 32, \
                   std::span<const uint8_t> salt = {})

      Perform a key decapsulation operation by passing in a pre-allocated
      out-buffer. Use shared_key_length() to determine the byte-length required.

Botan implements the following KEM schemes:

1. RSA
#. ML-KEM (formerly known as Kyber)
#. FrodoKEM
#. Classic McEliece
#. HyMES McEliece (deprecated)

.. _mlkem_example:

Code Example: ML-KEM
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The code below demonstrates key encapsulation using ML-KEM (FIPS 203), formerly
known as Kyber.

.. literalinclude:: /../src/examples/ml_kem.cpp
   :language: cpp

.. _mceliece:

HyMES McEliece cryptosystem
------------------------------

McEliece is a cryptographic scheme based on error correcting codes which is
thought to be resistant to quantum computers. First proposed in 1978, it is fast
and patent-free. Variants have been proposed and broken, but with suitable
parameters the original scheme remains secure. However the public keys are quite
large, which has hindered deployment in the past.

The implementation of McEliece in Botan was contributed by cryptosource GmbH. It
is based on the implementation HyMES, with the kind permission of Nicolas
Sendrier and INRIA to release a C++ adaption of their original C code under the
Botan license. It was then modified by Falko Strenzke to add side channel and
fault attack countermeasures. You can read more about the implementation at
http://www.cryptosource.de/docs/mceliece_in_botan.pdf

Encryption in the McEliece scheme consists of choosing a message block of size
`n`, encoding it in the error correcting code which is the public key, then
adding `t` bit errors. The code is created such that knowing only the public
key, decoding `t` errors is intractable, but with the additional knowledge of
the secret structure of the code a fast decoding technique exists.

The McEliece implementation in HyMES, and also in Botan, uses an optimization to
reduce the public key size, by converting the public key into a systemic code.
This means a portion of the public key is a identity matrix, and can be excluded
from the published public key. However it also means that in McEliece the
plaintext is represented directly in the ciphertext, with only a small number of
bit errors. Thus it is absolutely essential to only use McEliece with a CCA2
secure scheme.

For a given security level (SL) a McEliece key would use
parameters n and t, and have the corresponding key sizes listed:

+-----+------+-----+---------------+----------------+
| SL  |   n  |   t | public key KB | private key KB |
+=====+======+=====+===============+================+
|  80 | 1632 |  33 |            59 |            140 |
+-----+------+-----+---------------+----------------+
| 107 | 2280 |  45 |           128 |            300 |
+-----+------+-----+---------------+----------------+
| 128 | 2960 |  57 |           195 |            459 |
+-----+------+-----+---------------+----------------+
| 147 | 3408 |  67 |           265 |            622 |
+-----+------+-----+---------------+----------------+
| 191 | 4624 |  95 |           516 |           1234 |
+-----+------+-----+---------------+----------------+
| 256 | 6624 | 115 |           942 |           2184 |
+-----+------+-----+---------------+----------------+

You can check the speed of McEliece with the suggested parameters above
using ``botan speed McEliece``

Classic McEliece KEM
--------------------

`Classic McEliece <https://classic.mceliece.org/>`_ is an IND-CCA2 secure key
encapsulation algorithm based on the McEliece cryptosystem introduced in 1978.
It is a code-based scheme that relies on conservative security assumptions and
is considered secure against quantum computers. It is an alternative to
lattice-based schemes.

Other advantages of Classic McEliece are the small ciphertext size and the fast
encapsulation. Key generation and decapsulation are slower than in lattice-based
schemes. The main disadvantage of Classic McEliece is the large public key size,
ranging from 0.26 MB to 1.36 MB, depending on the instance. Due to its large key
size, Classic McEliece is recommended for applications where the public key is
stored for a long time, and memory is not a critical resource. Usage with
ephemeral keys is not recommended.

Botan's implementation covers the parameter sets of the `NIST round 4
specification <https://classic.mceliece.org/mceliece-spec-20221023.pdf#page=15>`_
and the `Classic McEliece ISO draft specification
<https://classic.mceliece.org/iso-mceliece-20230419.pdf#page=13>`_.
These are the following:

+------------------+-------------------+-------------------+--------------------+-------------------+
| Set without f/pc | Set with f        | Set with pc       | Set with pcf       | Public Key Size   |
+==================+===================+===================+====================+===================+
|  mceliece348864  | mceliece348864f   |                   |                    | 0.26 MB           |
+------------------+-------------------+-------------------+--------------------+-------------------+
| mceliece460896   | mceliece460896f   |                   |                    | 0.52 MB           |
+------------------+-------------------+-------------------+--------------------+-------------------+
| mceliece6688128  | mceliece6688128f  | mceliece6688128pc | mceliece6688128pcf | 1.04 MB           |
+------------------+-------------------+-------------------+--------------------+-------------------+
| mceliece6960119  | mceliece6960119f  | mceliece6960119pc | mceliece6960119pcf | 1.05 MB           |
+------------------+-------------------+-------------------+--------------------+-------------------+
| mceliece8192128  | mceliece8192128f  | mceliece8192128pc | mceliece8192128pcf | 1.36 MB           |
+------------------+-------------------+-------------------+--------------------+-------------------+

The instances with the suffix 'f' use a faster key generation algorithm that is more consistent in
runtime. The instances with the suffix 'pc' use plaintext confirmation, which is only specified in
the ISO document. The instances mceliece348864(f) and mceliece460896(f) are only defined in the
NIST round 4 submission.


eXtended Merkle Signature Scheme (XMSS)
----------------------------------------

Botan implements the single tree version of the eXtended Merkle Signature
Scheme (XMSS) using Winternitz One Time Signatures+ (WOTS+). The implementation
is based on `RFC 8391 "XMSS: eXtended Merkle Signature Scheme"
<https://tools.ietf.org/html/rfc8391>`_.

.. warning::

   XMSS is stateful, meaning the private key updates after each signature
   creation. Applications are responsible for updating their persistent secret
   with the new output of ``Private_Key::private_key_bits()`` after each signature
   creation. If the same private key is ever used to generate
   two different signatures, then the scheme becomes insecure. For this reason,
   it can be challenging to use XMSS securely.

XMSS uses the Botan interfaces for public key cryptography.
The following algorithms are implemented:

1. XMSS-SHA2_10_256
#. XMSS-SHA2_16_256
#. XMSS-SHA2_20_256
#. XMSS-SHA2_10_512
#. XMSS-SHA2_16_512
#. XMSS-SHA2_20_512
#. XMSS-SHAKE_10_256
#. XMSS-SHAKE_16_256
#. XMSS-SHAKE_20_256
#. XMSS-SHAKE_10_512
#. XMSS-SHAKE_16_512
#. XMSS-SHAKE_20_512

The algorithm name contains the hash function name, tree height and digest
width defined by the corresponding parameter set. Choosing `XMSS-SHA2_10_256`
for instance will use the SHA2-256 hash function to generate a tree of height
ten.

.. _xmss_example:

Code Example: XMSS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following code snippet shows a minimum example on how to create an XMSS
public/private key pair and how to use these keys to create and verify a
signature:

.. literalinclude:: /../src/examples/xmss.cpp
   :language: cpp


Hierarchical Signature System with Leighton-Micali Hash-Based Signatures (HSS-LMS)
----------------------------------------------------------------------------------

HSS-LMS is a stateful hash-based signature scheme which is defined in `RFC 8554
"Leighton-Micali Hash-Based Signatures" <https://datatracker.ietf.org/doc/html/rfc8554>`_.

It is a multitree scheme, which is highly configurable. Multitree means, it consists
of multiple layers of Merkle trees, which can be defined individually. Moreover, the
used hash function and the Winternitz Parameter of the underlying one-time signature
can be chosen for each tree layer. For a sensible selection of parameters refer to
`RFC 8554 Section 6.4. <https://datatracker.ietf.org/doc/html/rfc8554#section-6.4>`_.

.. warning::

   HSS-LMS is stateful, meaning the private key updates after each signature
   creation. Applications are responsible for updating their persistent secret
   with the new output of ``Private_Key::private_key_bits()`` after each signature
   creation. If the same private key is ever used to generate
   two different signatures, then the scheme becomes insecure. For this reason,
   it can be challenging to use HSS-LMS securely.

HSS-LMS uses the Botan interfaces for public key cryptography. The ``params``
argument of the HSS-LMS private key is used to define the parameter set.
The syntax of this argument must be the following:

``HSS-LMS(<hash>,HW(<h>,<w>),HW(<h>,<w>),...)``

e.g. ``HSS-LMS(SHA-256,HW(5,1),HW(5,1))`` to use SHA-256 in a two-layer HSS instance
with LMS tree height 5 and Winternitz parameter 1. This results in a
private key that can be used to create up to 2^(5+5)=1024 signatures.

The following parameters are allowed (which are specified in
`RFC 8554 <https://datatracker.ietf.org/doc/html/rfc8554>`_ and
and `draft-fluhrer-lms-more-parm-sets-11 <https://datatracker.ietf.org/doc/html/draft-fluhrer-lms-more-parm-sets-11>`_):

- hash: ``SHA-256``, ``Truncated(SHA-256,192)``, ``SHAKE-256(256)``, ``SHAKE-256(192)``
- h: ``5``, ``10``, ``15``, ``20``, ``25``
- w: ``1``, ``2``, ``4``, ``8``

