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
``Public_Key``, so that a private key can also be used as the cooresponding
public key. It is best to avoid relying on this, as this inheritance will be
removed in a future major release.

.. cpp:class:: Asymmetric_Key

  .. cpp:function:: std::string algo_name()

     Return a short string identifying the algorithm of this key,
     eg "RSA" or "Dilithium".

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

   .. cpp:function:: std::vector<uint8_t> subject_public_key() const;

      Return the X.509 SubjectPublicKeyInfo encoding of this key

   .. cpp:function:: std::string fingerprint_public(const std::string& alg = "SHA-256") const;

      Return a hashed fingerprint of this public key.

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

ECDH, DH, and X25519
~~~~~~~~~~~~~~~~~~~~~~~

Key agreement schemes. DH uses arithmetic over finite fields and is slower and
with larger keys. ECDH and X25519 use elliptic curves instead.

Dilithium
~~~~~~~~~~

Post-quantum secure signature scheme based on lattice problems.

Kyber
~~~~~~~~~~~

Post-quantum key encapsulation scheme based on lattices.

.. note::

   Currently two modes for Kyber are defined: the round3 specification
   from the NIST PQC competetition, and the "90s mode" (which uses
   AES/SHA-2 instead of SHA-3 based primitives). The 90s mode Kyber is
   deprecated and will be removed in a future release.

   The final NIST specification version of Kyber is not yet implemented.

Ed25519
~~~~~~~~~~

Signature scheme based on a specific elliptic curve.

XMSS
~~~~~~~~~

A post-quantum secure signature scheme whose security is based (only) on the
security of a hash function. Unfortunately XMSS is stateful, meaning the private
key changes with each signature, and only a certain pre-specified number of
signatures can be created. If the same state is ever used to generate two
signatures, then the whole scheme becomes insecure, and signatures can be
forged.

SPHINCS+
~~~~~~~~~

A post-quantum secure signature scheme whose security is based (only) on the
security of a hash function. Unlike XMSS, it is a stateless signature
scheme, meaning that the private key does not change with each signature. It
has high security but very long signatures and high runtime.

McEliece
~~~~~~~~~~

Post-quantum secure key encapsulation scheme based on the hardness of certain
decoding problems.

ElGamal
~~~~~~~~

Encryption scheme based on the discrete logarithm problem. Generally unused
except in PGP.

DSA
~~~~

Finite field based signature scheme. A NIST standard but now quite obsolete.

ECGDSA, ECKCDSA, SM2, GOST-34.10
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A set of signature schemes based on elliptic curves. All are national standards
in their respective countries (Germany, South Korea, China, and Russia, resp),
and are completely obscure and unused outside of that context.

.. _creating_new_private_keys:

Creating New Private Keys
----------------------------------------

Creating a new private key requires two things: a source of random numbers
(see :ref:`random_number_generators`) and some algorithm specific parameters
that define the *security level* of the resulting key. For instance, the
security level of an RSA key is (at least in part) defined by the length of
the public key modulus in bits. So to create a new RSA private key, you would
call

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

Algorithms based on the discrete-logarithm problem use what is called a
*group*; a group can safely be used with many keys, and for some operations,
like key agreement, the two keys *must* use the same group.  There are
currently two kinds of discrete logarithm groups supported in botan: the
integers modulo a prime, represented by :ref:`dl_group`, and elliptic curves
in GF(p), represented by :ref:`ec_group`. A rough generalization is that the
larger the group is, the more secure the algorithm is, but correspondingly the
slower the operations will be.

Given a ``DL_Group``, you can create new DSA, Diffie-Hellman and ElGamal key pairs with

.. cpp:function:: DSA_PrivateKey::DSA_PrivateKey(RandomNumberGenerator& rng, \
   const DL_Group& group, const BigInt& x = 0)

.. cpp:function:: DH_PrivateKey::DH_PrivateKey(RandomNumberGenerator& rng, \
   const DL_Group& group, const BigInt& x = 0)

.. cpp:function:: ElGamal_PrivateKey::ElGamal_PrivateKey(RandomNumberGenerator& rng, \
   const DL_Group& group, const BigInt& x = 0)

  The optional *x* parameter to each of these constructors is a private key
  value. This allows you to create keys where the private key is formed by
  some special technique; for instance you can use the hash of a password (see
  :ref:`pbkdf` for how to do that) as a private key value. Normally, you would
  leave the value as zero, letting the class generate a new random key.

Finally, given an ``EC_Group`` object, you can create a new ECDSA, ECKCDSA, ECGDSA,
ECDH, or GOST 34.10-2001 private key with

.. cpp:function:: ECDSA_PrivateKey::ECDSA_PrivateKey(RandomNumberGenerator& rng, \
   const EC_Group& domain, const BigInt& x = 0)

.. cpp:function:: ECKCDSA_PrivateKey::ECKCDSA_PrivateKey(RandomNumberGenerator& rng, \
      const EC_Group& domain, const BigInt& x = 0)

.. cpp:function:: ECGDSA_PrivateKey::ECGDSA_PrivateKey(RandomNumberGenerator& rng, \
   const EC_Group& domain, const BigInt& x = 0)

.. cpp:function:: ECDH_PrivateKey::ECDH_PrivateKey(RandomNumberGenerator& rng, \
   const EC_Group& domain, const BigInt& x = 0)

.. cpp:function:: GOST_3410_PrivateKey::GOST_3410_PrivateKey(RandomNumberGenerator& rng, \
   const EC_Group& domain, const BigInt& x = 0)

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

As described in :ref:`creating_new_private_keys`, a discrete logarithm group
can be shared among many keys, even keys created by users who do not trust
each other. However, it is necessary to trust the entity who created the
group; that is why organization like NIST use algorithms which generate groups
in a deterministic way such that creating a bogus group would require breaking
some trusted cryptographic primitive like SHA-2.

Instantiating a ``DL_Group`` simply requires calling

.. cpp:function:: DL_Group::DL_Group(const std::string& name)

  The *name* parameter is a specially formatted string that consists of three
  things, the type of the group ("modp" or "dsa"), the creator of the group,
  and the size of the group in bits, all delimited by '/' characters.

  Currently all "modp" groups included in botan are ones defined by the
  Internet Engineering Task Force, so the provider is "ietf", and the strings
  look like "modp/ietf/N" where N can be any of 1024, 1536, 2048, 3072,
  4096, 6144, or 8192. This group type is used for Diffie-Hellman and ElGamal
  algorithms.

  The other type, "dsa" is used for DSA keys. They can also be used with
  Diffie-Hellman and ElGamal, but this is less common. The currently available
  groups are "dsa/jce/1024" and "dsa/botan/N" with N being 2048 or 3072.  The
  "jce" groups are the standard DSA groups used in the Java Cryptography
  Extensions, while the "botan" groups were randomly generated using the
  FIPS 186-3 algorithm by the library maintainers.

You can generate a new random group using

.. cpp:function:: DL_Group::DL_Group(RandomNumberGenerator& rng, \
   PrimeType type, size_t pbits, size_t qbits = 0)

  The *type* can be either ``Strong``, ``Prime_Subgroup``, or
  ``DSA_Kosherizer``. *pbits* specifies the size of the prime in
  bits. If the *type* is ``Prime_Subgroup`` or ``DSA_Kosherizer``,
  then *qbits* specifies the size of the subgroup.

You can serialize a ``DL_Group`` using

.. cpp:function:: secure_vector<uint8_t> DL_Group::DER_Encode(Format format)

or

.. cpp:function:: std::string DL_Group::PEM_encode(Format format)

where *format* is any of

* ``ANSI_X9_42`` (or ``DH_PARAMETERS``) for modp groups
* ``ANSI_X9_57`` (or ``DSA_PARAMETERS``) for DSA-style groups
* ``PKCS_3`` is an older format for modp groups; it should only
  be used for backwards compatibility.

You can reload a serialized group using

.. cpp:function:: void DL_Group::BER_decode(DataSource& source, Format format)

.. cpp:function:: void DL_Group::PEM_decode(DataSource& source)

Code Example
~~~~~~~~~~~~~~~
The example below creates a new 2048 bit ``DL_Group``, prints the generated
parameters and ANSI_X9_42 encodes the created group for further usage with DH.

.. literalinclude:: /../src/examples/dl_group.cpp
   :language: cpp


.. _ec_group:

EC_Group
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An ``EC_Group`` is initialized by passing the name of the
group to be used to the constructor. These groups have
semi-standardized names like "secp256r1" and "brainpool512r1".

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

As key checks are not automatically performed they must be called
manually after loading keys from untrusted sources. If a key from an untrusted source
is not checked, the implementation might be vulnerable to algorithm specific attacks.

The following example loads the Subject Public Key from the x509 certificate ``cert.pem`` and checks the
loaded key. If the key check fails a respective error is thrown.

.. literalinclude:: /../src/examples/check_key.cpp
   :language: cpp

Public Key Encryption/Decrpytion
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
     use "EME-PKCS1-v1_5".

.. cpp:class:: DLIES_Encryptor

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

The decryption classes are named :cpp:class:`PK_Decryptor`,
:cpp:class:`PK_Decryptor_EME`, :cpp:class:`DLIES_Decryptor` and
:cpp:class:`ECIES_Decryptor`. They are created in the exact same way, except
they take the private key, and the processing function is named ``decrypt``.

Botan implements the following encryption algorithms and padding schemes:

1. RSA
    - "PKCS1v15" || "EME-PKCS1-v1_5"
    - "OAEP" || "EME-OAEP" || "EME1" || "EME1(SHA-1)" || "EME1(SHA-256)"
#. DLIES
#. ECIES
#. SM2

Code Example
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following Code sample reads a PKCS #8 keypair from the passed location and
subsequently encrypts a fixed plaintext with the included public key, using OAEP
with SHA-256. For the sake of completeness, the ciphertext is then decrypted using
the private key.

.. literalinclude:: /../src/examples/rsa_encrypt.cpp
   :language: cpp


Public Key Signature Schemes
---------------------------------

Signature generation is performed using

.. cpp:class:: PK_Signer

   .. cpp:function:: PK_Signer(const Private_Key& key, \
      const std::string& padding, \
      Signature_Format format = Siganture_Format::Standard)

     Constructs a new signer object for the private key *key* using the
     hash/padding specified in *padding*. The key must support signature operations. In
     the current version of the library, this includes RSA, ECDSA, Dilithium,
     ECKCDSA, ECGDSA, GOST 34.10-2001, and SM2.

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
     possible. There *padding* should be left blank, or may possibly be used to identify
     some algorithm-specific option. For instance Dilithium may be parameterized with
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

1. RSA
#. DSA
#. ECDSA
#. ECGDSA
#. ECKDSA
#. GOST 34.10-2001
#. Ed25519
#. SM2
#. Dilithium

Code Example
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following sample program below demonstrates the generation of a new ECDSA keypair over
the curve secp512r1 and a ECDSA signature using SHA-256. Subsequently the computed
signature is validated.

.. literalinclude:: /../src/examples/ecdsa.cpp
   :language: cpp


Ed25519 Variants
~~~~~~~~~~~~~~~~~~

Most signature schemes in Botan follow a hash-then-sign paradigm. That is, the
entire message is digested to a fixed length representative using a collision
resistant hash function, and then the digest is signed. Ed25519 instead signs
the message directly. This is beneficial, in that the Ed25519 design should
remain secure even in the (extremely unlikely) event that a collision attack on
SHA-512 is found. However it means the entire message must be buffered in
memory, which can be a problem for many applications which might need to sign
large inputs. To use this variety of Ed25519, use a padding name of "Pure".

Ed25519ph (pre-hashed) instead hashes the message with SHA-512 and then signs
the digest plus a special prefix specified in RFC 8032. To use it, specify
padding name "Ed25519ph".

Another variant of pre-hashing is used by GnuPG. There the message is digested
with any hash function, then the digest is signed. To use it, specify any valid
hash function. Even if SHA-512 is used, this variant is not compatible with
Ed25519ph.

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

Typically the raw output of the key agreement function is not uniformily distributed,
and may not be of an appropriate length to use as a key. To resolve these problems,
key agreement will use a :ref:`key_derivation_function` on the shared secret to
produce an output of the desired length.

1. ECDH over GF(p) Weierstrass curves
#. ECDH over x25519
#. DH over prime fields

.. cpp:class:: PK_Key_Agreement

  .. cpp:function:: PK_Key_Agreement(const Private_Key& key, \
                    RandomNumberGenerator& rng, \
                    const std::string& kdf, \
                    const std::string& provider = "")

      Set up to perform key derivation using the given private key and specified KDF.

  .. cpp:function:: SymmetricKey derive_key(size_t key_len, \
                    const uint8_t in[], \
                    size_t in_len, \
                    const uint8_t params[], \
                    size_t params_len) const

  .. cpp:function:: SymmetricKey derive_key(size_t key_len, \
                    std::span<const uint8_t> in, \
                    const uint8_t params[], size_t params_len) const

  .. cpp:function:: SymmetricKey derive_key(size_t key_len, \
                    const uint8_t in[], size_t in_len, \
                    const std::string& params = "") const

  .. cpp:function:: SymmetricKey derive_key(size_t key_len, \
                    const std::span<const uint8_t> in, \
                    const std::string& params = "") const

     Return a shared key. The *params* will be hashed along with the shared secret by the
     KDF; this can be useful to bind the shared secret to a specific usage.

     The *in* parameter must be the public key associated with the other party.

Code Example
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The code below performs an unauthenticated ECDH key agreement using the secp521r elliptic
curve and applies the key derivation function KDF2(SHA-256) with 256 bit output length to
the computed shared secret.

.. literalinclude:: /../src/examples/ecdh.cpp
   :language: cpp

Key Encapsulation
-------------------

Key encapsulation (KEM) is a variation on public key encryption which is commonly used by
post-quantum secure schemes. Instead of choosing a random secret and encrypting it, as in
typical public key encryption, a KEM encryption takes no inputs and produces two values,
the shared secret and the encapulated key. The decryption operation takes in the
encapulated key and returns the shared secret.

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
#. Kyber
#. McEliece

Code Example
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The code below demonstrates key encapsulation using the Kyber post-quantum scheme.

.. literalinclude:: /../src/examples/kyber.cpp
   :language: cpp

.. _mceliece:

McEliece
--------------------------

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


eXtended Merkle Signature Scheme (XMSS)
----------------------------------------

Botan implements the single tree version of the eXtended Merkle Signature
Scheme (XMSS) using Winternitz One Time Signatures+ (WOTS+). The implementation
is based on `RFC 8391 "XMSS: eXtended Merkle Signature Scheme"
<https://tools.ietf.org/html/rfc8391>`_.

.. warning::

   XMSS is stateful, meaning the private key must be updated after
   each signature. If the same private key is ever used to generate
   two different signatures, then the scheme becomes insecure. For
   this reason it can be challening to use XMSS securely.

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

Code Example
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following code snippet shows a minimum example on how to create an XMSS
public/private key pair and how to use these keys to create and verify a
signature:

.. literalinclude:: /../src/examples/xmss.cpp
   :language: cpp
