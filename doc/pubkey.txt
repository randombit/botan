
Public Key Cryptography
=================================

Public key cryptography (also called assymmetric cryptography) is a collection
of techniques allowing for encryption, signatures, and key agreement.

Key Objects
----------------------------------------

Public and private keys are represented by classes ``Public_Key`` and it's
subclass ``Private_Key``. The use of inheritence here means that a
``Private_Key`` can be converted into a reference to a public key.

None of the functions on ``Public_Key`` and ``Private_Key`` itself are
particularly useful for users of the library, because 'bare' public key
operations are *very insecure*. The only purpose of these functions is to
provide a clean interface that higher level operations can be built on. So
really the only thing you need to know is that when a function takes a
reference to a ``Public_Key``, it can take any public key or private key, and
similiarly for ``Private_Key``.

Types of ``Public_Key`` include ``RSA_PublicKey``, ``DSA_PublicKey``,
``ECDSA_PublicKey``, ``DH_PublicKey``, ``ECDH_PublicKey``, ``RW_PublicKey``,
``NR_PublicKey``,, and ``GOST_3410_PublicKey``.  There are cooresponding
``Private_Key`` classes for each of these algorithms.

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

Algorithms based on the discrete-logarithm problem uses what is called a
*group*; a group can safely be used with many keys, and for some operations,
like key agreement, the two keys *must* use the same group.  There are
currently two kinds of discrete logarithm groups supported in botan: the
integers modulo a prime, represented by :ref:`dl_group`, and elliptic curves
in GF(p), represented by :ref:`ec_group`. A rough generalization is that the
larger the group is, the more secure the algorithm is, but coorespondingly the
slower the operations will be.

Given a ``DL_Group``, you can create new DSA, Diffie-Hellman, and
Nyberg-Rueppel key pairs with

.. cpp:function:: DSA_PrivateKey::DSA_PrivateKey(RandomNumberGenerator& rng, \
   const DL_Group& group, const BigInt& x = 0)

.. cpp:function:: DH_PrivateKey::DH_PrivateKey(RandomNumberGenerator& rng, \
   const DL_Group& group, const BigInt& x = 0)

.. cpp:function:: NR_PrivateKey::NR_PrivateKey(RandomNumberGenerator& rng, \
   const DL_Group& group, const BigInt& x = 0)

.. cpp:function:: ElGamal_PrivateKey::ElGamal_PrivateKey(RandomNumberGenerator& rng, \
   const DL_Group& group, const BigInt& x = 0)

  The optional *x* parameter to each of these contructors is a private key
  value. This allows you to create keys where the private key is formed by
  some special technique; for instance you can use the hash of a password (see
  :ref:`pbkdf` for how to do that) as a private key value. Normally, you would
  leave the value as zero, letting the class generate a new random key.

Finally, given an ``EC_Group`` object, you can create a new ECDSA,
ECDH, or GOST 34.10-2001 private key with

.. cpp:function:: ECDSA_PrivateKey::ECDSA_PrivateKey(RandomNumberGenerator& rng, \
   const EC_Group& domain, const BigInt& x = 0)

.. cpp:function:: ECDH_PrivateKey::ECDH_PrivateKey(RandomNumberGenerator& rng, \
   const EC_Group& domain, const BigInt& x = 0)

.. cpp:function:: GOST_3410_PrivateKey::GOST_3410_PrivateKey(RandomNumberGenerator& rng, \
   const EC_Group& domain, const BigInt& x = 0)


Generating RSA keys
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This example will generate an RSA key of a specified bitlength, and put it
into a pair of key files. One is the public key in X.509 format (PEM encoded),
the private key is in PKCS #8 format (also PEM encoded), either encrypted or
unencrypted depending on if a password was given.

.. literalinclude:: examples/rsa_kgen.cpp

Generate DSA keys
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This example generates a 2048 bit DSA key

.. literalinclude:: examples/dsa_kgen.cpp


.. _serializing_private_keys:

Serializing Private Keys Using PKCS #8
----------------------------------------

The standard format for serializing a private key is PKCS #8, the operations
for which are defined in ``pkcs8.h``. It supports both unencrypted and
encrypted storage.

.. cpp:function:: SecureVector<byte> PKCS8::BER_encode(const Private_Key& key, \
   RandomNumberGenerator& rng, const std::string& password, const std::string& pbe_algo = "")

  Takes any private key object, serializes it, encrypts it using
  *password*, and returns a binary structure representing the private
  key.

  The final (optional) argument, *pbe_algo*, specifies a particular
  password based encryption (or PBE) algorithm. If you don't specify a
  PBE, a sensible default will be used.

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

  In most situations, using unecrypted private key storage is a bad idea,
  because anyone can come along and grab the private key without having to
  know any passwords or other secrets. Unless you have very particular
  security requirements, always use the versions that encrypt the key based on
  a passphrase, described above.

.. cpp:function:: SecureVector<byte> PKCS8::BER_encode(const Private_Key& key)

  Serializes the private key and returns the result.

.. cpp:function:: std::string PKCS8::PEM_encode(const Private_Key& key)

  Serializes the private key, base64 encodes it, and returns the
  result.

Last but not least, there are some functions that will load (and
decrypt, if necessary) a PKCS #8 private key:

.. cpp:function:: Private_Key* PKCS8::load_key(DataSource& in, \
   RandomNumberGenerator& rng, const User_Interface& ui)

.. cpp:function:: Private_Key* PKCS8::load_key(DataSource& in, \
   RandomNumberGenerator& rng, std::string passphrase = "")

.. cpp:function:: Private_Key* PKCS8::load_key(const std::string& filename, \
   RandomNumberGenerator& rng, const User_Interface& ui)

.. cpp:function:: Private_Key* PKCS8::load_key(const std::string& filename, \
   RandomNumberGenerator& rng, const std::string& passphrase = "")

These functions will return an object allocated key object based on the data
from whatever source it is using (assuming, of course, the source is in fact
storing a representation of a private key, and the decryption was
sucessful). The encoding used (PEM or BER) need not be specified; the format
will be detected automatically. The key is allocated with ``new``, and should
be released with ``delete`` when you are done with it. The first takes a
generic ``DataSource`` that you have to create - the other is a simple wrapper
functions that take either a filename or a memory buffer and create the
appropriate ``DataSource``.

The versions taking a ``std::string`` attempt to decrypt using the password
given (if the key is encrypted; if it is not, the passphase value will be
ignored). If the passphrase does not decrypt the key, an exception will be
thrown.

The ones taking a ``User_Interface`` provide a simple callback interface which
makes handling incorrect passphrases and such a bit simpler. A
``User_Interface`` has very little to do with talking to users; it's just a
way to glue together Botan and whatever user interface you happen to be using.

.. note::

  In a future version, it is likely that ``User_Interface`` will be
  replaced by a simple callback using ``std::function``.

To use ``User_Interface``, derive a subclass and implement:

.. cpp:function:: std::string User_Interface::get_passphrase(const std::string& what, \
   const std::string& source, UI_Result& result) const

  The ``what`` argument specifies what the passphrase is needed for (for
  example, PKCS #8 key loading passes ``what`` as "PKCS #8 private key"). This
  lets you provide the user with some indication of *why* your application is
  asking for a passphrase; feel free to pass the string through ``gettext(3)``
  or moral equivalent for i18n purposes. Similarly, ``source`` specifies where
  the data in question came from, if available (for example, a file name). If
  the source is not available for whatever reason, then ``source`` will be an
  empty string; be sure to account for this possibility.

  The function returns the passphrase as the return value, and a status code
  in ``result`` (either ``OK`` or ``CANCEL_ACTION``). If ``CANCEL_ACTION`` is
  returned in ``result``, then the return value will be ignored, and the
  caller will take whatever action is necessary (typically, throwing an
  exception stating that the passphrase couldn't be determined). In the
  specific case of PKCS #8 key decryption, a ``Decoding_Error`` exception will
  be thrown; your UI should assume this can happen, and provide appropriate
  error handling (such as putting up a dialog box informing the user of the
  situation, and canceling the operation in progress).

.. _serializing_public_keys:

Serializing Public Keys
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To import and export public keys, use:

.. cpp:function:: MemoryVector<byte> X509::BER_encode(const Public_Key& key)

.. cpp:function:: std::string X509::PEM_encode(const Public_Key& key)

.. cpp:function:: Public_Key* X509::load_key(DataSource& in)

.. cpp:function:: Public_Key* X509::load_key(const SecureVector<byte>& buffer)

.. cpp:function:: Public_Key* X509::load_key(const std::string& filename)

  These functions operate in the same way as the ones described in
  :ref:`serializing_private_keys`, except that no encryption option is
  availabe.

.. _dl_group:

DL_Group
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

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
  look like "modp/ietf/N" where N can be any of 768, 1024, 1536, 2048, 3072,
  4096, 6144, or 8192. This group type is used for Diffie-Hellman and ElGamal
  algorithms.

  The other type, "dsa" is used for DSA and Nyberg-Rueppel keys.  They can
  also be used with Diffie-Hellman and ElGamal, but this is less common. The
  currently available groups are "dsa/jce/N" for N in 512, 768, or 1024, and
  "dsa/botan/N" with N being 2048 or 3072.  The "jce" groups are the standard
  DSA groups used in the Java Cryptography Extensions, while the "botan"
  groups were randomly generated using the FIPS 186-3 algorithm by the library
  maintainers.

You can generate a new random group using

.. cpp:function:: DL_Group::DL_Group(RandomNumberGenerator& rng, \
   PrimeType type, size_t pbits, size_t qbits = 0)

  The *type* can be either ``Strong``, ``Prime_Subgroup``, or
  ``DSA_Kosherizer``. *pbits* specifies the size of the prime in
  bits. If the *type* is ``Prime_Subgroup`` or ``DSA_Kosherizer``,
  then *qbits* specifies the size of the subgroup.

You can serialize a ``DL_Group`` using

.. cpp:function:: SecureVector<byte> DL_Group::DER_Encode(Format format)

or

.. cpp:function:: std::string DL_Group::PEM_encode(Format format)

where *format* is any of

* ``ANSI_X9_42`` (or ``DH_PARAMETERS``) for modp groups
* ``ANSI_X9_57`` (or ``DSA_PARAMETERS``) for DSA-style groups
* ``PKCS_3`` is an older format for modp groups; it should only
  be used for backwards compatability.

You can reload a serialized group using

.. cpp:function:: void DL_Group::BER_decode(DataSource& source, Format format)

.. cpp:function:: void DL_Group::PEM_decode(DataSource& source)

.. _ec_group:

EC_Group
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

An ``EC_Group`` is initialized by passing the name of the
group to be used to the constructor. These groups have
semi-standardized names like "secp256r1" and "brainpool512r1".

Key Checking
---------------------------------

Most public key algorithms have limitations or restrictions on their
parameters. For example RSA requires an odd exponent, and algorithms
based on the discrete logarithm problem need a generator $> 1$.

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

Encryption
---------------------------------

Safe public key encryption requires the use of a padding scheme which hides
the underlying mathematical properties of the algorithm.  Additionally, they
will add randomness, so encrypting the same plaintext twice produces two
different ciphertexts.

The primary interface for encryption is

.. cpp:class:: PK_Encryptor

   .. cpp:function:: SecureVector<byte> encrypt( \
         const byte* in, size_t length, RandomNumberGenerator& rng) const

   .. cpp:function:: SecureVector<byte> encrypt( \
      const MemoryRegion<byte>& in, RandomNumberGenerator& rng) const

      These encrypt a message, returning the ciphertext.

   .. cpp:function::  size_t maximum_input_size() const

      Returns the maximum size of the message that can be processed, in
      bytes. If you call :cpp:func:`PK_Encryptor::encrypt` with a value larger
      than this the operation will fail with an exception.

:cpp:class:`PK_Encryptor` is only an interface - to actually encrypt you have
to create an implementation, of which there are currently two available in the
library, :cpp:class:`PK_Encryptor_EME` and :cpp:class:`DLIES_Encryptor`. DLIES
is a standard method (from IEEE 1363) that uses a key agreement technique such
as DH or ECDH to perform message encryption. Normally, public key encryption
is done using algorithms which support it directly, such as RSA or ElGamal;
these use the EME class:

.. cpp:class:: PK_Encryptor_EME

   .. cpp:function:: PK_Encryptor_EME(const Public_Key& key, std::string eme)

     With *key* being the key you want to encrypt messages to. The padding
     method to use is specified in *eme*.

     The recommended values for *eme* is "EME1(SHA-1)" or "EME1(SHA-256)". If
     you need compatability with protocols using the PKCS #1 v1.5 standard,
     you can also use "EME-PKCS1-v1_5".

.. cpp:class:: DLIES_Encryptor

   Available in the header ``dlies.h``

   .. cpp:function:: DLIES_Encryptor(const PK_Key_Agreement_Key& key, \
         KDF* kdf, MessageAuthenticationCode* mac, size_t mac_key_len = 20)

      Where *kdf* is a key derivation function (see
      :ref:`key_derivation_function`) and *mac* is a
      MessageAuthenticationCode.

The decryption classes are named ``PK_Decryptor``, ``PK_Decryptor_EME``, and
``DLIES_Decryptor``. They are created in the exact same way, except they take
the private key, and the processing function is named ``decrypt``.


Signatures
---------------------------------

Signature generation is performed using

.. cpp:class:: PK_Signer

   .. cpp:function:: PK_Signer(const Private_Key& key, \
      const std::string& emsa, \
      Signature_Format format = IEEE_1363)

     Constructs a new signer object for the private key *key* using the
     signature format *emsa*. The key must support signature operations.  In
     the current version of the library, this includes RSA, DSA, ECDSA, GOST
     34.10-2001, Nyberg-Rueppel, and Rabin-Williams. Other signature schemes
     may be supported in the future.

     Currently available values for *emsa* include EMSA1, EMSA2, EMSA3, EMSA4,
     and Raw. All of them, except Raw, take a parameter naming a message
     digest function to hash the message with. The Raw encoding signs the
     input directly; if the message is too big, the signing operation will
     fail. Raw is not useful except in very specialized applications. Examples
     are "EMSA1(SHA-1)" and "EMSA4(SHA-256)".

     For RSA, use EMSA4 (also called PSS) unless you need compatability with
     software that uses the older PKCS #1 v1.5 standard, in which case use
     EMSA3 (also called "EMSA-PKCS1-v1_5"). For DSA, ECDSA, GOST 34.10-2001,
     and Nyberg-Rueppel, you should use EMSA1.

     The *format* defaults to ``IEEE_1363`` which is the only available
     format for RSA. For DSA and ECDSA, you can also use
     ``DER_SEQUENCE``, which will format the signature as an ASN.1
     SEQUENCE value.

   .. cpp:function:: void update(const byte* in, size_t length)
   .. cpp:function:: void update(const MemoryRegion<byte>& in)
   .. cpp:function:: void update(byte in)

      These add more data to be included in the signature
      computation. Typically, the input will be provided directly to a
      hash function.

   .. cpp:function:: SecureVector<byte> signature(RandomNumberGenerator& rng)

      Creates the signature and returns it

   .. cpp:function:: SecureVector<byte> sign_message( \
      const byte* in, size_t length, RandomNumberGenerator& rng)

   .. cpp:function:: SecureVector<byte> sign_message( \
      const MemoryRegion<byte>& in, RandomNumberGenerator& rng)

      These functions are equivalent to calling
      :cpp:func:`PK_Signer::update` and then
      :cpp:func:`PK_Signer::signature`. Any data previously provided
      using ``update`` will be included.

Signatures are verified using

.. cpp:class:: PK_Verifier

   .. cpp:function:: PK_Verifier(const Public_Key& pub_key, \
          const std::string& emsa, Signature_Format format = IEEE_1363)

      Construct a new verifier for signatures assicated with public
      key *pub_key*. The *emsa* and *format* should be the same as
      that used by the signer.

   .. cpp:function:: void update(const byte* in, size_t length)
   .. cpp:function:: void update(const MemoryRegion<byte>& in)
   .. cpp:function:: void update(byte in)

      Add further message data that is purportedly assocated with the
      signature that will be checked.

   .. cpp:function:: bool check_signature(const byte* sig, size_t length)
   .. cpp:function:: bool check_signature(const MemoryRegion<byte>& sig)

      Check to see if *sig* is a valid signature for the message data
      that was written in. Return true if so. This function clears the
      internal message state, so after this call you can call
      :cpp:func:`PK_Verifier::update` to start verifying another
      message.

   .. cpp:function:: bool verify_message(const byte* msg, size_t msg_length, \
                                         const byte* sig, size_t sig_length)

   .. cpp:function:: bool verify_message(const MemoryRegion<byte>& msg, \
                                         const MemoryRegion<byte>& sig)

      These are equivalent to calling :cpp:func:`PK_Verifier::update`
      on *msg* and then calling :cpp:func:`PK_Verifier::check_signature`
      on *sig*.

Here is an example of DSA signature generation

.. literalinclude:: examples/dsa_sign.cpp

Here is an example that verifies DSA signatures

.. literalinclude:: examples/dsa_ver.cpp

Key Agreement
---------------------------------

You can get a hold of a ``PK_Key_Agreement_Scheme`` object by calling
``get_pk_kas`` with a key that is of a type that supports key
agreement (such as a Diffie-Hellman key stored in a ``DH_PrivateKey``
object), and the name of a key derivation function. This can be "Raw",
meaning the output of the primitive itself is returned as the key, or
"KDF1(hash)" or "KDF2(hash)" where "hash" is any string you happen to
like (hopefully you like strings like "SHA-256" or "RIPEMD-160"), or
"X9.42-PRF(keywrap)", which uses the PRF specified in ANSI X9.42. It
takes the name or OID of the key wrap algorithm that will be used to
encrypt a content encryption key.

How key agreement works is that you trade public values with some
other party, and then each of you runs a computation with the other's
value and your key (this should return the same result to both
parties). This computation can be called by using
``derive_key`` with either a byte array/length pair, or a
``SecureVector<byte>`` than holds the public value of the other
party. The last argument to either call is a number that specifies how
long a key you want.

Depending on the KDF you're using, you *might not* get back a key
of the size you requested. In particular "Raw" will return a number
about the size of the Diffie-Hellman modulus, and KDF1 can only return
a key that is the same size as the output of the hash. KDF2, on the
other hand, will always give you a key exactly as long as you request,
regardless of the underlying hash used with it. The key returned is a
``SymmetricKey``, ready to pass to a block cipher, MAC, or other
symmetric algorithm.

The public value that should be used can be obtained by calling
``public_data``, which exists for any key that is associated with a
key agreement algorithm. It returns a ``SecureVector<byte>``.

"KDF2(SHA-256)" is by far the preferred algorithm for key derivation
in new applications. The X9.42 algorithm may be useful in some
circumstances, but unless you need X9.42 compatibility, KDF2 is easier
to use.

An example of using Diffie-Hellman:

.. literalinclude:: examples/dh.cpp
