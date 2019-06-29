Public Key Cryptography
=================================

Public key cryptography (also called asymmetric cryptography) is a collection
of techniques allowing for encryption, signatures, and key agreement.

Key Objects
----------------------------------------

Public and private keys are represented by classes ``Public_Key`` and it's
subclass ``Private_Key``. The use of inheritance here means that a
``Private_Key`` can be converted into a reference to a public key.

None of the functions on ``Public_Key`` and ``Private_Key`` itself are
particularly useful for users of the library, because 'bare' public key
operations are *very insecure*. The only purpose of these functions is to
provide a clean interface that higher level operations can be built on. So
really the only thing you need to know is that when a function takes a
reference to a ``Public_Key``, it can take any public key or private key, and
similarly for ``Private_Key``.

Types of ``Public_Key`` include ``RSA_PublicKey``, ``DSA_PublicKey``,
``ECDSA_PublicKey``, ``ECKCDSA_PublicKey``, ``ECGDSA_PublicKey``, ``DH_PublicKey``, ``ECDH_PublicKey``,
``Curve25519_PublicKey``, ``ElGamal_PublicKey``, ``McEliece_PublicKey``, ``XMSS_PublicKey``
and ``GOST_3410_PublicKey``.  There are corresponding ``Private_Key`` classes for each of these algorithms.

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
  ``PBE-PKCS5v20(CIPHER,PBKDF)``. Since 2.8.0, ``PBES2(CIPHER,PBKDF)`` also works.
  Cipher can be any block cipher with /CBC or /GCM appended, for example
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
  been supported in PBES2 since 1.11.10. SIV has been supported since 2.8.

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
successful). The encoding used (PEM or BER) need not be specified; the format
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

.. cpp:function:: std::vector<uint8_t> X509::BER_encode(const Public_Key& key)

.. cpp:function:: std::string X509::PEM_encode(const Public_Key& key)

.. cpp:function:: Public_Key* X509::load_key(DataSource& in)

.. cpp:function:: Public_Key* X509::load_key(const secure_vector<uint8_t>& buffer)

.. cpp:function:: Public_Key* X509::load_key(const std::string& filename)

  These functions operate in the same way as the ones described in
  :ref:`serializing_private_keys`, except that no encryption option is
  available.

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
"""""""""""""""""
The example below creates a new 2048 bit ``DL_Group``, prints the generated
parameters and ANSI_X9_42 encodes the created group for further usage with DH.

.. code-block:: cpp

    #include <botan/dl_group.h>
    #include <botan/auto_rng.h>
    #include <botan/rng.h>
    #include <iostream>

    int main()
       {
    	  std::unique_ptr<Botan::RandomNumberGenerator> rng(new Botan::AutoSeeded_RNG);
    	  std::unique_ptr<Botan::DL_Group> group(new Botan::DL_Group(*rng.get(), Botan::DL_Group::Strong, 2048));
    	  std::cout << std::endl << "p: " << group->get_p();
    	  std::cout << std::endl << "q: " << group->get_q();
    	  std::cout << std::endl << "g: " << group->get_q();
    	  std::cout << std::endl << "ANSI_X9_42: " << std::endl << group->PEM_encode(Botan::DL_Group::ANSI_X9_42);

        return 0;
       }


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

.. code-block:: cpp

    #include <botan/x509cert.h>
    #include <botan/auto_rng.h>
    #include <botan/rng.h>

    int main()
       {
       Botan::X509_Certificate cert("cert.pem");
       std::unique_ptr<Botan::RandomNumberGenerator> rng(new Botan::AutoSeeded_RNG);
       std::unique_ptr<Botan::Public_Key> key(cert.subject_public_key());
       if(!key->check_key(*rng.get(), false))
          {
          throw std::invalid_argument("Loaded key is invalid");
          }
       }

Encryption
---------------------------------

Safe public key encryption requires the use of a padding scheme which hides
the underlying mathematical properties of the algorithm.  Additionally, they
will add randomness, so encrypting the same plaintext twice produces two
different ciphertexts.

The primary interface for encryption is

.. cpp:class:: PK_Encryptor

   .. cpp:function:: secure_vector<uint8_t> encrypt( \
         const uint8_t* in, size_t length, RandomNumberGenerator& rng) const

   .. cpp:function:: secure_vector<uint8_t> encrypt( \
      const std::vector<uint8_t>& in, RandomNumberGenerator& rng) const

      These encrypt a message, returning the ciphertext.

   .. cpp:function::  size_t maximum_input_size() const

      Returns the maximum size of the message that can be processed, in
      bytes. If you call :cpp:func:`PK_Encryptor::encrypt` with a value larger
      than this the operation will fail with an exception.

:cpp:class:`PK_Encryptor` is only an interface - to actually encrypt you have
to create an implementation, of which there are currently three available in the
library, :cpp:class:`PK_Encryptor_EME`, :cpp:class:`DLIES_Encryptor` and
:cpp:class:`ECIES_Encryptor`. DLIES is a hybrid encryption scheme (from
IEEE 1363) that uses the DH key agreement technique in combination with a KDF, a
MAC and a symmetric encryption algorithm to perform message encryption. ECIES is
similar to DLIES, but uses ECDH for the key agreement. Normally, public key
encryption is done using algorithms which support it directly, such as RSA or
ElGamal; these use the EME class:

.. cpp:class:: PK_Encryptor_EME

   .. cpp:function:: PK_Encryptor_EME(const Public_Key& key, std::string eme)

     With *key* being the key you want to encrypt messages to. The padding
     method to use is specified in *eme*.

     The recommended values for *eme* is "EME1(SHA-1)" or "EME1(SHA-256)". If
     you need compatibility with protocols using the PKCS #1 v1.5 standard,
     you can also use "EME-PKCS1-v1_5".

.. cpp:class:: DLIES_Encryptor

   Available in the header ``dlies.h``

   .. cpp:function:: DLIES_Encryptor(const DH_PrivateKey& own_priv_key, \
         RandomNumberGenerator& rng, KDF* kdf, MessageAuthenticationCode* mac, \
         size_t mac_key_len = 20)

      Where *kdf* is a key derivation function (see
      :ref:`key_derivation_function`) and *mac* is a
      MessageAuthenticationCode. The encryption is performed by XORing the
      message with a stream of bytes provided by the KDF.

   .. cpp:function:: DLIES_Encryptor(const DH_PrivateKey& own_priv_key, \
         RandomNumberGenerator& rng, KDF* kdf, Cipher_Mode* cipher, \
         size_t cipher_key_len, MessageAuthenticationCode* mac, \
         size_t mac_key_len = 20)

      Instead of XORing the message a block cipher can be specified.

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
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The following Code sample reads a PKCS #8 keypair from the passed location and
subsequently encrypts a fixed plaintext with the included public key, using EME1
with SHA-256. For the sake of completeness, the ciphertext is then decrypted using
the private key.

.. code-block:: cpp

  #include <botan/pkcs8.h>
  #include <botan/hex.h>
  #include <botan/pk_keys.h>
  #include <botan/pubkey.h>
  #include <botan/auto_rng.h>
  #include <botan/rng.h>
  #include <iostream>
  int main (int argc, char* argv[])
    {
    if(argc!=2)
       return 1;
    std::string plaintext("Your great-grandfather gave this watch to your granddad for good luck. Unfortunately, Dane's luck wasn't as good as his old man's.");
    std::vector<uint8_t> pt(plaintext.data(),plaintext.data()+plaintext.length());
    std::unique_ptr<Botan::RandomNumberGenerator> rng(new Botan::AutoSeeded_RNG);

    //load keypair
    std::unique_ptr<Botan::Private_Key> kp(Botan::PKCS8::load_key(argv[1],*rng.get()));

    //encrypt with pk
    Botan::PK_Encryptor_EME enc(*kp,*rng.get(), "EME1(SHA-256)");
    std::vector<uint8_t> ct = enc.encrypt(pt,*rng.get());

    //decrypt with sk
    Botan::PK_Decryptor_EME dec(*kp,*rng.get(), "EME1(SHA-256)");
    std::cout << std::endl << "enc: " << Botan::hex_encode(ct) << std::endl << "dec: "<< Botan::hex_encode(dec.decrypt(ct));

    return 0;
    }


Signatures
---------------------------------

Signature generation is performed using

.. cpp:class:: PK_Signer

   .. cpp:function:: PK_Signer(const Private_Key& key, \
      const std::string& emsa, \
      Signature_Format format = IEEE_1363)

     Constructs a new signer object for the private key *key* using the
     signature format *emsa*. The key must support signature operations.  In
     the current version of the library, this includes RSA, DSA, ECDSA, ECKCDSA,
     ECGDSA, GOST 34.10-2001. Other signature schemes may be supported in the future.

     .. note::

       Botan both supports non-deterministic and deterministic (as per RFC
       6979) DSA and ECDSA signatures. Deterministic signatures are compatible
       in the way that they can be verified with a non-deterministic implementation.
       If the ``rfc6979`` module is enabled, deterministic DSA and ECDSA signatures
       will be generated.

     Currently available values for *emsa* include EMSA1, EMSA2, EMSA3, EMSA4,
     and Raw. All of them, except Raw, take a parameter naming a message
     digest function to hash the message with. The Raw encoding signs the
     input directly; if the message is too big, the signing operation will
     fail. Raw is not useful except in very specialized applications. Examples
     are "EMSA1(SHA-1)" and "EMSA4(SHA-256)".

     For RSA, use EMSA4 (also called PSS) unless you need compatibility with
     software that uses the older PKCS #1 v1.5 standard, in which case use
     EMSA3 (also called "EMSA-PKCS1-v1_5"). For DSA, ECDSA, ECKCDSA, ECGDSA and
     GOST 34.10-2001 you should use EMSA1.

     The *format* defaults to ``IEEE_1363`` which is the only available
     format for RSA. For DSA, ECDSA, ECGDSA and ECKCDSA you can also use
     ``DER_SEQUENCE``, which will format the signature as an ASN.1
     SEQUENCE value.

   .. cpp:function:: void update(const uint8_t* in, size_t length)
   .. cpp:function:: void update(const std::vector<uint8_t>& in)
   .. cpp:function:: void update(uint8_t in)

      These add more data to be included in the signature
      computation. Typically, the input will be provided directly to a
      hash function.

   .. cpp:function:: secure_vector<uint8_t> signature(RandomNumberGenerator& rng)

      Creates the signature and returns it

   .. cpp:function:: secure_vector<uint8_t> sign_message( \
      const uint8_t* in, size_t length, RandomNumberGenerator& rng)

   .. cpp:function:: secure_vector<uint8_t> sign_message( \
      const std::vector<uint8_t>& in, RandomNumberGenerator& rng)

      These functions are equivalent to calling
      :cpp:func:`PK_Signer::update` and then
      :cpp:func:`PK_Signer::signature`. Any data previously provided
      using ``update`` will be included.

Signatures are verified using

.. cpp:class:: PK_Verifier

   .. cpp:function:: PK_Verifier(const Public_Key& pub_key, \
          const std::string& emsa, Signature_Format format = IEEE_1363)

      Construct a new verifier for signatures associated with public
      key *pub_key*. The *emsa* and *format* should be the same as
      that used by the signer.

   .. cpp:function:: void update(const uint8_t* in, size_t length)
   .. cpp:function:: void update(const std::vector<uint8_t>& in)
   .. cpp:function:: void update(uint8_t in)

      Add further message data that is purportedly associated with the
      signature that will be checked.

   .. cpp:function:: bool check_signature(const uint8_t* sig, size_t length)
   .. cpp:function:: bool check_signature(const std::vector<uint8_t>& sig)

      Check to see if *sig* is a valid signature for the message data
      that was written in. Return true if so. This function clears the
      internal message state, so after this call you can call
      :cpp:func:`PK_Verifier::update` to start verifying another
      message.

   .. cpp:function:: bool verify_message(const uint8_t* msg, size_t msg_length, \
                                         const uint8_t* sig, size_t sig_length)

   .. cpp:function:: bool verify_message(const std::vector<uint8_t>& msg, \
                                         const std::vector<uint8_t>& sig)

      These are equivalent to calling :cpp:func:`PK_Verifier::update`
      on *msg* and then calling :cpp:func:`PK_Verifier::check_signature`
      on *sig*.


Botan implements the following signature algorithms:

1. RSA
#. DSA
#. ECDSA
#. ECGDSA
#. ECKDSA
#. GOST 34.10-2001
#. Ed25519
#. SM2

Code Example
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following sample program below demonstrates the generation of a new ECDSA keypair over the curve secp512r1
and a ECDSA signature using EMSA1 with SHA-256. Subsequently the computed signature is validated.

.. code-block:: cpp

  #include <botan/auto_rng.h>
  #include <botan/ecdsa.h>
  #include <botan/ec_group.h>
  #include <botan/pubkey.h>
  #include <botan/hex.h>
  #include <iostream>

  int main()
    {
    Botan::AutoSeeded_RNG rng;
    // Generate ECDSA keypair
    Botan::ECDSA_PrivateKey key(rng, Botan::EC_Group("secp521r1"));

    std::string text("This is a tasty burger!");
    std::vector<uint8_t> data(text.data(),text.data()+text.length());
    // sign data
    Botan::PK_Signer signer(key, rng, "EMSA1(SHA-256)");
    signer.update(data);
    std::vector<uint8_t> signature = signer.signature(rng);
    std::cout << "Signature:" << std::endl << Botan::hex_encode(signature);
    // verify signature
    Botan::PK_Verifier verifier(key, "EMSA1(SHA-256)");
    verifier.update(data);
    std::cout << std::endl << "is " << (verifier.check_signature(signature)? "valid" : "invalid");
    return 0;
    }


Ed25519 Variants
^^^^^^^^^^^^^^^^^^

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
``secure_vector<uint8_t>`` than holds the public value of the other
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
key agreement algorithm. It returns a ``secure_vector<uint8_t>``.

"KDF2(SHA-256)" is by far the preferred algorithm for key derivation
in new applications. The X9.42 algorithm may be useful in some
circumstances, but unless you need X9.42 compatibility, KDF2 is easier
to use.


Botan implements the following key agreement methods:

1. ECDH over GF(p) Weierstrass curves
#. ECDH over x25519
#. DH over prime fields
#. McEliece
#. NewHope

Code Example
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The code below performs an unauthenticated ECDH key agreement using the secp521r elliptic curve and
applies the key derivation function KDF2(SHA-256) with 256 bit output length to the computed shared secret.

.. code-block:: cpp

  #include <botan/auto_rng.h>
  #include <botan/ecdh.h>
  #include <botan/ec_group.h>
  #include <botan/pubkey.h>
  #include <botan/hex.h>
  #include <iostream>

  int main()
     {
     Botan::AutoSeeded_RNG rng;
     // ec domain and
     Botan::EC_Group domain("secp521r1");
     std::string kdf = "KDF2(SHA-256)";
     // generate ECDH keys
     Botan::ECDH_PrivateKey keyA(rng, domain);
     Botan::ECDH_PrivateKey keyB(rng, domain);
     // Construct key agreements
     Botan::PK_Key_Agreement ecdhA(keyA,rng,kdf);
     Botan::PK_Key_Agreement ecdhB(keyB,rng,kdf);
     // Agree on shared secret and derive symmetric key of 256 bit length
     Botan::secure_vector<uint8_t> sA = ecdhA.derive_key(32,keyB.public_value()).bits_of();
     Botan::secure_vector<uint8_t> sB = ecdhB.derive_key(32,keyA.public_value()).bits_of();

     if(sA != sB)
        return 1;

     std::cout << "agreed key: " << std::endl << Botan::hex_encode(sA);
     return 0;
     }


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

One such scheme, KEM, is provided in Botan currently. It it a somewhat unusual
scheme in that it outputs two values, a symmetric key for use with an AEAD, and
an encrypted key. It does this by choosing a random plaintext (n - log2(n)*t
bits) using ``McEliece_PublicKey::random_plaintext_element``. Then a random
error mask is chosen and the message is coded and masked. The symmetric key is
SHA-512(plaintext || error_mask). As long as the resulting key is used with a
secure AEAD scheme (which can be used for transporting arbitrary amounts of
data), CCA2 security is provided.

In ``mcies.h`` there are functions for this combination:

.. cpp:function:: secure_vector<uint8_t> mceies_encrypt(const McEliece_PublicKey& pubkey, \
                  const secure_vector<uint8_t>& pt, \
                  uint8_t ad[], size_t ad_len, \
                  RandomNumberGenerator& rng, \
                  const std::string& aead = "AES-256/OCB")

.. cpp:function:: secure_vector<uint8_t> mceies_decrypt(const McEliece_PrivateKey& privkey, \
                                                     const secure_vector<uint8_t>& ct, \
                                                     uint8_t ad[], size_t ad_len, \
                                                     const std::string& aead = "AES-256/OCB")

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

XMSS uses the Botan interfaces for public key cryptography.
The following algorithms are implemented:

1. XMSS-SHA2_10_256
# XMSS-SHA2_16_256
# XMSS-SHA2_20_256
# XMSS-SHA2_10_512
# XMSS-SHA2_16_512
# XMSS-SHA2_20_512
# XMSS-SHAKE_10_256
# XMSS-SHAKE_16_256
# XMSS-SHAKE_20_256
# XMSS-SHAKE_10_512
# XMSS-SHAKE_16_512
# XMSS-SHAKE_20_512

The algorithm name contains the hash function name, tree height and digest
width defined by the corresponding parameter set. Choosing `XMSS-SHA2_10_256`
for instance will use the SHA2-256 hash function to generate a tree of height
ten.

Code Example
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following code snippet shows a minimum example on how to create an XMSS
public/private key pair and how to use these keys to create and verify a
signature:

.. code-block:: cpp

    #include <iostream>
    #include <botan/secmem.h>
    #include <botan/auto_rng.h>
    #include <botan/xmss.h>

    int main()
       {
       // Create a random number generator used for key generation.
       Botan::AutoSeeded_RNG rng;

       // create a new public/private key pair using SHA2 256 as hash
       // function and a tree height of 10.
       Botan::XMSS_PrivateKey private_key(
          Botan::XMSS_Parameters::xmss_algorithm_t::XMSS_SHA2_10_256,
          rng);
       Botan::XMSS_PublicKey public_key(private_key);

       // create signature operation using the private key.
       std::unique_ptr<Botan::PK_Ops::Signature> sig_op =
          private_key.create_signature_op(rng, "", "");

       // create and sign a message using the signature operation.
       Botan::secure_vector<uint8_t> msg { 0x01, 0x02, 0x03, 0x04 };
       sig_op->update(msg.data(), msg.size());
       Botan::secure_vector<uint8_t> sig = sig_op->sign(rng);

       // create verification operation using the public key
       std::unique_ptr<Botan::PK_Ops::Verification> ver_op =
          public_key.create_verification_op("", "");

       // verify the signature for the previously generated message.
       ver_op->update(msg.data(), msg.size());
       if(ver_op->is_valid_signature(sig.data(), sig.size()))
          {
          std::cout << "Success." << std::endl;
          }
       else
          {
          std::cout << "Error." << std::endl;
          }
       }
