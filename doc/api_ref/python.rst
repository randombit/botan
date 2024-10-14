
Python Binding
========================================

.. versionadded:: 1.11.14

.. highlight:: python

.. py:module:: botan3

The Python binding is based on the `ffi` module of botan and the
`ctypes` module of the Python standard library.

The versioning of the Python module follows the major versioning of
the C++ library. So for Botan 2, the module is named ``botan2`` while
for Botan 3 it is ``botan3``.

Versioning
----------------------------------------
.. py:function:: version_major()

   Returns the major number of the library version.

.. py:function:: version_minor()

   Returns the minor number of the library version.

.. py:function:: version_patch()

   Returns the patch number of the library version.

.. py:function:: version_string()

   Returns a free form version string for the library

Random Number Generators
----------------------------------------

.. py:class:: RandomNumberGenerator(rng_type = 'system')

     Previously ``rng``

     Type 'user' also allowed (userspace HMAC_DRBG seeded from system
     rng). The system RNG is very cheap to create, as just a single file
     handle or CSP handle is kept open, from first use until shutdown,
     no matter how many 'system' rng instances are created. Thus it is
     easy to use the RNG in a one-off way, with `botan.RandomNumberGenerator().get(32)`.

     When Botan is configured with TPM 2.0 support, also 'tpm2' is allowed
     to instantiate a TPM-backed RNG. Note that this requires passing
     additional named arguments ``tpm2_context=`` with a ``TPM2Context`` and
     (optionally) ``tpm2_sessions=`` with one or more ``TPM2Session`` objects.

   .. py:method:: get(length)

      Return some bytes

   .. py:method:: reseed(bits = 256)

      Meaningless on system RNG, on userspace RNG causes a reseed/rekey

   .. py:method:: reseed_from_rng(source_rng, bits = 256)

      Take bits from the source RNG and use it to seed ``self``

   .. py:method:: add_entropy(seed)

      Add some unpredictable seed data to the RNG

Hash Functions
----------------------------------------

.. py:class:: HashFunction(algo)

    Previously ``hash_function``

    The ``algo`` param is a string (eg 'SHA-1', 'SHA-384', 'BLAKE2b')

    .. py:method:: algo_name()

       Returns the name of this algorithm

    .. py:method:: clear()

       Clear state

    .. py:method:: output_length()

       Return output length in bytes

    .. py:method:: update(x)

       Add some input

    .. py:method:: final()

       Returns the hash of all input provided, resets
       for another message.

Message Authentication Codes
----------------------------------------

.. py:class:: MsgAuthCode(algo)

    Previously ``message_authentication_code``

    Algo is a string (eg 'HMAC(SHA-256)', 'Poly1305', 'CMAC(AES-256)')

    .. py:method:: algo_name()

       Returns the name of this algorithm

    .. py:method:: clear()

       Clear internal state including the key

    .. py:method:: output_length()

       Return the output length in bytes

    .. py:method:: set_key(key)

       Set the key

    .. py:method:: update(x)

       Add some input

    .. py:method:: final()

       Returns the MAC of all input provided, resets
       for another message with the same key.

Ciphers
----------------------------------------

.. py:class:: SymmetricCipher(object, algo, encrypt = True)

       Previously ``cipher``

       The algorithm is spcified as a string (eg 'AES-128/GCM',
       'Serpent/OCB(12)', 'Threefish-512/EAX').

       Set the second param to False for decryption

    .. py:method:: algo_name()

       Returns the name of this algorithm

    .. py:method:: tag_length()

       Returns the tag length (0 for unauthenticated modes)

    .. py:method:: default_nonce_length()

       Returns default nonce length

    .. py:method:: update_granularity()

       Returns update block size. Call to update() must provide input
       of exactly this many bytes

    .. py:method:: is_authenticated()

       Returns True if this is an AEAD mode

    .. py:method:: valid_nonce_length(nonce_len)

       Returns True if nonce_len is a valid nonce len for this mode

    .. py:method:: clear()

       Resets all state

    .. py:method:: set_key(key)

       Set the key

    .. py:method:: set_assoc_data(ad)

       Sets the associated data. Fails if this is not an AEAD mode

    .. py:method:: start(nonce)

       Start processing a message using nonce

    .. py:method:: update(txt)

       Consumes input text and returns output. Input text must be of
       update_granularity() length.  Alternately, always call finish
       with the entire message, avoiding calls to update entirely

    .. py:method:: finish(txt = None)

       Finish processing (with an optional final input). May throw if
       message authentication checks fail, in which case all plaintext
       previously processed must be discarded. You may call finish()
       with the entire message

Bcrypt
----------------------------------------

.. py:function:: bcrypt(passwd, rng, work_factor = 10)

   Provided the password and an RNG object, returns a bcrypt string

.. py:function:: check_bcrypt(passwd, bcrypt)

   Check a bcrypt hash against the provided password, returning True
   iff the password matches.

PBKDF
----------------------------------------

.. py:function:: pbkdf(algo, password, out_len, iterations = 100000, salt = None)

   Runs a PBKDF2 algo specified as a string (eg 'PBKDF2(SHA-256)',
   'PBKDF2(CMAC(Blowfish))').  Runs with specified iterations, with
   meaning depending on the algorithm.  The salt can be provided or
   otherwise is randomly chosen. In any case it is returned from the
   call.

   Returns out_len bytes of output (or potentially less depending on
   the algorithm and the size of the request).

   Returns tuple of salt, iterations, and psk

.. py:function:: pbkdf_timed(algo, password, out_len, ms_to_run = 300, salt = rng().get(12))

   Runs for as many iterations as needed to consumed ms_to_run
   milliseconds on whatever we're running on. Returns tuple of salt,
   iterations, and psk

Scrypt
---------------

.. versionadded:: 2.8.0

.. py:function:: scrypt(out_len, password, salt, N=1024, r=8, p=8)

   Runs Scrypt key derivation function over the specified password
   and salt using Scrypt parameters N, r, p.

KDF
----------------------------------------

.. py:function:: kdf(algo, secret, out_len, salt)

   Performs a key derviation function (such as "HKDF(SHA-384)") over
   the provided secret and salt values. Returns a value of the
   specified length.

Public Key
----------------------------------------

.. py:class:: PublicKey(object)

  Previously ``public_key``

  .. py:classmethod:: load(val)

     Load a public key. The value should be a PEM or DER blob.

  .. py:classmethod:: load_rsa(n, e)

     Load an RSA public key giving the modulus and public exponent
     as integers.

  .. py:classmethod:: load_dsa(p, q, g, y)

     Load an DSA public key giving the parameters and public value
     as integers.

  .. py:classmethod:: load_dh(p, g, y)

     Load an Diffie-Hellman public key giving the parameters and
     public value as integers.

  .. py:classmethod:: load_elgamal(p, q, g, y)

     Load an ElGamal public key giving the parameters and
     public value as integers.

  .. py:classmethod:: load_ecdsa(curve, pub_x, pub_y)

     Load an ECDSA public key giving the curve as a string
     (like "secp256r1") and the public point as a pair of
     integers giving the affine coordinates.

  .. py:classmethod:: load_ecdh(curve, pub_x, pub_y)

     Load an ECDH public key giving the curve as a string
     (like "secp256r1") and the public point as a pair of
     integers giving the affine coordinates.

  .. py:classmethod:: load_sm2(curve, pub_x, pub_y)

     Load a SM2 public key giving the curve as a string (like
     "sm2p256v1") and the public point as a pair of integers giving
     the affine coordinates.

  .. py:classmethod:: load_ml_kem(mode, raw_encoding)

     Load an ML-KEM public key giving the mode as a string (like
     "ML-KEM-512") and the raw encoding of the public key.

  .. py:classmethod:: load_ml_dsa(mode, raw_encoding)

     Load an ML-DSA public key giving the mode as a string (like
     "ML-DSA-4x4") and the raw encoding of the public key.

  .. py:classmethod:: load_slh_dsa(mode, raw_encoding)

     Load an SLH-DSA public key giving the mode as a string (like
     "SLH-DSA-SHAKE-128f") and the raw encoding of the public key.

  .. py:method:: check_key(rng_obj, strong=True):

     Test the key for consistency. If ``strong`` is ``True`` then
     more expensive tests are performed.

  .. py:method:: export(pem=False)

     Exports the public key using the usual X.509 SPKI representation.
     If ``pem`` is True, the result is a PEM encoded string. Otherwise
     it is a binary DER value.

  .. py:method:: to_der()

     Like ``self.export(False)``

  .. py:method:: to_pem()

     Like ``self.export(True)``

  .. py:method:: to_raw()

     Exports the key in its canonical raw encoding. This might not be
     available for all key types and raise an exception in that case.

  .. py:method:: get_field(field_name)

     Return an integer field related to the public key. The valid field names
     vary depending on the algorithm. For example RSA public modulus can be
     extracted with ``rsa_key.get_field("n")``.

  .. py:method:: fingerprint(hash = 'SHA-256')

     Returns a hash of the public key

  .. py:method:: algo_name()

     Returns the algorithm name

  .. py:method:: estimated_strength()

     Returns the estimated strength of this key against known attacks
     (NFS, Pollard's rho, etc)

Private Key
----------------------------------------

.. py:class:: PrivateKey

  Previously ``private_key``

  .. py:classmethod:: create(algo, param, rng)

     Creates a new private key. The parameter type/value depends on
     the algorithm. For "rsa" is is the size of the key in bits.
     For "ecdsa" and "ecdh" it is a group name (for instance
     "secp256r1"). For "ecdh" there is also a special case for groups
     "curve25519" and "x448" (which are actually completely distinct key types
     with a non-standard encoding).

  .. py:classmethod:: load(val, passphrase="")

     Return a private key (DER or PEM formats accepted)

  .. py:classmethod:: load_rsa(p, q, e)

     Return a private RSA key

  .. py:classmethod:: load_dsa(p, q, g, x)

     Return a private DSA key

  .. py:classmethod:: load_dh(p, g, x)

     Return a private DH key

  .. py:classmethod:: load_elgamal(p, q, g, x)

     Return a private ElGamal key

  .. py:classmethod:: load_ecdsa(curve, x)

     Return a private ECDSA key

  .. py:classmethod:: load_ecdh(curve, x)

     Return a private ECDH key

  .. py:classmethod:: load_sm2(curve, x)

     Return a private SM2 key

  .. py:classmethod:: load_ml_kem(mode, raw_encoding)

     Return a private ML-KEM key

  .. py:classmethod:: load_ml_dsa(mode, raw_encoding)

      Return a private ML-DSA key

  .. py:classmethod:: load_slh_dsa(mode, raw_encoding)

      Return a private SLH-DSA key

  .. py:method:: get_public_key()

     Return a public_key object

  .. py:method:: to_pem()

     Return the PEM encoded private key (unencrypted). Like ``self.export(True)``

  .. py:method:: to_der()

     Return the PEM encoded private key (unencrypted). Like ``self.export(False)``

  .. py:method:: to_raw()

     Exports the key in its canonical raw encoding. This might not be
     available for all key types and raise an exception in that case.

  .. py:method:: check_key(rng_obj, strong=True):

     Test the key for consistency. If ``strong`` is ``True`` then
     more expensive tests are performed.

  .. py:method:: algo_name()

     Returns the algorithm name

  .. py:method:: export(pem=False)

     Exports the private key in PKCS8 format. If ``pem`` is True, the
     result is a PEM encoded string. Otherwise it is a binary DER
     value. The key will not be encrypted.

  .. py:method:: export_encrypted(passphrase, rng, pem=False, msec=300, cipher=None, pbkdf=None)

     Exports the private key in PKCS8 format, encrypted using the
     provided passphrase. If ``pem`` is True, the result is a PEM
     encoded string. Otherwise it is a binary DER value.

  .. py:method:: get_field(field_name)

     Return an integer field related to the public key. The valid field names
     vary depending on the algorithm. For example first RSA secret prime can be
     extracted with ``rsa_key.get_field("p")``. This function can also be
     used to extract the public parameters.

Public Key Operations
----------------------------------------

.. py:class:: PKEncrypt(pubkey, padding)

    Previously ``pk_op_encrypt``

    .. py:method:: encrypt(msg, rng)

.. py:class:: PKDecrypt(privkey, padding)

    Previously ``pk_op_decrypt``

    .. py:method:: decrypt(msg)

.. py:class:: PKSign(privkey, hash_w_padding)

    Previously ``pk_op_sign``

    .. py:method:: update(msg)
    .. py:method:: finish(rng)

.. py:class:: PKVerify(pubkey, hash_w_padding)

    Previously ``pk_op_verify``

    .. py:method:: update(msg)
    .. py:method:: check_signature(signature)

.. py:class:: PKKeyAgreement(privkey, kdf)

    Previously ``pk_op_key_agreement``

    .. py:method:: public_value()

    Returns the public value to be passed to the other party

    .. py:method:: agree(other, key_len, salt)

    Returns a key derived by the KDF.

TPM 2.0 Bindings
-------------------------------------

.. versionadded:: 3.6.0

.. py:class:: TPM2Context(tcti_nameconf = None, tcti_conf = None)

   Create a TPM 2.0 context optionally with a TCTI name and configuration,
   separated by a colon, or as separate parameters.

   .. py:method:: supports_botan_crypto_backend()

   Returns True if the TPM adapter can use Botan-based crypto primitives
   to communicate with the TPM

   .. py:method:: enable_botan_crypto_backend(rng)

   Enables the TPM adapter to use Botan-based crypto primitives. The passed
   RNG must not depend on the TPM itself.

.. py:class:: TPM2UnauthenticatedSession(ctx)

   Creates a TPM 2.0 session that is not bound to any authentication credential
   but provides basic parameter encryption between the TPM and the application.

Multiple Precision Integers (MPI)
-------------------------------------
.. versionadded:: 2.8.0

.. py:class:: MPI(initial_value=None, radix=None)

   Initialize an MPI object with specified value, left as zero otherwise.  The
   ``initial_value`` should be an ``int``, ``str``, or ``MPI``.
   The ``radix`` value should be set to 16 when initializing from a base 16 `str` value.


   Most of the usual arithmetic operators (``__add__``, ``__mul__``, etc) are
   defined.

   .. py:method:: inverse_mod(modulus)

      Return the inverse of ``self`` modulo ``modulus``, or zero if no inverse exists

   .. py:method:: is_prime(rng, prob=128)

      Test if ``self`` is prime

   .. py:method:: pow_mod(exponent, modulus):

      Return ``self`` to the ``exponent`` power modulo ``modulus``

   .. py:method:: mod_mul(other, modulus):

      Return the multiplication product of ``self`` and ``other`` modulo ``modulus``

   .. py:method:: gcd(other):

      Return the greatest common divisor of ``self`` and ``other``


Format Preserving Encryption (FE1 scheme)
-----------------------------------------
.. versionadded:: 2.8.0

.. py:class:: FormatPreservingEncryptionFE1(modulus, key, rounds=5, compat_mode=False)

   Initialize an instance for format preserving encryption

   .. py:method:: encrypt(msg, tweak)

      The msg should be a botan3.MPI or an object which can be converted to one

   .. py:method:: decrypt(msg, tweak)

      The msg should be a botan3.MPI or an object which can be converted to one

HOTP
-----------------------------------------
.. versionadded:: 2.8.0

.. py:class:: HOTP(key, hash="SHA-1", digits=6)

   .. py:method:: generate(counter)

      Generate an HOTP code for the provided counter

   .. py:method:: check(code, counter, resync_range=0)

      Check if provided ``code`` is the correct code for ``counter``.
      If ``resync_range`` is greater than zero, HOTP also checks
      up to ``resync_range`` following counter values.

      Returns a tuple of (bool,int) where the boolean indicates if the
      code was valid, and the int indicates the next counter value
      that should be used. If the code did not verify, the next
      counter value is always identical to the counter that was passed
      in. If the code did verify and resync_range was zero, then the
      next counter will always be counter+1.

X509Cert
-----------------------------------------

.. py:class:: X509Cert(filename=None, buf=None)

   .. py:method:: time_starts()

      Return the time the certificate becomes valid, as a string in form
      "YYYYMMDDHHMMSSZ" where Z is a literal character reflecting that this time is
      relative to UTC.

   .. py:method:: time_expires()

      Return the time the certificate expires, as a string in form
      "YYYYMMDDHHMMSSZ" where Z is a literal character reflecting that this time is
      relative to UTC.

   .. py:method:: to_string()

      Format the certificate as a free-form string.

   .. py:method:: fingerprint(hash_algo='SHA-256')

      Return a fingerprint for the certificate, which is basically just a hash
      of the binary contents. Normally SHA-1 or SHA-256 is used, but any hash
      function is allowed.

   .. py:method:: serial_number()

      Return the serial number of the certificate.

   .. py:method:: authority_key_id()

      Return the authority key ID set in the certificate, which may be empty.

   .. py:method:: subject_key_id()

      Return the subject key ID set in the certificate, which may be empty.

   .. py:method:: subject_public_key_bits()

      Get the serialized representation of the public key included in this certificate.

   .. py:method:: subject_public_key()

      Get the public key included in this certificate as an object of class ``PublicKey``.

   .. py:method:: subject_dn(key, index)

      Get a value from the subject DN field.

      ``key`` specifies a value to get, for instance ``"Name"`` or `"Country"`.

   .. py:method:: issuer_dn(key, index)

      Get a value from the issuer DN field.

      ``key`` specifies a value to get, for instance ``"Name"`` or `"Country"`.

   .. py:method:: hostname_match(hostname)

      Return True if the Common Name (CN) field of the certificate matches a given ``hostname``.

   .. py:method:: not_before()

      Return the time the certificate becomes valid, as seconds since epoch.

   .. py:method:: not_after()

      Return the time the certificate expires, as seconds since epoch.

   .. py:method:: allowed_usage(usage_list)

      Return True if the certificates Key Usage extension contains all constraints given in ``usage_list``.
      Also return True if the certificate doesn't have this extension.
      Example usage constraints are: ``"DIGITAL_SIGNATURE"``, ``"KEY_CERT_SIGN"``, ``"CRL_SIGN"``.

   .. py:method:: verify(intermediates=None, \
                  trusted=None, \
                  trusted_path=None, \
                  required_strength=0, \
                  hostname=None, \
                  reference_time=0 \
                  crls=None)

      Verify a certificate. Returns 0 if validation was successful, returns a positive error code
      if the validation was unsuccesful.

      ``intermediates`` is a list of untrusted subauthorities.

      ``trusted`` is a list of trusted root CAs.

      The `trusted_path` refers to a directory where one or more trusted CA
      certificates are stored.

      Set ``required_strength`` to indicate the minimum key and hash strength
      that is allowed. For instance setting to 80 allows 1024-bit RSA and SHA-1.
      Setting to 110 requires 2048-bit RSA and SHA-256 or higher. Set to zero
      to accept a default.

      If ``hostname`` is given, it will be checked against the certificates CN field.

      Set ``reference_time`` to be the time which the certificate chain is
      validated against. Use zero (default) to use the current system clock.

      ``crls`` is a list of CRLs issued by either trusted or untrusted authorities.

   .. py:classmethod:: validation_status(error_code)

      Return an informative string associated with the verification return code.

   .. py:method:: is_revoked(self, crl)

      Check if the certificate (``self``) is revoked on the given ``crl``.

X509CRL
-----------------------------------------

.. py:class:: X509CRL(filename=None, buf=None)

   Class representing an X.509 Certificate Revocation List.

   A CRL in PEM or DER format can be loaded from a file, with the ``filename`` argument,
   or from a bytestring, with the ``buf`` argument.






