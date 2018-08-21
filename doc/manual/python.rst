
Python Binding
========================================

.. versionadded:: 1.11.14

.. highlight:: python

.. py:module:: botan

The Python binding is based on the `ffi` module of botan and the
`ctypes` module of the Python standard library.

Starting in 2.8, the class names were renamed to match Python standard
conventions. However aliases are defined which allow older code to
continue to work; the older names are mentioned as "previously X".

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

     Type 'user' also allowed (userspace HKDF RNG seeded from system
     rng). The system RNG is very cheap to create, as just a single file
     handle or CSP handle is kept open, from first use until shutdown,
     no matter how many 'system' rng instances are created. Thus it is
     easy to use the RNG in a one-off way, with `botan.rng().get(32)`.

   .. py:method:: get(length)

      Return some bits

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

    Algo is a string (eg 'SHA-1', 'SHA-384', 'Skein-512')

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

  .. py:method:: fingerprint(hash = 'SHA-256')

     Returns a hash of the public key

  .. py:method:: algo_name()

     Returns the algorithm name

  .. py:method:: estimated_strength()

     Returns the estimated strength of this key against known attacks
     (NFS, Pollard's rho, etc)

  .. py:method:: encoding(pem=False)

     Returns the encoding of the key, PEM if set otherwise DER

Private Key
----------------------------------------

.. py:class:: PrivateKey(algo, param, rng)

    Previously ``private_key``

    Constructor creates a new private key. The parameter type/value
    depends on the algorithm. For "rsa" is is the size of the key in
    bits.  For "ecdsa" and "ecdh" it is a group name (for instance
    "secp256r1"). For "ecdh" there is also a special case for group
    "curve25519" (which is actually a completely distinct key type
    with a non-standard encoding).

    .. py:method:: get_public_key()

    Return a public_key object

    .. py:method:: export()

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

Multiple Precision Integers (MPI)
-------------------------------------
.. versionadded:: 2.8.0

.. py:class:: MPI(initial_value=None)

   Initialize an MPI object with specified value, left as zero otherwise.  The
   ``initial_value`` should be an ``int``, ``str``, or ``MPI``.

   Most of the usual arithmetic operators (``__add__``, ``__mul__``, etc) are
   defined.

   .. py:method:: inverse_mod(modulus)

      Return the inverse of ``self`` modulo modulus, or zero if no inverse exists

   .. py:method:: is_prime(rng, prob=128)

      Test if ``self`` is prime

   .. py:method:: pow_mod(exponent, modulus):

      Return ``self`` to the ``exponent`` power modulo ``modulus``

Format Preserving Encryption (FE1 scheme)
-----------------------------------------
.. versionadded:: 2.8.0

.. py:class:: FormatPreservingEncryptionFE1(modulus, key, rounds=5, compat_mode=False)

   Initialize an instance for format preserving encryption

   .. py:method:: encrypt(msg, tweak)

      The msg should be a botan2.MPI or an object which can be converted to one

   .. py:method:: decrypt(msg, tweak)

      The msg should be a botan2.MPI or an object which can be converted to one

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
