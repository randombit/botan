
Python Binding
========================================

.. versionadded:: 1.11.14

.. highlight:: python

.. py:module:: botan

The Python binding is based on the `ffi` module of botan and the
`ctypes` module of the Python standard library.

Versioning
----------------------------------------
.. py:function:: version_major()

   Returns the major number of the library version (currently, 1)
.. py:function:: version_minor()

   Returns the minor number of the library version (currently, 11)
.. py:function:: version_patch()

   Returns the patch number of the library version (currently, 14)

.. py:function:: version_string()

   Returns a free form version string for the library

Random Number Generators
----------------------------------------
.. py:class:: rng(rng_type = 'system')

     Type 'user' also allowed (userspace HKDF RNG seeded from system
     rng). The system RNG is very cheap to create, as just a single file
     handle or CSP handle is kept open, from first use until shutdown,
     no matter how many 'system' rng instances are created. Thus it is
     easy to use the RNG in a one-off way, with `botan.rng().get(32)`.

   .. py:method:: get(length)

      Return some bits

   .. py:method:: reseed(bits = 256)

      Meaningless on system RNG, on userspace RNG causes a reseed/rekey


Hash Functions
----------------------------------------
.. py:class:: hash_function(algo)

    Algo is a string (eg 'SHA-1', 'SHA-384', 'Skein-512')

    .. py:method:: clear()

       Clear state

    .. py:method:: output_length()

    .. py:method:: update(x)

                   Add some input

    .. py:method:: final()

       Returns the hash of all input provided, resets
       for another message.

Message Authentication Codes
----------------------------------------
.. py:class:: message_authentication_code(algo)

    Algo is a string (eg 'HMAC(SHA-256)', 'Poly1305', 'CMAC(AES-256)')

    .. py:method:: clear()

    .. py:method:: output_length()

    .. py:method:: set_key(key)

                   Set the key

    .. py:method:: update(x)

                   Add some input

    .. py:method:: final()

       Returns the MAC of all input provided, resets
       for another message with the same key.

Ciphers
----------------------------------------
.. py:class:: cipher(object, algo, encrypt = True)

          The algorithm is spcified as a string (eg 'AES-128/GCM',
          'Serpent/OCB(12)', 'Threefish-512/EAX').

          Set the second param to False for decryption

    .. py:method:: tag_length()

                   Returns the tag length (0 for unauthenticated modes)

    .. py:method:: default_nonce_length()

                   Returns default nonce length

    .. py:method:: update_granularity()

                   Returns update block size. Call to update() must provide
                   input of exactly this many bytes

    .. py:method:: is_authenticated()

                   Returns True if this is an AEAD mode

    .. py:method:: valid_nonce_length(nonce_len)

                   Returns True if nonce_len is a valid nonce len for
                   this mode

    .. py:method:: clear()

                   Resets all state

    .. py:method:: set_key(key)

                   Set the key

    .. py:method:: start(nonce)

                   Start processing a message using nonce

    .. py:method:: update(txt)

                   Consumes input text and returns output. Input text must be
                   of update_granularity() length.  Alternately, always call
                   finish with the entire message, avoiding calls to update
                   entirely

    .. py:method:: finish(txt = None)

                   Finish processing (with an optional final input). May throw
                   if message authentication checks fail, in which case all
                   plaintext previously processed must be discarded. You may
                   call finish() with the entire message

Bcrypt
----------------------------------------
.. py:function:: bcrypt(passwd, rng, work_factor = 10)

   Provided the password and an RNG object, returns a bcrypt string

.. py:function:: check_bcrypt(passwd, bcrypt)

   Check a bcrypt hash against the provided password, returning True
   iff the password matches.

PBKDF
----------------------------------------
.. py:function:: pbkdf(algo, password, out_len, iterations = 100000, salt = rng().get(12))

   Runs a PBKDF2 algo specified as a string (eg 'PBKDF2(SHA-256)', 'PBKDF2(CMAC(Blowfish))').
   Runs with n iterations with meaning depending on the algorithm.
   The salt can be provided or otherwise is randomly chosen. In any case it is returned
   from the call.

   Returns out_len bytes of output (or potentially less depending on
   the algorithm and the size of the request).

   Returns tuple of salt, iterations, and psk

.. py:function:: pbkdf_timed(algo, password, out_len, ms_to_run = 300, salt = rng().get(12))

   Runs for as many iterations as needed to consumed ms_to_run
   milliseconds on whatever we're running on. Returns tuple of salt,
   iterations, and psk

KDF
----------------------------------------
.. py:function:: kdf(algo, secret, out_len, salt)

Public Key
----------------------------------------
.. py:class:: public_key(object)

  .. py:method:: fingerprint(hash = 'SHA-256')

.. py:class:: private_key(algo, param, rng)

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
.. py:class:: pk_op_encrypt(pubkey, padding)

    .. py:method:: encrypt(msg, rng)

.. py:class:: pk_op_decrypt(privkey, padding)

    .. py:method:: decrypt(msg)

.. py:class:: pk_op_sign(privkey, hash_w_padding)

    .. py:method:: update(msg)
    .. py:method:: finish(rng)

.. py:class:: pk_op_verify(pubkey, hash_w_padding)

    .. py:method:: update(msg)
    .. py:method:: check_signature(signature)

.. py:class:: pk_op_key_agreement(privkey, kdf)

    .. py:method:: public_value()

    Returns the public value to be passed to the other party

    .. py:method:: agree(other, key_len, salt)

    Returns a key derived by the KDF.

