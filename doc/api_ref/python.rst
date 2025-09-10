
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
-----------------------------------------
.. py:function:: version_major() -> int

   Returns the major number of the library version.

.. py:function:: version_minor() -> int

   Returns the minor number of the library version.

.. py:function:: version_patch() -> int

   Returns the patch number of the library version.

.. py:function:: version_string() -> int

   Returns a free form version string for the library

Utilities
-----------------------------------------

.. py:function:: const_time_compare(x: str | bytes, y: str | bytes) -> bool

.. py:data:: MPIArg
   :type: str | MPI | Any | None

   Convenience alias for parameters that get turned into an MPI.

Random Number Generators
-----------------------------------------

.. py:class:: RandomNumberGenerator(rng_type: str = 'system')

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

   .. py:method:: get(length: int) -> bytes

      Return some bytes

   .. py:method:: reseed(bits: int = 256)

      Meaningless on system RNG, on userspace RNG causes a reseed/rekey

   .. py:method:: reseed_from_rng(source_rng: RandomNumberGenerator, bits: int = 256)

      Take bits from the source RNG and use it to seed ``self``

   .. py:method:: add_entropy(seed: str | bytes)

      Add some unpredictable seed data to the RNG

TPM 2.0 Bindings
-----------------------------------------

.. versionadded:: 3.6.0

.. py:class:: TPM2Context(tcti_name_maybe_with_conf: str | None = None, tcti_conf: str | None = None)

   Create a TPM 2.0 context with optional TCTI name and configuration,
   separated by a colon, or as separate parameters.

   .. py:method:: supports_botan_crypto_backend() -> bool

      Returns True if the TPM adapter can use Botan-based crypto primitives
      to communicate with the TPM

   .. py:method:: enable_botan_crypto_backend(rng: RandomNumberGenerator)

      Enables the TPM adapter to use Botan-based crypto primitives. The passed
      RNG must not depend on the TPM itself.

.. py:class:: TPM2UnauthenticatedSession(ctx)

   Creates a TPM 2.0 session that is not bound to any authentication credential
   but provides basic parameter encryption between the TPM and the application.


Hash Functions
-----------------------------------------

.. py:class:: HashFunction(algo: str | c_void_p)

   Previously ``hash_function``

   The ``algo`` param is a string (eg 'SHA-1', 'SHA-384', 'BLAKE2b')

   .. py:method:: copy_state() -> HashFunction

      Copy the state of this instance

   .. py:method:: algo_name() -> str

      Returns the name of this algorithm

   .. py:method:: clear()

      Clear state

   .. py:method:: output_length() -> int

      Return output length in bytes

   .. py:method:: block_size() -> int

      Return block size in bytes

   .. py:method:: update(x: str | bytes)

      Add some input

   .. py:method:: final() -> bytes

      Returns the hash of all input provided, resets
      for another message.

Message Authentication Codes
-----------------------------------------

.. py:class:: MsgAuthCode(algo: str)

   Previously ``message_authentication_code``

   Algo is a string (eg 'HMAC(SHA-256)', 'Poly1305', 'CMAC(AES-256)')

   .. py:method:: algo_name() -> str

      Returns the name of this algorithm

   .. py:method:: clear()

      Clear internal state including the key

   .. py:method:: output_length() -> int

      Return the output length in bytes

   .. py:method:: minimum_keylength() -> int

   .. py:method:: maximum_keylength() -> int

   .. py:method:: keylength_modulo() -> int

   .. py:method:: set_key(key: bytes)

      Set the key

   .. py:method:: set_nonce(nonce: bytes)

      Set the nonce

   .. py:method:: update(x: str | bytes)

      Add some input

   .. py:method:: final() -> bytes

      Returns the MAC of all input provided, resets
      for another message with the same key.

Ciphers
-----------------------------------------

.. py:class:: SymmetricCipher(algo: str, encrypt: bool = True)

   Previously ``cipher``

   The algorithm is specified as a string (eg 'AES-128/GCM',
   'Serpent/OCB(12)', 'Threefish-512/EAX').

   Set the second param to False for decryption

   .. py:method:: algo_name() -> str

      Returns the name of this algorithm

   .. py:method:: tag_length() -> int

      Returns the tag length (0 for unauthenticated modes)

   .. py:method:: default_nonce_length() -> int

      Returns default nonce length

   .. py:method:: valid_nonce_length(nonce_len: int) -> bool

      Returns True if nonce_len is a valid nonce len for this mode

   .. py:method:: update_granularity() -> int

      Returns update block size. Call to update() must provide input
      of exactly this many bytes

   .. py:method:: ideal_update_granularity() -> int

   .. py:method:: minimum_keylength() -> int

   .. py:method:: maximum_keylength() -> int

   .. py:method:: is_authenticated() -> bool

      Returns True if this is an AEAD mode

   .. py:method:: reset()

      Resets message specific state

   .. py:method:: clear()

      Resets all state

   .. py:method:: set_key(key: bytes)

      Set the key

   .. py:method:: set_assoc_data(ad: bytes)

      Sets the associated data. Fails if this is not an AEAD mode

   .. py:method:: start(nonce: bytes)

      Start processing a message using nonce

   .. py:method:: update(txt: str | bytes)

      Consumes input text and returns output. Input text must be of
      update_granularity() length.  Alternately, always call finish
      with the entire message, avoiding calls to update entirely

   .. py:method:: finish(txt: str | bytes | None = None)

      Finish processing (with an optional final input). May throw if
      message authentication checks fail, in which case all plaintext
      previously processed must be discarded. You may call finish()
      with the entire message

.. py:class:: BlockCipher(algo: str | c_void_p)

   Low level block cipher interface.

   .. py:method:: algo_name() -> str

   .. py:method:: block_size() -> int

   .. py:method:: minimum_keylength() -> int

   .. py:method:: maximum_keylength() -> int

   .. py:method:: keylength_module() -> int

   .. py:method:: clear()

   .. py:method:: set_key(key: bytes)

   .. py:method:: encrypt(pt: bytes) -> Array[c_char]

   .. py:method:: decrypt(ct: bytes) -> Array[c_char]

Bcrypt
-----------------------------------------

.. py:function:: bcrypt(passwd: str, rng: RandomNumberGenerator, work_factor: int = 10) -> str

   Provided the password and an RNG object, returns a bcrypt string

.. py:function:: check_bcrypt(passwd: str, passwd_hash: str) -> bool

   Check a bcrypt hash against the provided password, returning True
   iff the password matches.

PBKDF
-----------------------------------------

.. py:function:: pbkdf(algo: str, password: str, out_len: int, iterations: int = 100000, salt: bytes | None = None)

   Runs a PBKDF2 algo specified as a string (eg 'PBKDF2(SHA-256)',
   'PBKDF2(CMAC(Blowfish))').  Runs with specified iterations, with
   meaning depending on the algorithm.  The salt can be provided or
   otherwise is randomly chosen. In any case it is returned from the
   call.

   Returns out_len bytes of output (or potentially less depending on
   the algorithm and the size of the request).

   Returns tuple of salt, iterations, and psk

.. py:function:: pbkdf_timed(algo: str, password: str, out_len: int, ms_to_run: int = 300, salt: bytes | None = None)

   Runs for as many iterations as needed to consumed ms_to_run
   milliseconds on whatever we're running on. Returns tuple of salt,
   iterations, and psk

Scrypt
-----------------------------------------

.. versionadded:: 2.8.0

.. py:function:: scrypt(out_len: int, password: str, salt: str | bytes, n: int = 1024, r: int = 8, p: int = 8)

   Runs Scrypt key derivation function over the specified password
   and salt using Scrypt parameters n, r, p.

Argon2
-----------------------------------------

.. py:function:: argon2(variant: str, out_len: int, password: str, salt: str | bytes, m: int = 256, t: int = 1, p: int = 1) -> bytes

   Runs the specified Argon2 variant (`Argon2i`, `Argon2d`, `Argon2id`) over the specified password
   and salt using Argon2 parameters m, t, p.

KDF
-----------------------------------------

.. py:function:: kdf(algo: str, secret: bytes, out_len: int, salt: bytes, label: bytes) -> bytes

   Performs a key derviation function (such as "HKDF(SHA-384)") over
   the provided secret and salt values. Returns a value of the
   specified length.

Public Key
-----------------------------------------

.. py:class:: PublicKey(obj: c_void_p | None = None)

   Previously ``public_key``

   .. py:classmethod:: load(val: str | bytes) -> PublicKey

      Load a public key. The value should be a PEM or DER blob.

   .. py:classmethod:: load_rsa(n: MPIArg, e: MPIArg) -> PublicKey

      Load an RSA public key giving the modulus and public exponent
      as integers.

   .. py:classmethod:: load_dsa(p: MPIArg, q: MPIArg, g: MPIArg, y: MPIArg) -> PublicKey

      Load an DSA public key giving the parameters and public value
      as integers.

   .. py:classmethod:: load_dh(p: MPIArg, g: MPIArg, y: MPIArg) -> PublicKey

      Load an Diffie-Hellman public key giving the parameters and
      public value as integers.

   .. py:classmethod:: load_elgamal(p: MPIArg, q: MPIArg, g: MPIArg, y: MPIArg) -> PublicKey

      Load an ElGamal public key giving the parameters and
      public value as integers.

   .. py:classmethod:: load_ecdsa(curve: str, pub_x: MPIArg, pub_y: MPIArg) -> PublicKey

      Load an ECDSA public key giving the curve as a string
      (like "secp256r1") and the public point as a pair of
      integers giving the affine coordinates.

   .. py:classmethod:: load_ecdsa_sec1(curve: str, sec1_encoding: str | bytes) -> PublicKey

   .. py:classmethod:: load_ecdh(curve: str, pub_x: MPIArg, pub_y: MPIArg) -> PublicKey

      Load an ECDH public key giving the curve as a string
      (like "secp256r1") and the public point as a pair of
      integers giving the affine coordinates.

   .. py:classmethod:: load_ecdh_sec1(curve: str, sec1_encoding: str | bytes) -> PublicKey

   .. py:classmethod:: load_sm2(curve: str, pub_x: MPIArg, pub_y: MPIArg) -> PublicKey

      Load a SM2 public key giving the curve as a string (like
      "sm2p256v1") and the public point as a pair of integers giving
      the affine coordinates.

   .. py:classmethod:: load_sm2_sec1(curve: str, sec1_encoding: str | bytes) -> PublicKey

   .. py:classmethod:: load_ml_kem(mlkem_mode: str, key: bytes) -> PublicKey

      Load an ML-KEM public key giving the mode as a string (like
      "ML-KEM-512") and the raw encoding of the public key.

   .. py:classmethod:: load_ml_dsa(mldsa_mode: str, key: bytes) -> PublicKey

      Load an ML-DSA public key giving the mode as a string (like
      "ML-DSA-4x4") and the raw encoding of the public key.

   .. py:classmethod:: load_slh_dsa(slhdsa_mode: str, key: bytes) -> PublicKey

      Load an SLH-DSA public key giving the mode as a string (like
      "SLH-DSA-SHAKE-128f") and the raw encoding of the public key.

   .. py:classmethod:: load_frodokem(frodo_mode: str, key: bytes) -> PublicKey

   .. py:classmethod:: load_classic_mceliece(cmce_mode: str, key: bytes) -> PublicKey

   .. py:method:: algo_name() -> str

      Returns the algorithm name

   .. py:method:: check_key(rng_obj: RandomNumberGenerator, strong: bool = True) -> bool:

      Test the key for consistency. If ``strong`` is ``True`` then
      more expensive tests are performed.

   .. py:method:: estimated_strength() -> int

      Returns the estimated strength of this key against known attacks
      (NFS, Pollard's rho, etc)

   .. py:method:: export(pem: bool = False) -> str | bytes

      Exports the public key using the usual X.509 SPKI representation.
      If ``pem`` is True, the result is a PEM encoded string. Otherwise
      it is a binary DER value.

   .. py:method:: to_der() -> bytes

      Like ``self.export(False)``

   .. py:method:: to_pem() -> str

      Like ``self.export(True)``

   .. py:method:: to_raw() -> bytes

      Exports the key in its canonical raw encoding. This might not be
      available for all key types and raise an exception in that case.

   .. py:method:: fingerprint(hash: str  = 'SHA-256')

      Returns a hash of the public key

   .. py:method:: get_field(field_name: str) -> int

      Return an integer field related to the public key. The valid field names
      vary depending on the algorithm. For example RSA public modulus can be
      extracted with ``rsa_key.get_field("n")``.

   .. py:method:: object_identifier() -> OID

      Returns the associated OID

   .. py:method:: get_public_point() -> bytes

Private Key
-----------------------------------------

.. py:class:: PrivateKey(obj: c_void_p | None = None)

   Previously ``private_key``

   .. py:classmethod:: create(algo: str, param: str | int | tuple[int, int], rng: RandomNumberGenerator) -> PrivateKey

      Creates a new private key. The parameter type/value depends on
      the algorithm. For "rsa" is is the size of the key in bits.
      For "ecdsa" and "ecdh" it is a group name (for instance
      "secp256r1"). For "ecdh" there is also a special case for groups
      "curve25519" and "x448" (which are actually completely distinct key types
      with a non-standard encoding).

   .. py:classmethod:: create_ec(algo: str, ec_group: ECGroup, rng: RandomNumberGenerator) -> PrivateKey

      Creates a new ec private key.

   .. py:classmethod:: load(val: str | bytes, passphrase: str = "") -> PrivateKey

      Return a private key (DER or PEM formats accepted)

   .. py:classmethod:: load_rsa(p: MPIArg, q: MPIArg, e: MPIArg) -> PrivateKey

      Return a private RSA key

   .. py:classmethod:: load_dsa(p: MPIArg, q: MPIArg, g: MPIArg, x: MPIArg) -> PrivateKey

      Return a private DSA key

   .. py:classmethod:: load_dh(p: MPIArg, g: MPIArg, x: MPIArg) -> PrivateKey

      Return a private DH key

   .. py:classmethod:: load_elgamal(p: MPIArg, q: MPIArg, g: MPIArg, x: MPIArg) -> PrivateKey

      Return a private ElGamal key

   .. py:classmethod:: load_ecdsa(curve: str, x: MPIArg) -> PrivateKey

      Return a private ECDSA key

   .. py:classmethod:: load_ecdh(curve: str, x: MPIArg) -> PrivateKey

      Return a private ECDH key

   .. py:classmethod:: load_sm2(curve: str, x: MPIArg) -> PrivateKey

      Return a private SM2 key

   .. py:classmethod:: load_ml_kem(mlkem_mode: str, key: bytes) -> PrivateKey

      Return a private ML-KEM key

   .. py:classmethod:: load_ml_dsa(mldsa_mode: str, key: bytes) -> PrivateKey

      Return a private ML-DSA key

   .. py:classmethod:: load_slh_dsa(slh_dsa: str, key: bytes) -> PrivateKey

      Return a private SLH-DSA key

   .. py:classmethod:: load_frodokem(frodo_mode: str, key: bytes) -> PrivateKey

   .. py:classmethod:: load_classic_mceliece(cmce_mode: str, key: bytes) -> PrivateKey

   .. py:method:: algo_name() -> str

      Returns the algorithm name

   .. py:method:: check_key(rng_obj: RandomNumberGenerator, strong: bool = True) -> bool:

      Test the key for consistency. If ``strong`` is ``True`` then
      more expensive tests are performed.

   .. py:method:: to_der() -> bytes

      Return the PEM encoded private key (unencrypted). Like ``self.export(False)``

   .. py:method:: to_pem() -> str

      Return the PEM encoded private key (unencrypted). Like ``self.export(True)``

   .. py:method:: to_raw() -> bytes

      Exports the key in its canonical raw encoding. This might not be
      available for all key types and raise an exception in that case.

   .. py:method:: export(pem: bool = False) -> str | bytes

      Exports the private key in PKCS8 format. If ``pem`` is True, the
      result is a PEM encoded string. Otherwise it is a binary DER
      value. The key will not be encrypted.

   .. py:method:: export_encrypted(passphrase: str, rng: RandomNumberGenerator, pem: bool = False, msec: int = 300, cipher: str | None = None, pbkdf: str | None = None)

      Exports the private key in PKCS8 format, encrypted using the
      provided passphrase. If ``pem`` is True, the result is a PEM
      encoded string. Otherwise it is a binary DER value.

   .. py:method:: get_public_key() -> PublicKey

      Return a public_key object

   .. py:method:: get_field(field_name: str) -> int

      Return an integer field related to the public key. The valid field names
      vary depending on the algorithm. For example first RSA secret prime can be
      extracted with ``rsa_key.get_field("p")``. This function can also be
      used to extract the public parameters.

   .. py:method:: object_identifier() -> OID

      Returns the associated OID

   .. py:method:: stateful_operation() -> bool

      Return whether the key is stateful or not.

   .. py:method:: remaining_operations() -> int

      If the key is stateful, return the number of remaining operations.
      Raises an exception if the key is not stateful.

Public Key Operations
-----------------------------------------

.. py:class:: PKEncrypt(key: PublicKey, padding: str)

   Previously ``pk_op_encrypt``

   .. py:method:: encrypt(msg: bytes, rng: RandomNumberGenerator) -> bytes

.. py:class:: PKDecrypt(key: PrivateKey, padding: str)

   Previously ``pk_op_decrypt``

   .. py:method:: decrypt(msg: bytes) -> bytes

.. py:class:: PKSign(key: PrivateKey, padding: str, der: bool = False)

   Previously ``pk_op_sign``

   .. py:method:: update(msg: str | bytes)
   .. py:method:: finish(rng: RandomNumberGenerator) -> bytes

.. py:class:: PKVerify(key: PublicKey, padding: str, der: bool = False)

   Previously ``pk_op_verify``

   .. py:method:: update(msg: str | bytes)
   .. py:method:: check_signature(signature: str | bytes) -> bool

.. py:class:: PKKeyAgreement(key: PrivateKey, kdf_name: str)

   Previously ``pk_op_key_agreement``

   .. py:method:: public_value() -> bytes

      Returns the public value to be passed to the other party

   .. py:method:: agree(other: bytes, key_len: int, salt: bytes) -> bytes

      Returns a key derived by the KDF.

.. py:class:: KemEncrypt(key: PublicKey, params: str)

   .. py:method:: shared_key_length(desired_key_len: int) -> int
   .. py:method:: encapsulated_key_length() -> int
   .. py:method:: create_shared_key(rng: RandomNumberGenerator, salt: bytes, desired_key_len: int) -> tuple[bytes, bytes]

.. py:class:: KemDecrypt(key: PrivateKey, params: str)

   .. py:method:: shared_key_length(desired_key_len: int) -> int
   .. py:method:: decrypt_shared_key(salt: bytes, desired_key_len: int, encapsulated_key: bytes) -> bytes


X509Cert
-----------------------------------------

.. py:class:: X509Cert(filename: str | None = None, buf: bytes | None = None)

   .. py:method:: time_starts() -> datetime

      Return the time the certificate becomes valid, as a string in form
      "YYYYMMDDHHMMSSZ" where Z is a literal character reflecting that this time is
      relative to UTC.

   .. py:method:: time_expires() -> datetime

      Return the time the certificate expires, as a string in form
      "YYYYMMDDHHMMSSZ" where Z is a literal character reflecting that this time is
      relative to UTC.

   .. py:method:: to_string() -> str

      Format the certificate as a free-form string.

   .. py:method:: fingerprint(hash_algo: str = 'SHA-256') -> str

      Return a fingerprint for the certificate, which is basically just a hash
      of the binary contents. Normally SHA-1 or SHA-256 is used, but any hash
      function is allowed.

   .. py:method:: serial_number() -> bytes

      Return the serial number of the certificate.

   .. py:method:: authority_key_id() -> bytes

      Return the authority key ID set in the certificate, which may be empty.

   .. py:method:: subject_key_id() -> bytes

      Return the subject key ID set in the certificate, which may be empty.

   .. py:method:: subject_public_key_bits() -> bytes

      Get the serialized representation of the public key included in this certificate.

   .. py:method:: subject_public_key() -> PublicKey

      Get the public key included in this certificate as an object of class ``PublicKey``.

   .. py:method:: subject_dn(key: str, index: int) -> str

      Get a value from the subject DN field.

      ``key`` specifies a value to get, for instance ``"Name"`` or `"Country"`.

   .. py:method:: issuer_dn(key: str, index: int) -> str

      Get a value from the issuer DN field.

      ``key`` specifies a value to get, for instance ``"Name"`` or `"Country"`.

   .. py:method:: hostname_match(hostname: str) -> bool

      Return True if the Common Name (CN) field of the certificate matches a given ``hostname``.

   .. py:method:: not_before() -> int

      Return the time the certificate becomes valid, as seconds since epoch.

   .. py:method:: not_after() -> int

      Return the time the certificate expires, as seconds since epoch.

   .. py:method:: allowed_usage(usage_list: list[str]) -> bool

      Return True if the certificates Key Usage extension contains all constraints given in ``usage_list``.
      Also return True if the certificate doesn't have this extension.
      Example usage constraints are: ``"DIGITAL_SIGNATURE"``, ``"KEY_CERT_SIGN"``, ``"CRL_SIGN"``.

   .. py:method:: verify(intermediates: list[X509Cert] | None = None, \
                  trusted: list[X509Cert] | None = None, \
                  trusted_path: str | None = None, \
                  required_strength: int = 0, \
                  hostname: str | None = None, \
                  reference_time: int = 0 \
                  crls: list[X509Crl] | None = None) -> int

      Verify a certificate. Returns 0 if validation was successful, returns a positive error code
      if the validation was unsuccessful.

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

   .. py:classmethod:: validation_status(error_code: int)

      Return an informative string associated with the verification return code.

   .. py:method:: is_revoked(crl: X509Crl) -> bool

      Check if the certificate (``self``) is revoked on the given ``crl``.

X509CRL
-----------------------------------------

.. py:class:: X509CRL(filename: str | None = None, buf: bytes | None = None)

   Class representing an X.509 Certificate Revocation List.

   A CRL in PEM or DER format can be loaded from a file, with the ``filename`` argument,
   or from a bytestring, with the ``buf`` argument.

Multiple Precision Integers (MPI)
-----------------------------------------

.. versionadded:: 2.8.0

.. py:class:: MPI(initial_value: MPIArg = None, radix: int | None = None)

   Initialize an MPI object with specified value, left as zero otherwise.  The
   ``initial_value`` should be an ``int``, ``str``, or ``MPI``.
   The ``radix`` value should be set to 16 when initializing from a base 16 `str` value.


   Most of the usual arithmetic operators (``__add__``, ``__mul__``, etc) are
   defined.

   .. py:classmethod:: random(rng_obj: RandomNumberGenerator, bits: int) -> MPI

   .. py:classmethod:: random_range(rng_obj: RandomNumberGenerator, lower: MPI, upper: MPI) -> MPI

   .. py:method:: to_bytes() -> Array[c_char]

   .. py:method:: is_negative() -> bool

   .. py:method:: is_zero() -> bool

   .. py:method:: is_odd() -> bool

   .. py:method:: is_even() -> bool

   .. py:method:: is_prime(rng: RandomNumberGenerator, prob: int = 128) -> bool

      Test if ``self`` is prime

   .. py:method:: flip_sign()

   .. py:method:: gcd(other: MPI) -> MPI:

      Return the greatest common divisor of ``self`` and ``other``

   .. py:method:: pow_mod(exponent: MPI, modulus: MPI) -> MPI:

      Return ``self`` to the ``exponent`` power modulo ``modulus``

   .. py:method:: inverse_mod(modulus: MPI) -> MPI

      Return the inverse of ``self`` modulo ``modulus``, or zero if no inverse exists

   .. py:method:: mod_mul(other: MPI, modulus: MPI) -> MPI:

      Return the multiplication product of ``self`` and ``other`` modulo ``modulus``

   .. py:method:: bit_count() -> int

   .. py:method:: byte_count() -> int

   .. py:method:: get_bit(bit: int) -> bool

   .. py:method:: clear_bit(bit: int)

   .. py:method:: set_bit(int)

Object Identifiers (OID)
-----------------------------------------
.. versionadded:: 3.8.0

.. py:class:: OID(obj: c_void_p | None = None)

   .. py:classmethod:: from_string(value: str) -> OID

      Create a new OID from dot notation or from a known name

   .. py:method:: to_string() -> str

      Export the OID in dot notation

   .. py:method:: to_name() -> str

      Export the OID as a name if it has one, else in dot notation

   .. py:method:: register(name: str)

      Register the OID so that it may later be retrieved by the given name


EC Groups
-----------------------------------------
.. versionadded:: 3.8.0

.. py:class:: ECGroup(obj: c_void_p | None = None)

   .. py:classmethod:: supports_application_specific_group() -> bool

      Returns true if in this build configuration it is possible to register an application specific elliptic curve

   .. py:classmethod:: supports_named_group(name: str) -> bool

      Returns true if in this build configuration ECGroup.from_name(name) will succeed

   .. py:classmethod:: from_params(oid: OID, p: MPI, a: MPI, b: MPI, base_x: MPI, base_y: MPI, order: MPI) -> ECGroup

      Creates a new ECGroup from ec parameters

   .. py:classmethod:: from_ber(ber: bytes) -> ECGroup

      Creates a new ECGroup from a BER blob

   .. py:classmethod:: from_pem(pem: str) -> ECGroup

      Creates a new ECGroup from a pem encoding

   .. py:classmethod:: from_oid(oid: OID) -> ECGroup

      Creates a new ECGroup from a group named by an OID

   .. py:classmethod:: from_name(name: str) -> ECGroup

      Creates a new ECGroup from a common group name

   .. py:method:: to_der() -> bytes

      Export the group in DER encoding

   .. py:method:: to_pem() -> pem

      Export the group in PEM encoding

   .. py:method:: get_curve_oid() -> OID

      Get the curve OID

   .. py:method:: get_p() -> MPI

      Get the prime modulus of the field

   .. py:method:: get_a() -> MPI

      Get the a parameter of the elliptic curve equation

   .. py:method:: get_b() -> MPI

      Get the b parameter of the elliptic curve equation

   .. py:method:: get_g_x() -> MPI

      Get the x coordinate of the base point

   .. py:method:: get_g_y() -> MPI

      Get the y coordinate of the base point

   .. py:method:: get_order() -> MPI

      Get the order of the base point


Format Preserving Encryption (FE1 scheme)
-----------------------------------------
.. versionadded:: 2.8.0

.. py:class:: FormatPreservingEncryptionFE1(modulus: MPI, key: bytes, rounds: int = 5, compat_mode: bool = False)

   Initialize an instance for format preserving encryption

   .. py:method:: encrypt(msg: MPIArg, tweak: str | bytes) -> MPI

      The msg should be a botan3.MPI or an object which can be converted to one

   .. py:method:: decrypt(msg: MPIArg, tweak: str | bytes) -> MPI

      The msg should be a botan3.MPI or an object which can be converted to one

HOTP
-----------------------------------------
.. versionadded:: 2.8.0

.. py:class:: HOTP(key, hash="SHA-1", digits=6)

   .. py:method:: generate(counter: int) -> int

      Generate an HOTP code for the provided counter

   .. py:method:: check(code: int, counter: int, resync_range: int = 0) -> tuple[bool, int]

      Check if provided ``code`` is the correct code for ``counter``.
      If ``resync_range`` is greater than zero, HOTP also checks
      up to ``resync_range`` following counter values.

      Returns a tuple of (bool,int) where the boolean indicates if the
      code was valid, and the int indicates the next counter value
      that should be used. If the code did not verify, the next
      counter value is always identical to the counter that was passed
      in. If the code did verify and resync_range was zero, then the
      next counter will always be counter+1.







