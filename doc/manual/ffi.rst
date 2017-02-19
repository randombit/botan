
FFI Interface
========================================

.. versionadded:: 1.11.14

Botan's ffi module provides a C API intended to be easily usable with
other language's foreign function interface (FFI) libraries. For
instance the Python module using the FFI interface needs only the
ctypes module (included in default Python). Code examples can be found
in `src/tests/test_ffi.cpp`.

Versioning
----------------------------------------

.. cpp:function:: uint32_t botan_ffi_api_version()

   Returns the version of the currently supported FFI API.  This is
   expressed in the form YYYYMMDD of the release date of this version
   of the API.

.. cpp:function:: int botan_ffi_supports_api(uint32_t version)

   Returns 0 iff the FFI version specified is supported by this
   library. Otherwise returns -1. The expression
   botan_ffi_supports_api(botan_ffi_api_version()) will always
   evaluate to 0. A particular version of the library may also support
   other (older) versions of the FFI API.

.. cpp:function:: const char* botan_version_string()

   Returns a free-from version string, e.g., 2.0.0

.. cpp:function:: uint32_t botan_version_major()

   Returns the major version of the library

.. cpp:function:: uint32_t botan_version_minor()

   Returns the minor version of the library

.. cpp:function:: uint32_t botan_version_patch()

   Returns the patch version of the library

.. cpp:function:: uint32_t botan_version_datestamp()

   Returns the date this version was released as an integer, or 0
   if an unreleased version

Utility Functions
----------------------------------------

.. cpp:function:: int botan_same_mem(const uint8_t* x, const uint8_t* y, size_t len)

   Returns 0 if `x[0..len] == y[0..len]`, -1 otherwise.

.. cpp:function:: int botan_hex_encode(const uint8_t* x, size_t len, char* out, uint32_t flags)

   Performs hex encoding of binary data in *x* of size *len* bytes.
   The output buffer *out* must be of at least *x*2* bytes in size.
   If *flags* contains ``BOTAN_FFI_HEX_LOWER_CASE``, hex encoding
   will only contain lower-case letters, upper-case letters otherwise.
   Returns 0 on success, 1 otherwise.

Random Number Generators
----------------------------------------

.. cpp:type:: opaque* botan_rng_t

   An opaque data type for a random number generator. Don't mess with it.

.. cpp:function:: int botan_rng_init(botan_rng_t* rng, const char* rng_type)

   Initialize a random number generator object from the given
   *rng_type*: "system" or `nullptr`: `System_RNG`, "user": `AutoSeeded_RNG`.

.. cpp:function:: int botan_rng_get(botan_rng_t rng, uint8_t* out, size_t out_len)

   Get random bytes from a random number generator.

.. cpp:function:: int botan_rng_reseed(botan_rng_t rng, size_t bits)

   Reseeds the random number generator with *bits* number of bits
   from the `System_RNG`.

.. cpp:function:: int botan_rng_destroy(botan_rng_t rng)

   Destroy the object created by :cpp:func:`botan_rng_init`.

Hash Functions
----------------------------------------

.. cpp:type:: opaque* botan_hash_t

   An opaque data type for a hash. Don't mess with it.

.. cpp:function:: botan_hash_t botan_hash_init(const char* hash, uint32_t flags)

   Creates a hash of the given name, e.g., "SHA-384".
   Returns null on failure. Flags should always be zero in this version of the API.

.. cpp:function:: int botan_hash_destroy(botan_hash_t hash)

   Destroy the object created by :cpp:func:`botan_hash_init`.

.. cpp:function:: int botan_hash_clear(botan_hash_t hash)

   Reset the state of this object back to clean, as if no input has
   been supplied.

.. cpp:function:: size_t botan_hash_output_length(botan_hash_t hash)

   Return the output length of the hash function.

.. cpp:function:: int botan_hash_update(botan_hash_t hash, const uint8_t* input, size_t len)

   Add input to the hash computation.

.. cpp:function:: int botan_hash_final(botan_hash_t hash, uint8_t out[])

   Finalize the hash and place the output in out. Exactly
   :cpp:func:`botan_hash_output_length` bytes will be written.

Message Authentication Codes
----------------------------------------
.. cpp:type:: opaque* botan_mac_t

    An opaque data type for a MAC. Don't mess with it, but do remember
    to set a random key first.

.. cpp:function:: botan_mac_t botan_mac_init(const char* mac, uint32_t flags)

   Creates a MAC of the given name, e.g., "HMAC(SHA-384)".
   Returns null on failure. Flags should always be zero in this version of the API.

.. cpp:function:: int botan_mac_destroy(botan_mac_t mac)

   Destroy the object created by :cpp:func:`botan_mac_init`.

.. cpp:function:: int botan_mac_clear(botan_mac_t mac)

   Reset the state of this object back to clean, as if no key and input have
   been supplied.

.. cpp:function:: size_t botan_mac_output_length(botan_mac_t mac)

   Return the output length of the MAC.

.. cpp:function:: int botan_mac_set_key(botan_mac_t mac, const uint8_t* key, size_t key_len)

   Set the random key.

.. cpp:function:: int botan_mac_update(botan_mac_t mac, uint8_t buf[], size_t len)

   Add input to the MAC computation.

.. cpp:function:: int botan_mac_final(botan_mac_t mac, uint8_t out[], size_t* out_len)

   Finalize the MAC and place the output in out. Exactly
   :cpp:func:`botan_mac_output_length` bytes will be written.

Ciphers
----------------------------------------

.. cpp:type:: opaque* botan_cipher_t

    An opaque data type for a MAC. Don't mess with it, but do remember
    to set a random key first. And please use an AEAD.

.. cpp:function:: botan_cipher_t botan_cipher_init(const char* cipher_name, uint32_t flags)

    Create a cipher object from a name such as "AES-256/GCM" or "Serpent/OCB".

    Flags is a bitfield
    The low bit of flags specifies if encrypt or decrypt

.. cpp:function:: int botan_cipher_destroy(botan_cipher_t cipher)

.. cpp:function:: int botan_cipher_clear(botan_cipher_t hash)

.. cpp:function:: int botan_cipher_set_key(botan_cipher_t cipher, \
                  const uint8_t* key, size_t key_len)

.. cpp:function:: int botan_cipher_set_associated_data(botan_cipher_t cipher, \
                                               const uint8_t* ad, size_t ad_len)

.. cpp:function:: int botan_cipher_start(botan_cipher_t cipher, \
                                 const uint8_t* nonce, size_t nonce_len)

.. cpp:function:: int botan_cipher_is_authenticated(botan_cipher_t cipher)

.. cpp:function:: size_t botan_cipher_tag_size(botan_cipher_t cipher)

.. cpp:function:: int botan_cipher_valid_nonce_length(botan_cipher_t cipher, size_t nl)

.. cpp:function:: size_t botan_cipher_default_nonce_length(botan_cipher_t cipher)

PBKDF
----------------------------------------

.. cpp:function:: int botan_pbkdf(const char* pbkdf_algo, \
                          uint8_t out[], size_t out_len, \
                          const char* passphrase, \
                          const uint8_t salt[], size_t salt_len, \
                          size_t iterations)

   Derive a key from a passphrase for a number of iterations
   using the given PBKDF algorithm, e.g., "PBKDF2".

.. cpp:function:: int botan_pbkdf_timed(const char* pbkdf_algo, \
                                uint8_t out[], size_t out_len, \
                                const char* passphrase, \
                                const uint8_t salt[], size_t salt_len, \
                                size_t milliseconds_to_run, \
                                size_t* out_iterations_used)

   Derive a key from a passphrase using the given PBKDF algorithm,
   e.g., "PBKDF2". If *out_iterations_used* is zero, instead the
   PBKDF is run until *milliseconds_to_run* milliseconds have passed.
   In this case, the number of iterations run will be written to
   *out_iterations_used*.

KDF
----------------------------------------

.. cpp:function:: int botan_kdf(const char* kdf_algo, \
                        uint8_t out[], size_t out_len, \
                        const uint8_t secret[], size_t secret_len, \
                        const uint8_t salt[], size_t salt_len, \
                        const uint8_t label[], size_t label_len)

   Derive a key using the given KDF algorithm, e.g., "SP800-56C".
   The derived key of length *out_len* bytes will be placed in *out*.

Password Hashing
----------------------------------------

.. cpp:function:: int botan_bcrypt_generate(uint8_t* out, size_t* out_len, \
                                    const char* password, \
                                    botan_rng_t rng, \
                                    size_t work_factor, \
                                    uint32_t flags)

   Create a password hash using Bcrypt.
   The output buffer *out* should be of length 64 bytes.
   The output is formatted bcrypt $2a$...

.. cpp:function:: int botan_bcrypt_is_valid(const char* pass, const char* hash)

   Check a previously created password hash.
   Returns 0 if if this password/hash combination is valid,
   1 if the combination is not valid (but otherwise well formed),
   negative on error.

Public Key Creation, Import and Export
----------------------------------------

.. cpp:type:: opaque* botan_privkey_t

   An opaque data type for a private key. Don't mess with it.

.. cpp:function:: int botan_privkey_create(botan_privkey_t* key, \
                                   const char* algo_name, \
                                   const char* algo_params, \
                                   botan_rng_t rng)

.. cpp:function:: int botan_privkey_create_rsa(botan_privkey_t* key, botan_rng_t rng, size_t n_bits)

.. cpp:function:: int botan_privkey_create_ecdsa(botan_privkey_t* key, botan_rng_t rng, const char* params)

.. cpp:function:: int botan_privkey_create_ecdh(botan_privkey_t* key, botan_rng_t rng, const char* params)

.. cpp:function:: int botan_privkey_create_mceliece(botan_privkey_t* key, botan_rng_t rng, size_t n, size_t t)

.. cpp:function:: int botan_privkey_load(botan_privkey_t* key, botan_rng_t rng, \
                                 const uint8_t bits[], size_t len, \
                                 const char* password)

.. cpp:function:: int botan_privkey_destroy(botan_privkey_t key)

.. cpp:function:: int botan_privkey_export(botan_privkey_t key, \
                                   uint8_t out[], size_t* out_len, \
                                   uint32_t flags)

.. cpp:function:: int botan_privkey_export_encrypted(botan_privkey_t key, \
                                             uint8_t out[], size_t* out_len, \
                                             botan_rng_t rng, \
                                             const char* passphrase, \
                                             const char* encryption_algo, \
                                             uint32_t flags)

.. cpp:type:: opaque* botan_pubkey_t

   An opaque data type for a public key. Don't mess with it.

.. cpp:function:: int botan_pubkey_load(botan_pubkey_t* key, const uint8_t bits[], size_t len)

.. cpp:function:: int botan_privkey_export_pubkey(botan_pubkey_t* out, botan_privkey_t in)

.. cpp:function:: int botan_pubkey_export(botan_pubkey_t key, uint8_t out[], size_t* out_len, uint32_t flags)

.. cpp:function:: int botan_pubkey_algo_name(botan_pubkey_t key, char out[], size_t* out_len)

.. cpp:function:: int botan_pubkey_estimated_strength(botan_pubkey_t key, size_t* estimate)

.. cpp:function:: int botan_pubkey_fingerprint(botan_pubkey_t key, const char* hash, \
                                       uint8_t out[], size_t* out_len)

.. cpp:function:: int botan_pubkey_destroy(botan_pubkey_t key)

Public Key Encryption/Decryption
----------------------------------------

.. cpp:type:: opaque* botan_pk_op_encrypt_t

   An opaque data type for an encryption operation. Don't mess with it.

.. cpp:function:: int botan_pk_op_encrypt_create(botan_pk_op_encrypt_t* op, \
                                         botan_pubkey_t key, \
                                         const char* padding, \
                                         uint32_t flags)

.. cpp:function:: int botan_pk_op_encrypt_destroy(botan_pk_op_encrypt_t op)

.. cpp:function:: int botan_pk_op_encrypt(botan_pk_op_encrypt_t op, \
                                  botan_rng_t rng, \
                                  uint8_t out[], size_t* out_len, \
                                  const uint8_t plaintext[], size_t plaintext_len)

.. cpp:type:: opaque* botan_pk_op_decrypt_t

   An opaque data type for a decryption operation. Don't mess with it.

.. cpp:function:: int botan_pk_op_decrypt_create(botan_pk_op_decrypt_t* op, \
                                         botan_privkey_t key, \
                                         const char* padding, \
                                         uint32_t flags)

.. cpp:function:: int botan_pk_op_decrypt_destroy(botan_pk_op_decrypt_t op)

.. cpp:function:: int botan_pk_op_decrypt(botan_pk_op_decrypt_t op, \
                                  uint8_t out[], size_t* out_len, \
                                  uint8_t ciphertext[], size_t ciphertext_len)

Signatures
----------------------------------------

.. cpp:type:: opaque* botan_pk_op_sign_t

   An opaque data type for a signature generation operation. Don't mess with it.

.. cpp:function:: int botan_pk_op_sign_create(botan_pk_op_sign_t* op, \
                                      botan_privkey_t key, \
                                      const char* hash_and_padding, \
                                      uint32_t flags)

.. cpp:function:: int botan_pk_op_sign_destroy(botan_pk_op_sign_t op)

.. cpp:function:: int botan_pk_op_sign_update(botan_pk_op_sign_t op, \
                                      const uint8_t in[], size_t in_len)

.. cpp:function:: int botan_pk_op_sign_finish(botan_pk_op_sign_t op, botan_rng_t rng, \
                                      uint8_t sig[], size_t* sig_len)

.. cpp:type:: opaque* botan_pk_op_verify_t

   An opaque data type for a signature verification operation. Don't mess with it.

.. cpp:function:: int botan_pk_op_verify_create(botan_pk_op_verify_t* op, \
                                        botan_pubkey_t key, \
                                        const char* hash_and_padding, \
                                        uint32_t flags)

.. cpp:function:: int botan_pk_op_verify_destroy(botan_pk_op_verify_t op)

.. cpp:function:: int botan_pk_op_verify_update(botan_pk_op_verify_t op, \
                                        const uint8_t in[], size_t in_len)

.. cpp:function:: int botan_pk_op_verify_finish(botan_pk_op_verify_t op, \
                                        const uint8_t sig[], size_t sig_len)

Key Agreement
----------------------------------------

.. cpp:type:: opaque* botan_pk_op_ka_t

   An opaque data type for a key agreement operation. Don't mess with it.

.. cpp:function:: int botan_pk_op_key_agreement_create(botan_pk_op_ka_t* op, \
                                               botan_privkey_t key, \
                                               const char* kdf, \
                                               uint32_t flags)

.. cpp:function:: int botan_pk_op_key_agreement_destroy(botan_pk_op_ka_t op)

.. cpp:function:: int botan_pk_op_key_agreement_export_public(botan_privkey_t key, \
                                                      uint8_t out[], size_t* out_len)

.. cpp:function:: int botan_pk_op_key_agreement(botan_pk_op_ka_t op, \
                                        uint8_t out[], size_t* out_len, \
                                        const uint8_t other_key[], size_t other_key_len, \
                                        const uint8_t salt[], size_t salt_len)

.. cpp:function:: int botan_mceies_encrypt(botan_pubkey_t mce_key, \
                                   botan_rng_t rng, \
                                   const char* aead, \
                                   const uint8_t pt[], size_t pt_len, \
                                   const uint8_t ad[], size_t ad_len, \
                                   uint8_t ct[], size_t* ct_len)

.. cpp:function:: int botan_mceies_decrypt(botan_privkey_t mce_key, \
                                   const char* aead, \
                                   const uint8_t ct[], size_t ct_len, \
                                   const uint8_t ad[], size_t ad_len, \
                                   uint8_t pt[], size_t* pt_len)

X.509 Certificates
----------------------------------------

.. cpp:type:: opaque* botan_x509_cert_t

   An opaque data type for an X.509 certificate. Don't mess with it.

.. cpp:function:: int botan_x509_cert_load(botan_x509_cert_t* cert_obj, \
                                        const uint8_t cert[], size_t cert_len)

.. cpp:function:: int botan_x509_cert_load_file(botan_x509_cert_t* cert_obj, const char* filename)

.. cpp:function:: int botan_x509_cert_destroy(botan_x509_cert_t cert)

.. cpp:function:: int botan_x509_cert_gen_selfsigned(botan_x509_cert_t* cert, \
                                             botan_privkey_t key, \
                                             botan_rng_t rng, \
                                             const char* common_name, \
                                             const char* org_name)

.. cpp:function:: int botan_x509_cert_get_time_starts(botan_x509_cert_t cert, char out[], size_t* out_len)

.. cpp:function:: int botan_x509_cert_get_time_expires(botan_x509_cert_t cert, char out[], size_t* out_len)

.. cpp:function:: int botan_x509_cert_get_fingerprint(botan_x509_cert_t cert, const char* hash, uint8_t out[], size_t* out_len)

.. cpp:function:: int botan_x509_cert_get_serial_number(botan_x509_cert_t cert, uint8_t out[], size_t* out_len)

.. cpp:function:: int botan_x509_cert_get_authority_key_id(botan_x509_cert_t cert, uint8_t out[], size_t* out_len)

.. cpp:function:: int botan_x509_cert_get_subject_key_id(botan_x509_cert_t cert, uint8_t out[], size_t* out_len)

.. cpp:function:: int botan_x509_cert_path_verify(botan_x509_cert_t cert, \
                                          const char* ca_dir)

.. cpp:function:: int botan_x509_cert_get_public_key_bits(botan_x509_cert_t cert, \
                                                  uint8_t out[], size_t* out_len)

.. cpp:function:: int botan_x509_cert_get_public_key(botan_x509_cert_t cert, botan_pubkey_t* key)

.. cpp:function:: int botan_x509_cert_get_issuer_dn(botan_x509_cert_t cert, \
                                            const char* key, size_t index, \
                                            uint8_t out[], size_t* out_len)

.. cpp:function:: int botan_x509_cert_get_subject_dn(botan_x509_cert_t cert, \
                                             const char* key, size_t index, \
                                             uint8_t out[], size_t* out_len)

.. cpp:function:: int botan_x509_cert_to_string(botan_x509_cert_t cert, char out[], size_t* out_len)

.. cpp:enum:: botan_x509_cert_key_constraints

   Certificate key usage constraints. Allowed values: `NO_CONSTRAINTS`,
   `DIGITAL_SIGNATURE`, `NON_REPUDIATION`, `KEY_ENCIPHERMENT`,
   `DATA_ENCIPHERMENT`, `KEY_AGREEMENT`, `KEY_CERT_SIGN`,
   `CRL_SIGN`, `ENCIPHER_ONLY`, `DECIPHER_ONLY`.

.. cpp:function:: int botan_x509_cert_allowed_usage(botan_x509_cert_t cert, unsigned int key_usage)
