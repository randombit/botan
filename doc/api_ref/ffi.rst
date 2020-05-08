
FFI (C Binding)
========================================

.. versionadded:: 1.11.14

Botan's ffi module provides a C89 binding intended to be easily usable with other
language's foreign function interface (FFI) libraries. For instance the included
Python wrapper uses Python's ``ctypes`` module and the C89 API. This API is of
course also useful for programs written directly in C.

Code examples can be found in
`the tests <https://github.com/randombit/botan/blob/master/src/tests/test_ffi.cpp>`_.

Return Codes
---------------

Almost all functions in the Botan C interface return an ``int`` error code.  The
only exceptions are a handful of functions (like
:cpp:func:`botan_ffi_api_version`) which cannot fail in any circumstances.

The FFI functions return a non-negative integer (usually 0) to indicate success,
or a negative integer to represent an error. A few functions (like
:cpp:func:`botan_block_cipher_block_size`) return positive integers instead of
zero on success.

The error codes returned in certain error situations may change over time.  This
especially applies to very generic errors like
:cpp:enumerator:`BOTAN_FFI_ERROR_EXCEPTION_THROWN` and
:cpp:enumerator:`BOTAN_FFI_ERROR_UNKNOWN_ERROR`. For instance, before 2.8, setting
an invalid key length resulted in :cpp:enumerator:`BOTAN_FFI_ERROR_EXCEPTION_THROWN`
but now this is specially handled and returns
:cpp:enumerator:`BOTAN_FFI_ERROR_INVALID_KEY_LENGTH` instead.

The following enum values are defined in the FFI header:

.. cpp:enumerator:: BOTAN_FFI_SUCCESS = 0

   Generally returned to indicate success

.. cpp:enumerator:: BOTAN_FFI_INVALID_VERIFIER = 1

   Note this value is positive, but still represents an error condition.  In
   indicates that the function completed successfully, but the value provided
   was not correct. For example :cpp:func:`botan_bcrypt_is_valid` returns this
   value if the password did not match the hash.

.. cpp:enumerator:: BOTAN_FFI_ERROR_INVALID_INPUT = -1

   The input was invalid. (Currently this error return is not used.)

.. cpp:enumerator:: BOTAN_FFI_ERROR_BAD_MAC = -2

   While decrypting in an AEAD mode, the tag failed to verify.

.. cpp:enumerator:: BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE = -10

   Functions which write a variable amount of space return this if the indicated
   buffer length was insufficient to write the data. In that case, the output
   length parameter is set to the size that is required.

.. cpp:enumerator:: BOTAN_FFI_ERROR_EXCEPTION_THROWN = -20

   An exception was thrown while processing this request, but no further
   details are available.

   .. note::

      If the environment variable ``BOTAN_FFI_PRINT_EXCEPTIONS`` is set to any
      non-empty value, then any exception which is caught by the FFI layer will
      first print the exception message to stderr before returning an
      error. This is sometimes useful for debugging.

.. cpp:enumerator:: BOTAN_FFI_ERROR_OUT_OF_MEMORY = -21

   Memory allocation failed

.. cpp:enumerator:: BOTAN_FFI_ERROR_BAD_FLAG = -30

   A value provided in a `flag` variable was unknown.

.. cpp:enumerator:: BOTAN_FFI_ERROR_NULL_POINTER = -31

   A null pointer was provided as an argument where that is not allowed.

.. cpp:enumerator:: BOTAN_FFI_ERROR_BAD_PARAMETER = -32

   An argument did not match the function.

.. cpp:enumerator:: BOTAN_FFI_ERROR_KEY_NOT_SET = -33

   An object that requires a key normally must be keyed before use (eg before
   encrypting or MACing data). If this is not done, the operation will fail and
   return this error code.

.. cpp:enumerator:: BOTAN_FFI_ERROR_INVALID_KEY_LENGTH = -34

   An invalid key length was provided with a call to ``x_set_key``.

.. cpp:enumerator:: BOTAN_FFI_ERROR_NOT_IMPLEMENTED = -40

   This is returned if the functionality is not available for some reason.  For
   example if you call :cpp:func:`botan_hash_init` with a named hash function
   which is not enabled, this error is returned.

.. cpp:enumerator:: BOTAN_FFI_ERROR_INVALID_OBJECT = -50

   This is used if an object provided did not match the function.  For example
   calling :cpp:func:`botan_hash_destroy` on a ``botan_rng_t`` object will cause
   this return.

.. cpp:enumerator:: BOTAN_FFI_ERROR_UNKNOWN_ERROR = -100

   Something bad happened, but we are not sure why or how.

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

   Returns a free-form string describing the version.  The return
   value is a statically allocated string.

.. cpp:function:: uint32_t botan_version_major()

   Returns the major version of the library

.. cpp:function:: uint32_t botan_version_minor()

   Returns the minor version of the library

.. cpp:function:: uint32_t botan_version_patch()

   Returns the patch version of the library

.. cpp:function:: uint32_t botan_version_datestamp()

   Returns the date this version was released as an integer YYYYMMDD,
   or 0 if an unreleased version


FFI Versions
^^^^^^^^^^^^^

This maps the FFI API version to the first version of the library that
supported it.

============== ===================
FFI Version    Supported Starting
============== ===================
20191214       2.13.0
20180713       2.8.0
20170815       2.3.0
20170327       2.1.0
20150515       2.0.0
============== ===================

Utility Functions
----------------------------------------

.. const char* botan_error_description(int err)

   Return a string representation of the provided error code. If the error code
   is unknown, returns the string "Unknown error". The return values are static
   constant strings and should not be freed.

.. cpp:function:: int botan_same_mem(const uint8_t* x, const uint8_t* y, size_t len)

   Returns 0 if `x[0..len] == y[0..len]`, -1 otherwise.

.. cpp:function:: int botan_hex_encode(const uint8_t* x, size_t len, char* out, uint32_t flags)

   Performs hex encoding of binary data in *x* of size *len* bytes.
   The output buffer *out* must be of at least *x*2* bytes in size.
   If *flags* contains ``BOTAN_FFI_HEX_LOWER_CASE``, hex encoding
   will only contain lower-case letters, upper-case letters otherwise.
   Returns 0 on success, 1 otherwise.

.. cpp:function:: int botan_hex_decode(const char* hex_str, size_t in_len, uint8_t* out, size_t* out_len)

   Hex decode some data

Random Number Generators
----------------------------------------

.. cpp:type:: opaque* botan_rng_t

   An opaque data type for a random number generator. Don't mess with it.

.. cpp:function:: int botan_rng_init(botan_rng_t* rng, const char* rng_type)

   Initialize a random number generator object from the given
   *rng_type*: "system" (or ``nullptr``): ``System_RNG``,
   "user": ``AutoSeeded_RNG``,
   "user-threadsafe": serialized ``AutoSeeded_RNG``,
   "null": ``Null_RNG`` (always fails),
   "hwrnd" or "rdrand": ``Processor_RNG`` (if available)

.. cpp:function:: int botan_rng_get(botan_rng_t rng, uint8_t* out, size_t out_len)

   Get random bytes from a random number generator.

.. cpp:function:: int botan_rng_reseed(botan_rng_t rng, size_t bits)

   Reseeds the random number generator with *bits* number of bits
   from the `System_RNG`.

.. cpp:function:: int botan_rng_reseed_from_rng(botan_rng_t rng, botan_rng_t src, size_t bits)

   Reseeds the random number generator with *bits* number of bits
   taken from the given source RNG.

.. cpp:function:: int botan_rng_add_entropy(botan_rng_t rng, const uint8_t seed[], size_t len)

   Adds the provided seed material to the internal RNG state.

   This call may be ignored by certain RNG instances (such as RDRAND
   or, on some systems, the system RNG).

.. cpp:function:: int botan_rng_destroy(botan_rng_t rng)

   Destroy the object created by :cpp:func:`botan_rng_init`.

Block Ciphers
----------------------------------------

.. versionadded:: 2.1.0

This is a 'raw' interface to ECB mode block ciphers. Most applications
want the higher level cipher API which provides authenticated
encryption. This API exists as an escape hatch for applications which
need to implement custom primitives using a PRP.

.. cpp:type:: opaque* botan_block_cipher_t

   An opaque data type for a block cipher. Don't mess with it.

.. cpp:function:: int botan_block_cipher_init(botan_block_cipher_t* bc, const char* cipher_name)

   Create a new cipher mode object, `cipher_name` should be for example "AES-128" or "Threefish-512"

.. cpp:function:: int botan_block_cipher_block_size(botan_block_cipher_t bc)

   Return the block size of this cipher.

.. cpp:function:: int botan_block_cipher_name(botan_block_cipher_t cipher, \
                                              char* name, size_t* name_len)

   Return the name of this block cipher algorithm, which may nor may not exactly
   match what was passed to :cpp:func:`botan_block_cipher_init`.

.. cpp:function:: int botan_block_cipher_get_keyspec(botan_block_cipher_t cipher, \
                                                     size_t* out_minimum_keylength, \
                                                     size_t* out_maximum_keylength, \
                                                     size_t* out_keylength_modulo)

   Return the limits on the key which can be provided to this cipher. If any of the
   parameters are null, no output is written to that field. This allows retrieving only
   (say) the maximum supported keylength, if that is the only information needed.

.. cpp:function:: int botan_block_cipher_clear(botan_block_cipher_t bc)

   Clear the internal state (such as keys) of this cipher object, but do not deallocate it.

.. cpp:function:: int botan_block_cipher_set_key(botan_block_cipher_t bc, const uint8_t key[], size_t key_len)

   Set the cipher key, which is required before encrypting or decrypting.

.. cpp:function:: int botan_block_cipher_encrypt_blocks(botan_block_cipher_t bc, const uint8_t in[], uint8_t out[], size_t blocks)

   The key must have been set first with :cpp:func:`botan_block_cipher_set_key`.
   Encrypt *blocks* blocks of data stored in *in* and place the ciphertext into *out*.
   The two parameters may be the same buffer, but must not overlap.

.. cpp:function:: int botan_block_cipher_decrypt_blocks(botan_block_cipher_t bc, const uint8_t in[], uint8_t out[], size_t blocks)

   The key must have been set first with :cpp:func:`botan_block_cipher_set_key`.
   Decrypt *blocks* blocks of data stored in *in* and place the ciphertext into *out*.
   The two parameters may be the same buffer, but must not overlap.

.. cpp:function:: int botan_block_cipher_destroy(botan_block_cipher_t rng)

   Destroy the object created by :cpp:func:`botan_block_cipher_init`.


Hash Functions
----------------------------------------

.. cpp:type:: opaque* botan_hash_t

   An opaque data type for a hash. Don't mess with it.

.. cpp:function:: botan_hash_t botan_hash_init(const char* hash, uint32_t flags)

   Creates a hash of the given name, e.g., "SHA-384".
   Returns null on failure. Flags should always be zero in this version of the API.

.. cpp:function:: int botan_hash_destroy(botan_hash_t hash)

   Destroy the object created by :cpp:func:`botan_hash_init`.

.. cpp:function:: int botan_hash_name(botan_hash_t hash, char* name, size_t* name_len)

   Write the name of the hash function to the provided buffer.

.. cpp:function:: int botan_hash_copy_state(botan_hash_t* dest, const botan_hash_t source)

   Copies the state of the hash object to a new hash object.

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

Symmetric Ciphers
----------------------------------------

.. cpp:type:: opaque* botan_cipher_t

    An opaque data type for a symmetric cipher object. Don't mess with it, but do remember
    to set a random key first. And please use an AEAD.

.. cpp:function:: botan_cipher_t botan_cipher_init(const char* cipher_name, uint32_t flags)

    Create a cipher object from a name such as "AES-256/GCM" or "Serpent/OCB".

    Flags is a bitfield; the low bitof ``flags`` specifies if encrypt or decrypt,
    ie use 0 for encryption and 1 for decryption.

.. cpp:function:: int botan_cipher_destroy(botan_cipher_t cipher)

.. cpp:function:: int botan_cipher_clear(botan_cipher_t hash)

.. cpp:function:: int botan_cipher_set_key(botan_cipher_t cipher, \
                  const uint8_t* key, size_t key_len)

.. cpp:function:: int botan_cipher_is_authenticated(botan_cipher_t cipher)

.. cpp:function:: size_t botan_cipher_get_tag_length(botan_cipher_t cipher, size_t* tag_len)

   Write the tag length of the cipher to ``tag_len``. This will be zero for non-authenticated
   ciphers.

.. cpp:function:: int botan_cipher_valid_nonce_length(botan_cipher_t cipher, size_t nl)

   Returns 1 if the nonce length is valid, or 0 otherwise. Returns -1 on error (such as
   the cipher object being invalid).

.. cpp:function:: size_t botan_cipher_get_default_nonce_length(botan_cipher_t cipher, size_t* nl)

   Return the default nonce length

.. cpp:function:: int botan_cipher_set_associated_data(botan_cipher_t cipher, \
                                               const uint8_t* ad, size_t ad_len)

   Set associated data. Will fail unless the cipher is an AEAD.

.. cpp:function:: int botan_cipher_start(botan_cipher_t cipher, \
                                 const uint8_t* nonce, size_t nonce_len)

   Start processing a message using the provided nonce.

.. cpp:function:: int botan_cipher_update(botan_cipher_t cipher, \
                                  uint32_t flags, \
                                  uint8_t output[], \
                                  size_t output_size, \
                                  size_t* output_written, \
                                  const uint8_t input_bytes[], \
                                  size_t input_size, \
                                  size_t* input_consumed)

    Encrypt or decrypt data.

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

Multiple Precision Integers
----------------------------------------

.. versionadded: 2.1.0

.. cpp:type:: opaque* botan_mp_t

   An opaque data type for a multiple precision integer. Don't mess with it.

.. cpp:function:: int botan_mp_init(botan_mp_t* mp)

   Initialize a ``botan_mp_t``. Initial value is zero, use `botan_mp_set_X` to load a value.

.. cpp:function:: int botan_mp_destroy(botan_mp_t mp)

   Free a ``botan_mp_t``

.. cpp:function:: int botan_mp_to_hex(botan_mp_t mp, char* out)

   Writes exactly ``botan_mp_num_bytes(mp)*2 + 1`` bytes to out

.. cpp:function:: int botan_mp_to_str(botan_mp_t mp, uint8_t base, char* out, size_t* out_len)

   Base can be either 10 or 16.

.. cpp:function:: int botan_mp_set_from_int(botan_mp_t mp, int initial_value)

   Set ``botan_mp_t`` from an integer value.

.. cpp:function:: int botan_mp_set_from_mp(botan_mp_t dest, botan_mp_t source)

   Set ``botan_mp_t`` from another MP.

.. cpp:function:: int botan_mp_set_from_str(botan_mp_t dest, const char* str)

   Set ``botan_mp_t`` from a string. Leading prefix of "0x" is accepted.

.. cpp:function:: int botan_mp_num_bits(botan_mp_t n, size_t* bits)

   Return the size of ``n`` in bits.

.. cpp:function:: int botan_mp_num_bytes(botan_mp_t n, size_t* uint8_ts)

   Return the size of ``n`` in bytes.

.. cpp:function:: int botan_mp_to_bin(botan_mp_t mp, uint8_t vec[])

   Writes exactly ``botan_mp_num_bytes(mp)`` to ``vec``.

.. cpp:function:: int botan_mp_from_bin(botan_mp_t mp, const uint8_t vec[], size_t vec_len)

   Loads ``botan_mp_t`` from a binary vector (as produced by ``botan_mp_to_bin``).

.. cpp:function:: int botan_mp_is_negative(botan_mp_t mp)

   Return 1 if ``mp`` is negative, otherwise 0.

.. cpp:function:: int botan_mp_flip_sign(botan_mp_t mp)

   Flip the sign of ``mp``.

.. cpp:function:: int botan_mp_add(botan_mp_t result, botan_mp_t x, botan_mp_t y)

   Add two ``botan_mp_t`` and store the output in ``result``.

.. cpp:function:: int botan_mp_sub(botan_mp_t result, botan_mp_t x, botan_mp_t y)

   Subtract two ``botan_mp_t`` and store the output in ``result``.

.. cpp:function:: int botan_mp_mul(botan_mp_t result, botan_mp_t x, botan_mp_t y)

   Multiply two ``botan_mp_t`` and store the output in ``result``.

.. cpp:function:: int botan_mp_div(botan_mp_t quotient, botan_mp_t remainder, \
                           botan_mp_t x, botan_mp_t y)

   Divide ``x`` by ``y`` and store the output in ``quotient`` and ``remainder``.

.. cpp:function:: int botan_mp_mod_mul(botan_mp_t result, botan_mp_t x, botan_mp_t y, botan_mp_t mod)

   Set ``result`` to ``x`` times ``y`` modulo ``mod``.

.. cpp:function:: int botan_mp_equal(botan_mp_t x, botan_mp_t y)

   Return 1 if ``x`` is equal to ``y``, 0 if ``x`` is not equal to ``y``

.. cpp:function:: int botan_mp_is_zero(const botan_mp_t x)

   Return 1 if ``x`` is equal to zero, otherwise 0.

.. cpp:function:: int botan_mp_is_odd(const botan_mp_t x)

   Return 1 if ``x`` is odd, otherwise 0.

.. cpp:function:: int botan_mp_is_even(const botan_mp_t x)

   Return 1 if ``x`` is even, otherwise 0.

.. cpp:function:: int botan_mp_is_positive(const botan_mp_t x)

   Return 1 if ``x`` is greater than or equal to zero.

.. cpp:function:: int botan_mp_is_negative(const botan_mp_t x)

   Return 1 if ``x`` is less than zero.

.. cpp:function:: int botan_mp_to_uint32(const botan_mp_t x, uint32_t* val)

   If x fits in a 32-bit integer, set val to it and return 0. If x is out of
   range an error is returned.

.. cpp:function:: int botan_mp_cmp(int* result, botan_mp_t x, botan_mp_t y)

   Three way comparison: set result to -1 if ``x`` is less than ``y``,
   0 if ``x`` is equal to ``y``, and 1 if ``x`` is greater than ``y``.

.. cpp:function:: int botan_mp_swap(botan_mp_t x, botan_mp_t y)

   Swap two ``botan_mp_t`` values.

.. cpp:function:: int botan_mp_powmod(botan_mp_t out, botan_mp_t base, botan_mp_t exponent, botan_mp_t modulus)

   Modular exponentiation.

.. cpp:function:: int botan_mp_lshift(botan_mp_t out, botan_mp_t in, size_t shift)

   Left shift by specified bit count, place result in ``out``.

.. cpp:function:: int botan_mp_rshift(botan_mp_t out, botan_mp_t in, size_t shift)

   Right shift by specified bit count, place result in ``out``.

.. cpp:function:: int botan_mp_mod_inverse(botan_mp_t out, botan_mp_t in, botan_mp_t modulus)

   Compute modular inverse. If no modular inverse exists (for instance because ``in`` and
   ``modulus`` are not relatively prime), then sets ``out`` to -1.

.. cpp:function:: int botan_mp_rand_bits(botan_mp_t rand_out, botan_rng_t rng, size_t bits)

   Create a random ``botan_mp_t`` of the specified bit size.

.. cpp:function:: int botan_mp_rand_range(botan_mp_t rand_out, botan_rng_t rng, \
                                  botan_mp_t lower_bound, botan_mp_t upper_bound)

   Create a random ``botan_mp_t`` within the provided range.

.. cpp:function:: int botan_mp_gcd(botan_mp_t out, botan_mp_t x, botan_mp_t y)

   Compute the greatest common divisor of ``x`` and ``y``.

.. cpp:function:: int botan_mp_is_prime(botan_mp_t n, botan_rng_t rng, size_t test_prob)

   Test if ``n`` is prime. The algorithm used (Miller-Rabin) is probabilistic,
   set ``test_prob`` to the desired assurance level. For example if
   ``test_prob`` is 64, then sufficient Miller-Rabin iterations will run to
   assure there is at most a ``1/2**64`` chance that ``n`` is composite.

.. cpp:function:: int botan_mp_get_bit(botan_mp_t n, size_t bit)

   Returns 0 if the specified bit of ``n`` is not set, 1 if it is set.

.. cpp:function:: int botan_mp_set_bit(botan_mp_t n, size_t bit)

   Set the specified bit of ``n``

.. cpp:function:: int botan_mp_clear_bit(botan_mp_t n, size_t bit)

   Clears the specified bit of ``n``


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

   Check a previously created password hash.  Returns
   :cpp:enumerator:`BOTAN_SUCCESS` if if this password/hash
   combination is valid, :cpp:enumerator:`BOTAN_FFI_INVALID_VERIFIER`
   if the combination is not valid (but otherwise well formed),
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

   Create an RSA key of the given size

.. cpp:function:: int botan_privkey_create_ecdsa(botan_privkey_t* key, botan_rng_t rng, const char* curve)

   Create a ECDSA key of using a named curve

.. cpp:function:: int botan_privkey_create_ecdh(botan_privkey_t* key, botan_rng_t rng, const char* curve)

   Create a ECDH key of using a named curve

.. cpp:function:: int botan_privkey_create_mceliece(botan_privkey_t* key, botan_rng_t rng, size_t n, size_t t)

   Create a McEliece key using the specified parameters. See
   :ref:`mceliece` for details on choosing parameters.

.. cpp:function:: int botan_privkey_create_dh(botan_privkey_t* key, botan_rng_t rng, const char* params)

   Create a finite field Diffie-Hellman key using the specified named group, for example
   "modp/ietf/3072".

.. cpp:function:: int botan_privkey_load(botan_privkey_t* key, botan_rng_t rng, \
                                 const uint8_t bits[], size_t len, \
                                 const char* password)

   Load a private key. If the key is encrypted, ``password`` will be
   used to attempt decryption.

.. cpp:function:: int botan_privkey_destroy(botan_privkey_t key)

   Destroy the object.

.. cpp:function:: int botan_privkey_export(botan_privkey_t key, \
                                   uint8_t out[], size_t* out_len, \
                                   uint32_t flags)

   Export a public key. If flags is 1 then PEM format is used.

.. cpp:function:: int botan_privkey_export_encrypted(botan_privkey_t key, \
                                             uint8_t out[], size_t* out_len, \
                                             botan_rng_t rng, \
                                             const char* passphrase, \
                                             const char* encryption_algo, \
                                             uint32_t flags)

   Deprecated, use ``botan_privkey_export_encrypted_msec`` or ``botan_privkey_export_encrypted_iter``

.. cpp::function:: int botan_privkey_export_encrypted_pbkdf_msec(botan_privkey_t key,
                                                        uint8_t out[], size_t* out_len, \
                                                        botan_rng_t rng, \
                                                        const char* passphrase, \
                                                        uint32_t pbkdf_msec_runtime, \
                                                        size_t* pbkdf_iterations_out, \
                                                        const char* cipher_algo, \
                                                        const char* pbkdf_algo, \
                                                        uint32_t flags);

    Encrypt a key, running the key derivation function for ``pbkdf_msec_runtime`` milliseconds.
    Returns the number of iterations used in ``pbkdf_iterations_out``.

    ``cipher_algo`` must specify a CBC mode cipher (such as "AES-128/CBC") or as
    a Botan-specific extension a GCM mode may be used.

.. cpp::function:: int botan_privkey_export_encrypted_pbkdf_iter(botan_privkey_t key, \
                                                        uint8_t out[], size_t* out_len, \
                                                        botan_rng_t rng, \
                                                        const char* passphrase, \
                                                        size_t pbkdf_iterations, \
                                                        const char* cipher_algo, \
                                                        const char* pbkdf_algo, \
                                                        uint32_t flags);

   Encrypt a private key. The PBKDF function runs for the specified number of iterations.
   At least 100,000 is recommended.

.. cpp:function:: int botan_privkey_export_pubkey(botan_pubkey_t* out, botan_privkey_t in)

.. cpp:function:: int botan_privkey_get_field(botan_mp_t output, \
                                      botan_privkey_t key, \
                                      const char* field_name)

    Read an algorithm specific field from the private key object, placing it into output.
    For example "p" or "q" for RSA keys, or "x" for DSA keys or ECC keys.

.. cpp:type:: opaque* botan_pubkey_t

   An opaque data type for a public key. Don't mess with it.

.. cpp:function:: int botan_pubkey_load(botan_pubkey_t* key, const uint8_t bits[], size_t len)

.. cpp:function:: int botan_pubkey_export(botan_pubkey_t key, uint8_t out[], size_t* out_len, uint32_t flags)

.. cpp:function:: int botan_pubkey_algo_name(botan_pubkey_t key, char out[], size_t* out_len)

.. cpp:function:: int botan_pubkey_estimated_strength(botan_pubkey_t key, size_t* estimate)

.. cpp:function:: int botan_pubkey_fingerprint(botan_pubkey_t key, const char* hash, \
                                       uint8_t out[], size_t* out_len)

.. cpp:function:: int botan_pubkey_destroy(botan_pubkey_t key)

.. cpp:function:: int botan_pubkey_get_field(botan_mp_t output, \
                                     botan_pubkey_t key, \
                                     const char* field_name)

    Read an algorithm specific field from the public key object, placing it into output.
    For example "n" or "e" for RSA keys or "p", "q", "g", and "y" for DSA keys.

RSA specific functions
----------------------------------------

.. cpp:function:: int botan_privkey_rsa_get_p(botan_mp_t p, botan_privkey_t rsa_key)

   Set ``p`` to the first RSA prime.

.. cpp:function:: int botan_privkey_rsa_get_q(botan_mp_t q, botan_privkey_t rsa_key)

   Set ``q`` to the second RSA prime.

.. cpp:function:: int botan_privkey_rsa_get_d(botan_mp_t d, botan_privkey_t rsa_key)

   Set ``d`` to the RSA private exponent.

.. cpp:function:: int botan_privkey_rsa_get_n(botan_mp_t n, botan_privkey_t rsa_key)

   Set ``n`` to the RSA modulus.

.. cpp:function:: int botan_privkey_rsa_get_e(botan_mp_t e, botan_privkey_t rsa_key)

   Set ``e`` to the RSA public exponent.

.. cpp:function:: int botan_pubkey_rsa_get_e(botan_mp_t e, botan_pubkey_t rsa_key)

   Set ``e`` to the RSA public exponent.

.. cpp:function:: int botan_pubkey_rsa_get_n(botan_mp_t n, botan_pubkey_t rsa_key)

   Set ``n`` to the RSA modulus.

.. cpp:function:: int botan_privkey_load_rsa(botan_privkey_t* key, \
                                     botan_mp_t p, botan_mp_t q, botan_mp_t e)

   Initialize a private RSA key using parameters p, q, and e.

.. cpp:function:: int botan_pubkey_load_rsa(botan_pubkey_t* key, \
                                    botan_mp_t n, botan_mp_t e)

   Initialize a public RSA key using parameters n and e.

DSA specific functions
----------------------------------------

.. cpp:function:: int botan_privkey_load_dsa(botan_privkey_t* key, \
                                     botan_mp_t p, botan_mp_t q, botan_mp_t g, botan_mp_t x)

   Initialize a private DSA key using group parameters p, q, and g and private key x.

.. cpp:function:: int botan_pubkey_load_dsa(botan_pubkey_t* key, \
                                     botan_mp_t p, botan_mp_t q, botan_mp_t g, botan_mp_t y)

   Initialize a private DSA key using group parameters p, q, and g and public key y.

ElGamal specific functions
----------------------------------------

.. cpp:function:: int botan_privkey_load_elgamal(botan_privkey_t* key, \
                                     botan_mp_t p, botan_mp_t g, botan_mp_t x)

   Initialize a private ElGamal key using group parameters p and g and private key x.

.. cpp:function:: int botan_pubkey_load_elgamal(botan_pubkey_t* key, \
                                     botan_mp_t p, botan_mp_t g, botan_mp_t y)

   Initialize a public ElGamal key using group parameters p and g and public key y.

Diffie-Hellman specific functions
----------------------------------------

.. cpp:function:: int botan_privkey_load_dh(botan_privkey_t* key, \
                                     botan_mp_t p, botan_mp_t g, botan_mp_t x)

   Initialize a private Diffie-Hellman key using group parameters p and g and private key x.

.. cpp:function:: int botan_pubkey_load_dh(botan_pubkey_t* key, \
                                     botan_mp_t p, botan_mp_t g, botan_mp_t y)

   Initialize a public Diffie-Hellman key using group parameters p and g and public key y.

Public Key Encryption/Decryption
----------------------------------------

.. cpp:type:: opaque* botan_pk_op_encrypt_t

   An opaque data type for an encryption operation. Don't mess with it.

.. cpp:function:: int botan_pk_op_encrypt_create(botan_pk_op_encrypt_t* op, \
                                         botan_pubkey_t key, \
                                         const char* padding, \
                                         uint32_t flags)

   Create a new operation object which can be used to encrypt using the provided
   key and the specified padding scheme (such as "OAEP(SHA-256)" for use with
   RSA). Flags should be 0 in this version.

.. cpp:function:: int botan_pk_op_encrypt_destroy(botan_pk_op_encrypt_t op)

   Destroy the object.

.. cpp:function:: int botan_pk_op_encrypt_output_length(botan_pk_op_encrypt_t op, \
                  size_t ptext_len, size_t* ctext_len)

   Returns an upper bound on the output length if a plaintext of length ``ptext_len``
   is encrypted with this key/parameter setting. This allows correctly sizing the
   buffer that is passed to :cpp:func:`botan_pk_op_encrypt`.

.. cpp:function:: int botan_pk_op_encrypt(botan_pk_op_encrypt_t op, \
                                  botan_rng_t rng, \
                                  uint8_t out[], size_t* out_len, \
                                  const uint8_t plaintext[], size_t plaintext_len)

   Encrypt the provided data using the key, placing the output in `out`.  If
   `out` is NULL, writes the length of what the ciphertext would have been to
   `*out_len`. However this is computationally expensive (the encryption
   actually occurs, then the result is discarded), so it is better to use
   :cpp:func:`botan_pk_op_encrypt_output_length` to correctly size the buffer.

.. cpp:type:: opaque* botan_pk_op_decrypt_t

   An opaque data type for a decryption operation. Don't mess with it.

.. cpp:function:: int botan_pk_op_decrypt_create(botan_pk_op_decrypt_t* op, \
                                         botan_privkey_t key, \
                                         const char* padding, \
                                         uint32_t flags)

.. cpp:function:: int botan_pk_op_decrypt_destroy(botan_pk_op_decrypt_t op)

.. cpp:function:: int botan_pk_op_decrypt_output_length(botan_pk_op_decrypt_t op, \
                  size_t ctext_len, size_t* ptext_len)

   For a given ciphertext length, returns the upper bound on the size of the
   plaintext that might be enclosed. This allows properly sizing the output
   buffer passed to :cpp:func:`botan_pk_op_decrypt`.

.. cpp:function:: int botan_pk_op_decrypt(botan_pk_op_decrypt_t op, \
                                  uint8_t out[], size_t* out_len, \
                                  uint8_t ciphertext[], size_t ciphertext_len)

Signature Generation
----------------------------------------

.. cpp:type:: opaque* botan_pk_op_sign_t

   An opaque data type for a signature generation operation. Don't mess with it.

.. cpp:function:: int botan_pk_op_sign_create(botan_pk_op_sign_t* op, \
                                      botan_privkey_t key, \
                                      const char* hash_and_padding, \
                                      uint32_t flags)

   Create a signature operator for the provided key. The padding string
   specifies what hash function and padding should be used, for example
   "PKCS1v15(SHA-256)" or "EMSA1(SHA-384)".

.. cpp:function:: int botan_pk_op_sign_destroy(botan_pk_op_sign_t op)

   Destroy an object created by :cpp:func:`botan_pk_op_sign_create`.

.. cpp:function:: int botan_pk_op_sign_output_length(botan_pk_op_sign_t op, size_t* sig_len)

   Writes the length of the signatures that this signer will produce. This
   allows properly sizing the buffer passed to
   :cpp:func:`botan_pk_op_sign_finish`.

.. cpp:function:: int botan_pk_op_sign_update(botan_pk_op_sign_t op, \
                                      const uint8_t in[], size_t in_len)

   Add bytes of the message to be signed.

.. cpp:function:: int botan_pk_op_sign_finish(botan_pk_op_sign_t op, botan_rng_t rng, \
                                      uint8_t sig[], size_t* sig_len)

   Produce a signature over all of the bytes passed to :cpp:func:`botan_pk_op_sign_update`.
   Afterwards, the sign operator is reset and may be used to sign a new message.

Signature Verification
----------------------------------------

.. cpp:type:: opaque* botan_pk_op_verify_t

   An opaque data type for a signature verification operation. Don't mess with it.

.. cpp:function:: int botan_pk_op_verify_create(botan_pk_op_verify_t* op, \
                                        botan_pubkey_t key, \
                                        const char* hash_and_padding, \
                                        uint32_t flags)

.. cpp:function:: int botan_pk_op_verify_destroy(botan_pk_op_verify_t op)

.. cpp:function:: int botan_pk_op_verify_update(botan_pk_op_verify_t op, \
                                        const uint8_t in[], size_t in_len)

   Add bytes of the message to be verified

.. cpp:function:: int botan_pk_op_verify_finish(botan_pk_op_verify_t op, \
                                        const uint8_t sig[], size_t sig_len)

   Verify if the signature provided matches with the message provided as calls
   to :cpp:func:`botan_pk_op_verify_update`.

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

   Load a certificate from the DER or PEM representation

.. cpp:function:: int botan_x509_cert_load_file(botan_x509_cert_t* cert_obj, const char* filename)

   Load a certificate from a file.

.. cpp:function:: int botan_x509_cert_dup(botan_x509_cert_t* cert_obj, botan_x509_cert_t cert)

   Create a new object that refers to the same certificate.

.. cpp:function:: int botan_x509_cert_destroy(botan_x509_cert_t cert)

   Destroy the certificate object

.. cpp:function:: int botan_x509_cert_gen_selfsigned(botan_x509_cert_t* cert, \
                                             botan_privkey_t key, \
                                             botan_rng_t rng, \
                                             const char* common_name, \
                                             const char* org_name)

.. cpp:function:: int botan_x509_cert_get_time_starts(botan_x509_cert_t cert, char out[], size_t* out_len)

   Return the time the certificate becomes valid, as a string in form
   "YYYYMMDDHHMMSSZ" where Z is a literal character reflecting that this time is
   relative to UTC. Prefer :cpp:func:`botan_x509_cert_not_before`.

.. cpp:function:: int botan_x509_cert_get_time_expires(botan_x509_cert_t cert, char out[], size_t* out_len)

   Return the time the certificate expires, as a string in form
   "YYYYMMDDHHMMSSZ" where Z is a literal character reflecting that this time is
   relative to UTC. Prefer :cpp:func:`botan_x509_cert_not_after`.

.. cpp:function:: int botan_x509_cert_not_before(botan_x509_cert_t cert, uint64_t* time_since_epoch)

   Return the time the certificate becomes valid, as seconds since epoch.

.. cpp:function:: int botan_x509_cert_not_after(botan_x509_cert_t cert, uint64_t* time_since_epoch)

   Return the time the certificate expires, as seconds since epoch.

.. cpp:function:: int botan_x509_cert_get_fingerprint(botan_x509_cert_t cert, const char* hash, uint8_t out[], size_t* out_len)

.. cpp:function:: int botan_x509_cert_get_serial_number(botan_x509_cert_t cert, uint8_t out[], size_t* out_len)

   Return the serial number of the certificate.

.. cpp:function:: int botan_x509_cert_get_authority_key_id(botan_x509_cert_t cert, uint8_t out[], size_t* out_len)

   Return the authority key ID set in the certificate, which may be empty.

.. cpp:function:: int botan_x509_cert_get_subject_key_id(botan_x509_cert_t cert, uint8_t out[], size_t* out_len)

   Return the subject key ID set in the certificate, which may be empty.

.. cpp:function:: int botan_x509_cert_get_public_key_bits(botan_x509_cert_t cert, \
                                                  uint8_t out[], size_t* out_len)

   Get the serialized representation of the public key included in this certificate

.. cpp:function:: int botan_x509_cert_get_public_key(botan_x509_cert_t cert, botan_pubkey_t* key)

   Get the public key included in this certificate as a newly allocated object

.. cpp:function:: int botan_x509_cert_get_issuer_dn(botan_x509_cert_t cert, \
                                            const char* key, size_t index, \
                                            uint8_t out[], size_t* out_len)

   Get a value from the issuer DN field.

.. cpp:function:: int botan_x509_cert_get_subject_dn(botan_x509_cert_t cert, \
                                             const char* key, size_t index, \
                                             uint8_t out[], size_t* out_len)

   Get a value from the subject DN field.

.. cpp:function:: int botan_x509_cert_to_string(botan_x509_cert_t cert, char out[], size_t* out_len)

   Format the certificate as a free-form string.

.. cpp:enum:: botan_x509_cert_key_constraints

   Certificate key usage constraints. Allowed values: `NO_CONSTRAINTS`,
   `DIGITAL_SIGNATURE`, `NON_REPUDIATION`, `KEY_ENCIPHERMENT`,
   `DATA_ENCIPHERMENT`, `KEY_AGREEMENT`, `KEY_CERT_SIGN`,
   `CRL_SIGN`, `ENCIPHER_ONLY`, `DECIPHER_ONLY`.

.. cpp:function:: int botan_x509_cert_allowed_usage(botan_x509_cert_t cert, unsigned int key_usage)


.. cpp:function:: int botan_x509_cert_verify(int* validation_result, \
                  botan_x509_cert_t cert, \
                  const botan_x509_cert_t* intermediates, \
                  size_t intermediates_len, \
                  const botan_x509_cert_t* trusted, \
                  size_t trusted_len, \
                  const char* trusted_path, \
                  size_t required_strength, \
                  const char* hostname, \
                  uint64_t reference_time)

    Verify a certificate. Returns 0 if validation was successful, 1 if
    unsuccessful, or negative on error.

    Sets ``validation_result`` to a code that provides more information.

    If not needed, set ``intermediates`` to NULL and ``intermediates_len`` to
    zero.

    If not needed, set ``trusted`` to NULL and ``trusted_len`` to zero.

    The ``trusted_path`` refers to a directory where one or more trusted CA
    certificates are stored. It may be NULL if not needed.

    Set ``required_strength`` to indicate the minimum key and hash strength
    that is allowed. For instance setting to 80 allows 1024-bit RSA and SHA-1.
    Setting to 110 requires 2048-bit RSA and SHA-256 or higher. Set to zero
    to accept a default.

    Set ``reference_time`` to be the time which the certificate chain is
    validated against. Use zero to use the current system clock.

.. cpp:function:: int botan_x509_cert_verify_with_crl(int* validation_result, \
                  botan_x509_cert_t cert, \
                  const botan_x509_cert_t* intermediates, \
                  size_t intermediates_len, \
                  const botan_x509_cert_t* trusted, \
                  size_t trusted_len, \
                  const botan_x509_crl_t* crls, \
                  size_t crls_len, \
                  const char* trusted_path, \
                  size_t required_strength, \
                  const char* hostname, \
                  uint64_t reference_time)

   Certificate path validation supporting Certificate Revocation Lists.

   Works the same as ``botan_x509_cert_cerify``.

   ``crls`` is an array of ``botan_x509_crl_t`` objects, ``crls_len`` is its length.

.. cpp:function:: const char* botan_x509_cert_validation_status(int code)

   Return a (statically allocated) string associated with the verification
   result.

X.509 Certificate Revocation Lists
----------------------------------------

.. cpp:type:: opaque* botan_x509_crl_t

   An opaque data type for an X.509 CRL.

.. cpp:function:: int botan_x509_crl_load(botan_x509_crl_t* crl_obj, \
                                        const uint8_t crl[], size_t crl_len)

   Load a CRL from the DER or PEM representation.

.. cpp:function:: int botan_x509_crl_load_file(botan_x509_crl_t* crl_obj, const char* filename)

   Load a CRL from a file.

.. cpp:function:: int botan_x509_crl_destroy(botan_x509_crl_t crl)

   Destroy the CRL object.

.. cpp:function:: int botan_x509_is_revoked(botan_x509_crl_t crl, botan_x509_cert_t cert)

   Check whether a given ``crl`` contains a given ``cert``.
   Return ``0`` when the certificate is revoked, ``-1`` otherwise.
