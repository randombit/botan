
FFI (C Binding)
========================================

.. versionadded:: 2.0.0

Botan's ffi module provides a C89 binding intended to be easily usable with other
language's foreign function interface (FFI) libraries. For instance the included
Python wrapper uses Python's ``ctypes`` module and the C89 API. This API is of
course also useful for programs written directly in C.

Code examples can be found in `the tests
<https://github.com/randombit/botan/blob/master/src/tests/test_ffi.cpp>`_ as
well as the implementations of the various `language bindings
<https://github.com/randombit/botan/wiki/Language-Bindings>`_. At the time of
this writing, the Python and Rust bindings are probably the most comprehensive.

Rules of Engagement
---------------------

Writing language bindings for C or C++ libraries is typically a tedious and
bug-prone experience. This FFI layer was designed to make the experience, if not
pleasant, at least straighforward.

* All objects manipulated by the API are opaque structs. Each struct is tagged
  with a 32-bit magic number which is unique to its type; accidentally passing
  the wrong object type to a function will result in a
  :cpp:enumerator:`BOTAN_FFI_ERROR_INVALID_OBJECT` error, instead of a crash or
  memory corruption.

* (Almost) all functions return an integer error code indicating success or
  failure. The exception is a small handful of version query functions, which
  are guaranteed to never fail. All functions returning errors use the same
  set of error codes.

* The set of types used is small and commonly supported: ``uint8_t`` arrays for
  binary data, ``size_t`` for lengths, and NULL-terminated UTF-8 encoded
  strings.

* No ownership of pointers crosses the boundary. If the library is producing
  output, it does so by either writing to a buffer that was provided by the
  application, or calling a view callback.

  In the first case, the application typically passes both an output buffer and
  a pointer to a length field. On entry, the length field should be set to the
  number of bytes available in the output buffer. If there is sufficient room,
  the output is written to the buffer, the actual number of bytes written is
  returned in the length field, and the function returns 0 (success). Otherwise,
  the number of bytes required is placed in the length parameter, and then
  :cpp:enumerator:`BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE` is returned.

  In most cases, for this style of function, there is also a function which
  allows querying the actual (or possibly upper bound) number of bytes in the
  function's output. For example calling :cpp:func:`botan_hash_output_length`
  allows the application to determine in advance the number of bytes that
  :cpp:func:`botan_hash_final` will want to write.

  In some situations, it is not possible to determine exactly what the output
  size of the function will be in advance. Here the FFI layer uses what it terms
  :ref:`view_functions`; callbacks that are allowed to view the entire output of
  the function, but once the callback returns, no further access is allowed.
  View functions are called with an opaque pointer provided by the application,
  which allows passing arbitrary context information.

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

.. cpp:enumerator:: BOTAN_FFI_ERROR_NO_VALUE = -3

   The requested value was not available or does not exist.

.. cpp:enumerator:: BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE = -10

   Functions which write a variable amount of space return this if the indicated
   buffer length was insufficient to write the data. In that case, the output
   length parameter is set to the size that is required.

.. cpp:enumerator:: BOTAN_FFI_ERROR_STRING_CONVERSION_ERROR = -11

   A string view function which attempts to convert a string to a specified
   charset, and fails, can use this function to indicate the error.

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

.. cpp:enumerator:: BOTAN_FFI_ERROR_SYSTEM_ERROR = -22

   A system call failed

.. cpp:enumerator:: BOTAN_FFI_ERROR_INTERNAL_ERROR = -23

   An internal bug was encountered (please open a ticket on github)

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

   An invalid key length was provided with a call to ``foo_set_key``.

.. cpp:enumerator:: BOTAN_FFI_ERROR_INVALID_OBJECT_STATE = -35

   An operation was invoked that makes sense for the object, but it is in the
   wrong state to perform it.

.. cpp:enumerator:: BOTAN_FFI_ERROR_NOT_IMPLEMENTED = -40

   This is returned if the functionality is not available for some reason.  For
   example if you call :cpp:func:`botan_hash_init` with a named hash function
   which is not enabled, this error is returned.

.. cpp:enumerator:: BOTAN_FFI_ERROR_INVALID_OBJECT = -50

   This is used if an object provided did not match the function.  For example
   calling :cpp:func:`botan_hash_destroy` on a ``botan_rng_t`` object will cause
   this error.

.. cpp:enumerator:: BOTAN_FFI_TPM_ERROR = -78

   An error occured when performing TPM2 interactions.

.. cpp:enumerator:: BOTAN_FFI_ERROR_UNKNOWN_ERROR = -100

   Something bad happened, but we are not sure why or how.

Error values below -10000 are reserved for the application (these can be returned
from view functions).

Further information about the error that occured is available via

.. cpp:function:: const char* botan_error_last_exception_message()

   .. versionadded:: 3.0.0

   Returns a static string stored in a thread local variable which contains
   the last exception message thrown.

   .. warning::
      This string buffer is overwritten on the next call to the FFI layer

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
20250506       3.8.0
20240408       3.4.0
20231009       3.2.0
20230711       3.1.0
20230403       3.0.0
20210220       2.18.0
20191214       2.13.0
20180713       2.8.0
20170815       2.3.0
20170327       2.1.0
20150515       2.0.0
============== ===================

.. _view_functions:

View Functions
----------------------------------------

.. versionadded:: 3.0.0

Starting in Botan 3.0, certain functions were added which produce a "view".
That is instead of copying data to a user provided buffer, they instead invoke a
callback, passing the data that was requested. This avoids an issue where in
some cases it is not possible for the caller to know what the output length of
the FFI function will be. In these cases, the best they can do is set a large
length, invoke the function, and then accept that they may need to retry the
(potentially expensive) operation.

View functions avoid this by always providing the full data, and allowing
the caller to allocate memory as necessary to copy out the result, without
having to guess the length in advance.

In all cases the pointer passed to the view function is deallocated after
the view function returns, and should not be retained.

The view functions return an integer value; if they return non-zero, then the
overall FFI function will also return this integer. To avoid confusion when
mapping the errors, any error returns should either match Botan's FFI error
codes, or else use an integer value in the application reserved range.

.. cpp:type:: void* botan_view_ctx

   The application context, which is passed back to the view function.

.. cpp:type:: int (*botan_view_bin_fn)(botan_view_ctx view_ctx, const uint8_t* data, size_t len)

   A viewer of arbitrary binary data.

.. cpp:type:: int (*botan_view_str_fn)(botan_view_ctx view_ctx, const char* str, size_t len)

   A viewer of a null terminated C-style string. The length *includes* the null terminator byte.
   The string should be UTF-8 encoded, but in certain circumstances may not be.
   (Typically this would be due to a bug or oversight; please report the issue.)
   :cpp:enumerator:`BOTAN_FFI_ERROR_STRING_CONVERSION_ERROR` is reserved to allow the FFI
   call to indicate the problem, should it be unable to convert the data.

Utility Functions
----------------------------------------

.. const char* botan_error_description(int err)

   Return a string representation of the provided error code. If the error code
   is unknown, returns the string "Unknown error". The return values are static
   constant strings and should not be freed.

.. cpp:function:: int botan_constant_time_compare(const uint8_t* x, const uint8_t* y, size_t len)

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

.. cpp:function:: int botan_rng_init_custom(botan_rng_t* rng,\
                  const char* rng_name, void* context, \
                  int(* get_cb)(void* context, uint8_t* out, size_t out_len), \
                  int(* add_entropy_cb)(void* context, const uint8_t input[], size_t length), \
                  void(* destroy_cb)(void* context));

   .. versionadded:: 2.18.0

   Create a new custom RNG object, which will invoke the provided callbacks.

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

.. cpp:function:: int botan_hash_init(botan_hash_t hash, const char* hash_name, uint32_t flags)

   Creates a hash of the given name, e.g., "SHA-384".

   Flags should always be zero in this version of the API.

.. cpp:function:: int botan_hash_destroy(botan_hash_t hash)

   Destroy the object created by :cpp:func:`botan_hash_init`.

.. cpp:function:: int botan_hash_name(botan_hash_t hash, char* name, size_t* name_len)

   Write the name of the hash function to the provided buffer.

.. cpp:function:: int botan_hash_copy_state(botan_hash_t* dest, const botan_hash_t source)

   Copies the state of the hash object to a new hash object.

.. cpp:function:: int botan_hash_clear(botan_hash_t hash)

   Reset the state of this object back to clean, as if no input has
   been supplied.

.. cpp:function:: int botan_hash_output_length(botan_hash_t hash, size_t* output_length)

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

.. cpp:function:: int botan_mac_init(botan_mac_t* mac, const char* mac_name, uint32_t flags)

   Creates a MAC of the given name, e.g., "HMAC(SHA-384)".
   Flags should always be zero in this version of the API.

.. cpp:function:: int botan_mac_destroy(botan_mac_t mac)

   Destroy the object created by :cpp:func:`botan_mac_init`.

.. cpp:function:: int botan_mac_clear(botan_mac_t mac)

   Reset the state of this object back to clean, as if no key and input have
   been supplied.

.. cpp:function:: int botan_mac_output_length(botan_mac_t mac, size_t* output_length)

   Return the output length of the MAC.

.. cpp:function:: int botan_mac_set_key(botan_mac_t mac, const uint8_t* key, size_t key_len)

   Set the random key.

.. cpp:function:: int botan_mac_set_nonce(botan_mac_t mac, const uint8_t* key, size_t key_len)

   Set a nonce for the MAC. This is used for certain (relatively uncommon) MACs such as GMAC

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

.. cpp:function:: int botan_cipher_init(botan_cipher_t* cipher, const char* cipher_name, uint32_t flags)

    Create a cipher object from a name such as "AES-256/GCM" or "Serpent/OCB".

    Flags is a bitfield; the low bitof ``flags`` specifies if encrypt or decrypt,
    ie use 0 for encryption and 1 for decryption.

.. cpp:function:: int botan_cipher_destroy(botan_cipher_t cipher)

.. cpp:function:: int botan_cipher_clear(botan_cipher_t hash)

.. cpp:function:: int botan_cipher_set_key(botan_cipher_t cipher, \
                  const uint8_t* key, size_t key_len)

.. cpp:function:: int botan_cipher_is_authenticated(botan_cipher_t cipher)

.. cpp:function:: int botan_cipher_requires_entire_message(botan_cipher_t cipher)

.. cpp:function:: int botan_cipher_get_tag_length(botan_cipher_t cipher, size_t* tag_len)

   Write the tag length of the cipher to ``tag_len``. This will be zero for non-authenticated
   ciphers.

.. cpp:function:: int botan_cipher_valid_nonce_length(botan_cipher_t cipher, size_t nl)

   Returns 1 if the nonce length is valid, or 0 otherwise. Returns -1 on error (such as
   the cipher object being invalid).

.. cpp:function:: int botan_cipher_get_default_nonce_length(botan_cipher_t cipher, size_t* nl)

   Return the default nonce length

.. cpp:function:: int botan_cipher_get_update_granularity(botan_cipher_t cipher, size_t* ug)

   Return the minimum update granularity, ie the size of a buffer that must be
   passed to :cpp:func:`botan_cipher_update`

.. cpp:function:: int botan_cipher_get_ideal_update_granularity(botan_cipher_t cipher, size_t* ug)

   Return the ideal update granularity, ie the size of a buffer that must be
   passed to :cpp:func:`botan_cipher_update` that maximizes performance.

   .. note::

      Using larger buffers than the value returned here is unlikely to hurt
      (within reason). Typically the returned value is a small multiple of the
      minimum granularity, with the multiplier depending on the algorithm and
      hardware support.

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
   using the given PBKDF algorithm, e.g., "PBKDF2(SHA-512)".

.. cpp:function:: int botan_pbkdf_timed(const char* pbkdf_algo, \
                                uint8_t out[], size_t out_len, \
                                const char* passphrase, \
                                const uint8_t salt[], size_t salt_len, \
                                size_t milliseconds_to_run, \
                                size_t* out_iterations_used)

   Derive a key from a passphrase using the given PBKDF algorithm,
   e.g., "PBKDF2(SHA-512)". If *out_iterations_used* is zero, instead the
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

.. versionadded:: 2.1.0

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


Object Identifiers
----------------------------------------

.. versionadded:: 3.8.0

.. cpp:type:: opaque* botan_asn1_oid_t

   An opaque data type for an object identifier. Don't mess with it.

.. cpp:function:: int botan_oid_destroy(botan_asn1_oid_t oid)

   Destroy an object.

.. cpp:function:: int botan_oid_from_string(botan_asn1_oid_t* oid, const char* oid_str)

   Create an OID from a string, either dot notation (e.g. '1.2.3.4') or a registered name (e.g. 'RSA')

.. cpp:function:: int botan_oid_register(botan_asn1_oid_t oid, const char* name)

   Register an OID so that it may later be retrieved by name

.. cpp:function:: int botan_oid_view_string(botan_asn1_oid_t oid, botan_view_ctx ctx, botan_view_str_fn view)

   View the OID in dot notation

.. cpp:function:: int botan_oid_view_name(botan_asn1_oid_t oid, botan_view_ctx ctx, botan_view_str_fn view)

   View the OID as a name if it has one, otherwise as dot notation

.. cpp:function:: int botan_oid_equal(botan_asn1_oid_t a, botan_asn1_oid_t b)

   Three way comparison: set result to -1 if ``a`` is less than ``b``,
   0 if ``a`` is equal to ``b``, and 1 if ``a`` is greater than ``b``.

.. cpp:function:: int botan_oid_cmp(int* result, botan_asn1_oid_t a, botan_asn1_oid_t b)

   Return 1 if ``a`` is equal to ``b``, 0 if ``a`` is not equal to ``b``


EC Groups
----------------------------------------

.. versionadded:: 3.8.0

.. cpp:type:: opaque* botan_ec_group_t

   An opaque data type for an EC Group. Don't mess with it.

.. cpp:function:: int botan_ec_group_destroy(botan_ec_group_t oid)

   Destroy an object.

.. cpp:function:: int botan_ec_group_supports_application_specific_group(int* out)

   Checks if in this build configuration it is possible to register an application specific elliptic curve,
   and sets ``out`` to 1 if so, 0 otherwise.

.. cpp:function:: int botan_ec_group_supports_named_group(const char* name, int* out)

   Checks if in this build configuration botan_ec_group_from_name(group_ptr, name) will succeed,
   and sets ``out`` to 1 if so, 0 otherwise.

.. cpp:function:: int botan_ec_group_from_params(botan_ec_group_t* ec_group, \
                               botan_asn1_oid_t oid, \
                               botan_mp_t p, \
                               botan_mp_t a, \
                               botan_mp_t b, \
                               botan_mp_t base_x, \
                               botan_mp_t base_y, \
                               botan_mp_t order)

   Create a new EC Group from the given parameters.

   .. warning::
      Use only elliptic curve parameters you trust.

.. cpp:function:: int botan_ec_group_from_ber(botan_ec_group_t* ec_group, const uint8_t* ber, size_t ber_len)

   Decode a BER encoded ECC domain parameter set

.. cpp:function:: int botan_ec_group_from_pem(botan_ec_group_t* ec_group, const char* pem)

   Initialize an EC Group from the PEM/ASN.1 encoding

.. cpp:function:: int botan_ec_group_from_oid(botan_ec_group_t* ec_group, botan_asn1_oid_t oid)

   Initialize an EC Group from a group named by an object identifier

.. cpp:function:: int botan_ec_group_from_name(botan_ec_group_t* ec_group, const char* name)

   Initialize an EC Group from a common group name (eg "secp256r1")

.. cpp:function:: int botan_ec_group_view_der(botan_ec_group_t ec_group, botan_view_ctx ctx, botan_view_bin_fn view)

   View an EC Group in DER encoding

.. cpp:function:: int botan_ec_group_view_pem(botan_ec_group_t ec_group, botan_view_ctx ctx, botan_view_str_fn view)

   View an EC Group in PEM encoding

.. cpp:function:: int botan_ec_group_get_curve_oid(botan_asn1_oid_t* oid, botan_ec_group_t ec_group)

   Get the curve OID of an EC Group

.. cpp:function:: int botan_ec_group_get_p(botan_mp_t* p, botan_ec_group_t ec_group)

   Get the prime modulus of the field

.. cpp:function:: int botan_ec_group_get_a(botan_mp_t* a, botan_ec_group_t ec_group)

   Get the a parameter of the elliptic curve equation

.. cpp:function:: int botan_ec_group_get_b(botan_mp_t* b, botan_ec_group_t ec_group)

   Get the b parameter of the elliptic curve equation

.. cpp:function:: int botan_ec_group_get_g_x(botan_mp_t* g_x, botan_ec_group_t ec_group)

   Get the x coordinate of the base point

.. cpp:function:: int botan_ec_group_get_g_y(botan_mp_t* g_y, botan_ec_group_t ec_group)

   Get the y coordinate of the base point

.. cpp:function:: int botan_ec_group_get_order(botan_mp_t* order, botan_ec_group_t ec_group)

   Get the order of the base point

.. cpp:function:: int botan_ec_group_equal(botan_ec_group_t curve1, botan_ec_group_t curve2)

   Return 1 if ``curve1`` is equal to ``curve2``, 0 if ``curve1`` is not equal to ``curve2``


Public Key Creation, Import and Export
----------------------------------------

.. cpp:type:: opaque* botan_privkey_t

   An opaque data type for a private key. Don't mess with it.

.. cpp:function:: int botan_privkey_destroy(botan_privkey_t key)

   Destroy an object.

.. cpp:function:: int botan_privkey_create(botan_privkey_t* key, \
                                   const char* algo_name, \
                                   const char* algo_params, \
                                   botan_rng_t rng)

.. cpp:function:: int botan_ec_privkey_create(botan_privkey_t* key, \
                                   const char* algo_name, \
                                   botan_ec_group_t ec_group, \
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

.. cpp:function:: int botan_privkey_export(botan_privkey_t key, \
                                   uint8_t out[], size_t* out_len, \
                                   uint32_t flags)

   Export a private key. If flags is 1 then PEM format is used.

.. cpp:function:: int botan_privkey_view_encrypted_der(botan_privkey_t key, \
        botan_rng_t rng, \
        const char* passphrase, \
        const char* cipher_algo, \
        const char* pbkdf_hash, \
        size_t pbkdf_iterations, \
        botan_view_ctx ctx, \
        botan_view_bin_fn view)

     View the encrypted DER private key. In this version the number of PKBDF2
     iterations is specified.

     Set cipher_algo and pbkdf_hash to NULL to select defaults.

.. cpp:function:: int botan_privkey_view_encrypted_der_timed(botan_privkey_t key, \
        botan_rng_t rng, \
        const char* passphrase, \
        const char* cipher_algo, \
        const char* pbkdf_hash, \
        size_t pbkdf_runtime_msec, \
        botan_view_ctx ctx, \
        botan_view_bin_fn view)

     View the encrypted DER private key. In this version the desired PBKDF runtime
     is specified in milliseconds.

     Set cipher_algo and pbkdf_hash to NULL to select defaults.

.. cpp:function:: int botan_privkey_view_encrypted_pem(botan_privkey_t key, \
        botan_rng_t rng, \
        const char* passphrase, \
        const char* cipher_algo, \
        const char* pbkdf_hash, \
        size_t pbkdf_iterations, \
        botan_view_ctx ctx, \
        botan_view_str_fn view)

     View the encrypted PEM private key. In this version the number of PKBDF2
     iterations is specified.

     Set cipher_algo and pbkdf_hash to NULL to select defaults.

.. cpp:function:: int botan_privkey_view_encrypted_pem_timed(botan_privkey_t key, \
        botan_rng_t rng, \
        const char* passphrase, \
        const char* cipher_algo, \
        const char* pbkdf_hash, \
        size_t pbkdf_runtime_msec, \
        botan_view_ctx ctx, \
        botan_view_str_fn view)

     View the encrypted PEM private key. In this version the desired PBKDF runtime
     is specified in milliseconds.

     Set cipher_algo and pbkdf_hash to NULL to select defaults.

.. cpp:function:: int botan_privkey_view_der(botan_privkey_t key, \
      botan_view_ctx ctx, botan_view_bin_fn view)

   View the unencrypted DER encoding of the private key

.. cpp:function:: int botan_privkey_view_pem(botan_privkey_t key, \
      botan_view_ctx ctx, botan_view_str_fn view)

   View the unencrypted PEM encoding of the private key

.. cpp:function:: int botan_privkey_view_raw(botan_privkey_t key, \
      botan_view_ctx ctx, botan_view_str_fn view)

   View the unencrypted canonical raw encoding of the private key
   This might not be defined for all key types and throw in that case.

.. cpp:function:: int botan_privkey_export_encrypted(botan_privkey_t key, \
                                             uint8_t out[], size_t* out_len, \
                                             botan_rng_t rng, \
                                             const char* passphrase, \
                                             const char* encryption_algo, \
                                             uint32_t flags)

   Deprecated, use ``botan_privkey_export_encrypted_msec`` or ``botan_privkey_export_encrypted_iter``

.. cpp:function:: int botan_privkey_export_encrypted_pbkdf_msec(botan_privkey_t key, \
                                                        uint8_t out[], size_t* out_len, \
                                                        botan_rng_t rng, \
                                                        const char* passphrase, \
                                                        uint32_t pbkdf_msec_runtime, \
                                                        size_t* pbkdf_iterations_out, \
                                                        const char* cipher_algo, \
                                                        const char* pbkdf_hash, \
                                                        uint32_t flags);

    Encrypt a key, running the key derivation function for ``pbkdf_msec_runtime`` milliseconds.
    Returns the number of iterations used in ``pbkdf_iterations_out``.

    ``cipher_algo`` must specify a CBC mode cipher (such as "AES-128/CBC") or as
    a Botan-specific extension a GCM mode may be used.

.. cpp:function:: int botan_privkey_export_encrypted_pbkdf_iter(botan_privkey_t key, \
                                                        uint8_t out[], size_t* out_len, \
                                                        botan_rng_t rng, \
                                                        const char* passphrase, \
                                                        size_t pbkdf_iterations, \
                                                        const char* cipher_algo, \
                                                        const char* pbkdf_hash, \
                                                        uint32_t flags);

   Encrypt a private key. The PBKDF function runs for the specified number of iterations.
   At least 100,000 is recommended.

.. cpp:function:: int botan_privkey_export_pubkey(botan_pubkey_t* out, botan_privkey_t in)

.. cpp:function:: int botan_privkey_get_field(botan_mp_t output, \
                                      botan_privkey_t key, \
                                      const char* field_name)

    Read an algorithm specific field from the private key object, placing it into output.
    For example "p" or "q" for RSA keys, or "x" for DSA keys or ECC keys.

.. cpp:function:: int botan_privkey_oid(botan_asn1_oid_t* oid, botan_privkey_t key)

   Get the key's associated OID.

.. cpp:function:: int botan_privkey_stateful_operation(botan_privkey_t key, int* out)

   Checks whether a key is stateful and set ``out`` to 1 if it is, 0 otherwise.

.. cpp:function:: int botan_privkey_remaining_operations(botan_privkey_t key, uint64_t* out)

   Set ``out`` to the number of remaining operations.
   If the key is not stateful, an error will be returned.

.. cpp:type:: opaque* botan_pubkey_t

   An opaque data type for a public key. Don't mess with it.

.. cpp:function:: int botan_pubkey_load(botan_pubkey_t* key, const uint8_t bits[], size_t len)

.. cpp:function:: int botan_pubkey_export(botan_pubkey_t key, uint8_t out[], size_t* out_len, uint32_t flags)

.. cpp:function:: int botan_pubkey_view_der(botan_pubkey_t key, \
      botan_view_ctx ctx, botan_view_bin_fn view)

   View the DER encoding of the public key

.. cpp:function:: int botan_pubkey_view_pem(botan_pubkey_t key, \
      botan_view_ctx ctx, botan_view_str_fn view)

   View the PEM encoding of the public key

.. cpp:function:: int botan_pubkey_view_raw(botan_pubkey_t key, \
      botan_view_ctx ctx, botan_view_bin_fn view)

   View the canonical raw encoding of the public key.
   This may not be defined for all public key types and throw.

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

.. cpp:function:: int botan_pubkey_oid(botan_asn1_oid_t* oid, botan_privkey_t key)

   Get the key's associated OID.

RSA specific functions
----------------------------------------

.. note::
   These functions are deprecated. Instead use :cpp:func:`botan_privkey_get_field`
   and :cpp:func:`botan_pubkey_get_field`.

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
   "PKCS1v15(SHA-256)" for PKCS #1 v1.5 padding (used with RSA) or "SHA-384".
   Generally speaking only RSA has special padding modes; for other algorithms
   like ECDSA one just names the hash.

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

.. cpp:function:: int botan_pk_op_key_agreement_view_public(botan_privkey_t key, \
      botan_view_ctx ctx, botan_view_bin_fn view)

.. cpp:function:: int botan_pk_op_key_agreement(botan_pk_op_ka_t op, \
                                        uint8_t out[], size_t* out_len, \
                                        const uint8_t other_key[], size_t other_key_len, \
                                        const uint8_t salt[], size_t salt_len)

Public Key Encapsulation
----------------------------------------

.. versionadded:: 3.0.0

.. cpp:type:: opaque* botan_pk_op_kem_encrypt_t

   An opaque data type for a KEM operation. Don't mess with it.

.. cpp:function:: int botan_pk_op_kem_encrypt_create(botan_pk_op_kem_encrypt_t* op, \
                         botan_pubkey_t key, const char* kdf)

   Create a KEM operation, encrypt version

.. cpp:function:: int botan_pk_op_kem_encrypt_destroy(botan_pk_op_kem_encrypt_t op)

   Destroy the operation, freeing memory

.. cpp:function:: int botan_pk_op_kem_encrypt_shared_key_length( \
       botan_pk_op_kem_encrypt_t op, \
       size_t desired_shared_key_length, \
       size_t* output_shared_key_length)

   Return the output shared key length, assuming `desired_shared_key_length`
   is provided.

   .. note::

      Normally this will just return `desired_shared_key_length` but may return
      a different value if a "raw" KDF is used (returning the unhashed output),
      or potentially depending on KDF limitations.

.. cpp:function:: int botan_pk_op_kem_encrypt_encapsulated_key_length(botan_pk_op_kem_encrypt_t op, \
        size_t* output_encapsulated_key_length)

   Return the length of the encapsulated key

.. cpp:function:: int botan_pk_op_kem_encrypt_create_shared_key(botan_pk_op_kem_encrypt_t op, \
        botan_rng_t rng, \
        const uint8_t salt[], \
        size_t salt_len, \
        size_t desired_shared_key_len, \
        uint8_t shared_key[], \
        size_t* shared_key_len, \
        uint8_t encapsulated_key[], \
        size_t* encapsulated_key_len)

   Create a new encapsulated key. Use the length query functions beforehand to correctly
   size the output buffers, otherwise an error will be returned.

.. cpp:type:: opaque* botan_pk_op_kem_decrypt_t

   An opaque data type for a KEM operation. Don't mess with it.

.. cpp:function:: int botan_pk_op_kem_decrypt_create(botan_pk_op_kem_decrypt_t* op, \
                         botan_pubkey_t key, const char* kdf)

   Create a KEM operation, decrypt version

.. cpp:function:: int botan_pk_op_kem_decrypt_shared_key_length( \
       botan_pk_op_kem_decrypt_t op, \
       size_t desired_shared_key_length, \
       size_t* output_shared_key_length)

   See :cpp:func:`botan_pk_op_kem_encrypt_shared_key_length`

.. cpp:function:: int botan_pk_op_kem_decrypt_shared_key(botan_pk_op_kem_decrypt_t op, \
        const uint8_t salt[], \
        size_t salt_len, \
        const uint8_t encapsulated_key[], \
        size_t encapsulated_key_len, \
        size_t desired_shared_key_len, \
        uint8_t shared_key[], \
        size_t* shared_key_len)

   Decrypt an encapsulated key and return the shared secret

.. cpp:function:: int botan_pk_op_kem_decrypt_destroy(botan_pk_op_kem_decrypt_t op)

   Destroy the operation, freeing memory


TPM 2.0 Functions
----------------------------------------

.. versionadded:: 3.6.0

.. cpp:type:: opaque* botan_tpm2_ctx_t

   An opaque data type for a TPM 2.0 context object. Don't mess with it.

.. cpp:type:: opaque* botan_tpm2_session_t

   An opaque data type for a TPM 2.0 session object. Don't mess with it.

.. cpp:type:: opaque* botan_tpm2_crypto_backend_state_t

   An opaque data type to hold the TPM 2.0 crypto backend state when registering
   the botan-based crypto backend on a bare ESYS_CONTEXT. When the TPM 2.0
   context is managed via Botan botan_tpm2_ctx_t, this state object is maintained
   internally.

.. cpp:function:: int botan_tpm2_supports_crypto_backend()

   Returns 1 if the Botan-based TPM 2.0 crypto backend is available, 0 otherwise.

.. cpp:function:: int botan_tpm2_ctx_init(botan_tpm2_ctx_t* ctx_out, const char* tcti_nameconf)

   Initialize a TPM 2.0 context object. The TCTI name and configuration are
   mangled into a single string separated by a colon. for instance "device:/dev/tpm0".

.. cpp:function:: int botan_tpm2_ctx_init_ex(botan_tpm2_ctx_t* ctx_out, const char* tcti_name, const char* tcti_conf)

   Initialize a TPM 2.0 context object. The TCTI name and configuration are
   passed as separate strings.

.. cpp:function:: int botan_tpm2_ctx_from_esys(botan_tpm2_ctx_t* ctx_out, ESYS_CONTEXT* esys_ctx)

   Initialize a TPM 2.0 context object from a pre-existing ``ESYS_CONTEXT`` that
   is managed by the application. Destroying this object *will not* finalize the
   ``ESYS_CONTEXT``, this responsibility remains with the application.

.. cpp:function:: int botan_tpm2_ctx_enable_crypto_backend(botan_tpm2_ctx_t ctx, botan_rng_t rng)

   Enable the Botan-based TPM 2.0 crypto backend. Note that the random number
   generator passed to this function must not be dependent on the TPM itself.
   This should be used when the ``ESYS_CONTEXT`` is managed by the TPM 2.0
   wrapper provided by Botan (i.e. the application did not explicitly instantiate
   the ``ESYS_CONTEXT`` itself).

.. cpp:function:: int botan_tpm2_enable_crypto_backend(botan_tpm2_crypto_backend_state_t* cbs_out, \
                                                       ESYS_CONTEXT* esys_ctx, \
                                                       botan_rng_t rng)

   Enable the Botan-based TPM 2.0 crypto backend on a pre-existing ``ESYS_CONTEXT``
   that is managed by the application. Note that the random number generator
   passed to this function must not be dependent on the TPM itself.
   The crypto backend has to keep internal state. The application is responsible
   to keep this state alive and destroy it after the ``ESYS_CONTEXT`` is no longer
   used.

.. cpp:function:: int botan_tpm2_unauthenticated_session_init(botan_tpm2_session_t* session_out, botan_tpm2_ctx_t ctx)

   Initialize an unauthenticated session that can be used to encrypt the
   communication between your application and the TPM.

.. cpp:function:: int botan_tpm2_rng_init(botan_rng_t* rng_out, \
                                          botan_tpm2_ctx_t ctx, \
                                          botan_tpm2_session_t s1, \
                                          botan_tpm2_session_t s2, \
                                          botan_tpm2_session_t s3)

   Initialize a random number generator that uses the TPM as a source of entropy.

.. cpp:function:: int botan_tpm2_ctx_destroy(botan_tpm2_ctx_t ctx)

   Destroy a TPM 2.0 context object.

.. cpp:function:: int botan_tpm2_session_destroy(botan_tpm2_session_t session)

   Destroy a TPM 2.0 session object.

.. cpp:function:: int botan_tpm2_crypto_backend_state_destroy(botan_tpm2_crypto_backend_state_t cbs)

   Destroy a TPM 2.0 crypto backend state. This is required when registering the
   botan-based crypto backend on an ESYS_CONTEXT managed by the application
   using botan_tpm2_enable_crypto_backend. When the ESYS_CONTEXT is managed in
   the botan wrapper, and botan_tpm2_ctx_enable_crypto_backend was used, this
   state is managed within the library and does not need to be cleaned up.

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

.. cpp:function::int botan_x509_cert_is_ca(botan_x509_cert_t cert, int* is_ca, size_t* limit)

   Checks whether the certificate is a CA certificate and sets ``is_ca`` to 1 if it is, 0 otherwise.
   If it is a CA certificate, ``limit`` is set to the path limit, otherwise 0.

.. cpp:function::int botan_x509_cert_get_allowed_usage(botan_x509_cert_t cert, uint32_t* usage)

   Returns the key usage constraints.

.. cpp:function::int botan_x509_cert_get_ocsp_responder(botan_x509_cert_t cert, botan_view_ctx ctx, botan_view_str_fn view)

   Returns the OCSP responder.

.. cpp:function::int botan_x509_cert_is_self_signed(botan_x509_cert_t cert, int* out)

   Checks whether the certificate is self signed and sets ``out`` to 1 if it is, 0 otherwise.

.. cpp:function:: int botan_x509_cert_get_public_key_bits(botan_x509_cert_t cert, \
                                                  uint8_t out[], size_t* out_len)

   Get the serialized (DER) representation of the public key included in this certificate

.. cpp:function:: int botan_x509_cert_view_public_key_bits(botan_x509_cert_t cert, \
      botan_view_ctx ctx, botan_view_bin_fn view)

   View the serialized (DER) representation of the public key included in this certificate

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

.. cpp:function:: int botan_x509_cert_view_as_string(botan_x509_cert_t cert, \
      botan_view_ctx ctx, botan_view_str_fn view)

   View the certificate as a free-form string.

.. cpp:function::int botan_x509_cert_view_pem(botan_x509_cert_t cert, botan_view_ctx ctx, botan_view_str_fn view)

   View the certificate as a PEM string.

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
   result, or NULL if the code is not known.


.. cpp:type:: opaque* botan_x509_ext_ip_addr_blocks_t

   An opaque data type for an X.509 IP Address Blocks extension (RFC 3779). Don't mess with it.

.. cpp:function::int botan_x509_ext_ip_addr_blocks_destroy(botan_x509_ext_ip_addr_blocks_t ip_addr_blocks)

   Destroy the IP Address Blocks object.

.. cpp:function::int botan_x509_ext_ip_addr_blocks_create(botan_x509_ext_ip_addr_blocks_t* ip_addr_blocks)

   Create a new IP Address Blocks object.

.. cpp:function::int botan_x509_ext_ip_addr_blocks_create_from_cert(botan_x509_cert_t cert, \
                  botan_x509_ext_ip_addr_blocks_t* ip_addr_blocks)

   Get an IP Address Blocks object from a certificate. Cannot be mutated.

.. cpp:function::int botan_x509_ext_ip_addr_blocks_add_ip_addr(botan_x509_ext_ip_addr_blocks_t ip_addr_blocks, \
                  const uint8_t* min, \
                  const uint8_t* max, \
                  int ipv6, \
                  uint8_t* safi)

   Add a new IP Address to the extension. Set ``ipv6`` to 0 if the address is v4, 1 if it is v6.
   ``safi`` may be NULL.

.. cpp:function::int botan_x509_ext_ip_addr_blocks_restrict(botan_x509_ext_ip_addr_blocks_t ip_addr_blocks, int ipv6, uint8_t* safi)

   Make the extension contain no allowed IP addresses for the specified IP version.
   Set ``ipv6`` to 0 for v4, 1 for v6. ``safi`` may be NULL.

.. cpp:function::int botan_x509_ext_ip_addr_blocks_inherit(botan_x509_ext_ip_addr_blocks_t ip_addr_blocks, int ipv6, uint8_t* safi)

   Mark the specified IP version as "inherit". Set ``ipv6`` to 0 for v4, 1 for v6. ``safi`` may be NULL.

.. cpp:function::int botan_x509_ext_ip_addr_blocks_get_counts(botan_x509_ext_ip_addr_blocks_t ip_addr_blocks, \
                  size_t* v4_count, \
                  size_t* v6_count)

   Retrieve the counts of v4/v6 entries in the extension.
   v4 entries always precede v6 entries.

.. cpp:function::int botan_x509_ext_ip_addr_blocks_get_family(botan_x509_ext_ip_addr_blocks_t ip_addr_blocks,
                  int ipv6, \
                  size_t i, \
                  int* has_safi, \
                  uint8_t* safi, \
                  int* present, \
                  size_t* count)

   Retrieve information about an entry in the extension.
   Set ``ipv6`` to 0 to indicate the index is v4, 1 to indicate it is v6.
   Set ``i`` to the index you want to access.
   You can get these values from :cpp:func:`botan_x509_ext_ip_addr_blocks_get_counts`.
   ``has_afi`` will be set to 1 if the entry has a SAFI, 0 otherwise.
   If a SAFI is present, ``safi`` will be set to its value, otherwise it will not be written to.
   ``present`` will be set to one to indicate a value, 0 otherwise (inherit).
   ``count`` will be set to the number of address pairs present for the entry if present.

.. cpp:function::int botan_x509_ext_ip_addr_blocks_get_address(botan_x509_ext_ip_addr_blocks_t ip_addr_blocks,
                  int ipv6, \
                  size_t i, \
                  size_t entry, \
                  uint8_t min_out[], \
                  uint8_t max_out[], \
                  size_t* out_len)

   Retrieve a single address pair for an entry in the extension.
   Retrieve information about an entry in the extension.
   Set ``ipv6`` to 0 to indicate the index is v4, 1 to indicate it is v6.
   Set ``i`` to the index you want to access.
   Set ``entry`` to the index of the address pair you want to access.
   ``ipv6`` and ``i`` are retrieved from :cpp:func:`botan_x509_ext_ip_addr_blocks_get_counts`, ``entry`` is the inferred from the ``count`` parameter of :cpp:func:`botan_x509_ext_ip_addr_blocks_get_family`.
   ``min_out`` and ``max_out`` will be set to the minimum and maximum of the IP range.
   You must provide 4 / 16 bytes of buffer space for each for IP v4 / v6 respectively.

.. cpp:type:: opaque* botan_x509_ext_as_blocks_t

   An opaque data type for an X.509 AS Blocks extension (RFC 3779). Don't mess with it.

.. cpp:function::int botan_x509_ext_as_blocks_destroy(botan_x509_ext_as_blocks_t as_blocks)

   Destroy the AS Blocks object.

.. cpp:function::int botan_x509_ext_as_blocks_create(botan_x509_ext_as_blocks_t* as_blocks)

   Create a new AS Blocks object.

.. cpp:function::int botan_x509_ext_as_blocks_create_from_cert(botan_x509_cert_t cert, botan_x509_ext_as_blocks_t* as_blocks)

   Get an AS Blocks object from a certificate. Cannot be mutated.

.. cpp:function::int botan_x509_ext_as_blocks_add_asnum(botan_x509_ext_as_blocks_t as_blocks, uint32_t min, uint32_t max)

   Add an asnum to the extension.

.. cpp:function::int botan_x509_ext_as_blocks_restrict_asnum(botan_x509_ext_as_blocks_t as_blocks)

   Make the extension contain no allowed asnum's

.. cpp:function::int botan_x509_ext_as_blocks_inherit_asnum(botan_x509_ext_as_blocks_t as_blocks)

   Mark the asnum entry as "inherit".

.. cpp:function::int botan_x509_ext_as_blocks_add_rdi(botan_x509_ext_as_blocks_t as_blocks, uint32_t min, uint32_t max)

.. cpp:function::int botan_x509_ext_as_blocks_restrict_rdi(botan_x509_ext_as_blocks_t as_blocks)

.. cpp:function::int botan_x509_ext_as_blocks_inherit_rdi(botan_x509_ext_as_blocks_t as_blocks)

.. cpp:function::int botan_x509_ext_as_blocks_get_asnum(botan_x509_ext_as_blocks_t as_blocks, int* present, size_t* count)

   If the extension has an asnum entry, ``present`` will be set to 1, otherwise 0 (inherit).
   If an entry is present ``count`` will be set to the number of elements.

.. cpp:function::int botan_x509_ext_as_blocks_get_asnum_at(botan_x509_ext_as_blocks_t as_blocks, size_t i, uint32_t* min, uint32_t* max)

   Retrieve information on a single asnum entry.

.. cpp:function::int botan_x509_ext_as_blocks_get_rdi(botan_x509_ext_as_blocks_t as_blocks, int* present, size_t* count)

.. cpp:function::int botan_x509_ext_as_blocks_get_rdi_at(botan_x509_ext_as_blocks_t as_blocks, size_t i, uint32_t* min, uint32_t* max)

.. cpp:type:: opaque* botan_x509_cert_params_builder_t

.. cpp:function::int botan_x509_cert_params_builder_destroy(botan_x509_cert_params_builder_t builder)

   Destroy the Certificate Params Builder object.

.. cpp:function::int botan_x509_cert_params_builder_create(botan_x509_cert_params_builder_t* builder_obj);

   Create a new Certificate Params Builder object.

.. cpp:function::int botan_x509_cert_params_builder_add_common_name(botan_x509_cert_params_builder_t builder, const char* name);

.. cpp:function::int botan_x509_cert_params_builder_add_country(botan_x509_cert_params_builder_t builder, const char* country);

.. cpp:function::int botan_x509_cert_params_builder_add_state(botan_x509_cert_params_builder_t builder, const char* state);

.. cpp:function::int botan_x509_cert_params_builder_add_locality(botan_x509_cert_params_builder_t builder, const char* locality);

.. cpp:function::int botan_x509_cert_params_builder_add_serial_number(botan_x509_cert_params_builder_t builder, const char* serial_number);

.. cpp:function::int botan_x509_cert_params_builder_add_organization(botan_x509_cert_params_builder_t builder, const char* organization);

.. cpp:function::int botan_x509_cert_params_builder_add_organizational_unit(botan_x509_cert_params_builder_t builder, const char* org_unit);

.. cpp:function::int botan_x509_cert_params_builder_add_email(botan_x509_cert_params_builder_t builder, const char* email);

.. cpp:function::int botan_x509_cert_params_builder_add_dns(botan_x509_cert_params_builder_t builder, const char* dns);

.. cpp:function::int botan_x509_cert_params_builder_add_uri(botan_x509_cert_params_builder_t builder, const char* uri);

.. cpp:function::int botan_x509_cert_params_builder_add_xmpp(botan_x509_cert_params_builder_t builder, const char* xmpp);

.. cpp:function::int botan_x509_cert_params_builder_add_ip(botan_x509_cert_params_builder_t builder, uint32_t ipv4);

.. cpp:function::int botan_x509_cert_params_builder_add_allowed_usage(botan_x509_cert_params_builder_t builder, uint32_t usage);

.. cpp:function::int botan_x509_cert_params_builder_add_allowed_extended_usage(botan_x509_cert_params_builder_t builder, botan_asn1_oid_t oid);

.. cpp:function::int botan_x509_cert_params_builder_set_as_ca_certificate(botan_x509_cert_params_builder_t builder, size_t limit=None);

   Mark the certificate for CA usage.

.. cpp:function::int botan_x509_cert_params_builder_add_ext_ip_addr_blocks(botan_x509_cert_params_builder_t builder, \
                  botan_x509_ext_ip_addr_blocks_t ip_addr_blocks, int is_critical);

.. cpp:function::int botan_x509_cert_params_builder_add_ext_as_blocks(botan_x509_cert_params_builder_t builder, \
                  botan_x509_ext_as_blocks_t as_blocks, int is_critical);

.. cpp:function::int botan_x509_cert_create_self_signed(botan_x509_cert_t* cert_obj, \
                  botan_privkey_t key, \
                  botan_x509_cert_params_builder_t builder, \
                  botan_rng_t rng, \
                  uint64_t not_before, \
                  uint64_t not_after, \
                  const botan_mp_t* serial_number, \
                  const char* hash_fn, \
                  const char* padding)

   Create a new self-signed X.509 certificate. ``not_before`` and ``not_after`` are expected to be the time since the UNIX epoch, in seconds.

.. cpp:type:: opaque* botan_x509_pkcs10_req_t

   An opaque data type for a PKCS #10 certificate request. Don't mess with it.

.. cpp:function::int botan_x509_pkcs10_req_destroy(botan_x509_pkcs10_req_t req)

   Destroy the PKCS #10 certificate request object.

.. cpp:function::int botan_x509_pkcs10_req_load_file(botan_x509_pkcs10_req_t* req_obj, const char* req_path)

.. cpp:function::int botan_x509_pkcs10_req_load(botan_x509_pkcs10_req_t* req_obj, const uint8_t req_bits[], size_t req_bits_len)

.. cpp:function::int int botan_x509_pkcs10_req_get_public_key(botan_x509_pkcs10_req_t req, botan_pubkey_t* key)

.. cpp:function::int int botan_x509_pkcs10_req_get_allowed_usage(botan_x509_pkcs10_req_t req, uint32_t* usage)

.. cpp:function::int int botan_x509_pkcs10_req_is_ca(botan_x509_pkcs10_req_t req, int* is_ca, size_t* limit)

.. cpp:function::int int botan_x509_pkcs10_req_verify_signature(botan_x509_pkcs10_req_t req, botan_pubkey_t key, int* result)


.. cpp:function::int botan_x509_pkcs10_req_create(botan_x509_pkcs10_req_t* req_obj, \
                  botan_privkey_t key, \
                  botan_x509_cert_params_builder_t builder, \
                  botan_rng_t rng, \
                  const char* hash_fn, \
                  const char* padding, \
                  const char* challenge_password)

   Create a PCKS #10 certificate request. ``challenge_password``, ``hash_fn`` and ``padding`` may be NULL.

.. cpp:function::int botan_x509_pkcs10_req_view_pem(botan_x509_pkcs10_req_t req, botan_view_ctx ctx, botan_view_str_fn view)

.. cpp:function::int int botan_x509_pkcs10_req_view_der(botan_x509_pkcs10_req_t req, botan_view_ctx ctx, botan_view_bin_fn view)

.. cpp:function::int botan_x509_pkcs10_req_sign(botan_x509_cert_t* subject_cert, \
                  botan_x509_pkcs10_req_t subject_req, \
                  botan_x509_cert_t issuing_cert, \
                  botan_privkey_t issuing_key, \
                  botan_rng_t rng, \
                  uint64_t not_before, \
                  uint64_t not_after, \
                  const botan_mp_t* serial_number, \
                  const char* hash_fn, \
                  const char* padding)

   Sign a PKCS #10 certificate request. ``not_before`` and ``not_after`` are expected to be the time since the UNIX epoch, in seconds.

X.509 Certificate Revocation Lists
----------------------------------------

.. cpp:type:: opaque* botan_x509_crl_t

   An opaque data type for an X.509 CRL.

.. cpp:function:: int botan_x509_crl_load(botan_x509_crl_t* crl_obj, \
                                        const uint8_t crl[], size_t crl_len)

   Load a CRL from the DER or PEM representation.

.. cpp:function:: int botan_x509_crl_load_file(botan_x509_crl_t* crl_obj, const char* filename)

   Load a CRL from a file.

.. cpp:function:: int botan_x509_crl_create(botan_x509_crl_t* crl_obj, \
                          botan_rng_t rng, \
                          botan_x509_cert_t ca_cert, \
                          botan_privkey_t ca_key, \
                          uint64_t issue_time, \
                          uint32_t next_update, \
                          const char* hash_fn, \
                          const char* padding)

.. cpp:function:: int botan_x509_crl_update(botan_x509_crl_t* crl_obj, \
                          botan_x509_crl_t last_crl, \
                          botan_rng_t rng, \
                          botan_x509_cert_t ca_cert, \
                          botan_privkey_t ca_key, \
                          uint64_t issue_time, \
                          uint32_t next_update, \
                          const botan_x509_cert_t* revoked, \
                          size_t revoked_len, \
                          uint8_t reason, \
                          const char* hash_fn, \
                          const char* padding)

.. cpp:function:: int botan_x509_crl_get_count(botan_x509_crl_t crl, size_t* count);

.. cpp:function:: int botan_x509_crl_get_entry(botan_x509_crl_t crl, size_t i, uint8_t serial[], size_t* serial_len, uint64_t* expire_time, uint8_t* reason)

.. cpp:function:: int botan_x509_crl_verify_signature(botan_x509_crl_t crl, botan_pubkey_t key, int* result)

.. cpp:function:: int botan_x509_crl_view_pem(botan_x509_crl_t crl, botan_view_ctx ctx, botan_view_str_fn view)

.. cpp:function:: int botan_x509_crl_view_der(botan_x509_crl_t crl, botan_view_ctx ctx, botan_view_bin_fn view)

.. cpp:function:: int botan_x509_crl_destroy(botan_x509_crl_t crl)

   Destroy the CRL object.

.. cpp:function:: int botan_x509_is_revoked(botan_x509_crl_t crl, botan_x509_cert_t cert)

   Check whether a given ``crl`` contains a given ``cert``.
   Return ``0`` when the certificate is revoked, ``-1`` otherwise.

ZFEC (Forward Error Correction)
----------------------------------------

.. versionadded:: 3.0.0

.. cpp:function:: int botan_zfec_encode(size_t K, size_t N, \
                  const uint8_t *input, size_t size, uint8_t **outputs)

  Perform forward error correction encoding. The input length must be a multiple
  of `K` bytes. The `outputs` parameter must point to `N` output buffers,
  each of length `size / K`.

  Any `K` of the `N` output shares is sufficient to recover the original input.

.. cpp:function:: int botan_zfec_decode(size_t K, size_t N, const size_t *indexes, \
                  uint8_t *const*const inputs, size_t shareSize, uint8_t **outputs)

  Decode some FEC shares. The indexes and inputs must be exactly K in length.
  The `indexes` array specifies which shares are presented in `inputs`.
  Each input must be of length `shareSize`. The output is written to the
  `K` buffers in `outputs`, each buffer must be `shareSize` long.
