/*
* FFI (C89 API)
* (C) 2015,2017 Jack Lloyd
* (C) 2021 René Fischer
* (C) 2024,2025,2026 Amos Treiber, René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_FFI_H_
#define BOTAN_FFI_H_

#ifdef __cplusplus
extern "C" {
#endif

/*
This header exports some of botan's functionality via a C89 interface. This API
is used by the Python, OCaml, Rust, Ruby, and Haskell bindings via those languages
respective ctypes/FFI libraries.

The API is intended to be as easy as possible to call from other
languages, which often have easy ways to call C, because C. But some C
code is easier to deal with than others, so to make things easy this
API follows a few simple rules:

- All interactions are via pointers to opaque structs. No need to worry about
  structure padding issues and the like.

- All functions return an int error code (except the version calls, which are
  assumed to always have something to say).

- Use simple types: size_t for lengths, const char* NULL terminated strings,
  uint8_t for binary.

- No ownership of memory transfers across the API boundary. The API will consume
  data from const pointers with specified lengths. Outputs are either placed into
  buffers provided by (and allocated by) the caller, or are returned via a
  callback (what the FFI layer calls "view" functions).

  When writing to an application-provided buffer, the function takes a pointer
  to the output array and a read/write pointer to the length. The length field
  is always set to the actual amount of data that would have been written. If
  the input buffer's size was insufficient an error is returned.

  In many situations the length of the output can be known in advance without
  difficulty, in which case there will be a function which allows querying the
  expected output length. For example `botan_hash_output_length` allows knowing
  in advance the expected size for `botan_hash_final`. Some of these are exact,
  while others such as `botan_pk_op_decrypt_output_length` can only provide an
  upper bound for various technical reasons.

  In some cases knowing the exact size is difficult or impossible. In these
  situations view functions are used; see the handbook for further details.
*/

#include <stddef.h>
#include <stdint.h>

/* NOLINTBEGIN(*-macro-usage,*-misplaced-const) */

/**
* The compile time API version. This matches the value of
* botan_ffi_api_version. This can be used for compile-time checking if a
* particular feature is available.
*
* Note this same value is also reflected in BOTAN_HAS_FFI in build.h, however
* that declaration is not visible here since this header is intentionally
* free-standing, depending only on a few C standard library headers.
*/
#define BOTAN_FFI_API_VERSION 20260811

/**
* BOTAN_FFI_EXPORT indicates public FFI functions.
*
* The arguments to the macro are to indicate the version that
* that particular FFI function was first available
*/
#if defined(BOTAN_DLL)
   #define BOTAN_FFI_EXPORT(maj, min) BOTAN_DLL
#else
   #if defined(__has_attribute)
      #if __has_attribute(visibility)
         #define BOTAN_FFI_EXPORT(maj, min) __attribute__((visibility("default")))
      #endif
   #elif defined(_MSC_VER) && !defined(BOTAN_IS_BEING_BUILT)
      #define BOTAN_FFI_EXPORT(maj, min) __declspec(dllimport)
   #else
      #define BOTAN_FFI_EXPORT(maj, min)
   #endif
#endif

#if !defined(BOTAN_NO_DEPRECATED_WARNINGS) && !defined(BOTAN_AMALGAMATION_H_) && !defined(BOTAN_IS_BEING_BUILT)
   #if defined(__has_attribute)
      #if __has_attribute(deprecated)
         #define BOTAN_FFI_DEPRECATED(msg) __attribute__((deprecated(msg)))
      #endif
   #elif defined(_MSC_VER)
      #define BOTAN_FFI_DEPRECATED(msg) __declspec(deprecated(msg))
   #endif
#endif

#if !defined(BOTAN_FFI_DEPRECATED)
   #define BOTAN_FFI_DEPRECATED(msg) /**/
#endif

/**
* Error codes
*
* If you add a new value here be sure to also add it in
* botan_error_description
*/
enum BOTAN_FFI_ERROR /* NOLINT(*-enum-size,*-use-enum-class) */ {
   BOTAN_FFI_SUCCESS = 0,

   BOTAN_FFI_INVALID_VERIFIER = 1,

   BOTAN_FFI_ERROR_INVALID_INPUT = -1,
   BOTAN_FFI_ERROR_BAD_MAC = -2,
   BOTAN_FFI_ERROR_NO_VALUE = -3,

   BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE = -10,
   BOTAN_FFI_ERROR_STRING_CONVERSION_ERROR = -11,

   BOTAN_FFI_ERROR_EXCEPTION_THROWN = -20,
   BOTAN_FFI_ERROR_OUT_OF_MEMORY = -21,
   BOTAN_FFI_ERROR_SYSTEM_ERROR = -22,
   BOTAN_FFI_ERROR_INTERNAL_ERROR = -23,

   BOTAN_FFI_ERROR_BAD_FLAG = -30,
   BOTAN_FFI_ERROR_NULL_POINTER = -31,
   BOTAN_FFI_ERROR_BAD_PARAMETER = -32,
   BOTAN_FFI_ERROR_KEY_NOT_SET = -33,
   BOTAN_FFI_ERROR_INVALID_KEY_LENGTH = -34,
   BOTAN_FFI_ERROR_INVALID_OBJECT_STATE = -35,
   BOTAN_FFI_ERROR_OUT_OF_RANGE = -36,

   BOTAN_FFI_ERROR_NOT_IMPLEMENTED = -40,
   BOTAN_FFI_ERROR_INVALID_OBJECT = -50,

   BOTAN_FFI_ERROR_TLS_ERROR = -75,
   BOTAN_FFI_ERROR_HTTP_ERROR = -76,
   BOTAN_FFI_ERROR_ROUGHTIME_ERROR = -77,
   BOTAN_FFI_ERROR_TPM_ERROR = -78,

   BOTAN_FFI_ERROR_UNKNOWN_ERROR = -100,
};

/**
* The application provided context for a view function
*/
typedef void* botan_view_ctx;

/**
* Viewer function for binary data
*
* @param view_ctx some application context
* @param data the binary data
* @param len the length of data in bytes
*/
typedef int (*botan_view_bin_fn)(botan_view_ctx view_ctx, const uint8_t* data, size_t len);

/**
* Viewer function for string data
*
* @param view_ctx some application context
* @param str the null terminated string
* @param len the length of string *including* the null terminator
*/
typedef int (*botan_view_str_fn)(botan_view_ctx view_ctx, const char* str, size_t len);

/**
* Convert an error code into a string. Returns "Unknown error"
* if the error code is not a known one.
*/
BOTAN_FFI_EXPORT(2, 8) const char* botan_error_description(int err);

/**
* Return the message of the last exception caught in this thread.
*
* This pointer can/will be reallocated or overwritten the next time
* this thread calls any other Botan FFI function and must be copied
* to persistent storage first.
*/
BOTAN_FFI_EXPORT(3, 0) const char* botan_error_last_exception_message(void);

/**
* Return the version of the currently supported FFI API. This is
* expressed in the form YYYYMMDD of the release date of this version
* of the API.
*/
BOTAN_FFI_EXPORT(2, 0) uint32_t botan_ffi_api_version(void);

/**
* Return 0 (ok) if the version given is one this library supports.
* botan_ffi_supports_api(botan_ffi_api_version()) will always return 0.
*/
BOTAN_FFI_EXPORT(2, 0) int botan_ffi_supports_api(uint32_t api_version);

/**
* Return a free-form version string, e.g., 2.0.0
*/
BOTAN_FFI_EXPORT(2, 0) const char* botan_version_string(void);

/**
* Return the major version of the library
*/
BOTAN_FFI_EXPORT(2, 0) uint32_t botan_version_major(void);

/**
* Return the minor version of the library
*/
BOTAN_FFI_EXPORT(2, 0) uint32_t botan_version_minor(void);

/**
* Return the patch version of the library
*/
BOTAN_FFI_EXPORT(2, 0) uint32_t botan_version_patch(void);

/**
* Return the date this version was released as an integer.
*
* Returns 0 if the library was not built from an official release
*/
BOTAN_FFI_EXPORT(2, 0) uint32_t botan_version_datestamp(void);

/**
* Returns 0 if x[0..len] == y[0..len], or otherwise -1
*/
BOTAN_FFI_EXPORT(2, 3) int botan_constant_time_compare(const uint8_t* x, const uint8_t* y, size_t len);

/**
* Deprecated equivalent to botan_constant_time_compare
*/
BOTAN_FFI_DEPRECATED("Use botan_constant_time_compare")
BOTAN_FFI_EXPORT(2, 0) int botan_same_mem(const uint8_t* x, const uint8_t* y, size_t len);

/**
* Clear out memory using a system specific approach to bypass elision by the
* compiler (currently using RtlSecureZeroMemory or tricks with volatile pointers).
*/
BOTAN_FFI_EXPORT(2, 2) int botan_scrub_mem(void* mem, size_t bytes);

/**
* Flag that can be provided to botan_hex_encode to request lower case hex
*/
#define BOTAN_FFI_HEX_LOWER_CASE 1

/**
* Perform hex encoding
* @param x is some binary data
* @param len length of x in bytes
* @param out an array of at least x*2 bytes
* @param flags flags out be upper or lower case?
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_hex_encode(const uint8_t* x, size_t len, char* out, uint32_t flags);

/**
* Perform hex decoding
* @param hex_str a string of hex chars (whitespace is ignored)
* @param in_len the length of hex_str
* @param out the output buffer should be at least strlen(hex_str)/2 bytes
* @param out_len the size of the output buffer on input, set to the number of bytes written
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 3) int botan_hex_decode(const char* hex_str, size_t in_len, uint8_t* out, size_t* out_len);

/**
* Perform base64 encoding
*
* @param x the input data
* @param len the length of x
* @param out the output buffer
* @param out_len the size of the output buffer on input, set to the number of bytes written
* @return 0 on success, a negative value on failure

*/
BOTAN_FFI_EXPORT(2, 3) int botan_base64_encode(const uint8_t* x, size_t len, char* out, size_t* out_len);

/**
* Perform base64 decoding
*/
BOTAN_FFI_EXPORT(2, 3) int botan_base64_decode(const char* base64_str, size_t in_len, uint8_t* out, size_t* out_len);

/**
* RNG type
*/
typedef struct botan_rng_struct* botan_rng_t;

/**
* Initialize a random number generator object
* @param rng rng object
* @param rng_type type of the rng, possible values:
*    "system": system RNG
*    "esdm-full": ESDM RNG (fully seeded)
*    "esdm-pr": ESDM RNG (w. prediction resistance)
*    "user": userspace RNG
*    "user-threadsafe": userspace RNG, with internal locking
*    "rdrand": directly read RDRAND
* Set rng_type to null to let the library choose some default.
*/
BOTAN_FFI_EXPORT(2, 0) int botan_rng_init(botan_rng_t* rng, const char* rng_type);

/**
* Initialize a custom random number generator from a set of callback functions
* @param rng_out rng object to create
* @param rng_name name of the rng
* @param context An application-specific context passed to the callback functions
* @param get_cb Callback for getting random bytes from the rng, return 0 for success
* @param add_entropy_cb Callback for adding entropy to the rng, return 0 for success, may be NULL
* @param destroy_cb Callback called when rng is destroyed, may be NULL
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_rng_init_custom(botan_rng_t* rng_out,
                          const char* rng_name,
                          void* context,
                          int (*get_cb)(void* context, uint8_t* out, size_t out_len),
                          int (*add_entropy_cb)(void* context, const uint8_t input[], size_t length),
                          void (*destroy_cb)(void* context));

/**
* Get random bytes from a random number generator
*
* @param rng rng object
* @param out output buffer of size out_len
* @param out_len number of requested bytes
* @return 0 on success, negative on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_rng_get(botan_rng_t rng, uint8_t* out, size_t out_len);

/**
* Get random bytes from system random number generator
*
* @param out output buffer of size out_len
* @param out_len number of requested bytes
* @return 0 on success, negative on failure
*/
BOTAN_FFI_EXPORT(3, 0) int botan_system_rng_get(uint8_t* out, size_t out_len);

/**
* Reseed a random number generator
* Uses the System_RNG as a seed generator.
*
* @param rng rng object
* @param bits number of bits to reseed with
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_rng_reseed(botan_rng_t rng, size_t bits);

/**
* Reseed a random number generator
*
* @param rng rng object
* @param source_rng the rng that will be read from
* @param bits number of bits to reseed with
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 8) int botan_rng_reseed_from_rng(botan_rng_t rng, botan_rng_t source_rng, size_t bits);

/**
* Add some seed material to a random number generator
*
* @param rng rng object
* @param entropy the data to add
* @param entropy_len length of entropy buffer
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 8) int botan_rng_add_entropy(botan_rng_t rng, const uint8_t* entropy, size_t entropy_len);

/**
* Create and seed a DRBG
*
* @param rng_out the new DRBG object
* @param drbg_name the name of the DRBG (e.g. "HMAC_DRBG(SHA-256)")
* @param seed the seed material (entropy || nonce || personalization_string)
* @param seed_len length of seed in bytes
* @return 0 on success, negative on failure
*/
BOTAN_FFI_EXPORT(3, 12)
int botan_rng_init_drbg(botan_rng_t* rng_out, const char* drbg_name, const uint8_t* seed, size_t seed_len);

/**
* Generate random bytes from an RNG with additional input.
*
* For a DRBG, the additional input is mixed in before generating.
* Many other RNG types (eg RDRAND or system RNG) will ignore the input.
*
* @param rng the RNG object
* @param out output buffer
* @param out_len number of bytes to generate
* @param addl_input additional input to mix in (may be NULL if addl_len is 0)
* @param addl_len length of additional input
* @return 0 on success, negative on failure
*/
BOTAN_FFI_EXPORT(3, 12)
int botan_rng_generate_with_input(
   botan_rng_t rng, uint8_t* out, size_t out_len, const uint8_t* addl_input, size_t addl_len);

/**
* Frees all resources of the random number generator object
* @param rng rng object
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 0) int botan_rng_destroy(botan_rng_t rng);

/**
* Opaque type of an eXtendable Output Function (XOF)
*/
typedef struct botan_xof_struct* botan_xof_t;

/**
* Initialize an eXtendable Output Function
* @param xof XOF object
* @param xof_name name of the XOF, e.g., "SHAKE-128"
* @param flags should be 0 in current API revision, all other uses are reserved
*       and return BOTAN_FFI_ERROR_BAD_FLAG
*/
BOTAN_FFI_EXPORT(3, 11) int botan_xof_init(botan_xof_t* xof, const char* xof_name, uint32_t flags);

/**
* Copy the state of an eXtendable Output Function
* @param dest destination XOF object
* @param source source XOF object
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 11) int botan_xof_copy_state(botan_xof_t* dest, botan_xof_t source);

/**
* Writes the block size of the eXtendable Output Function to *block_size
* @param xof XOF object
* @param block_size variable to hold the XOF's block size
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 11) int botan_xof_block_size(botan_xof_t xof, size_t* block_size);

/**
* Get the name of this eXtendable Output Function
* @param xof the object to read
* @param name output buffer
* @param name_len on input, the length of buffer, on success the number of bytes written
*/
BOTAN_FFI_EXPORT(3, 11) int botan_xof_name(botan_xof_t xof, char* name, size_t* name_len);

/**
* Get the input/output state of this eXtendable Output Function
* Typically, XOFs don't accept input as soon as the first output bytes were requested.
* @param xof the object to read
* @returns 1 iff the XOF is still accepting input bytes
*/
BOTAN_FFI_EXPORT(3, 11) int botan_xof_accepts_input(botan_xof_t xof);

/**
* Reinitializes the state of the eXtendable Output Function.
* @param xof XOF object
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 11) int botan_xof_clear(botan_xof_t xof);

/**
* Send more input to the eXtendable Output Function
* @param xof XOF object
* @param in input buffer
* @param in_len number of bytes to read from the input buffer
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 11) int botan_xof_update(botan_xof_t xof, const uint8_t* in, size_t in_len);

/**
* Generate output bytes from the eXtendable Output Function
* @param xof XOF object
* @param out output buffer
* @param out_len number of bytes to write into the output buffer
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 11) int botan_xof_output(botan_xof_t xof, uint8_t* out, size_t out_len);

/**
* Frees all resources of the eXtendable Output Function object
* @param xof xof object
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(3, 11) int botan_xof_destroy(botan_xof_t xof);

/**
* Opaque type of a hash function
*/
typedef struct botan_hash_struct* botan_hash_t;

/**
* Initialize a hash function object
* @param hash hash object
* @param hash_name name of the hash function, e.g., "SHA-384"
* @param flags should be 0 in current API revision, all other uses are reserved
*       and return BOTAN_FFI_ERROR_BAD_FLAG
*/
BOTAN_FFI_EXPORT(2, 0) int botan_hash_init(botan_hash_t* hash, const char* hash_name, uint32_t flags);

/**
* Copy the state of a hash function object
* @param dest destination hash object
* @param source source hash object
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 2) int botan_hash_copy_state(botan_hash_t* dest, botan_hash_t source);

/**
* Writes the output length of the hash function to *output_length
* @param hash hash object
* @param output_length output buffer to hold the hash function output length
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_hash_output_length(botan_hash_t hash, size_t* output_length);

/**
* Writes the block size of the hash function to *block_size
* @param hash hash object
* @param block_size output buffer to hold the hash function output length
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 2) int botan_hash_block_size(botan_hash_t hash, size_t* block_size);

/**
* Writes the estimated security level of the hash function, in bits, with
* respect to collision resistance, to *security_level. Returns zero for
* checksums and any hash where finding collisions is trivial.
* @param hash hash object
* @param security_level output variable to hold the security level
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 13) int botan_hash_security_level(botan_hash_t hash, size_t* security_level);

/**
* Send more input to the hash function
* @param hash hash object
* @param in input buffer
* @param in_len number of bytes to read from the input buffer
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_hash_update(botan_hash_t hash, const uint8_t* in, size_t in_len);

/**
* Finalizes the hash computation and writes the output to
* out[0:botan_hash_output_length()] then reinitializes for computing
* another digest as if botan_hash_clear had been called.
* @param hash hash object
* @param out output buffer
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_hash_final(botan_hash_t hash, uint8_t out[]);

/**
* Reinitializes the state of the hash computation. A hash can
* be computed (with update/final) immediately.
* @param hash hash object
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_hash_clear(botan_hash_t hash);

/**
* Frees all resources of the hash object
* @param hash hash object
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 0) int botan_hash_destroy(botan_hash_t hash);

/**
* Get the name of this hash function
* @param hash the object to read
* @param name output buffer
* @param name_len on input, the length of buffer, on success the number of bytes written
*/
BOTAN_FFI_EXPORT(2, 8) int botan_hash_name(botan_hash_t hash, char* name, size_t* name_len);

/**
* Opaque type of a message authentication code
*/
typedef struct botan_mac_struct* botan_mac_t;

/**
* Initialize a message authentication code object
* @param mac mac object
* @param mac_name name of the hash function, e.g., "HMAC(SHA-384)"
* @param flags should be 0 in current API revision, all other uses are reserved
*       and return a negative value (error code)
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_mac_init(botan_mac_t* mac, const char* mac_name, uint32_t flags);

/**
* Writes the output length of the message authentication code to *output_length
* @param mac mac object
* @param output_length output buffer to hold the MAC output length
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_mac_output_length(botan_mac_t mac, size_t* output_length);

/**
* Sets the key on the MAC
* @param mac mac object
* @param key buffer holding the key
* @param key_len size of the key buffer in bytes
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_mac_set_key(botan_mac_t mac, const uint8_t* key, size_t key_len);

/**
* Sets the nonce on the MAC
* @param mac mac object
* @param nonce buffer holding the key
* @param nonce_len size of the key buffer in bytes
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 0) int botan_mac_set_nonce(botan_mac_t mac, const uint8_t* nonce, size_t nonce_len);

/**
* Send more input to the message authentication code
* @param mac mac object
* @param buf input buffer
* @param len number of bytes to read from the input buffer
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_mac_update(botan_mac_t mac, const uint8_t* buf, size_t len);

/**
* Finalizes the MAC computation and writes the output to
* out[0:botan_mac_output_length()] then reinitializes for computing
* another MAC as if botan_mac_clear had been called.
* @param mac mac object
* @param out output buffer
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_mac_final(botan_mac_t mac, uint8_t out[]);

/**
* Reinitializes the state of the MAC computation. A MAC can
* be computed (with update/final) immediately.
* @param mac mac object
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_mac_clear(botan_mac_t mac);

/**
* Get the name of this MAC
* @param mac the object to read
* @param name output buffer
* @param name_len on input, the length of buffer, on success the number of bytes written
*/
BOTAN_FFI_EXPORT(2, 8) int botan_mac_name(botan_mac_t mac, char* name, size_t* name_len);

/**
* Get the key length limits of this auth code
* @param mac the object to read
* @param out_minimum_keylength if non-NULL, will be set to minimum keylength of MAC
* @param out_maximum_keylength if non-NULL, will be set to maximum keylength of MAC
* @param out_keylength_modulo if non-NULL will be set to byte multiple of valid keys
*/
BOTAN_FFI_EXPORT(2, 8)
int botan_mac_get_keyspec(botan_mac_t mac,
                          size_t* out_minimum_keylength,
                          size_t* out_maximum_keylength,
                          size_t* out_keylength_modulo);

/**
* Frees all resources of the MAC object
* @param mac mac object
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 0) int botan_mac_destroy(botan_mac_t mac);

/**
* Opaque type of a cipher mode
*/
typedef struct botan_cipher_struct* botan_cipher_t;

#define BOTAN_CIPHER_INIT_FLAG_MASK_DIRECTION 1
#define BOTAN_CIPHER_INIT_FLAG_ENCRYPT 0
#define BOTAN_CIPHER_INIT_FLAG_DECRYPT 1

/**
* Initialize a cipher object
*/
BOTAN_FFI_EXPORT(2, 0) int botan_cipher_init(botan_cipher_t* cipher, const char* name, uint32_t flags);

/**
* Return the name of the cipher object
*/
BOTAN_FFI_EXPORT(2, 8) int botan_cipher_name(botan_cipher_t cipher, char* name, size_t* name_len);

/**
* Return the output length of this cipher, for a particular input length.
*/
BOTAN_FFI_EXPORT(2, 8) int botan_cipher_output_length(botan_cipher_t cipher, size_t in_len, size_t* out_len);

/**
* Return if the specified nonce length is valid for this cipher
*/
BOTAN_FFI_EXPORT(2, 0) int botan_cipher_valid_nonce_length(botan_cipher_t cipher, size_t nl);

/**
* Get the tag length of the cipher (0 for non-AEAD modes)
*/
BOTAN_FFI_EXPORT(2, 0) int botan_cipher_get_tag_length(botan_cipher_t cipher, size_t* tag_size);

/**
* Returns 1 iff the cipher provides authentication as well as confidentiality.
*/
BOTAN_FFI_EXPORT(3, 3) int botan_cipher_is_authenticated(botan_cipher_t cipher);

/**
 * Returns 1 iff the cipher requires the entire message before any
 * encryption or decryption can be performed. No output data will be produced
 * in botan_cipher_update() until the final flag is set.
 */
BOTAN_FFI_EXPORT(3, 4) int botan_cipher_requires_entire_message(botan_cipher_t cipher);

/**
* Get the default nonce length of this cipher
*/
BOTAN_FFI_EXPORT(2, 0) int botan_cipher_get_default_nonce_length(botan_cipher_t cipher, size_t* nl);

/**
* Return the update granularity of the cipher; botan_cipher_update must be
* called with blocks of this size, except for the final.
*/
BOTAN_FFI_EXPORT(2, 0) int botan_cipher_get_update_granularity(botan_cipher_t cipher, size_t* ug);

/**
* Return the ideal update granularity of the cipher. This is some multiple of the
* update granularity, reflecting possibilities for optimization.
*/
BOTAN_FFI_EXPORT(3, 0) int botan_cipher_get_ideal_update_granularity(botan_cipher_t cipher, size_t* ug);

/**
* Get information about the key lengths. Prefer botan_cipher_get_keyspec
*/
BOTAN_FFI_EXPORT(2, 0)
int botan_cipher_query_keylen(botan_cipher_t cipher, size_t* out_minimum_keylength, size_t* out_maximum_keylength);

/**
* Get information about the supported key lengths.
*/
BOTAN_FFI_EXPORT(2, 8)
int botan_cipher_get_keyspec(botan_cipher_t cipher, size_t* min_keylen, size_t* max_keylen, size_t* mod_keylen);

/**
* Set the key for this cipher object
*/
BOTAN_FFI_EXPORT(2, 0) int botan_cipher_set_key(botan_cipher_t cipher, const uint8_t* key, size_t key_len);

/**
* Reset the message specific state for this cipher.
* Without resetting the keys, this resets the nonce, and any state
* associated with any message bits that have been processed so far.
*
* It is conceptually equivalent to calling botan_cipher_clear followed
* by botan_cipher_set_key with the original key.
*/
BOTAN_FFI_EXPORT(2, 8) int botan_cipher_reset(botan_cipher_t cipher);

/**
* Set the associated data. Will fail if cipher is not an AEAD
*/
BOTAN_FFI_EXPORT(2, 0) int botan_cipher_set_associated_data(botan_cipher_t cipher, const uint8_t* ad, size_t ad_len);

/**
* Begin processing a new message using the provided nonce
*/
BOTAN_FFI_EXPORT(2, 0) int botan_cipher_start(botan_cipher_t cipher, const uint8_t* nonce, size_t nonce_len);

#define BOTAN_CIPHER_UPDATE_FLAG_FINAL (1U << 0)

/**
* @brief Encrypt/Decrypt some data and/or finalize the encryption/decryption
*
* This encrypts as many bytes from @p input_bytes into @p output_bytes as
* possible. Unless ``BOTAN_CIPHER_UPDATE_FLAG_FINAL`` is set, this function will
* consume bytes in multiples of botan_cipher_get_update_granularity().
* @p input_consumed and @p output_written will be set accordingly and it is the
* caller's responsibility to adapt their buffers accordingly before calling this
* function again. Note that, unless ``BOTAN_CIPHER_UPDATE_FLAG_FINAL`` is set,
* the cipher will at most generate @p input_size output bytes.
*
* Eventually, the caller must set the ``BOTAN_CIPHER_UPDATE_FLAG_FINAL`` flag to
* indicate that no more input will be provided. This will cause the cipher to
* consume all given input bytes and produce the final output; or return a
* ``BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE`` error if the given output buffer
* was too small. In the latter case, @p output_written will be set to the
* required buffer size. Calling again with ``BOTAN_CIPHER_UPDATE_FLAG_FINAL``, a
* big enough buffer and no further input will then produce the final output.
*
* Note that some ciphers require the entire message to be provided before any
* output is produced. @sa botan_cipher_requires_entire_message().
*/
BOTAN_FFI_EXPORT(2, 0)
int botan_cipher_update(botan_cipher_t cipher,
                        uint32_t flags,
                        uint8_t output[],
                        size_t output_size,
                        size_t* output_written,
                        const uint8_t input_bytes[],
                        size_t input_size,
                        size_t* input_consumed);

/**
* Reset the key, nonce, AD and all other state on this cipher object
*/
BOTAN_FFI_EXPORT(2, 0) int botan_cipher_clear(botan_cipher_t hash);

/**
* Destroy the cipher object
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 0) int botan_cipher_destroy(botan_cipher_t cipher);

/**
* Derive a key from a passphrase for a number of iterations
* @param pbkdf_algo PBKDF algorithm, e.g., "PBKDF2(SHA-256)"
* @param out buffer to store the derived key, must be of out_len bytes
* @param out_len the desired length of the key to produce
* @param passphrase the password to derive the key from
* @param salt a randomly chosen salt
* @param salt_len length of salt in bytes
* @param iterations the number of iterations to use (use 10K or more)
* @return 0 on success, a negative value on failure
*
* Deprecated: use
*  botan_pwdhash(pbkdf_algo, iterations, 0, 0, out, out_len,
*                passphrase, 0, salt, salt_len);
*/
BOTAN_FFI_DEPRECATED("Use botan_pwdhash")
BOTAN_FFI_EXPORT(2, 0)
int botan_pbkdf(const char* pbkdf_algo,
                uint8_t out[],
                size_t out_len,
                const char* passphrase,
                const uint8_t salt[],
                size_t salt_len,
                size_t iterations);

/**
* Derive a key from a passphrase, running until msec time has elapsed.
* @param pbkdf_algo PBKDF algorithm, e.g., "PBKDF2(SHA-256)"
* @param out buffer to store the derived key, must be of out_len bytes
* @param out_len the desired length of the key to produce
* @param passphrase the password to derive the key from
* @param salt a randomly chosen salt
* @param salt_len length of salt in bytes
* @param milliseconds_to_run if iterations is zero, then instead the PBKDF is
*        run until milliseconds_to_run milliseconds has passed
* @param out_iterations_used set to the number iterations executed
* @return 0 on success, a negative value on failure
*
* Deprecated: use
*
* botan_pwdhash_timed(pbkdf_algo,
*                     static_cast<uint32_t>(ms_to_run),
*                     iterations_used,
*                     nullptr,
*                     nullptr,
*                     out, out_len,
*                     password, 0,
*                     salt, salt_len);
*/
BOTAN_FFI_EXPORT(2, 0)
int botan_pbkdf_timed(const char* pbkdf_algo,
                      uint8_t out[],
                      size_t out_len,
                      const char* passphrase,
                      const uint8_t salt[],
                      size_t salt_len,
                      size_t milliseconds_to_run,
                      size_t* out_iterations_used);

/**
* Derive a key from a passphrase
* @param algo PBKDF algorithm, e.g., "PBKDF2(SHA-256)" or "Scrypt"
* @param param1 the first PBKDF algorithm parameter
* @param param2 the second PBKDF algorithm parameter (may be zero if unneeded)
* @param param3 the third PBKDF algorithm parameter (may be zero if unneeded)
* @param out buffer to store the derived key, must be of out_len bytes
* @param out_len the desired length of the key to produce
* @param passphrase the password to derive the key from
* @param passphrase_len if > 0, specifies length of password. If len == 0, then
*        strlen will be called on passphrase to compute the length.
* @param salt a randomly chosen salt
* @param salt_len length of salt in bytes
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 8)
int botan_pwdhash(const char* algo,
                  size_t param1,
                  size_t param2,
                  size_t param3,
                  uint8_t out[],
                  size_t out_len,
                  const char* passphrase,
                  size_t passphrase_len,
                  const uint8_t salt[],
                  size_t salt_len);

/**
* Derive a key from a passphrase, choosing parameters to hit a target runtime
* @param algo PBKDF algorithm, e.g., "Scrypt" or "PBKDF2(SHA-256)"
* @param msec the desired runtime in milliseconds
* @param param1 will be set to the first password hash parameter
* @param param2 will be set to the second password hash parameter
* @param param3 will be set to the third password hash parameter
* @param out buffer to store the derived key, must be of out_len bytes
* @param out_len the desired length of the key to produce
* @param passphrase the password to derive the key from
* @param passphrase_len if > 0, specifies length of password. If len == 0, then
*        strlen will be called on passphrase to compute the length.
* @param salt a randomly chosen salt
* @param salt_len length of salt in bytes
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 8)
int botan_pwdhash_timed(const char* algo,
                        uint32_t msec,
                        size_t* param1,
                        size_t* param2,
                        size_t* param3,
                        uint8_t out[],
                        size_t out_len,
                        const char* passphrase,
                        size_t passphrase_len,
                        const uint8_t salt[],
                        size_t salt_len);

/**
* Derive a key using scrypt
* Deprecated; use
* botan_pwdhash("Scrypt", N, r, p, out, out_len, password, 0, salt, salt_len);
*/
BOTAN_FFI_DEPRECATED("Use botan_pwdhash")
BOTAN_FFI_EXPORT(2, 8)
int botan_scrypt(uint8_t out[],
                 size_t out_len,
                 const char* passphrase,
                 const uint8_t salt[],
                 size_t salt_len,
                 size_t N,
                 size_t r,
                 size_t p);

/**
* Derive a key
* @param kdf_algo KDF algorithm, e.g., "SP800-56C"
* @param out buffer holding the derived key, must be of length out_len
* @param out_len the desired output length in bytes
* @param secret the secret input
* @param secret_len size of secret in bytes
* @param salt a diversifier
* @param salt_len size of salt in bytes
* @param label purpose for the derived keying material
* @param label_len size of label in bytes
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0)
int botan_kdf(const char* kdf_algo,
              uint8_t out[],
              size_t out_len,
              const uint8_t secret[],
              size_t secret_len,
              const uint8_t salt[],
              size_t salt_len,
              const uint8_t label[],
              size_t label_len);

/**
* Opaque type of a raw block cipher (PRP)
*/
typedef struct botan_block_cipher_struct* botan_block_cipher_t;

/**
* Initialize a block cipher object
*/
BOTAN_FFI_EXPORT(2, 1) int botan_block_cipher_init(botan_block_cipher_t* bc, const char* cipher_name);

/**
* Destroy a block cipher object
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 1) int botan_block_cipher_destroy(botan_block_cipher_t bc);

/**
* Reinitializes the block cipher
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 1) int botan_block_cipher_clear(botan_block_cipher_t bc);

/**
* Set the key for a block cipher instance
*/
BOTAN_FFI_EXPORT(2, 1) int botan_block_cipher_set_key(botan_block_cipher_t bc, const uint8_t key[], size_t len);

/**
* Return the positive block size of this block cipher, or negative to
* indicate an error
*/
BOTAN_FFI_EXPORT(2, 1) int botan_block_cipher_block_size(botan_block_cipher_t bc);

/**
* Encrypt one or more blocks with the cipher
*/
BOTAN_FFI_EXPORT(2, 1)
int botan_block_cipher_encrypt_blocks(botan_block_cipher_t bc, const uint8_t in[], uint8_t out[], size_t blocks);

/**
* Decrypt one or more blocks with the cipher
*/
BOTAN_FFI_EXPORT(2, 1)
int botan_block_cipher_decrypt_blocks(botan_block_cipher_t bc, const uint8_t in[], uint8_t out[], size_t blocks);

/**
* Get the name of this block cipher
* @param cipher the object to read
* @param name output buffer
* @param name_len on input, the length of buffer, on success the number of bytes written
*/
BOTAN_FFI_EXPORT(2, 8) int botan_block_cipher_name(botan_block_cipher_t cipher, char* name, size_t* name_len);

/**
* Get the key length limits of this block cipher
* @param cipher the object to read
* @param out_minimum_keylength if non-NULL, will be set to minimum keylength of cipher
* @param out_maximum_keylength if non-NULL, will be set to maximum keylength of cipher
* @param out_keylength_modulo if non-NULL will be set to byte multiple of valid keys
*/
BOTAN_FFI_EXPORT(2, 8)
int botan_block_cipher_get_keyspec(botan_block_cipher_t cipher,
                                   size_t* out_minimum_keylength,
                                   size_t* out_maximum_keylength,
                                   size_t* out_keylength_modulo);

/**
* Opaque type of a multiple precision integer (MPI)
*/
typedef struct botan_mp_struct* botan_mp_t;

/**
* Initialize an MPI
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_init(botan_mp_t* mp);

/**
* Destroy (deallocate) an MPI
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_destroy(botan_mp_t mp);

/**
* Convert the MPI to a hex string. Writes up to botan_mp_num_bytes(mp)*2 + 5 bytes
*
* Prefer botan_mp_view_hex
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_to_hex(botan_mp_t mp, char* out);

/**
* View the hex string encoding of the MPI.
*/
BOTAN_FFI_EXPORT(3, 10) int botan_mp_view_hex(botan_mp_t mp, botan_view_ctx ctx, botan_view_str_fn view);

/**
* Convert the MPI to a string. Currently radix == 10 and radix == 16 are supported.
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_to_str(botan_mp_t mp, uint8_t radix, char* out, size_t* out_len);

/**
* View the MPI as a radix-N integer. Currently only radix 10 and radix 16 are supported
*/
BOTAN_FFI_EXPORT(3, 10) int botan_mp_view_str(botan_mp_t mp, uint8_t radix, botan_view_ctx ctx, botan_view_str_fn view);

/**
* Set the MPI to zero
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_clear(botan_mp_t mp);

/**
* Set the MPI value from an int
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_set_from_int(botan_mp_t mp, int initial_value);

/**
* Set the MPI value from another MP object
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_set_from_mp(botan_mp_t dest, botan_mp_t source);

/**
* Set the MPI value from a string
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_set_from_str(botan_mp_t dest, const char* str);

/**
* Set the MPI value from a string with arbitrary radix.
* For arbitrary being 10 or 16.
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_set_from_radix_str(botan_mp_t dest, const char* str, size_t radix);

/**
* Return the number of significant bits in the MPI
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_num_bits(botan_mp_t n, size_t* bits);

/**
* Return the number of significant bytes in the MPI
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_num_bytes(botan_mp_t n, size_t* bytes);

/**
* Convert the MPI to a big-endian binary string. Writes botan_mp_num_bytes to vec
*
* Note that the sign of the integer is ignored here; only the absolute value is copied
*
* @param mp the integer to encode
* @param vec output buffer of at least botan_mp_num_bytes(mp) bytes
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_to_bin(botan_mp_t mp, uint8_t vec[]);

/**
* View the big-endian binary string encoding of this integer
*
* Note that the sign of the integer is ignored here; only the absolute value is viewed
*
* @param mp the integer to encode
* @param ctx an application context passed to the view function
* @param view the view callback which receives the encoding
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 10) int botan_mp_view_bin(botan_mp_t mp, botan_view_ctx ctx, botan_view_bin_fn view);

/**
* Set an MP to the big-endian binary value
*
* @param mp the integer to set
* @param vec the big-endian encoding to decode
* @param vec_len length of vec in bytes
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_from_bin(botan_mp_t mp, const uint8_t vec[], size_t vec_len);

/**
* Convert the MPI to a uint32_t, if possible. Fails if MPI is negative or too large.
*
* @param mp the integer to convert
* @param val set to the value of mp
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_to_uint32(botan_mp_t mp, uint32_t* val);

/**
* This function should have been named mp_is_non_negative. Returns 1
* iff mp is greater than *or equal to* zero. Use botan_mp_is_negative
* to detect negative numbers, botan_mp_is_zero to check for zero.
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_is_positive(botan_mp_t mp);

/**
* Return 1 iff mp is less than 0
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_is_negative(botan_mp_t mp);

/**
* Negate the MPI, ie replace it by its additive inverse
* @param mp the integer to negate, modified in place
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_flip_sign(botan_mp_t mp);

/**
* Return 1 iff mp is equal to zero
* @param mp the integer to test
* @return 1 if zero, 0 if not, or a negative value on error
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_is_zero(botan_mp_t mp);

/**
* Return 1 iff mp is odd
* @param mp the integer to test
* @return 1 if odd, 0 if even, or a negative value on error
*/
BOTAN_FFI_DEPRECATED("Use botan_mp_get_bit(0)") BOTAN_FFI_EXPORT(2, 1) int botan_mp_is_odd(botan_mp_t mp);

/**
* Return 1 iff mp is even
* @param mp the integer to test
* @return 1 if even, 0 if odd, or a negative value on error
*/
BOTAN_FFI_DEPRECATED("Use botan_mp_get_bit(0)") BOTAN_FFI_EXPORT(2, 1) int botan_mp_is_even(botan_mp_t mp);

/**
* Set result to x + y
* @param result set to the sum
* @param x the first addend
* @param y the second addend
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 8) int botan_mp_add_u32(botan_mp_t result, botan_mp_t x, uint32_t y);

/**
* Set result to x - y
* @param result set to the difference
* @param x the minuend
* @param y the subtrahend
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 8) int botan_mp_sub_u32(botan_mp_t result, botan_mp_t x, uint32_t y);

/**
* Set result to x + y
* @param result set to the sum
* @param x the first addend
* @param y the second addend
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_add(botan_mp_t result, botan_mp_t x, botan_mp_t y);

/**
* Set result to x - y
* @param result set to the difference
* @param x the minuend
* @param y the subtrahend
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_sub(botan_mp_t result, botan_mp_t x, botan_mp_t y);

/**
* Set result to x * y
* @param result set to the product
* @param x the first factor
* @param y the second factor
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_mul(botan_mp_t result, botan_mp_t x, botan_mp_t y);

/**
* Divide x by y, producing both the quotient and the remainder
* @param quotient set to x / y
* @param remainder set to x % y
* @param x the dividend
* @param y the divisor, which must not be zero
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 1)
int botan_mp_div(botan_mp_t quotient, botan_mp_t remainder, botan_mp_t x, botan_mp_t y);

/**
* Set result to (x * y) % mod
* @param result set to the modular product
* @param x the first factor
* @param y the second factor
* @param mod the modulus, which must be positive
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 1)
int botan_mp_mod_mul(botan_mp_t result, botan_mp_t x, botan_mp_t y, botan_mp_t mod);

/**
* Test if two integers are equal
* @param x the first integer
* @param y the second integer
* @return 1 if x == y, 0 if x != y, or a negative value on error
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_equal(botan_mp_t x, botan_mp_t y);

/**
* Compare two integers
* @param result set to -1 if x < y, 0 if x == y, 1 if x > y
* @param x the first integer
* @param y the second integer
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_cmp(int* result, botan_mp_t x, botan_mp_t y);

/**
* Swap the values of two integers
* @param x the first integer
* @param y the second integer
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_swap(botan_mp_t x, botan_mp_t y);

/**
* Set out to (base^exponent) % modulus
* @param out set to the result of the modular exponentiation
* @param base the base
* @param exponent the exponent
* @param modulus the modulus, which must be positive
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 1)
int botan_mp_powmod(botan_mp_t out, botan_mp_t base, botan_mp_t exponent, botan_mp_t modulus);

/**
* Set out to in shifted left by the specified number of bits
* @param out set to the shifted value
* @param in the integer to shift
* @param shift the number of bits to shift by
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_lshift(botan_mp_t out, botan_mp_t in, size_t shift);

/**
* Set out to in shifted right by the specified number of bits
* @param out set to the shifted value
* @param in the integer to shift
* @param shift the number of bits to shift by
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_rshift(botan_mp_t out, botan_mp_t in, size_t shift);

/**
* Set out to the inverse of in modulo the specified modulus. If no
* inverse exists, out is set to zero.
* @param out set to the modular inverse
* @param in the value to invert
* @param modulus the modulus
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_mod_inverse(botan_mp_t out, botan_mp_t in, botan_mp_t modulus);

/**
* Set rand_out to a random integer of the specified bit length
* @param rand_out set to the random integer
* @param rng a random number generator
* @param bits the desired bit length
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_rand_bits(botan_mp_t rand_out, botan_rng_t rng, size_t bits);

/**
* Set rand_out to a random integer within the half-open range [lower_bound, upper_bound)
* @param rand_out set to the random integer
* @param rng a random number generator
* @param lower_bound the inclusive lower bound
* @param upper_bound the exclusive upper bound
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 1)
int botan_mp_rand_range(botan_mp_t rand_out, botan_rng_t rng, botan_mp_t lower_bound, botan_mp_t upper_bound);

/**
* Set out to the greatest common divisor of x and y
* @param out set to gcd(x, y)
* @param x the first integer
* @param y the second integer
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_gcd(botan_mp_t out, botan_mp_t x, botan_mp_t y);

/**
* Returns 0 if n is not prime
* Returns 1 if n is prime
* Returns negative number on error
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_is_prime(botan_mp_t n, botan_rng_t rng, size_t test_prob);

/**
* Returns 0 if specified bit of n is not set
* Returns 1 if specified bit of n is set
* Returns negative number on error
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_get_bit(botan_mp_t n, size_t bit);

/**
* Set the specified bit
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_set_bit(botan_mp_t n, size_t bit);

/**
* Clear the specified bit
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_clear_bit(botan_mp_t n, size_t bit);

/* Bcrypt password hashing */

/**
* Create a password hash using Bcrypt
* @param out buffer holding the password hash, should be of length 64 bytes
* @param out_len the desired output length in bytes
* @param password the password
* @param rng a random number generator
* @param work_factor how much work to do to slow down guessing attacks
* @param flags should be 0 in current API revision, all other uses are reserved
*       and return BOTAN_FFI_ERROR_BAD_FLAG
* @return 0 on success, a negative value on failure
*
* Output is formatted bcrypt $2a$...
*
* TOD(Botan4) this should use char for the type of `out`
*/
BOTAN_FFI_EXPORT(2, 0)
int botan_bcrypt_generate(
   uint8_t* out, size_t* out_len, const char* password, botan_rng_t rng, size_t work_factor, uint32_t flags);

/**
* Check a previously created password hash
* @param pass the password to check against
* @param hash the stored hash to check against
* @return 0 if if this password/hash combination is valid,
*       1 if the combination is not valid (but otherwise well formed),
*       negative on error
*/
BOTAN_FFI_EXPORT(2, 0) int botan_bcrypt_is_valid(const char* pass, const char* hash);

/*
* OIDs
*/

/**
* Opaque type of an ASN.1 object identifier
*/
typedef struct botan_asn1_oid_struct* botan_asn1_oid_t;

/**
* Frees all resources of the OID object
* @param oid the OID object to destroy
* @returns negative number on error, or zero on success
*/
BOTAN_FFI_EXPORT(3, 8) int botan_oid_destroy(botan_asn1_oid_t oid);

/**
* Create an OID from a string, either dot notation (e.g. '1.2.3.4') or a registered name (e.g. 'RSA')
* @param oid handle to the resulting OID
* @param oid_str the name of the OID to create
* @returns negative number on error, or zero on success
*/
BOTAN_FFI_EXPORT(3, 8) int botan_oid_from_string(botan_asn1_oid_t* oid, const char* oid_str);

/**
* Registers an OID so that it may later be retrieved by name
* @returns negative number on error, or zero on success
*/
BOTAN_FFI_EXPORT(3, 8) int botan_oid_register(botan_asn1_oid_t oid, const char* name);

/**
* View an OID in dot notation
*/
BOTAN_FFI_EXPORT(3, 8) int botan_oid_view_string(botan_asn1_oid_t oid, botan_view_ctx ctx, botan_view_str_fn view);

/**
* View an OIDs registered name if it exists, else its dot notation
*/
BOTAN_FFI_EXPORT(3, 8) int botan_oid_view_name(botan_asn1_oid_t oid, botan_view_ctx ctx, botan_view_str_fn view);

/**
* Test if two OIDs are equal
* @param a the first OID
* @param b the second OID
* @returns 0 if a != b
* @returns 1 if a == b
* @returns negative number on error
*/
BOTAN_FFI_EXPORT(3, 8) int botan_oid_equal(botan_asn1_oid_t a, botan_asn1_oid_t b);

/**
* Sets @param result to comparison result:
* -1 if a < b, 0 if a == b, 1 if a > b
* @returns negative number on error or zero on success
*/
BOTAN_FFI_EXPORT(3, 8) int botan_oid_cmp(int* result, botan_asn1_oid_t a, botan_asn1_oid_t b);

/*
* EC Groups
*/

/**
* Opaque type of a set of elliptic curve domain parameters
*/
typedef struct botan_ec_group_struct* botan_ec_group_t;

/**
* Frees all resources of the EC Group object
* @param ec_group the EC Group object to destroy
* @returns negative number on error, or zero on success
*/
BOTAN_FFI_EXPORT(3, 8) int botan_ec_group_destroy(botan_ec_group_t ec_group);

/**
* Checks if in this build configuration it is possible to register an application specific elliptic curve and sets
* @param out to 1 if so, 0 otherwise
* @returns 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 8) int botan_ec_group_supports_application_specific_group(int* out);

/**
* Checks if in this build configuration botan_ec_group_from_name(group_ptr, name) will succeed and sets
* @param name the name of the group to check
* @param out to 1 if so, 0 otherwise.
* @returns negative number on error, or zero on success
*/
BOTAN_FFI_EXPORT(3, 8) int botan_ec_group_supports_named_group(const char* name, int* out);

/**
* Create a new EC Group from parameters
* @warning use only elliptic curve parameters that you trust
*
* @param ec_group the new object will be placed here
* @param oid the OID to associate with the group
* @param p the elliptic curve prime (at most 521 bits)
* @param a the elliptic curve a param
* @param b the elliptic curve b param
* @param base_x the x coordinate of the group generator
* @param base_y the y coordinate of the group generator
* @param order the order of the group
* @returns negative number on error, or zero on success
*/
BOTAN_FFI_EXPORT(3, 8)
int botan_ec_group_from_params(botan_ec_group_t* ec_group,
                               botan_asn1_oid_t oid,
                               botan_mp_t p,
                               botan_mp_t a,
                               botan_mp_t b,
                               botan_mp_t base_x,
                               botan_mp_t base_y,
                               botan_mp_t order);

/**
* Decode a BER encoded ECC domain parameter set
* @param ec_group the new object will be placed here
* @param ber encoding
* @param ber_len size of the encoding in bytes
* @returns negative number on error, or zero on success
*/
BOTAN_FFI_EXPORT(3, 8) int botan_ec_group_from_ber(botan_ec_group_t* ec_group, const uint8_t* ber, size_t ber_len);

/**
* Initialize an EC Group from the PEM/ASN.1 encoding
* @param ec_group the new object will be placed here
* @param pem encoding
* @returns negative number on error, or zero on success
*/
BOTAN_FFI_EXPORT(3, 8) int botan_ec_group_from_pem(botan_ec_group_t* ec_group, const char* pem);

/**
* Initialize an EC Group from a group named by an object identifier
* @param ec_group the new object will be placed here
* @param oid a known OID
* @returns negative number on error, or zero on success
*/
BOTAN_FFI_EXPORT(3, 8) int botan_ec_group_from_oid(botan_ec_group_t* ec_group, botan_asn1_oid_t oid);

/**
* Initialize an EC Group from a common group name (eg "secp256r1")
* @param ec_group the new object will be placed here
* @param name a known group name
* @returns negative number on error, or zero on success
*/
BOTAN_FFI_EXPORT(3, 8) int botan_ec_group_from_name(botan_ec_group_t* ec_group, const char* name);

/**
* Unregister a previously registered group.
* @param oid the oid associated with the group to unregister
* @returns 1 if the group was found and unregistered, else 0
*
* Using this is discouraged for normal use. This is only useful or necessary if
* you are registering a very large number of distinct groups, and need to worry about memory constraints.
*/
BOTAN_FFI_EXPORT(3, 11) int botan_ec_group_unregister(botan_asn1_oid_t oid);

/**
* View an EC Group in DER encoding
*/
BOTAN_FFI_EXPORT(3, 8)
int botan_ec_group_view_der(botan_ec_group_t ec_group, botan_view_ctx ctx, botan_view_bin_fn view);

/**
* View an EC Group in PEM encoding
*/
BOTAN_FFI_EXPORT(3, 8)
int botan_ec_group_view_pem(botan_ec_group_t ec_group, botan_view_ctx ctx, botan_view_str_fn view);

/**
* Get the curve OID of an EC Group
*/
BOTAN_FFI_EXPORT(3, 8) int botan_ec_group_get_curve_oid(botan_asn1_oid_t* oid, botan_ec_group_t ec_group);

/**
* Get the prime modulus of the field
*/
BOTAN_FFI_EXPORT(3, 8) int botan_ec_group_get_p(botan_mp_t* p, botan_ec_group_t ec_group);

/**
* Get the a parameter of the elliptic curve equation
*/
BOTAN_FFI_EXPORT(3, 8) int botan_ec_group_get_a(botan_mp_t* a, botan_ec_group_t ec_group);

/**
* Get the b parameter of the elliptic curve equation
*/
BOTAN_FFI_EXPORT(3, 8) int botan_ec_group_get_b(botan_mp_t* b, botan_ec_group_t ec_group);

/**
* Get the x coordinate of the base point
*/
BOTAN_FFI_EXPORT(3, 8) int botan_ec_group_get_g_x(botan_mp_t* g_x, botan_ec_group_t ec_group);

/**
* Get the y coordinate of the base point
*/
BOTAN_FFI_EXPORT(3, 8) int botan_ec_group_get_g_y(botan_mp_t* g_y, botan_ec_group_t ec_group);

/**
* Get the order of the base point
*/
BOTAN_FFI_EXPORT(3, 8) int botan_ec_group_get_order(botan_mp_t* order, botan_ec_group_t ec_group);

/**
* Test if two EC Groups describe the same curve
* @param curve1 the first group
* @param curve2 the second group
* @returns 0 if curve1 != curve2
* @returns 1 if curve1 == curve2
* @returns negative number on error
*/
BOTAN_FFI_EXPORT(3, 8) int botan_ec_group_equal(botan_ec_group_t curve1, botan_ec_group_t curve2);

/**
* Opaque type of a scalar, that is an integer modulo the group order
*/
typedef struct botan_ec_scalar_struct* botan_ec_scalar_t;

/**
* Opaque type of an elliptic curve point
*/
typedef struct botan_ec_point_struct* botan_ec_point_t;

/**
* Frees all resources of the scalar object
* @param ec_scalar the scalar object to destroy
* @returns negative number on error, or zero on success
*/
BOTAN_FFI_EXPORT(3, 12) int botan_ec_scalar_destroy(botan_ec_scalar_t ec_scalar);

/**
* Create a new random scalar value
*/
BOTAN_FFI_EXPORT(3, 12)
int botan_ec_scalar_random(botan_ec_scalar_t* ec_scalar, botan_ec_group_t ec_group, botan_rng_t rng);

/**
* Convert from an MPI to a scalar
* @returns a negative number if the provided MPI is negative or too large, 0 on success
*/
BOTAN_FFI_EXPORT(3, 12)
int botan_ec_scalar_from_mp(botan_ec_scalar_t* ec_scalar, botan_ec_group_t ec_group, botan_mp_t mp);

/**
* Convert from a scalar to an MPI
* @returns a negative number on failure, 0 on success
*/
BOTAN_FFI_EXPORT(3, 12)
int botan_ec_scalar_to_mp(botan_ec_scalar_t ec_scalar, botan_mp_t* mp);

/**
* Frees all resources of the point object
* @param ec_point the point object to destroy
* @returns negative number on error, or zero on success
*/
BOTAN_FFI_EXPORT(3, 12) int botan_ec_point_destroy(botan_ec_point_t ec_point);

/**
* Create a point set to the identity element of the group
*/
BOTAN_FFI_EXPORT(3, 12) int botan_ec_point_identity(botan_ec_point_t* ec_point, botan_ec_group_t ec_group);

/**
* Create a point set to the standard group generator
*/
BOTAN_FFI_EXPORT(3, 12) int botan_ec_point_generator(botan_ec_point_t* ec_point, botan_ec_group_t ec_group);

/**
* Create a point from a pair (x,y) of integers
* The integers must be within the field and must satisfy the curve equation
*/
BOTAN_FFI_EXPORT(3, 12)
int botan_ec_point_from_xy(botan_ec_point_t* ec_point, botan_ec_group_t ec_group, botan_mp_t x, botan_mp_t y);

/**
* Create a point from a SEC1 compressed or uncompressed format.
* @returns negative number on error
*/
BOTAN_FFI_EXPORT(3, 12)
int botan_ec_point_from_bytes(botan_ec_point_t* ec_point,
                              botan_ec_group_t ec_group,
                              const uint8_t* bytes,
                              size_t bytes_len);

/**
* View the fixed length encoding of the affine x coordinate
* @returns negative number on error
*/
BOTAN_FFI_EXPORT(3, 12)
int botan_ec_point_view_x_bytes(botan_ec_point_t ec_point, botan_view_ctx ctx, botan_view_bin_fn view);

/**
* View the fixed length encoding of the affine y coordinate
* @returns negative number on error
*/
BOTAN_FFI_EXPORT(3, 12)
int botan_ec_point_view_y_bytes(botan_ec_point_t ec_point, botan_view_ctx ctx, botan_view_bin_fn view);

/**
* View the fixed length encoding of the affine x and y coordinates
* @returns negative number on error
*/
BOTAN_FFI_EXPORT(3, 12)
int botan_ec_point_view_xy_bytes(botan_ec_point_t ec_point, botan_view_ctx ctx, botan_view_bin_fn view);

/**
* View the fixed length SEC1 uncompressed encoding
* @returns negative number on error
*/
BOTAN_FFI_EXPORT(3, 12)
int botan_ec_point_view_uncompressed(botan_ec_point_t ec_point, botan_view_ctx ctx, botan_view_bin_fn view);

/**
* View the fixed length SEC1 compressed encoding
* @returns negative number on error
*/
BOTAN_FFI_EXPORT(3, 12)
int botan_ec_point_view_compressed(botan_ec_point_t ec_point, botan_view_ctx ctx, botan_view_bin_fn view);

/**
* Test if a point is the identity element of the group
* @param ec_point the point to test
* @returns 1 if ec_point is the identity element, else 0
* @returns negative number on error
*/
BOTAN_FFI_EXPORT(3, 12) int botan_ec_point_is_identity(botan_ec_point_t ec_point);

/**
* Test if two points are equal
* @param x the first point
* @param y the second point
* @returns 1 if x == y, else 0
* @returns negative number on error
*/
BOTAN_FFI_EXPORT(3, 12) int botan_ec_point_equal(botan_ec_point_t x, botan_ec_point_t y);

/**
* Compute the additive inverse of a point
* @param result the new object will be placed here
* @param ec_point point to negate
* @returns negative number on error, or zero on success
*/
BOTAN_FFI_EXPORT(3, 12) int botan_ec_point_negate(botan_ec_point_t* result, botan_ec_point_t ec_point);

/**
* Add two points
* @param result the new object will be placed here
* @param x the first point
* @param y the second point
* @returns negative number on error, or zero on success
*/
BOTAN_FFI_EXPORT(3, 12) int botan_ec_point_add(botan_ec_point_t* result, botan_ec_point_t x, botan_ec_point_t y);

/**
* Multiply a point by a scalar
* @param result the new object will be placed here
* @param ec_point the point to multiply
* @param ec_scalar the scalar to multiply by
* @param rng a random number generator, used for blinding
* @returns negative number on error, or zero on success
*/
BOTAN_FFI_EXPORT(3, 12)
int botan_ec_point_mul(botan_ec_point_t* result,
                       botan_ec_point_t ec_point,
                       botan_ec_scalar_t ec_scalar,
                       botan_rng_t rng);

/**
* Opaque type of a private key
*/
typedef struct botan_privkey_struct* botan_privkey_t;

/**
* Create a new private key
* @param key the new object will be placed here
* @param algo_name something like "RSA" or "ECDSA"
* @param algo_params is specific to the algorithm. For RSA, specifies
*        the modulus bit length. For ECC is the name of the curve.
* @param rng a random number generator
*/
BOTAN_FFI_EXPORT(2, 0)
int botan_privkey_create(botan_privkey_t* key, const char* algo_name, const char* algo_params, botan_rng_t rng);

/**
* Create a new ec private key
* @param key the new object will be placed here
* @param algo_name something like "ECDSA" or "ECDH"
* @param ec_group a (possibly application specific) elliptic curve
* @param rng a random number generator
*/
BOTAN_FFI_EXPORT(3, 8)
int botan_ec_privkey_create(botan_privkey_t* key, const char* algo_name, botan_ec_group_t ec_group, botan_rng_t rng);

#define BOTAN_CHECK_KEY_EXPENSIVE_TESTS 1

/**
* Test the consistency of a private key
* @param key the private key to check
* @param rng a random number generator
* @param flags either 0 or BOTAN_CHECK_KEY_EXPENSIVE_TESTS
* @return 0 if the key is valid, negative if invalid or some other error
*/
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_check_key(botan_privkey_t key, botan_rng_t rng, uint32_t flags);

/**
* Create a new RSA private key
* @param key the new object will be placed here
* @param rng a random number generator
* @param n_bits the bit length of the modulus
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Use botan_privkey_create")
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_create_rsa(botan_privkey_t* key, botan_rng_t rng, size_t n_bits);

/**
* Create a new ECDSA private key
* @param key the new object will be placed here
* @param rng a random number generator
* @param params the name of the curve, eg "secp256r1"
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Use botan_privkey_create")
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_create_ecdsa(botan_privkey_t* key, botan_rng_t rng, const char* params);

/**
* Create a new ECDH private key
* @param key the new object will be placed here
* @param rng a random number generator
* @param params the name of the curve, eg "secp256r1"
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Use botan_privkey_create")
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_create_ecdh(botan_privkey_t* key, botan_rng_t rng, const char* params);

/**
* Create a new McEliece private key
* @param key the new object will be placed here
* @param rng a random number generator
* @param n the code length
* @param t the error correction capability
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Use botan_privkey_create")
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_create_mceliece(botan_privkey_t* key, botan_rng_t rng, size_t n, size_t t);

/**
* Create a new Diffie-Hellman private key
* @param key the new object will be placed here
* @param rng a random number generator
* @param param the name of the group, eg "modp/ietf/2048"
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Use botan_privkey_create")
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_create_dh(botan_privkey_t* key, botan_rng_t rng, const char* param);

/**
 * Generates DSA key pair. Gives to a caller control over key length
 * and order of a subgroup 'q'.
 *
 * @param   key   handler to the resulting key
 * @param   rng   initialized PRNG
 * @param   pbits length of the key in bits. Must be between in range (1024, 3072)
 *          and multiple of 64. Bit size of the prime 'p'
 * @param   qbits order of the subgroup. Must be in range (160, 256) and multiple
 *          of 8
 *
 * @returns BOTAN_FFI_SUCCESS Success, `key' initialized with DSA key
 * @returns BOTAN_FFI_ERROR_NULL_POINTER  either `key' or `rng' is NULL
 * @returns BOTAN_FFI_ERROR_BAD_PARAMETER unexpected value for either `pbits' or
 *          `qbits'
 * @returns BOTAN_FFI_ERROR_NOT_IMPLEMENTED functionality not implemented
 *
*/
BOTAN_FFI_EXPORT(2, 5) int botan_privkey_create_dsa(botan_privkey_t* key, botan_rng_t rng, size_t pbits, size_t qbits);

/**
 * Generates ElGamal key pair. Caller has a control over key length
 * and order of a subgroup 'q'. Function is able to use two types of
 * primes:
 *    * if pbits-1 == qbits then safe primes are used for key generation
 *    * otherwise generation uses group of prime order
 *
 * @param   key   handler to the resulting key
 * @param   rng   initialized PRNG
 * @param   pbits length of the key in bits. Must be at least 1024
 * @param   qbits order of the subgroup. Must be at least 160
 *
 * @returns BOTAN_FFI_SUCCESS Success, `key' initialized with DSA key
 * @returns BOTAN_FFI_ERROR_NULL_POINTER  either `key' or `rng' is NULL
 * @returns BOTAN_FFI_ERROR_BAD_PARAMETER unexpected value for either `pbits' or
 *          `qbits'
 * @returns BOTAN_FFI_ERROR_NOT_IMPLEMENTED functionality not implemented
 *
*/
BOTAN_FFI_EXPORT(2, 5)
int botan_privkey_create_elgamal(botan_privkey_t* key, botan_rng_t rng, size_t pbits, size_t qbits);

/**
* Input currently assumed to be PKCS #8 structure;
* Set password to NULL to indicate no encryption expected
* Starting in 2.8.0, the rng parameter is unused and may be set to null
*/
BOTAN_FFI_EXPORT(2, 0)
int botan_privkey_load(botan_privkey_t* key, botan_rng_t rng, const uint8_t bits[], size_t len, const char* password);

/**
* Frees all resources of the private key object
* @param key the private key to destroy
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_destroy(botan_privkey_t key);

#define BOTAN_PRIVKEY_EXPORT_FLAG_DER 0
#define BOTAN_PRIVKEY_EXPORT_FLAG_PEM 1
#define BOTAN_PRIVKEY_EXPORT_FLAG_RAW 2

/**
* Export a private key in DER, PEM or raw encoding
*
* On input *out_len is number of bytes in out[]
* On output *out_len is number of bytes written (or required)
* If out is not big enough no output is written, *out_len is set and 1 is returned
* Returns 0 on success and sets
* If some other error occurs a negative integer is returned.
*
* @param key the private key to export
* @param out output buffer
* @param out_len on input the size of out, on output the number of bytes written or required
* @param flags one of BOTAN_PRIVKEY_EXPORT_FLAG_DER, _PEM or _RAW
* @return 0 on success, 1 if the buffer was too small, a negative value on other failures
*/
BOTAN_FFI_DEPRECATED("Use botan_privkey_view_{der,pem,raw}")
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_export(botan_privkey_t key, uint8_t out[], size_t* out_len, uint32_t flags);

/**
* View the private key's DER encoding
*/
BOTAN_FFI_EXPORT(3, 0) int botan_privkey_view_der(botan_privkey_t key, botan_view_ctx ctx, botan_view_bin_fn view);

/**
* View the private key's PEM encoding
*/
BOTAN_FFI_EXPORT(3, 0) int botan_privkey_view_pem(botan_privkey_t key, botan_view_ctx ctx, botan_view_str_fn view);

/**
* View the private key's raw encoding
*/
BOTAN_FFI_EXPORT(3, 6) int botan_privkey_view_raw(botan_privkey_t key, botan_view_ctx ctx, botan_view_bin_fn view);

/**
* Get the name of the algorithm this private key is for
* @param key the private key to query
* @param out output buffer
* @param out_len on input the length of out, on success the number of bytes written
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 8) int botan_privkey_algo_name(botan_privkey_t key, char out[], size_t* out_len);

/**
* Export a private key encrypted with a passphrase
*
* Set encryption_algo to NULL or "" to have the library choose a default (recommended)
*
* @param key the private key to export
* @param out output buffer
* @param out_len on input the size of out, on output the number of bytes written or required
* @param rng a random number generator
* @param passphrase the passphrase to encrypt under
* @param encryption_algo the cipher to use, or NULL for the default
* @param flags either BOTAN_PRIVKEY_EXPORT_FLAG_DER or BOTAN_PRIVKEY_EXPORT_FLAG_PEM
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Use botan_privkey_export_encrypted_pbkdf_{msec,iter}")
BOTAN_FFI_EXPORT(2, 0)
int botan_privkey_export_encrypted(botan_privkey_t key,
                                   uint8_t out[],
                                   size_t* out_len,
                                   botan_rng_t rng,
                                   const char* passphrase,
                                   const char* encryption_algo,
                                   uint32_t flags);

/**
* Export a private key encrypted with a passphrase, running the PBKDF for a
* specified amount of time
*
* Note: starting in 3.0, the output iterations count is not provided
*
* @param key the private key to export
* @param out output buffer
* @param out_len on input the size of out, on output the number of bytes written or required
* @param rng a random number generator
* @param passphrase the passphrase to encrypt under
* @param pbkdf_msec_runtime desired PBKDF runtime in milliseconds
* @param pbkdf_iterations_out ignored since 3.0
* @param cipher_algo the cipher to use, or NULL for the default
* @param pbkdf_algo the password hash to use, or NULL for the default
* @param flags either BOTAN_PRIVKEY_EXPORT_FLAG_DER or BOTAN_PRIVKEY_EXPORT_FLAG_PEM
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Use botan_privkey_view_encrypted_{der,pem}_timed")
BOTAN_FFI_EXPORT(2, 0)
int botan_privkey_export_encrypted_pbkdf_msec(botan_privkey_t key,
                                              uint8_t out[],
                                              size_t* out_len,
                                              botan_rng_t rng,
                                              const char* passphrase,
                                              uint32_t pbkdf_msec_runtime,
                                              size_t* pbkdf_iterations_out,
                                              const char* cipher_algo,
                                              const char* pbkdf_algo,
                                              uint32_t flags);

/**
* Export a private key encrypted with a passphrase, using the specified number
* of PBKDF iterations.
*
* @param key the private key to export
* @param out output buffer
* @param out_len on input the size of out, on output the number of bytes written or required
* @param rng a random number generator
* @param passphrase the passphrase to encrypt under
* @param pbkdf_iterations the number of PBKDF iterations to run
* @param cipher_algo the cipher to use, or NULL for the default
* @param pbkdf_algo the password hash to use, or NULL for the default
* @param flags either BOTAN_PRIVKEY_EXPORT_FLAG_DER or BOTAN_PRIVKEY_EXPORT_FLAG_PEM
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Use botan_privkey_view_encrypted_{der,pem}")
BOTAN_FFI_EXPORT(2, 0)
int botan_privkey_export_encrypted_pbkdf_iter(botan_privkey_t key,
                                              uint8_t out[],
                                              size_t* out_len,
                                              botan_rng_t rng,
                                              const char* passphrase,
                                              size_t pbkdf_iterations,
                                              const char* cipher_algo,
                                              const char* pbkdf_algo,
                                              uint32_t flags);

/**
* View the encryption of a private key (binary DER encoding)
*
* Set cipher_algo, pbkdf_algo to NULL to use defaults
* Set pbkdf_iterations to 0 to use defaults
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_privkey_view_encrypted_der(botan_privkey_t key,
                                     botan_rng_t rng,
                                     const char* passphrase,
                                     const char* cipher_algo,
                                     const char* pbkdf_algo,
                                     size_t pbkdf_iterations,
                                     botan_view_ctx ctx,
                                     botan_view_bin_fn view);

/**
* View the encryption of a private key (binary DER encoding)
*
* Set cipher_algo, pbkdf_algo to NULL to use defaults
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_privkey_view_encrypted_der_timed(botan_privkey_t key,
                                           botan_rng_t rng,
                                           const char* passphrase,
                                           const char* cipher_algo,
                                           const char* pbkdf_algo,
                                           size_t pbkdf_runtime_msec,
                                           botan_view_ctx ctx,
                                           botan_view_bin_fn view);

/**
* View the encryption of a private key (PEM encoding)
*
* Set cipher_algo, pbkdf_algo to NULL to use defaults
* Set pbkdf_iterations to 0 to use defaults
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_privkey_view_encrypted_pem(botan_privkey_t key,
                                     botan_rng_t rng,
                                     const char* passphrase,
                                     const char* cipher_algo,
                                     const char* pbkdf_algo,
                                     size_t pbkdf_iterations,
                                     botan_view_ctx ctx,
                                     botan_view_str_fn view);

/**
* View the encryption of a private key (PEM encoding)
*
* Set cipher_algo, pbkdf_algo to NULL to use defaults
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_privkey_view_encrypted_pem_timed(botan_privkey_t key,
                                           botan_rng_t rng,
                                           const char* passphrase,
                                           const char* cipher_algo,
                                           const char* pbkdf_algo,
                                           size_t pbkdf_runtime_msec,
                                           botan_view_ctx ctx,
                                           botan_view_str_fn view);

/**
* Opaque type of a public key
*/
typedef struct botan_pubkey_struct* botan_pubkey_t;

/**
* Load a public key from an X.509 SubjectPublicKeyInfo structure
* @param key the new object will be placed here
* @param bits the DER encoding to load
* @param len length of bits in bytes
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_pubkey_load(botan_pubkey_t* key, const uint8_t bits[], size_t len);

/**
* Extract the public key associated with a private key
* @param out the new object will be placed here
* @param in the private key to extract the public key from
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_export_pubkey(botan_pubkey_t* out, botan_privkey_t in);

/**
* Export a public key in DER, PEM or raw encoding
* @param key the public key to export
* @param out output buffer
* @param out_len on input the size of out, on output the number of bytes written or required
* @param flags one of BOTAN_PRIVKEY_EXPORT_FLAG_DER, _PEM or _RAW
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Use botan_pubkey_view_{der,pem,raw}")
BOTAN_FFI_EXPORT(2, 0) int botan_pubkey_export(botan_pubkey_t key, uint8_t out[], size_t* out_len, uint32_t flags);

/**
* View the public key's DER encoding
*/
BOTAN_FFI_EXPORT(3, 0) int botan_pubkey_view_der(botan_pubkey_t key, botan_view_ctx ctx, botan_view_bin_fn view);

/**
* View the public key's PEM encoding
*/
BOTAN_FFI_EXPORT(3, 0) int botan_pubkey_view_pem(botan_pubkey_t key, botan_view_ctx ctx, botan_view_str_fn view);

/**
* View the public key's raw encoding
*/
BOTAN_FFI_EXPORT(3, 6) int botan_pubkey_view_raw(botan_pubkey_t key, botan_view_ctx ctx, botan_view_bin_fn view);

/**
* Get the name of the algorithm this public key is for
* @param key the public key to query
* @param out output buffer
* @param out_len on input the length of out, on success the number of bytes written
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_pubkey_algo_name(botan_pubkey_t key, char out[], size_t* out_len);

/**
* Returns 0 if key is valid, negative if invalid key or some other error
*/
BOTAN_FFI_EXPORT(2, 0) int botan_pubkey_check_key(botan_pubkey_t key, botan_rng_t rng, uint32_t flags);

/**
* Estimate the strength of this key, in bits, against the best known attack
* @param key the public key to query
* @param estimate set to the estimated strength in bits
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_pubkey_estimated_strength(botan_pubkey_t key, size_t* estimate);

/**
* Compute a fingerprint (hash of the public key encoding)
* @param key the public key to fingerprint
* @param hash the name of the hash to use, eg "SHA-256"
* @param out output buffer
* @param out_len on input the size of out, on output the number of bytes written or required
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0)
int botan_pubkey_fingerprint(botan_pubkey_t key, const char* hash, uint8_t out[], size_t* out_len);

/**
* Frees all resources of the public key object
* @param key the public key to destroy
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 0) int botan_pubkey_destroy(botan_pubkey_t key);

/**
* Get an arbitrary named field from a public key, eg "n" or "e" for RSA
* @param output set to the value of the requested field
* @param key the public key to query
* @param field_name the name of the field to retrieve
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_pubkey_get_field(botan_mp_t output, botan_pubkey_t key, const char* field_name);

/**
* Get an arbitrary named field from a private key, eg "p" or "q" for RSA
* @param output set to the value of the requested field
* @param key the private key to query
* @param field_name the name of the field to retrieve
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_get_field(botan_mp_t output, botan_privkey_t key, const char* field_name);

/**
* Get the object identifier associated with a public key
* @param oid the new object will be placed here
* @param key the public key to query
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 8)
int botan_pubkey_oid(botan_asn1_oid_t* oid, botan_pubkey_t key);

/**
* Get the object identifier associated with a private key
* @param oid the new object will be placed here
* @param key the private key to query
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 8)
int botan_privkey_oid(botan_asn1_oid_t* oid, botan_privkey_t key);

/**
* Checks whether a key is stateful and sets
* @param key the private key to check
* @param out to 1 if it is, or 0 if the key is not stateful
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 8) int botan_privkey_stateful_operation(botan_privkey_t key, int* out);

/**
* Gets information on many operations a (stateful) key has remaining and sets
* @param key the private key to check
* @param out to that value
* @return 0 on success, a negative value on failure or if the key is not stateful
*/
BOTAN_FFI_EXPORT(3, 8) int botan_privkey_remaining_operations(botan_privkey_t key, uint64_t* out);

/*
* Algorithm specific key operations: RSA
*/

/**
* Load an RSA private key from its factors and public exponent
* @param key the new object will be placed here
* @param p the first prime factor
* @param q the second prime factor
* @param e the public exponent
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_load_rsa(botan_privkey_t* key, botan_mp_t p, botan_mp_t q, botan_mp_t e);

/**
* Load an RSA private key from a PKCS #1 RSAPrivateKey structure
* @param key the new object will be placed here
* @param bits the DER encoding to load
* @param len length of bits in bytes
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 8) int botan_privkey_load_rsa_pkcs1(botan_privkey_t* key, const uint8_t bits[], size_t len);

/**
* Get the first prime factor of an RSA private key
* @param p set to the value of the factor
* @param rsa_key the RSA private key
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Use botan_privkey_get_field")
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_rsa_get_p(botan_mp_t p, botan_privkey_t rsa_key);

/**
* Get the second prime factor of an RSA private key
* @param q set to the value of the factor
* @param rsa_key the RSA private key
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Use botan_privkey_get_field")
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_rsa_get_q(botan_mp_t q, botan_privkey_t rsa_key);

/**
* Get the private exponent of an RSA private key
* @param d set to the value of the private exponent
* @param rsa_key the RSA private key
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Use botan_privkey_get_field")
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_rsa_get_d(botan_mp_t d, botan_privkey_t rsa_key);

/**
* Get the modulus of an RSA private key
* @param n set to the value of the modulus
* @param rsa_key the RSA private key
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Use botan_privkey_get_field")
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_rsa_get_n(botan_mp_t n, botan_privkey_t rsa_key);

/**
* Get the public exponent of an RSA private key
* @param e set to the value of the public exponent
* @param rsa_key the RSA private key
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Use botan_privkey_get_field")
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_rsa_get_e(botan_mp_t e, botan_privkey_t rsa_key);

/**
* Export an RSA private key as a PKCS #1 RSAPrivateKey structure
* @param rsa_key the RSA private key
* @param out output buffer
* @param out_len on input the size of out, on output the number of bytes written or required
* @param flags either BOTAN_PRIVKEY_EXPORT_FLAG_DER or BOTAN_PRIVKEY_EXPORT_FLAG_PEM
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 8)
int botan_privkey_rsa_get_privkey(botan_privkey_t rsa_key, uint8_t out[], size_t* out_len, uint32_t flags);

/**
* Load an RSA public key from its modulus and public exponent
* @param key the new object will be placed here
* @param n the modulus
* @param e the public exponent
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_pubkey_load_rsa(botan_pubkey_t* key, botan_mp_t n, botan_mp_t e);

/**
* Load an RSA public key from a PKCS #1 RSAPublicKey structure
* @param key the new object will be placed here
* @param bits the DER encoding to load
* @param len length of bits in bytes
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 11) int botan_pubkey_load_rsa_pkcs1(botan_pubkey_t* key, const uint8_t bits[], size_t len);

/**
* Get the public exponent of an RSA public key
* @param e set to the value of the public exponent
* @param rsa_key the RSA public key
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Use botan_pubkey_get_field")
BOTAN_FFI_EXPORT(2, 0) int botan_pubkey_rsa_get_e(botan_mp_t e, botan_pubkey_t rsa_key);

/**
* Get the modulus of an RSA public key
* @param n set to the value of the modulus
* @param rsa_key the RSA public key
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Use botan_pubkey_get_field")
BOTAN_FFI_EXPORT(2, 0) int botan_pubkey_rsa_get_n(botan_mp_t n, botan_pubkey_t rsa_key);

/*
* Algorithm specific key operations: DSA
*/

/**
* Load a DSA private key from its group parameters and secret value
* @param key the new object will be placed here
* @param p the group prime
* @param q the order of the subgroup
* @param g the subgroup generator
* @param x the private key
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0)
int botan_privkey_load_dsa(botan_privkey_t* key, botan_mp_t p, botan_mp_t q, botan_mp_t g, botan_mp_t x);

/**
* Load a DSA public key from its group parameters and public value
* @param key the new object will be placed here
* @param p the group prime
* @param q the order of the subgroup
* @param g the subgroup generator
* @param y the public key
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0)
int botan_pubkey_load_dsa(botan_pubkey_t* key, botan_mp_t p, botan_mp_t q, botan_mp_t g, botan_mp_t y);

/**
* Get the secret value of a DSA private key
* @param n set to the value of the private key
* @param key the DSA private key
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Use botan_privkey_get_field")
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_dsa_get_x(botan_mp_t n, botan_privkey_t key);

/**
* Get the group prime of a DSA public key
* @param p set to the value of the group prime
* @param key the DSA public key
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Use botan_pubkey_get_field")
BOTAN_FFI_EXPORT(2, 0) int botan_pubkey_dsa_get_p(botan_mp_t p, botan_pubkey_t key);

/**
* Get the subgroup order of a DSA public key
* @param q set to the value of the subgroup order
* @param key the DSA public key
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Use botan_pubkey_get_field")
BOTAN_FFI_EXPORT(2, 0) int botan_pubkey_dsa_get_q(botan_mp_t q, botan_pubkey_t key);

/**
* Get the subgroup generator of a DSA public key
* @param d set to the value of the generator
* @param key the DSA public key
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Use botan_pubkey_get_field")
BOTAN_FFI_EXPORT(2, 0) int botan_pubkey_dsa_get_g(botan_mp_t d, botan_pubkey_t key);

/**
* Get the public value of a DSA public key
* @param y set to the value of the public key
* @param key the DSA public key
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Use botan_pubkey_get_field")
BOTAN_FFI_EXPORT(2, 0) int botan_pubkey_dsa_get_y(botan_mp_t y, botan_pubkey_t key);

/**
* Loads Diffie Hellman private key
*
* @param key variable populated with key material
* @param p prime order of a Z_p group
* @param g group generator
* @param x private key
*
* @pre key is NULL on input
* @post function allocates memory and assigns to `key'
*
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_load_dh(botan_privkey_t* key, botan_mp_t p, botan_mp_t g, botan_mp_t x);
/**
* Loads Diffie Hellman public key
*
* @param key variable populated with key material
* @param p prime order of a Z_p group
* @param g group generator
* @param y public key
*
* @pre key is NULL on input
* @post function allocates memory and assigns to `key'
*
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_pubkey_load_dh(botan_pubkey_t* key, botan_mp_t p, botan_mp_t g, botan_mp_t y);

/*
* Algorithm specific key operations: ElGamal
*/

/**
* Loads ElGamal public key
* @param key variable populated with key material
* @param p prime order of a Z_p group
* @param g group generator
* @param y public key
*
* @pre key is NULL on input
* @post function allocates memory and assigns to `key'
*
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_pubkey_load_elgamal(botan_pubkey_t* key, botan_mp_t p, botan_mp_t g, botan_mp_t y);

/**
* Loads ElGamal private key
*
* @param key variable populated with key material
* @param p prime order of a Z_p group
* @param g group generator
* @param x private key
*
* @pre key is NULL on input
* @post function allocates memory and assigns to `key'
*
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_load_elgamal(botan_privkey_t* key, botan_mp_t p, botan_mp_t g, botan_mp_t x);

/*
* Algorithm specific key operations: EC keys
*/

/**
* Get the secret scalar of an elliptic curve private key
* @param key the EC private key
* @param value the new object will be placed here
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 12) int botan_ec_privkey_get_private_key(botan_privkey_t key, botan_ec_scalar_t* value);

/**
* Get the group of an elliptic curve private key
* @param key the EC private key
* @param ec_group the new object will be placed here
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 12) int botan_ec_privkey_get_group(botan_privkey_t key, botan_ec_group_t* ec_group);

/**
* Get the group of an elliptic curve public key
* @param key the EC public key
* @param ec_group the new object will be placed here
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 12) int botan_ec_pubkey_get_group(botan_pubkey_t key, botan_ec_group_t* ec_group);

/*
* Algorithm specific key operations: Ed25519
*/

/**
* Load an Ed25519 private key from its raw 32 byte encoding
* @param key the new object will be placed here
* @param privkey the raw private key
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 2) int botan_privkey_load_ed25519(botan_privkey_t* key, const uint8_t privkey[32]);

/**
* Load an Ed25519 public key from its raw 32 byte encoding
* @param key the new object will be placed here
* @param pubkey the raw public key
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 2) int botan_pubkey_load_ed25519(botan_pubkey_t* key, const uint8_t pubkey[32]);

/**
* Get the raw encoding of an Ed25519 private key, followed by the public key
* @param key the Ed25519 private key
* @param output set to the 64 byte concatenation of the private and public keys
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Use botan_privkey_view_raw")
BOTAN_FFI_EXPORT(2, 2) int botan_privkey_ed25519_get_privkey(botan_privkey_t key, uint8_t output[64]);

/**
* Get the raw 32 byte encoding of an Ed25519 public key
* @param key the Ed25519 public key
* @param pubkey set to the raw public key
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Use botan_pubkey_view_raw")
BOTAN_FFI_EXPORT(2, 2) int botan_pubkey_ed25519_get_pubkey(botan_pubkey_t key, uint8_t pubkey[32]);

/*
* Algorithm specific key operations: Ed448
*/

/**
* Load an Ed448 private key from its raw 57 byte encoding
* @param key the new object will be placed here
* @param privkey the raw private key
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 4) int botan_privkey_load_ed448(botan_privkey_t* key, const uint8_t privkey[57]);

/**
* Load an Ed448 public key from its raw 57 byte encoding
* @param key the new object will be placed here
* @param pubkey the raw public key
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 4) int botan_pubkey_load_ed448(botan_pubkey_t* key, const uint8_t pubkey[57]);

/**
* Get the raw 57 byte encoding of an Ed448 private key
* @param key the Ed448 private key
* @param output set to the raw private key
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Use botan_privkey_view_raw")
BOTAN_FFI_EXPORT(3, 4) int botan_privkey_ed448_get_privkey(botan_privkey_t key, uint8_t output[57]);

/**
* Get the raw 57 byte encoding of an Ed448 public key
* @param key the Ed448 public key
* @param pubkey set to the raw public key
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Use botan_pubkey_view_raw")
BOTAN_FFI_EXPORT(3, 4) int botan_pubkey_ed448_get_pubkey(botan_pubkey_t key, uint8_t pubkey[57]);

/*
* Algorithm specific key operations: X25519
*/

/**
* Load an X25519 private key from its raw 32 byte encoding
* @param key the new object will be placed here
* @param privkey the raw private key
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 8) int botan_privkey_load_x25519(botan_privkey_t* key, const uint8_t privkey[32]);

/**
* Load an X25519 public key from its raw 32 byte encoding
* @param key the new object will be placed here
* @param pubkey the raw public key
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 8) int botan_pubkey_load_x25519(botan_pubkey_t* key, const uint8_t pubkey[32]);

/**
* Get the raw 32 byte encoding of an X25519 private key
* @param key the X25519 private key
* @param output set to the raw private key
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Use botan_privkey_view_raw")
BOTAN_FFI_EXPORT(2, 8) int botan_privkey_x25519_get_privkey(botan_privkey_t key, uint8_t output[32]);

/**
* Get the raw 32 byte encoding of an X25519 public key
* @param key the X25519 public key
* @param pubkey set to the raw public key
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Use botan_pubkey_view_raw")
BOTAN_FFI_EXPORT(2, 8) int botan_pubkey_x25519_get_pubkey(botan_pubkey_t key, uint8_t pubkey[32]);

/*
* Algorithm specific key operations: X448
*/

/**
* Load an X448 private key from its raw 56 byte encoding
* @param key the new object will be placed here
* @param privkey the raw private key
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 4) int botan_privkey_load_x448(botan_privkey_t* key, const uint8_t privkey[56]);

/**
* Load an X448 public key from its raw 56 byte encoding
* @param key the new object will be placed here
* @param pubkey the raw public key
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 4) int botan_pubkey_load_x448(botan_pubkey_t* key, const uint8_t pubkey[56]);

/**
* Get the raw 56 byte encoding of an X448 private key
* @param key the X448 private key
* @param output set to the raw private key
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Use botan_privkey_view_raw")
BOTAN_FFI_EXPORT(3, 4) int botan_privkey_x448_get_privkey(botan_privkey_t key, uint8_t output[56]);

/**
* Get the raw 56 byte encoding of an X448 public key
* @param key the X448 public key
* @param pubkey set to the raw public key
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Use botan_pubkey_view_raw")
BOTAN_FFI_EXPORT(3, 4) int botan_pubkey_x448_get_pubkey(botan_pubkey_t key, uint8_t pubkey[56]);

/*
* Algorithm specific key operations: ML-DSA
*/

/**
* Load an ML-DSA private key from its raw encoding
* @param key the new object will be placed here
* @param privkey the raw private key
* @param key_len length of privkey in bytes
* @param mldsa_mode the parameter set, eg "ML-DSA-6x5"
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 6)
int botan_privkey_load_ml_dsa(botan_privkey_t* key, const uint8_t privkey[], size_t key_len, const char* mldsa_mode);

/**
* Load an ML-DSA public key from its raw encoding
* @param key the new object will be placed here
* @param pubkey the raw public key
* @param key_len length of pubkey in bytes
* @param mldsa_mode the parameter set, eg "ML-DSA-6x5"
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 6)
int botan_pubkey_load_ml_dsa(botan_pubkey_t* key, const uint8_t pubkey[], size_t key_len, const char* mldsa_mode);

/*
* Algorithm specific key operations: Kyber R3
*
* Note that Kyber R3 support is somewhat deprecated and may be removed in a
* future major release. Using the final ML-KEM is highly recommended in any new
* system.
*/

/**
* Load a Kyber private key from its raw encoding. The parameter set is
* inferred from the key length.
* @param key the new object will be placed here
* @param privkey the raw private key
* @param key_len length of privkey in bytes
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Kyber R3 support is deprecated")
BOTAN_FFI_EXPORT(3, 1) int botan_privkey_load_kyber(botan_privkey_t* key, const uint8_t privkey[], size_t key_len);

/**
* Load a Kyber public key from its raw encoding. The parameter set is
* inferred from the key length.
* @param key the new object will be placed here
* @param pubkey the raw public key
* @param key_len length of pubkey in bytes
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Kyber R3 support is deprecated")
BOTAN_FFI_EXPORT(3, 1) int botan_pubkey_load_kyber(botan_pubkey_t* key, const uint8_t pubkey[], size_t key_len);

/**
* View the raw encoding of a Kyber private key
* @param key the Kyber private key
* @param ctx an application context passed to the view function
* @param view the view callback which receives the encoding
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Use generic botan_privkey_view_raw")
BOTAN_FFI_EXPORT(3, 1)
int botan_privkey_view_kyber_raw_key(botan_privkey_t key, botan_view_ctx ctx, botan_view_bin_fn view);

/**
* View the raw encoding of a Kyber public key
* @param key the Kyber public key
* @param ctx an application context passed to the view function
* @param view the view callback which receives the encoding
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Use generic botan_pubkey_view_raw")
BOTAN_FFI_EXPORT(3, 1)
int botan_pubkey_view_kyber_raw_key(botan_pubkey_t key, botan_view_ctx ctx, botan_view_bin_fn view);

/*
* Algorithm specific key operation: FrodoKEM
*/

/**
* Load a FrodoKEM private key from its raw encoding
* @param key the new object will be placed here
* @param privkey the raw private key
* @param key_len length of privkey in bytes
* @param frodo_mode the parameter set, eg "FrodoKEM-640-SHAKE"
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 6)
int botan_privkey_load_frodokem(botan_privkey_t* key, const uint8_t privkey[], size_t key_len, const char* frodo_mode);

/**
* Load a FrodoKEM public key from its raw encoding
* @param key the new object will be placed here
* @param pubkey the raw public key
* @param key_len length of pubkey in bytes
* @param frodo_mode the parameter set, eg "FrodoKEM-640-SHAKE"
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 6)
int botan_pubkey_load_frodokem(botan_pubkey_t* key, const uint8_t pubkey[], size_t key_len, const char* frodo_mode);

/*
* Algorithm specific key operation: Classic McEliece
*/

/**
* Load a Classic McEliece private key from its raw encoding
* @param key the new object will be placed here
* @param privkey the raw private key
* @param key_len length of privkey in bytes
* @param cmce_mode the parameter set, eg "348864"
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 6)
int botan_privkey_load_classic_mceliece(botan_privkey_t* key,
                                        const uint8_t privkey[],
                                        size_t key_len,
                                        const char* cmce_mode);

/**
* Load a Classic McEliece public key from its raw encoding
* @param key the new object will be placed here
* @param pubkey the raw public key
* @param key_len length of pubkey in bytes
* @param cmce_mode the parameter set, eg "348864"
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 6)
int botan_pubkey_load_classic_mceliece(botan_pubkey_t* key,
                                       const uint8_t pubkey[],
                                       size_t key_len,
                                       const char* cmce_mode);

/*
* Algorithm specific key operations: ML-KEM
*/

/**
* Load an ML-KEM private key from its raw encoding
* @param key the new object will be placed here
* @param privkey the raw private key
* @param key_len length of privkey in bytes
* @param mlkem_mode the parameter set, eg "ML-KEM-768"
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 6)
int botan_privkey_load_ml_kem(botan_privkey_t* key, const uint8_t privkey[], size_t key_len, const char* mlkem_mode);

/**
* Load an ML-KEM public key from its raw encoding
* @param key the new object will be placed here
* @param pubkey the raw public key
* @param key_len length of pubkey in bytes
* @param mlkem_mode the parameter set, eg "ML-KEM-768"
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 6)
int botan_pubkey_load_ml_kem(botan_pubkey_t* key, const uint8_t pubkey[], size_t key_len, const char* mlkem_mode);

/*
* Algorithm specific key operations: SLH-DSA
*/

/**
* Load an SLH-DSA private key from its raw encoding
* @param key the new object will be placed here
* @param privkey the raw private key
* @param key_len length of privkey in bytes
* @param slhdsa_mode the parameter set, eg "SLH-DSA-SHA2-128s"
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 6)
int botan_privkey_load_slh_dsa(botan_privkey_t* key, const uint8_t privkey[], size_t key_len, const char* slhdsa_mode);

/**
* Load an SLH-DSA public key from its raw encoding
* @param key the new object will be placed here
* @param pubkey the raw public key
* @param key_len length of pubkey in bytes
* @param slhdsa_mode the parameter set, eg "SLH-DSA-SHA2-128s"
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 6)
int botan_pubkey_load_slh_dsa(botan_pubkey_t* key, const uint8_t pubkey[], size_t key_len, const char* slhdsa_mode);

/*
* Algorithm specific key operations: ECDSA and ECDH
*/

/**
* Check if the group of this EC key was encoded using explicit curve parameters
* rather than a named curve OID
* @param key the EC public key to examine
* @return 1 if explicit encoding was used, 0 if not, negative on error
*/
BOTAN_FFI_EXPORT(3, 2)
int botan_pubkey_ecc_key_used_explicit_encoding(botan_pubkey_t key);

/**
* Load an ECDSA private key from its secret scalar
* @param key the new object will be placed here
* @param scalar the private scalar
* @param curve_name the name of the curve, eg "secp256r1"
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 2)
int botan_privkey_load_ecdsa(botan_privkey_t* key, botan_mp_t scalar, const char* curve_name);

/**
* Load an ECDSA public key from the affine coordinates of the public point
* @param key the new object will be placed here
* @param public_x the x coordinate of the public point
* @param public_y the y coordinate of the public point
* @param curve_name the name of the curve, eg "secp256r1"
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 2)
int botan_pubkey_load_ecdsa(botan_pubkey_t* key, botan_mp_t public_x, botan_mp_t public_y, const char* curve_name);

/**
* Load an ECDSA public key from the SEC1 encoding of the public point
* @param key the new object will be placed here
* @param sec1 the SEC1 compressed or uncompressed point encoding
* @param sec1_len length of sec1 in bytes
* @param curve_name the name of the curve, eg "secp256r1"
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 10)
int botan_pubkey_load_ecdsa_sec1(botan_pubkey_t* key, const uint8_t sec1[], size_t sec1_len, const char* curve_name);

/**
* Load an ECDH public key from the affine coordinates of the public point
* @param key the new object will be placed here
* @param public_x the x coordinate of the public point
* @param public_y the y coordinate of the public point
* @param curve_name the name of the curve, eg "secp256r1"
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 2)
int botan_pubkey_load_ecdh(botan_pubkey_t* key, botan_mp_t public_x, botan_mp_t public_y, const char* curve_name);

/**
* Load an ECDH public key from the SEC1 encoding of the public point
* @param key the new object will be placed here
* @param sec1 the SEC1 compressed or uncompressed point encoding
* @param sec1_len length of sec1 in bytes
* @param curve_name the name of the curve, eg "secp256r1"
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 10)
int botan_pubkey_load_ecdh_sec1(botan_pubkey_t* key, const uint8_t sec1[], size_t sec1_len, const char* curve_name);

/**
* Load an ECDH private key from its secret scalar
* @param key the new object will be placed here
* @param scalar the private scalar
* @param curve_name the name of the curve, eg "secp256r1"
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 2)
int botan_privkey_load_ecdh(botan_privkey_t* key, botan_mp_t scalar, const char* curve_name);

/**
* Load an SM2 public key from the affine coordinates of the public point
* @param key the new object will be placed here
* @param public_x the x coordinate of the public point
* @param public_y the y coordinate of the public point
* @param curve_name the name of the curve, typically "sm2p256v1"
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 2)
int botan_pubkey_load_sm2(botan_pubkey_t* key, botan_mp_t public_x, botan_mp_t public_y, const char* curve_name);

/**
* Load an SM2 public key from the SEC1 encoding of the public point
* @param key the new object will be placed here
* @param sec1 the SEC1 compressed or uncompressed point encoding
* @param sec1_len length of sec1 in bytes
* @param curve_name the name of the curve, typically "sm2p256v1"
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 10)
int botan_pubkey_load_sm2_sec1(botan_pubkey_t* key, const uint8_t sec1[], size_t sec1_len, const char* curve_name);

/**
* Load an SM2 private key from its secret scalar
* @param key the new object will be placed here
* @param scalar the private scalar
* @param curve_name the name of the curve, typically "sm2p256v1"
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 2)
int botan_privkey_load_sm2(botan_privkey_t* key, botan_mp_t scalar, const char* curve_name);

/**
* Load an SM2 encryption public key; identical to botan_pubkey_load_sm2
* @param key the new object will be placed here
* @param public_x the x coordinate of the public point
* @param public_y the y coordinate of the public point
* @param curve_name the name of the curve, typically "sm2p256v1"
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Use botan_pubkey_load_sm2")
BOTAN_FFI_EXPORT(2, 2)
int botan_pubkey_load_sm2_enc(botan_pubkey_t* key, botan_mp_t public_x, botan_mp_t public_y, const char* curve_name);

/**
* Load an SM2 encryption private key; identical to botan_privkey_load_sm2
* @param key the new object will be placed here
* @param scalar the private scalar
* @param curve_name the name of the curve, typically "sm2p256v1"
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_DEPRECATED("Use botan_privkey_load_sm2")
BOTAN_FFI_EXPORT(2, 2)
int botan_privkey_load_sm2_enc(botan_privkey_t* key, botan_mp_t scalar, const char* curve_name);

/**
* Compute the SM2 ZA value, the hash of the user identity and public key which
* is prefixed to the message before signing
* @param out output buffer
* @param out_len on input the size of out, on output the number of bytes written or required
* @param ident the user identifier
* @param hash_algo the hash to use, typically "SM3"
* @param key the SM2 public key
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 3)
int botan_pubkey_sm2_compute_za(
   uint8_t out[], size_t* out_len, const char* ident, const char* hash_algo, botan_pubkey_t key);

/**
* View the uncompressed public point associated with the key
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_pubkey_view_ec_public_point(botan_pubkey_t key, botan_view_ctx ctx, botan_view_bin_fn view);

/*
* Public Key Encryption
*/
/**
* Opaque type of a public key encryption operation
*/
typedef struct botan_pk_op_encrypt_struct* botan_pk_op_encrypt_t;

/**
* Create a public key encryption operation
* @param op the new object will be placed here
* @param key the public key to encrypt to
* @param padding the padding/encoding method, eg "OAEP(SHA-256)"
* @param flags should be 0 in current API revision
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0)
int botan_pk_op_encrypt_create(botan_pk_op_encrypt_t* op, botan_pubkey_t key, const char* padding, uint32_t flags);

/**
* Frees all resources of the encryption operation object
* @param op the operation to destroy
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 0) int botan_pk_op_encrypt_destroy(botan_pk_op_encrypt_t op);

/**
* Return the ciphertext length for a given plaintext length
* @param op the encryption operation
* @param ptext_len the plaintext length in bytes
* @param ctext_len set to the resulting ciphertext length in bytes
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 8)
int botan_pk_op_encrypt_output_length(botan_pk_op_encrypt_t op, size_t ptext_len, size_t* ctext_len);

/**
* Encrypt a message with a public key
* @param op the encryption operation
* @param rng a random number generator
* @param out output buffer
* @param out_len on input the size of out, on output the number of bytes written or required
* @param plaintext the message to encrypt
* @param plaintext_len length of plaintext in bytes
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0)
int botan_pk_op_encrypt(botan_pk_op_encrypt_t op,
                        botan_rng_t rng,
                        uint8_t out[],
                        size_t* out_len,
                        const uint8_t plaintext[],
                        size_t plaintext_len);

/**
* Opaque type of a public key decryption operation
*/
typedef struct botan_pk_op_decrypt_struct* botan_pk_op_decrypt_t;

/**
* Create a public key decryption operation
* @param op the new object will be placed here
* @param key the private key to decrypt with
* @param padding the padding/encoding method, eg "OAEP(SHA-256)"
* @param flags should be 0 in current API revision
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0)
int botan_pk_op_decrypt_create(botan_pk_op_decrypt_t* op, botan_privkey_t key, const char* padding, uint32_t flags);

/**
* Frees all resources of the decryption operation object
* @param op the operation to destroy
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 0) int botan_pk_op_decrypt_destroy(botan_pk_op_decrypt_t op);

/**
* Return an upper bound on the plaintext length for a given ciphertext length
* @param op the decryption operation
* @param ctext_len the ciphertext length in bytes
* @param ptext_len set to the maximum plaintext length in bytes
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 8)
int botan_pk_op_decrypt_output_length(botan_pk_op_decrypt_t op, size_t ctext_len, size_t* ptext_len);

/**
* Decrypt a message with a private key
* @param op the decryption operation
* @param out output buffer
* @param out_len on input the size of out, on output the number of bytes written or required
* @param ciphertext the message to decrypt
* @param ciphertext_len length of ciphertext in bytes
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0)
int botan_pk_op_decrypt(
   botan_pk_op_decrypt_t op, uint8_t out[], size_t* out_len, const uint8_t ciphertext[], size_t ciphertext_len);

/*
* Signature Generation
*/

#define BOTAN_PUBKEY_DER_FORMAT_SIGNATURE 1

/**
* Opaque type of a signature generation operation
*/
typedef struct botan_pk_op_sign_struct* botan_pk_op_sign_t;

/**
* Create a signature generation operation
* @param op the new object will be placed here
* @param key the private key to sign with
* @param hash_and_padding the signature padding and hash, eg "PSS(SHA-256)"
* @param flags 0, or BOTAN_PUBKEY_DER_FORMAT_SIGNATURE to request DER encoded signatures
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0)
int botan_pk_op_sign_create(botan_pk_op_sign_t* op, botan_privkey_t key, const char* hash_and_padding, uint32_t flags);

/**
* Frees all resources of the signature generation operation object
* @param op the operation to destroy
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 0) int botan_pk_op_sign_destroy(botan_pk_op_sign_t op);

/**
* Return the length of the signatures this operation produces
* @param op the signature operation
* @param olen set to the signature length in bytes
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 8) int botan_pk_op_sign_output_length(botan_pk_op_sign_t op, size_t* olen);

/**
* Add more data to the message being signed
* @param op the signature operation
* @param in input buffer
* @param in_len number of bytes to read from the input buffer
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_pk_op_sign_update(botan_pk_op_sign_t op, const uint8_t in[], size_t in_len);

/**
* Produce a signature over the message, then reset for signing another message
* @param op the signature operation
* @param rng a random number generator
* @param sig output buffer
* @param sig_len on input the size of sig, on output the number of bytes written or required
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0)
int botan_pk_op_sign_finish(botan_pk_op_sign_t op, botan_rng_t rng, uint8_t sig[], size_t* sig_len);

/**
* Opaque type of a signature verification operation
*/
typedef struct botan_pk_op_verify_struct* botan_pk_op_verify_t;

/**
* Create a signature verification operation
* @param op the new object will be placed here
* @param key the public key to verify with
* @param hash_and_padding the signature padding and hash, eg "PSS(SHA-256)"
* @param flags 0, or BOTAN_PUBKEY_DER_FORMAT_SIGNATURE if the signature is DER encoded
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0)
int botan_pk_op_verify_create(botan_pk_op_verify_t* op,
                              botan_pubkey_t key,
                              const char* hash_and_padding,
                              uint32_t flags);

/**
* Frees all resources of the signature verification operation object
* @param op the operation to destroy
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 0) int botan_pk_op_verify_destroy(botan_pk_op_verify_t op);

/**
* Add more data to the message being verified
* @param op the verification operation
* @param in input buffer
* @param in_len number of bytes to read from the input buffer
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_pk_op_verify_update(botan_pk_op_verify_t op, const uint8_t in[], size_t in_len);

/**
* Check the signature over the message, then reset for verifying another message
* @param op the verification operation
* @param sig the signature to check
* @param sig_len length of sig in bytes
* @return 0 if the signature is valid, BOTAN_FFI_INVALID_VERIFIER if it is not,
*         or some other negative value on error
*/
BOTAN_FFI_EXPORT(2, 0) int botan_pk_op_verify_finish(botan_pk_op_verify_t op, const uint8_t sig[], size_t sig_len);

/**
* Opaque type of a key agreement operation
*/
typedef struct botan_pk_op_ka_struct* botan_pk_op_ka_t;

/**
* Create a key agreement operation
* @param op the new object will be placed here
* @param key our private key
* @param kdf the KDF applied to the shared secret, or "Raw" for no KDF
* @param flags should be 0 in current API revision
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0)
int botan_pk_op_key_agreement_create(botan_pk_op_ka_t* op, botan_privkey_t key, const char* kdf, uint32_t flags);

/**
* Frees all resources of the key agreement operation object
* @param op the operation to destroy
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 0) int botan_pk_op_key_agreement_destroy(botan_pk_op_ka_t op);

/**
* Export the public value of a key agreement private key, in the format
* expected by botan_pk_op_key_agreement
* @param key the key agreement private key
* @param out output buffer
* @param out_len on input the size of out, on output the number of bytes written or required
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_pk_op_key_agreement_export_public(botan_privkey_t key, uint8_t out[], size_t* out_len);

/**
* View the public value of a key agreement private key
* @param key the key agreement private key
* @param ctx an application context passed to the view function
* @param view the view callback which receives the encoding
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_pk_op_key_agreement_view_public(botan_privkey_t key, botan_view_ctx ctx, botan_view_bin_fn view);

/**
* Return the length of the shared secret this operation produces
* @param op the key agreement operation
* @param out_len set to the output length in bytes
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 8) int botan_pk_op_key_agreement_size(botan_pk_op_ka_t op, size_t* out_len);

/**
* Perform key agreement with the counterparty's public value
* @param op the key agreement operation
* @param out output buffer
* @param out_len on input the size of out, on output the number of bytes written or required
* @param other_key the counterparty's public value
* @param other_key_len length of other_key in bytes
* @param salt a salt passed to the KDF, may be NULL if salt_len is 0
* @param salt_len length of salt in bytes
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0)
int botan_pk_op_key_agreement(botan_pk_op_ka_t op,
                              uint8_t out[],
                              size_t* out_len,
                              const uint8_t other_key[],
                              size_t other_key_len,
                              const uint8_t salt[],
                              size_t salt_len);

/**
* Opaque type of a key encapsulation (KEM encryption) operation
*/
typedef struct botan_pk_op_kem_encrypt_struct* botan_pk_op_kem_encrypt_t;

/**
* Create a key encapsulation operation
* @param op the new object will be placed here
* @param key the public key to encapsulate to
* @param kdf the KDF applied to the shared secret, or "Raw" for no KDF
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_pk_op_kem_encrypt_create(botan_pk_op_kem_encrypt_t* op, botan_pubkey_t key, const char* kdf);

/**
* Frees all resources of the key encapsulation operation object
* @param op the operation to destroy
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(3, 0) int botan_pk_op_kem_encrypt_destroy(botan_pk_op_kem_encrypt_t op);

/**
* Return the length of the shared key this operation will produce
* @param op the encapsulation operation
* @param desired_shared_key_length the requested shared key length in bytes
* @param output_shared_key_length set to the shared key length that will result
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_pk_op_kem_encrypt_shared_key_length(botan_pk_op_kem_encrypt_t op,
                                              size_t desired_shared_key_length,
                                              size_t* output_shared_key_length);

/**
* Return the length of the encapsulated key this operation produces
* @param op the encapsulation operation
* @param output_encapsulated_key_length set to the encapsulated key length in bytes
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_pk_op_kem_encrypt_encapsulated_key_length(botan_pk_op_kem_encrypt_t op,
                                                    size_t* output_encapsulated_key_length);

/**
* Generate a shared key along with the encapsulation of it for the counterparty
* @param op the encapsulation operation
* @param rng a random number generator
* @param salt a salt passed to the KDF, may be NULL if salt_len is 0
* @param salt_len length of salt in bytes
* @param desired_shared_key_len the requested shared key length in bytes
* @param shared_key output buffer for the shared key
* @param shared_key_len on input the size of shared_key, on output the number of bytes written
* @param encapsulated_key output buffer for the encapsulated key
* @param encapsulated_key_len on input the size of encapsulated_key, on output the number of bytes written
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_pk_op_kem_encrypt_create_shared_key(botan_pk_op_kem_encrypt_t op,
                                              botan_rng_t rng,
                                              const uint8_t salt[],
                                              size_t salt_len,
                                              size_t desired_shared_key_len,
                                              uint8_t shared_key[],
                                              size_t* shared_key_len,
                                              uint8_t encapsulated_key[],
                                              size_t* encapsulated_key_len);

/**
* Opaque type of a key decapsulation (KEM decryption) operation
*/
typedef struct botan_pk_op_kem_decrypt_struct* botan_pk_op_kem_decrypt_t;

/**
* Create a key decapsulation operation
* @param op the new object will be placed here
* @param key the private key to decapsulate with
* @param kdf the KDF applied to the shared secret, or "Raw" for no KDF
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_pk_op_kem_decrypt_create(botan_pk_op_kem_decrypt_t* op, botan_privkey_t key, const char* kdf);

/**
* Frees all resources of the key decapsulation operation object
* @param op the operation to destroy
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(3, 0) int botan_pk_op_kem_decrypt_destroy(botan_pk_op_kem_decrypt_t op);

/**
* Return the length of the shared key this operation will produce
* @param op the decapsulation operation
* @param desired_shared_key_length the requested shared key length in bytes
* @param output_shared_key_length set to the shared key length that will result
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_pk_op_kem_decrypt_shared_key_length(botan_pk_op_kem_decrypt_t op,
                                              size_t desired_shared_key_length,
                                              size_t* output_shared_key_length);

/**
* Recover the shared key from an encapsulated key
* @param op the decapsulation operation
* @param salt a salt passed to the KDF, may be NULL if salt_len is 0
* @param salt_len length of salt in bytes
* @param encapsulated_key the encapsulated key from the counterparty
* @param encapsulated_key_len length of encapsulated_key in bytes
* @param desired_shared_key_len the requested shared key length in bytes
* @param shared_key output buffer for the shared key
* @param shared_key_len on input the size of shared_key, on output the number of bytes written
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_pk_op_kem_decrypt_shared_key(botan_pk_op_kem_decrypt_t op,
                                       const uint8_t salt[],
                                       size_t salt_len,
                                       const uint8_t encapsulated_key[],
                                       size_t encapsulated_key_len,
                                       size_t desired_shared_key_len,
                                       uint8_t shared_key[],
                                       size_t* shared_key_len);

/**
* Signature Scheme Utility Functions
*/

BOTAN_FFI_EXPORT(2, 0) int botan_pkcs_hash_id(const char* hash_name, uint8_t pkcs_id[], size_t* pkcs_id_len);

/**
* Formerly encrypted a message using McEliece with an AEAD.
*
* Always returns BOTAN_FFI_ERROR_NOT_IMPLEMENTED
*
* @param mce_key ignored
* @param rng ignored
* @param aead ignored
* @param pt ignored
* @param pt_len ignored
* @param ad ignored
* @param ad_len ignored
* @param ct ignored
* @param ct_len ignored
* @return BOTAN_FFI_ERROR_NOT_IMPLEMENTED
*/
BOTAN_FFI_DEPRECATED("No longer implemented")
BOTAN_FFI_EXPORT(2, 0)
int botan_mceies_encrypt(botan_pubkey_t mce_key,
                         botan_rng_t rng,
                         const char* aead,
                         const uint8_t pt[],
                         size_t pt_len,
                         const uint8_t ad[],
                         size_t ad_len,
                         uint8_t ct[],
                         size_t* ct_len);

/**
* Formerly decrypted a message using McEliece with an AEAD.
*
* Always returns BOTAN_FFI_ERROR_NOT_IMPLEMENTED
*
* @param mce_key ignored
* @param aead ignored
* @param ct ignored
* @param ct_len ignored
* @param ad ignored
* @param ad_len ignored
* @param pt ignored
* @param pt_len ignored
* @return BOTAN_FFI_ERROR_NOT_IMPLEMENTED
*/
BOTAN_FFI_DEPRECATED("No longer implemented")
BOTAN_FFI_EXPORT(2, 0)
int botan_mceies_decrypt(botan_privkey_t mce_key,
                         const char* aead,
                         const uint8_t ct[],
                         size_t ct_len,
                         const uint8_t ad[],
                         size_t ad_len,
                         uint8_t pt[],
                         size_t* pt_len);

/*
* X.509 certificates
**************************/

/**
* Opaque type of an X.509 certificate
*/
typedef struct botan_x509_cert_struct* botan_x509_cert_t;

/**
 * Generic values that may be retrieved from X.509 certificates or CRLs via
 * the generic getter functions.
 *
 * When extending this list the existing entries must stay backward-compatible
 * to remain ABI compatible across versions. Therefore, new values must be added
 * to the end of this list.
 *
 * See:
 *   * botan_x509_cert_view_binary_values()
 *   * botan_x509_crl_view_binary_values()
 *   * botan_x509_cert_view_string_values()
 */
typedef enum /* NOLINT(*-enum-size,*-use-enum-class) */ {
   BOTAN_X509_SERIAL_NUMBER = 0,            /** singleton binary big-endian encoding */
   BOTAN_X509_SUBJECT_DN_BITS = 1,          /** singleton binary DER encoding of the subject distinguished name */
   BOTAN_X509_ISSUER_DN_BITS = 2,           /** singleton binary DER encoding of the issuer distinguished name */
   BOTAN_X509_SUBJECT_KEY_IDENTIFIER = 3,   /** singleton binary encoding */
   BOTAN_X509_AUTHORITY_KEY_IDENTIFIER = 4, /** singleton binary encoding */

   BOTAN_X509_PUBLIC_KEY_PKCS8_BITS = 200, /** singleton binary DER encoding of the PKCS#8 public key */
   BOTAN_X509_TBS_DATA_BITS = 201,         /** singleton binary DER encoding */
   BOTAN_X509_SIGNATURE_SCHEME_BITS = 202, /** singleton binary DER encoding of the algorithm identifier */
   BOTAN_X509_SIGNATURE_BITS = 203,        /** singleton binary signature bits */

   BOTAN_X509_DER_ENCODING = 300, /** singleton binary DER encoding of the whole object */
   BOTAN_X509_PEM_ENCODING = 301, /** singleton string value PEM encoding of the whole object */

   BOTAN_X509_CRL_DISTRIBUTION_URLS = 400, /** multi-value string of the CRL distribution points */
   BOTAN_X509_OCSP_RESPONDER_URLS = 401,   /** multi-value string of the OCSP responder URLs */
   BOTAN_X509_CA_ISSUERS_URLS = 402,       /** multi-value string of the CA issuer URLs */
} botan_x509_value_type;

/**
* Load a certificate from a DER or PEM encoding
* @param cert_obj the new object will be placed here
* @param cert the encoding to load
* @param cert_len length of cert in bytes
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_x509_cert_load(botan_x509_cert_t* cert_obj, const uint8_t cert[], size_t cert_len);

/**
* Load a certificate from a file containing a DER or PEM encoding
* @param cert_obj the new object will be placed here
* @param filename path of the file to read
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_x509_cert_load_file(botan_x509_cert_t* cert_obj, const char* filename);

/**
* Frees all resources of the certificate object
* @param cert the certificate to destroy
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 0) int botan_x509_cert_destroy(botan_x509_cert_t cert);

/**
* Create a new handle referring to the same certificate
* @param new_cert the new object will be placed here
* @param cert the certificate to duplicate
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 8) int botan_x509_cert_dup(botan_x509_cert_t* new_cert, botan_x509_cert_t cert);

/**
 * Retrieve a specific binary value from an X.509 certificate.
 *
 * For multi-values @p index allows enumerating the available entries, until
 * BOTAN_FFI_ERROR_OUT_OF_RANGE is returned. For singleton values, an @p index
 * of value "0" is expected.
 *
 * @returns BOTAN_FFI_ERROR_NO_VALUE if the provided @p cert does not provide
 *          the requested @p value_type at all or not in binary format.
 */
BOTAN_FFI_EXPORT(3, 11)
int botan_x509_cert_view_binary_values(
   botan_x509_cert_t cert, botan_x509_value_type value_type, size_t index, botan_view_ctx ctx, botan_view_bin_fn view);

/**
 * Count the binary values of the given type available in an X.509 certificate.
 *
 * @param cert the certificate to inspect
 * @param value_type the value type to count
 * @param count set to the number of available entries
 * @returns 0 on success, a negative value on failure
 */
BOTAN_FFI_EXPORT(3, 11)
int botan_x509_cert_view_binary_values_count(botan_x509_cert_t cert, botan_x509_value_type value_type, size_t* count);

/**
 * Retrieve a specific string value from an X.509 certificate.
 *
 * For multi-values @p index allows enumerating the available entries, until
 * BOTAN_FFI_ERROR_OUT_OF_RANGE is returned. For singleton values, an @p index
 * of value "0" is expected.
 *
 * @returns BOTAN_FFI_ERROR_NO_VALUE if the provided @p cert does not provide
 *          the requested @p value_type at all or not in string format.
 */
BOTAN_FFI_EXPORT(3, 11)
int botan_x509_cert_view_string_values(
   botan_x509_cert_t cert, botan_x509_value_type value_type, size_t index, botan_view_ctx ctx, botan_view_str_fn view);

/**
 * Count the string values of the given type available in an X.509 certificate.
 *
 * @param cert the certificate to inspect
 * @param value_type the value type to count
 * @param count set to the number of available entries
 * @returns 0 on success, a negative value on failure
 */
BOTAN_FFI_EXPORT(3, 11)
int botan_x509_cert_view_string_values_count(botan_x509_cert_t cert, botan_x509_value_type value_type, size_t* count);

/**
* Get the start of the validity period as a string
*
* Prefer botan_x509_cert_not_before
*
* @param cert the certificate to inspect
* @param out output buffer
* @param out_len on input the size of out, on output the number of bytes written or required
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_x509_cert_get_time_starts(botan_x509_cert_t cert, char out[], size_t* out_len);

/**
* Get the end of the validity period as a string
*
* Prefer botan_x509_cert_not_after
*
* @param cert the certificate to inspect
* @param out output buffer
* @param out_len on input the size of out, on output the number of bytes written or required
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_x509_cert_get_time_expires(botan_x509_cert_t cert, char out[], size_t* out_len);

/**
* Get the start of the validity period as seconds since the Unix epoch
* @param cert the certificate to inspect
* @param time_since_epoch set to the notBefore time
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 8) int botan_x509_cert_not_before(botan_x509_cert_t cert, uint64_t* time_since_epoch);

/**
* Get the end of the validity period as seconds since the Unix epoch
* @param cert the certificate to inspect
* @param time_since_epoch set to the notAfter time
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 8) int botan_x509_cert_not_after(botan_x509_cert_t cert, uint64_t* time_since_epoch);

/**
* Compute the fingerprint of the certificate, formatted as a hex string with
* colons between the bytes
*
* @param cert the certificate to inspect
* @param hash the name of the hash to use, eg "SHA-256"
* @param out output buffer
* @param out_len on input the size of out, on output the number of bytes written or required
* @return 0 on success, a negative value on failure
*
* TODO(Botan4) this should use char for the out param
*/
BOTAN_FFI_EXPORT(2, 0)
int botan_x509_cert_get_fingerprint(botan_x509_cert_t cert, const char* hash, uint8_t out[], size_t* out_len);

/**
* Get the serial number of the certificate as a big-endian binary string
* @param cert the certificate to inspect
* @param out output buffer
* @param out_len on input the size of out, on output the number of bytes written or required
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_x509_cert_get_serial_number(botan_x509_cert_t cert, uint8_t out[], size_t* out_len);

/**
* Get the serial number of the certificate as an integer
* @param cert the certificate to inspect
* @param serial_number the new object will be placed here
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 11) int botan_x509_cert_serial_number(botan_x509_cert_t cert, botan_mp_t* serial_number);

/**
* Get the key identifier from the authority key identifier extension
* @param cert the certificate to inspect
* @param out output buffer
* @param out_len on input the size of out, on output the number of bytes written or required
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_x509_cert_get_authority_key_id(botan_x509_cert_t cert, uint8_t out[], size_t* out_len);

/**
* Get the subject key identifier extension
* @param cert the certificate to inspect
* @param out output buffer
* @param out_len on input the size of out, on output the number of bytes written or required
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_x509_cert_get_subject_key_id(botan_x509_cert_t cert, uint8_t out[], size_t* out_len);

/**
* Get the DER encoded SubjectPublicKeyInfo of the certificate
* @param cert the certificate to inspect
* @param out output buffer
* @param out_len on input the size of out, on output the number of bytes written or required
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_x509_cert_get_public_key_bits(botan_x509_cert_t cert, uint8_t out[], size_t* out_len);

/**
* View the DER encoded SubjectPublicKeyInfo of the certificate
* @param cert the certificate to inspect
* @param ctx an application context passed to the view function
* @param view the view callback which receives the encoding
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_x509_cert_view_public_key_bits(botan_x509_cert_t cert, botan_view_ctx ctx, botan_view_bin_fn view);

/**
* Get the public key of the certificate
* @param cert the certificate to inspect
* @param key the new object will be placed here
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_x509_cert_get_public_key(botan_x509_cert_t cert, botan_pubkey_t* key);

/**
 * Returns 1 iff the cert is a CA certificate
 */
BOTAN_FFI_EXPORT(3, 11) int botan_x509_cert_is_ca(botan_x509_cert_t cert);

/**
 * Retrieves the path length constraint from the certificate.
 * If no such constraint is present, BOTAN_FFI_ERROR_NO_VALUE is returned.
 */
BOTAN_FFI_EXPORT(3, 11) int botan_x509_cert_get_path_length_constraint(botan_x509_cert_t cert, size_t* path_limit);

/**
 * Enumerates the names of the given @p key in the issuer DN. If @p index is
 * out of bounds, BOTAN_FFI_ERROR_BAD_PARAMETER is returned.
 *
 * TODO(Botan4) use BOTAN_FFI_ERROR_OUT_OF_RANGE instead of BAD_PARAMETER
 * TODO(Botan4) this should use char for the out param
 */
BOTAN_FFI_EXPORT(2, 0)
int botan_x509_cert_get_issuer_dn(
   botan_x509_cert_t cert, const char* key, size_t index, uint8_t out[], size_t* out_len);
/**
 * Count the names of the given @p key present in the issuer DN.
 *
 * @param cert the certificate to inspect
 * @param key the DN component to count, eg "Name"
 * @param count set to the number of available entries
 * @return 0 on success, a negative value on failure
 */
BOTAN_FFI_EXPORT(3, 11) int botan_x509_cert_get_issuer_dn_count(botan_x509_cert_t cert, const char* key, size_t* count);

/**
 * Enumerates the names of the given @p key in the subject DN. If @p index is
 * out of bounds, BOTAN_FFI_ERROR_BAD_PARAMETER is returned.
 *
 * TODO(Botan4) use BOTAN_FFI_ERROR_OUT_OF_RANGE instead of BAD_PARAMETER
 * TODO(Botan4) this should use char for the out param
 */
BOTAN_FFI_EXPORT(2, 0)
int botan_x509_cert_get_subject_dn(
   botan_x509_cert_t cert, const char* key, size_t index, uint8_t out[], size_t* out_len);
/**
 * Count the names of the given @p key present in the subject DN.
 *
 * @param cert the certificate to inspect
 * @param key the DN component to count, eg "Name"
 * @param count set to the number of available entries
 * @return 0 on success, a negative value on failure
 */
BOTAN_FFI_EXPORT(3, 11)
int botan_x509_cert_get_subject_dn_count(botan_x509_cert_t cert, const char* key, size_t* count);

/**
* Format the certificate as a human readable string
* @param cert the certificate to format
* @param out output buffer
* @param out_len on input the size of out, on output the number of bytes written or required
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_x509_cert_to_string(botan_x509_cert_t cert, char out[], size_t* out_len);

/**
* View the certificate formatted as a human readable string
* @param cert the certificate to format
* @param ctx an application context passed to the view function
* @param view the view callback which receives the string
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_x509_cert_view_as_string(botan_x509_cert_t cert, botan_view_ctx ctx, botan_view_str_fn view);

/**
* Key usage constraints from the key usage extension
*
* Must match values of Key_Constraints in pkix_enums.h
*/
enum botan_x509_cert_key_constraints /* NOLINT(*-enum-size,*-use-enum-class) */ {
   NO_CONSTRAINTS = 0,
   DIGITAL_SIGNATURE = 32768,
   NON_REPUDIATION = 16384,
   KEY_ENCIPHERMENT = 8192,
   DATA_ENCIPHERMENT = 4096,
   KEY_AGREEMENT = 2048,
   KEY_CERT_SIGN = 1024,
   CRL_SIGN = 512,
   ENCIPHER_ONLY = 256,
   DECIPHER_ONLY = 128
};

/**
* Check if the certificate allows the specified key usage. If no key usage
* extension is found in the certificate, this always returns success.
* @param cert the certificate to inspect
* @param key_usage one or more values from botan_x509_cert_key_constraints, ORed together
* @return 0 if the usage is allowed, 1 if it is not, negative on error
*/
BOTAN_FFI_EXPORT(2, 0) int botan_x509_cert_allowed_usage(botan_x509_cert_t cert, unsigned int key_usage);

/**
* Check if the certificate allows the specified extended usage OID. See RFC 5280
* Section 4.2.1.12 for OIDs to query for this. If no extended key usage
* extension is found in the certificate, this always returns "not success".
*
* Typical OIDs to check for:
*   * "PKIX.ServerAuth"
*   * "PKIX.ClientAuth"
*   * "PKIX.CodeSigning"
*   * "PKIX.OCSPSigning"
*
* The @p oid parameter can be either a canonical OID string or identifiers as
* indicated in the examples above.
*/
BOTAN_FFI_EXPORT(3, 11) int botan_x509_cert_allowed_extended_usage_str(botan_x509_cert_t cert, const char* oid);

/**
* Check if the certificate allows the specified extended usage OID. See RFC 5280
* Section 4.2.1.12 for OIDs to query for this. If no extended key usage
* extension is found in the certificate, this always returns "not success".
*
* This is similar to botan_x509_cert_allowed_extended_usage_str but takes an OID
* object instead of a string describing the OID.
*/
BOTAN_FFI_EXPORT(3, 11) int botan_x509_cert_allowed_extended_usage_oid(botan_x509_cert_t cert, botan_asn1_oid_t oid);

/**
* Opaque type of an X.509 GeneralName value
*/
typedef struct botan_x509_general_name_struct* botan_x509_general_name_t;

/**
* GeneralName type identifiers as defined in RFC 5280 A.2 (GeneralName ::= CHOICE)
* Type identifiers that are omitted here are (currently) not supported. Also,
* there is currently no way to access OTHER_NAME values via the FFI.
*/
enum botan_x509_general_name_types /* NOLINT(*-enum-size,*-use-enum-class) */ {
   BOTAN_X509_OTHER_NAME = 0,
   BOTAN_X509_EMAIL_ADDRESS = 1,
   BOTAN_X509_DNS_NAME = 2,
   BOTAN_X509_DIRECTORY_NAME = 4,
   BOTAN_X509_URI = 6,
   BOTAN_X509_IP_ADDRESS = 7,
};

/**
* Provides the contained type of the @p name and returns BOTAN_FFI_SUCCESS if
* that type is supported and may be retrieved via the view functions below.
* Otherwise BOTAN_FFI_ERROR_INVALID_OBJECT_STATE is returned.
*/
BOTAN_FFI_EXPORT(3, 11) int botan_x509_general_name_get_type(botan_x509_general_name_t name, unsigned int* type);

/**
* Views the name as a string or returns BOTAN_FFI_ERROR_INVALID_OBJECT_STATE
* if the contained GeneralName value cannot be represented as a string.
*
* The types BOTAN_X509_EMAIL_ADDRESS, BOTAN_X509_DNS_NAME, BOTAN_X509_URI,
* BOTAN_X509_IP_ADDRESS may be viewed as "string".
*/
BOTAN_FFI_EXPORT(3, 11)
int botan_x509_general_name_view_string_value(botan_x509_general_name_t name,
                                              botan_view_ctx ctx,
                                              botan_view_str_fn view);

/**
* Views the name as a bit string or returns BOTAN_FFI_ERROR_INVALID_OBJECT_STATE
* if the contained GeneralName value cannot be represented as a binary string.
*
* The types BOTAN_X509_DIRECTORY_NAME, BOTAN_X509_IP_ADDRESS may be viewed as
* "binary".
*/
BOTAN_FFI_EXPORT(3, 11)
int botan_x509_general_name_view_binary_value(botan_x509_general_name_t name,
                                              botan_view_ctx ctx,
                                              botan_view_bin_fn view);

/**
* Frees all resources of the GeneralName object
* @param alt_names the GeneralName to destroy
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(3, 11) int botan_x509_general_name_destroy(botan_x509_general_name_t alt_names);

/**
* Extracts "permitted" name constraints from a given @p cert one-by-one.
* Returns BOTAN_FFI_ERROR_OUT_OF_RANGE if the given @p index is larger than the
* available number of "permitted" name constraints.
*/
BOTAN_FFI_EXPORT(3, 11)
int botan_x509_cert_permitted_name_constraints(botan_x509_cert_t cert,
                                               size_t index,
                                               botan_x509_general_name_t* constraint);
/**
* Count the "permitted" name constraints of a given @p cert.
* @param cert the certificate to inspect
* @param count set to the number of available entries
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 11) int botan_x509_cert_permitted_name_constraints_count(botan_x509_cert_t cert, size_t* count);

/**
* Extracts "excluded" name constraints from a given @p cert one-by-one.
* Returns BOTAN_FFI_ERROR_OUT_OF_RANGE if the given @p index is larger than the
* available number of "excluded" name constraints.
*/
BOTAN_FFI_EXPORT(3, 11)
int botan_x509_cert_excluded_name_constraints(botan_x509_cert_t cert,
                                              size_t index,
                                              botan_x509_general_name_t* constraint);
/**
* Count the "excluded" name constraints of a given @p cert.
* @param cert the certificate to inspect
* @param count set to the number of available entries
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 11) int botan_x509_cert_excluded_name_constraints_count(botan_x509_cert_t cert, size_t* count);

/**
* Provides access to all "subject alternative names", where each entry is
* returned as a botan_x509_general_name_t. If the given @p index is not
* within range of the available entries, BOTAN_FFI_ERROR_OUT_OF_RANGE is
* returned. If @p cert does not contain a SubjectAlternativeNames extension,
* BOTAN_FFI_ERROR_NO_VALUE is returned.
*/
BOTAN_FFI_EXPORT(3, 11)
int botan_x509_cert_subject_alternative_names(botan_x509_cert_t cert,
                                              size_t index,
                                              botan_x509_general_name_t* alt_name);
/**
* Count the "subject alternative names" of a given @p cert.
* @param cert the certificate to inspect
* @param count set to the number of available entries
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 11) int botan_x509_cert_subject_alternative_names_count(botan_x509_cert_t cert, size_t* count);

/**
* Provides access to all "issuer alternative names", where each entry is
* returned as a botan_x509_general_name_t. If the given @p index is not
* within range of the available entries, BOTAN_FFI_ERROR_OUT_OF_RANGE is
* returned. If @p cert does not contain an IssuerAlternativeNames extension,
* BOTAN_FFI_ERROR_NO_VALUE is returned.
*/
BOTAN_FFI_EXPORT(3, 11)
int botan_x509_cert_issuer_alternative_names(botan_x509_cert_t cert, size_t index, botan_x509_general_name_t* alt_name);
/**
* Count the "issuer alternative names" of a given @p cert.
* @param cert the certificate to inspect
* @param count set to the number of available entries
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 11) int botan_x509_cert_issuer_alternative_names_count(botan_x509_cert_t cert, size_t* count);

/**
* Check if the certificate matches the specified hostname via alternative name or CN match.
* RFC 5280 wildcards also supported.
*/
BOTAN_FFI_EXPORT(2, 5) int botan_x509_cert_hostname_match(botan_x509_cert_t cert, const char* hostname);

/**
* Returns 0 if the validation was successful, 1 if validation failed,
* and negative on error. A status code with details is written to
* *validation_result
*
* Intermediates or trusted lists can be null
* Trusted path can be null
*/
BOTAN_FFI_EXPORT(2, 8)
int botan_x509_cert_verify(int* validation_result,
                           botan_x509_cert_t cert,
                           const botan_x509_cert_t* intermediates,
                           size_t intermediates_len,
                           const botan_x509_cert_t* trusted,
                           size_t trusted_len,
                           const char* trusted_path,
                           size_t required_strength,
                           const char* hostname,
                           uint64_t reference_time);

/**
* Returns a pointer to a static character string explaining the status code,
* or else NULL if unknown.
*/
BOTAN_FFI_EXPORT(2, 8) const char* botan_x509_cert_validation_status(int code);

/*
* X.509 Extensions
*/

/**
* Get info about the IP Address Blocks extension from RFC 3779
* @param cert the certificate to inspect
* @param v4_count is set to the number of v4 families contained in the extension
* @param v6_count is set to the number of v6 families
* @returns 0 on success, negative number on error
*
* If the extension is not present or an error occurs, `v4_count` and `v6_count` are not modified
*/
BOTAN_FFI_EXPORT(3, 13)
int botan_x509_ext_ip_addr_blocks_get_counts(botan_x509_cert_t cert, size_t* v4_count, size_t* v6_count);

/**
* Get info about a specific family in the IP Address Blocks extension from RFC 3779
* @param cert the certificate to inspect
* @param ipv6 must be set to 1 if the family is an IPv6 family, 0 for IPv4 families
* @param i is the (local) index for this family kind (the first v4 family is at i = 0, ipv6 = 0; the first v6 family is at i = 0, ipv6 = 1)
* @param has_safi will be set to 1 if the family has an associated SAFI
* @param safi will be set to the families' SAFI, if it has one, otherwise `safi` is not modified
* @param present is set to 1 if the family contains values (ranges), 0 if it is marked as "inherit"
* @param count is set to the number of values (ranges), if they were present, otherwise `count` is not modified
* @returns 0 on success, negative number on error
*
* The output parameters `has_safi`, `safi`, `present` and `count` may be modified even if the extension is not present or some other error occurs.
* In this event, the value of each output parameter after the call returns is undefined.
*/
BOTAN_FFI_EXPORT(3, 13)
int botan_x509_ext_ip_addr_blocks_get_family(
   botan_x509_cert_t cert, int ipv6, size_t i, int* has_safi, uint8_t* safi, int* present, size_t* count);

/**
* Get info about a specific range in the IP Address Blocks extension from RFC 3779
* @param cert the certificate to inspect
* @param ipv6 must be set to 1 if the family is an IPv6 family, 0 for IPv4 families
* @param i is the (local) index of the family, see `botan_x509_ext_ip_addr_blocks_get_family`
* @param entry is the index of the range
* @param min_out is set to the lower address of the range
* @param max_out is set to the upper address of the range
* @param out_len is set to the length of the addresses (4 for IPv4, 16 for IPv6)
* @returns 0 on success, negative number on error
*
* The output parameters `min_out`, `max_out` and `out_len` may be modified even if the extension is not present or some other error occurs.
* In this event, the value of each output parameter after the call returns is undefined.
*/
BOTAN_FFI_EXPORT(3, 13)
int botan_x509_ext_ip_addr_blocks_get_address(
   botan_x509_cert_t cert, int ipv6, size_t i, size_t entry, uint8_t min_out[], uint8_t max_out[], size_t* out_len);

/**
* Get basic info about the AS Blocks extension from RFC 3779
* @param cert the certificate to inspect
* @param asnum must be set to 1 to get info about AS numbers, 0 for RDIs (the type)
* @param present is set to 1 if the extension contains entries for the type, 0 if it is marked as "inherit"
* @param count is set to number of entries for this type, if it was present, otherwise `count` is not modified
* @returns 0 on success, negative number on error
*
* If the extension is not present or an error occurs, `present` and `count` are not modified
*/
BOTAN_FFI_EXPORT(3, 13)
int botan_x509_ext_as_blocks_get_info(botan_x509_cert_t cert, int asnum, int* present, size_t* count);

/**
* Get a specific entry in the AS Blocks extension from RFC 3779
* @param cert the certificate to inspect
* @param asnum Set to 1 to get info about AS numbers, 0 for RDIs (the type)
* @param i The index of the entry to get
* @param min is set to the min value of the range
* @param max is set to the max value of the range
* @returns 0 on success, negative number on error
*
* If the extension is not present or an error occurs, `min` and `max` are not modified
*/
BOTAN_FFI_EXPORT(3, 13)
int botan_x509_ext_as_blocks_get_entry_at(botan_x509_cert_t cert, int asnum, size_t i, uint32_t* min, uint32_t* max);

/*
* X.509 CRL
**************************/

/**
* Opaque type of an X.509 certificate revocation list
*/
typedef struct botan_x509_crl_struct* botan_x509_crl_t;

/**
* Opaque type of a single entry within an X.509 certificate revocation list
*/
typedef struct botan_x509_crl_entry_struct* botan_x509_crl_entry_t;

/**
* Load a CRL from a file containing a DER or PEM encoding
* @param crl_obj the new object will be placed here
* @param crl_path path of the file to read
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 13) int botan_x509_crl_load_file(botan_x509_crl_t* crl_obj, const char* crl_path);

/**
* Load a CRL from a DER or PEM encoding
* @param crl_obj the new object will be placed here
* @param crl_bits the encoding to load
* @param crl_bits_len length of crl_bits in bytes
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 13)
int botan_x509_crl_load(botan_x509_crl_t* crl_obj, const uint8_t crl_bits[], size_t crl_bits_len);

/**
* Get the thisUpdate field of the CRL as seconds since the Unix epoch
* @param crl the CRL to inspect
* @param time_since_epoch set to the thisUpdate time
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 11) int botan_x509_crl_this_update(botan_x509_crl_t crl, uint64_t* time_since_epoch);

/**
* Get the nextUpdate field of the CRL as seconds since the Unix epoch
* @param crl the CRL to inspect
* @param time_since_epoch set to the nextUpdate time
* @return 0 on success, or BOTAN_FFI_ERROR_NO_VALUE if the field is absent
*/
BOTAN_FFI_EXPORT(3, 11) int botan_x509_crl_next_update(botan_x509_crl_t crl, uint64_t* time_since_epoch);

/**
* Create a new CRL
* @param crl_obj The newly created CRL
* @param rng a random number generator object
* @param ca_cert The CA Certificate the CRL belongs to
* @param ca_key The private key of that CA
* @param issue_time The time when the CRL becomes valid
* @param next_update The number of seconds after issue_time until the CRL expires
* @param hash_fn The hash function to use, may be null
* @param padding The padding to use, may be null
*/
BOTAN_FFI_EXPORT(3, 11)
int botan_x509_crl_create(botan_x509_crl_t* crl_obj,
                          botan_rng_t rng,
                          botan_x509_cert_t ca_cert,
                          botan_privkey_t ca_key,
                          uint64_t issue_time,
                          uint32_t next_update,
                          const char* hash_fn,
                          const char* padding);

/**
* Revocation reason codes for CRL entries, see RFC 5280 Section 5.3.1
*
* Must match values of CRL_Code in pkix_enums.h
*/
enum botan_x509_crl_reason_code /* NOLINT(*-enum-size,*-use-enum-class) */ {
   BOTAN_CRL_ENTRY_UNSPECIFIED = 0,
   BOTAN_CRL_ENTRY_KEY_COMPROMISE = 1,
   BOTAN_CRL_ENTRY_CA_COMPROMISE = 2,
   BOTAN_CRL_ENTRY_AFFILIATION_CHANGED = 3,
   BOTAN_CRL_ENTRY_SUPERSEDED = 4,
   BOTAN_CRL_ENTRY_CESSATION_OF_OPERATION = 5,
   BOTAN_CRL_ENTRY_CERTIFICATE_HOLD = 6,
   BOTAN_CRL_ENTRY_REMOVE_FROM_CRL = 8,
   BOTAN_CRL_ENTRY_PRIVILEGE_WITHDRAWN = 9,
   BOTAN_CRL_ENTRY_AA_COMPROMISE = 10
};

/**
* Create a new CRL entry that marks @p cert as revoked
* @param entry The newly created CRL entry
* @param cert The certificate to mark as revoked
* @param reason_code The reason code for revocation
*/
BOTAN_FFI_EXPORT(3, 11)
int botan_x509_crl_entry_create(botan_x509_crl_entry_t* entry, botan_x509_cert_t cert, int reason_code);

/**
* Update a CRL with new revoked entries. This does not modify the old crl, and instead creates a new one.
* @param crl_obj The newly created CRL
* @param last_crl The CRL to update
* @param rng a random number generator object
* @param ca_cert The CA Certificate the CRL belongs to
* @param ca_key The private key of that CA
* @param issue_time The time when the CRL becomes valid
* @param next_update The number of seconds after issue_time until the CRL expires
* @param new_entries The entries to add to the CRL
* @param new_entries_len The number of entries
* @param hash_fn The hash function to use, may be null
* @param padding The padding to use, may be null
*/
BOTAN_FFI_EXPORT(3, 11)
int botan_x509_crl_update(botan_x509_crl_t* crl_obj,
                          botan_x509_crl_t last_crl,
                          botan_rng_t rng,
                          botan_x509_cert_t ca_cert,
                          botan_privkey_t ca_key,
                          uint64_t issue_time,
                          uint32_t next_update,
                          const botan_x509_crl_entry_t* new_entries,
                          size_t new_entries_len,
                          const char* hash_fn,
                          const char* padding);

/**
* Check the signature on a CRL against the issuer's public key
* @param crl the CRL to verify
* @param key the public key of the issuing CA
* @return 1 if the signature is valid, 0 if it is not, negative on error
*/
BOTAN_FFI_EXPORT(3, 11) int botan_x509_crl_verify_signature(botan_x509_crl_t crl, botan_pubkey_t key);

/**
* Frees all resources of the CRL object
* @param crl the CRL to destroy
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 13) int botan_x509_crl_destroy(botan_x509_crl_t crl);

/**
 * Retrieve a specific binary value from an X.509 certificate revocation list.
 *
 * For multi-values @p index allows enumerating the available entries, until
 * BOTAN_FFI_ERROR_OUT_OF_RANGE is returned. For singleton values, an @p index
 * of value "0" is expected.
 *
 * @returns BOTAN_FFI_ERROR_NO_VALUE if the provided @p crl_obj does not provide
 *          the requested @p value_type at all or not in binary format.
 */
BOTAN_FFI_EXPORT(3, 11)
int botan_x509_crl_view_binary_values(botan_x509_crl_t crl_obj,
                                      botan_x509_value_type value_type,
                                      size_t index,
                                      botan_view_ctx ctx,
                                      botan_view_bin_fn view);

/**
 * Count the binary values of the given type available in a CRL.
 *
 * @param crl_obj the CRL to inspect
 * @param value_type the value type to count
 * @param count set to the number of available entries
 * @returns 0 on success, a negative value on failure
 */
BOTAN_FFI_EXPORT(3, 11)
int botan_x509_crl_view_binary_values_count(botan_x509_crl_t crl_obj, botan_x509_value_type value_type, size_t* count);

/**
 * Retrieve a specific string value from an X.509 certificate revocation list.
 *
 * For multi-values @p index allows enumerating the available entries, until
 * BOTAN_FFI_ERROR_OUT_OF_RANGE is returned. For singleton values, an @p index
 * of value "0" is expected.
 *
 * @returns BOTAN_FFI_ERROR_NO_VALUE if the provided @p crl_obj does not provide
 *          the requested @p value_type at all or not in string format.
 */
BOTAN_FFI_EXPORT(3, 11)
int botan_x509_crl_view_string_values(botan_x509_crl_t crl_obj,
                                      botan_x509_value_type value_type,
                                      size_t index,
                                      botan_view_ctx ctx,
                                      botan_view_str_fn view);

/**
 * Count the string values of the given type available in a CRL.
 *
 * @param crl_obj the CRL to inspect
 * @param value_type the value type to count
 * @param count set to the number of available entries
 * @returns 0 on success, a negative value on failure
 */
BOTAN_FFI_EXPORT(3, 11)
int botan_x509_crl_view_string_values_count(botan_x509_crl_t crl_obj, botan_x509_value_type value_type, size_t* count);

/**
 * Given a CRL and a certificate,
 * check if the certificate is revoked on that particular CRL
 */
BOTAN_FFI_EXPORT(2, 13) int botan_x509_is_revoked(botan_x509_crl_t crl, botan_x509_cert_t cert);

/**
* Allows iterating all entries of the CRL.
*
* @param crl     the CRL whose entries should be listed
* @param index   the index of the CRL entry to return
* @param entry   an object handle containing the CRL entry data
*
* @returns BOTAN_FFI_ERROR_OUT_OF_RANGE if the given @p index is out of range of
*          the CRL entry list.
*/
BOTAN_FFI_EXPORT(3, 11)
int botan_x509_crl_entries(botan_x509_crl_t crl, size_t index, botan_x509_crl_entry_t* entry);

/**
* Count the entries of the CRL.
*
* @param crl the CRL whose entries should be counted
* @param count set to the number of available entries
* @returns 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 11) int botan_x509_crl_entries_count(botan_x509_crl_t crl, size_t* count);

/**
* Return the revocation reason code for the given CRL @p entry.
* See `botan_x509_crl_reason_code` and RFC 5280 - 5.3.1 for possible reason codes.
*/
BOTAN_FFI_EXPORT(3, 11) int botan_x509_crl_entry_reason(botan_x509_crl_entry_t entry, int* reason_code);

/**
* Return the revocation date for the given CRL @p entry as time since epoch
* in seconds.
*/
BOTAN_FFI_EXPORT(3, 11)
int botan_x509_crl_entry_revocation_date(botan_x509_crl_entry_t entry, uint64_t* time_since_epoch);

/**
* Return the serial number associated with the given CRL @p entry.
*/
BOTAN_FFI_EXPORT(3, 11)
int botan_x509_crl_entry_serial_number(botan_x509_crl_entry_t entry, botan_mp_t* serial_number);

/**
* View the serial number associated with the given CRL @p entry.
*/
BOTAN_FFI_EXPORT(3, 11)
int botan_x509_crl_entry_view_serial_number(botan_x509_crl_entry_t entry, botan_view_ctx ctx, botan_view_bin_fn view);

/**
* Frees all resources of the CRL entry object
* @param entry the CRL entry to destroy
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(3, 11) int botan_x509_crl_entry_destroy(botan_x509_crl_entry_t entry);

/**
 * Different flavor of `botan_x509_cert_verify`, supports revocation lists.
 * CRLs are passed as an array, same as intermediates and trusted CAs
 */
BOTAN_FFI_EXPORT(2, 13)
int botan_x509_cert_verify_with_crl(int* validation_result,
                                    botan_x509_cert_t cert,
                                    const botan_x509_cert_t* intermediates,
                                    size_t intermediates_len,
                                    const botan_x509_cert_t* trusted,
                                    size_t trusted_len,
                                    const botan_x509_crl_t* crls,
                                    size_t crls_len,
                                    const char* trusted_path,
                                    size_t required_strength,
                                    const char* hostname,
                                    uint64_t reference_time);

/**
 * Key wrapping as per RFC 3394
 */
BOTAN_FFI_DEPRECATED("Use botan_nist_kw_enc")
BOTAN_FFI_EXPORT(2, 2)
int botan_key_wrap3394(const uint8_t key[],
                       size_t key_len,
                       const uint8_t kek[],
                       size_t kek_len,
                       uint8_t wrapped_key[],
                       size_t* wrapped_key_len);

/**
 * Key unwrapping as per RFC 3394
 * @param wrapped_key the wrapped key to unwrap
 * @param wrapped_key_len length of wrapped_key in bytes
 * @param kek the key encryption key
 * @param kek_len length of kek in bytes
 * @param key output buffer for the unwrapped key
 * @param key_len on input the size of key, on output the number of bytes written or required
 * @return 0 on success, a negative value on failure
 */
BOTAN_FFI_DEPRECATED("Use botan_nist_kw_dec")
BOTAN_FFI_EXPORT(2, 2)
int botan_key_unwrap3394(const uint8_t wrapped_key[],
                         size_t wrapped_key_len,
                         const uint8_t kek[],
                         size_t kek_len,
                         uint8_t key[],
                         size_t* key_len);

/**
 * Key wrapping as per NIST SP 800-38F
 * @param cipher_algo the block cipher to use, eg "AES-256"
 * @param padded if non-zero use KWP (the padded variant), otherwise KW
 * @param key the key to wrap
 * @param key_len length of key in bytes
 * @param kek the key encryption key
 * @param kek_len length of kek in bytes
 * @param wrapped_key output buffer for the wrapped key
 * @param wrapped_key_len on input the size of wrapped_key, on output the number of bytes written or required
 * @return 0 on success, a negative value on failure
 */
BOTAN_FFI_EXPORT(3, 0)
int botan_nist_kw_enc(const char* cipher_algo,
                      int padded,
                      const uint8_t key[],
                      size_t key_len,
                      const uint8_t kek[],
                      size_t kek_len,
                      uint8_t wrapped_key[],
                      size_t* wrapped_key_len);

/**
 * Key unwrapping as per NIST SP 800-38F
 * @param cipher_algo the block cipher to use, eg "AES-256"
 * @param padded if non-zero use KWP (the padded variant), otherwise KW
 * @param wrapped_key the wrapped key to unwrap
 * @param wrapped_key_len length of wrapped_key in bytes
 * @param kek the key encryption key
 * @param kek_len length of kek in bytes
 * @param key output buffer for the unwrapped key
 * @param key_len on input the size of key, on output the number of bytes written or required
 * @return 0 on success, a negative value on failure
 */
BOTAN_FFI_EXPORT(3, 0)
int botan_nist_kw_dec(const char* cipher_algo,
                      int padded,
                      const uint8_t wrapped_key[],
                      size_t wrapped_key_len,
                      const uint8_t kek[],
                      size_t kek_len,
                      uint8_t key[],
                      size_t* key_len);

/**
* HOTP
*/

typedef struct botan_hotp_struct* botan_hotp_t;

/**
* Initialize a HOTP instance
*/
BOTAN_FFI_EXPORT(2, 8)
int botan_hotp_init(botan_hotp_t* hotp, const uint8_t key[], size_t key_len, const char* hash_algo, size_t digits);

/**
* Destroy a HOTP instance
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 8)
int botan_hotp_destroy(botan_hotp_t hotp);

/**
* Generate a HOTP code for the provided counter
*/
BOTAN_FFI_EXPORT(2, 8)
int botan_hotp_generate(botan_hotp_t hotp, uint32_t* hotp_code, uint64_t hotp_counter);

/**
* Verify a HOTP code
*/
BOTAN_FFI_EXPORT(2, 8)
int botan_hotp_check(
   botan_hotp_t hotp, uint64_t* next_hotp_counter, uint32_t hotp_code, uint64_t hotp_counter, size_t resync_range);

/**
* TOTP
*/

typedef struct botan_totp_struct* botan_totp_t;

/**
* Initialize a TOTP instance
*/
BOTAN_FFI_EXPORT(2, 8)
int botan_totp_init(
   botan_totp_t* totp, const uint8_t key[], size_t key_len, const char* hash_algo, size_t digits, size_t time_step);

/**
* Destroy a TOTP instance
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 8)
int botan_totp_destroy(botan_totp_t totp);

/**
* Generate a TOTP code for the provided timestamp
* @param totp the TOTP object
* @param totp_code the OTP code will be written here
* @param timestamp the current local timestamp
*/
BOTAN_FFI_EXPORT(2, 8)
int botan_totp_generate(botan_totp_t totp, uint32_t* totp_code, uint64_t timestamp);

/**
* Verify a TOTP code
* @param totp the TOTP object
* @param totp_code the presented OTP
* @param timestamp the current local timestamp
* @param acceptable_clock_drift specifies the acceptable amount
* of clock drift (in terms of time steps) between the two hosts.
*/
BOTAN_FFI_EXPORT(2, 8)
int botan_totp_check(botan_totp_t totp, uint32_t totp_code, uint64_t timestamp, size_t acceptable_clock_drift);

/**
* Format Preserving Encryption
*/

typedef struct botan_fpe_struct* botan_fpe_t;

#define BOTAN_FPE_FLAG_FE1_COMPAT_MODE 1

/**
* Initialize an FE1 format preserving encryption object, which encrypts
* integers in the range [0, n)
* @param fpe the new object will be placed here
* @param n the modulus defining the range of the permutation
* @param key the key
* @param key_len length of key in bytes
* @param rounds the number of Feistel rounds; at least 16 is recommended
* @param flags 0, or BOTAN_FPE_FLAG_FE1_COMPAT_MODE to match the encoding used
*        by Botan versions prior to 2.5
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 8)
int botan_fpe_fe1_init(
   botan_fpe_t* fpe, botan_mp_t n, const uint8_t key[], size_t key_len, size_t rounds, uint32_t flags);

/**
* Frees all resources of the FPE object
* @param fpe the FPE object to destroy
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 8)
int botan_fpe_destroy(botan_fpe_t fpe);

/**
* Encrypt an integer, replacing it with the result
* @param fpe the FPE object
* @param x the value to encrypt, modified in place; must be less than n
* @param tweak the tweak, may be NULL if tweak_len is 0
* @param tweak_len length of tweak in bytes
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 8)
int botan_fpe_encrypt(botan_fpe_t fpe, botan_mp_t x, const uint8_t tweak[], size_t tweak_len);

/**
* Decrypt an integer, replacing it with the result
* @param fpe the FPE object
* @param x the value to decrypt, modified in place; must be less than n
* @param tweak the tweak, may be NULL if tweak_len is 0
* @param tweak_len length of tweak in bytes
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 8)
int botan_fpe_decrypt(botan_fpe_t fpe, botan_mp_t x, const uint8_t tweak[], size_t tweak_len);

/**
* SRP-6 Server Session type
*/
typedef struct botan_srp6_server_session_struct* botan_srp6_server_session_t;

/**
* Initialize an SRP-6 server session object
* @param srp6 SRP-6 server session object
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_srp6_server_session_init(botan_srp6_server_session_t* srp6);

/**
* Frees all resources of the SRP-6 server session object
* @param srp6 SRP-6 server session object
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_srp6_server_session_destroy(botan_srp6_server_session_t srp6);

/**
* SRP-6 Server side step 1
* @param srp6 SRP-6 server session object
* @param verifier the verification value saved from client registration
* @param verifier_len SRP-6 verifier value length
* @param group_id the SRP group id
* @param hash_id the SRP hash in use
* @param rng_obj a random number generator object
* @param B_pub out buffer to store the SRP-6 B value
* @param B_pub_len SRP-6 B value length
* @return 0 on success, negative on failure
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_srp6_server_session_step1(botan_srp6_server_session_t srp6,
                                    const uint8_t verifier[],
                                    size_t verifier_len,
                                    const char* group_id,
                                    const char* hash_id,
                                    botan_rng_t rng_obj,
                                    uint8_t B_pub[],
                                    size_t* B_pub_len);

/**
* SRP-6 Server side step 2
* @param srp6 SRP-6 server session object
* @param A the client's value
* @param A_len the client's value length
* @param key out buffer to store the symmetric key value
* @param key_len symmetric key length
* @return 0 on success, negative on failure
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_srp6_server_session_step2(
   botan_srp6_server_session_t srp6, const uint8_t A[], size_t A_len, uint8_t key[], size_t* key_len);

/**
* Generate a new SRP-6 verifier
* @param identifier a username or other client identifier
* @param password the secret used to authenticate user
* @param salt a randomly chosen value, at least 128 bits long
* @param salt_len the length of salt
* @param group_id specifies the shared SRP group
* @param hash_id specifies a secure hash function
* @param verifier out buffer to store the SRP-6 verifier value
* @param verifier_len SRP-6 verifier value length
* @return 0 on success, negative on failure
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_srp6_generate_verifier(const char* identifier,
                                 const char* password,
                                 const uint8_t salt[],
                                 size_t salt_len,
                                 const char* group_id,
                                 const char* hash_id,
                                 uint8_t verifier[],
                                 size_t* verifier_len);

/**
* SRP6a Client side
* @param username the username we are attempting login for
* @param password the password we are attempting to use
* @param group_id specifies the shared SRP group
* @param hash_id specifies a secure hash function
* @param salt is the salt value sent by the server
* @param salt_len the length of salt
* @param B is the server's public value
* @param B_len is the server's public value length
* @param rng_obj is a random number generator object
* @param A out buffer to store the SRP-6 A value
* @param A_len SRP-6 A verifier value length
* @param K out buffer to store the symmetric value
* @param K_len symmetric key length
* @return 0 on success, negative on failure
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_srp6_client_agree(const char* username,
                            const char* password,
                            const char* group_id,
                            const char* hash_id,
                            const uint8_t salt[],
                            size_t salt_len,
                            const uint8_t B[],
                            size_t B_len,
                            botan_rng_t rng_obj,
                            uint8_t A[],
                            size_t* A_len,
                            uint8_t K[],
                            size_t* K_len);

/**
* Return the size, in bytes, of the prime associated with group_id
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_srp6_group_size(const char* group_id, size_t* group_p_bytes);

/**
* SPAKE2+ (RFC 9383) password authenticated key exchange
*
* All operations are relative to a set of system parameters, which select
* the elliptic curve group, the SPAKE2+ M/N group elements, and the hash
* function. The parameters are created either from the name of one of the
* RFC 9383 ciphersuites using HMAC key confirmation ("P256-SHA256",
* "P256-SHA512", "P384-SHA256", "P384-SHA512", or "P521-SHA512"), or for
* an application specific group using botan_spake2p_params_init_custom.
*
* The identity, salt, and context parameters may be null, if the
* corresponding length is zero.
*
* Since the lengths of the outputs vary with the system parameters, all
* outputs are produced using view callbacks. The expected lengths of the
* messages received from the peer can be obtained from
* botan_spake2p_params_share_size and
* botan_spake2p_params_confirmation_size.
*/

/**
* SPAKE2+ system parameters
*/
typedef struct botan_spake2p_params_struct* botan_spake2p_params_t;

/**
* Create SPAKE2+ system parameters from an RFC 9383 ciphersuite name
*
* Objects created from the system parameters hold their own copy, so the
* parameters may be destroyed at any time.
*
* @param params output parameter for the created system parameters
* @param ciphersuite the SPAKE2+ ciphersuite name
*/
BOTAN_FFI_EXPORT(3, 13)
int botan_spake2p_params_init(botan_spake2p_params_t* params, const char* ciphersuite);

/**
* Create custom SPAKE2+ system parameters for an arbitrary group
*
* The M/N group elements are derived from the seed using hash to curve;
* returns BOTAN_FFI_ERROR_NOT_IMPLEMENTED if the group does not support
* hash to curve. Both peers must use the same group, seed, and hash.
*
* If the seed includes the identities of the participants, this
* additionally makes the scheme "quantum annoying", in that an attacker
* with a discrete logarithm oracle must compute a new discrete log for
* each (prover, verifier) pair they wish to attack.
*
* @param params output parameter for the created system parameters
* @param group the elliptic curve group to use
* @param seed the seed bytes used to derive the M/N group elements
* @param seed_len length of seed in bytes
* @param hash_fn the hash function to use (eg "SHA-256")
*/
BOTAN_FFI_EXPORT(3, 13)
int botan_spake2p_params_init_custom(
   botan_spake2p_params_t* params, botan_ec_group_t group, const uint8_t seed[], size_t seed_len, const char* hash_fn);

/**
* Frees all resources of SPAKE2+ system parameters
*/
BOTAN_FFI_EXPORT(3, 13)
int botan_spake2p_params_destroy(botan_spake2p_params_t params);

/**
* Return the size in bytes of a SPAKE2+ key share (shareP or shareV)
*
* @param params the SPAKE2+ system parameters
* @param share_size output parameter for the key share size
*/
BOTAN_FFI_EXPORT(3, 13)
int botan_spake2p_params_share_size(botan_spake2p_params_t params, size_t* share_size);

/**
* Return the size in bytes of a SPAKE2+ key confirmation message (confirmP or confirmV)
*
* @param params the SPAKE2+ system parameters
* @param confirmation_size output parameter for the key confirmation size
*/
BOTAN_FFI_EXPORT(3, 13)
int botan_spake2p_params_confirmation_size(botan_spake2p_params_t params, size_t* confirmation_size);

/**
* Derive a SPAKE2+ prover secret (w0 and w1) from a password, using Argon2id
*
* The view callback is invoked with the serialized prover secret, which is
* password equivalent and must be protected accordingly. It is used with
* botan_spake2p_registration_record and botan_spake2p_prover_init.
*
* @param params the SPAKE2+ system parameters
* @param password the (null terminated) password
* @param prover_id the identity of the prover
* @param prover_id_len length of prover_id in bytes
* @param verifier_id the identity of the verifier
* @param verifier_id_len length of verifier_id in bytes
* @param salt a salt value, ideally random and stored with the registration record
* @param salt_len length of salt in bytes
* @param ctx a context pointer passed to the view callback
* @param view a view callback which is invoked with the serialized prover secret
*/
BOTAN_FFI_EXPORT(3, 13)
int botan_spake2p_derive_secret(botan_spake2p_params_t params,
                                const char* password,
                                const uint8_t prover_id[],
                                size_t prover_id_len,
                                const uint8_t verifier_id[],
                                size_t verifier_id_len,
                                const uint8_t salt[],
                                size_t salt_len,
                                botan_view_ctx ctx,
                                botan_view_bin_fn view);

/**
* Compute a SPAKE2+ registration record (w0 and L) from a prover secret
*
* The registration record is provided to the verifier during registration.
* While it does not allow directly impersonating the prover, it does allow
* offline password guessing attacks, so it should be protected.
*
* @param params the SPAKE2+ system parameters
* @param rng a random number generator
* @param secret the serialized prover secret
* @param secret_len length of secret in bytes
* @param ctx a context pointer passed to the view callback
* @param view a view callback which is invoked with the serialized registration record
*/
BOTAN_FFI_EXPORT(3, 13)
int botan_spake2p_registration_record(botan_spake2p_params_t params,
                                      botan_rng_t rng,
                                      const uint8_t secret[],
                                      size_t secret_len,
                                      botan_view_ctx ctx,
                                      botan_view_bin_fn view);

/**
* SPAKE2+ prover
*/
typedef struct botan_spake2p_prover_struct* botan_spake2p_prover_t;

/**
* SPAKE2+ verifier
*/
typedef struct botan_spake2p_verifier_struct* botan_spake2p_verifier_t;

/**
* Initialize a SPAKE2+ prover
*
* The identities and context must be agreed upon by both parties; the
* identities must additionally match the values used when deriving the
* prover secret.
*
* @param prover output parameter for the created prover object
* @param params the SPAKE2+ system parameters
* @param secret the serialized prover secret
* @param secret_len length of secret in bytes
* @param prover_id the identity of the prover
* @param prover_id_len length of prover_id in bytes
* @param verifier_id the identity of the verifier
* @param verifier_id_len length of verifier_id in bytes
* @param context an application specific context string
* @param context_len length of context in bytes
*/
BOTAN_FFI_EXPORT(3, 13)
int botan_spake2p_prover_init(botan_spake2p_prover_t* prover,
                              botan_spake2p_params_t params,
                              const uint8_t secret[],
                              size_t secret_len,
                              const uint8_t prover_id[],
                              size_t prover_id_len,
                              const uint8_t verifier_id[],
                              size_t verifier_id_len,
                              const uint8_t context[],
                              size_t context_len);

/**
* Frees all resources of a SPAKE2+ prover
*/
BOTAN_FFI_EXPORT(3, 13)
int botan_spake2p_prover_destroy(botan_spake2p_prover_t prover);

/**
* Generate the prover's key share (shareP), which is sent to the verifier
*
* This can be called only once per prover object.
*
* @param prover the prover object
* @param rng a random number generator
* @param ctx a context pointer passed to the view callback
* @param view a view callback which is invoked with the key share
*/
BOTAN_FFI_EXPORT(3, 13)
int botan_spake2p_prover_generate_message(botan_spake2p_prover_t prover,
                                          botan_rng_t rng,
                                          botan_view_ctx ctx,
                                          botan_view_bin_fn view);

/**
* Consume the verifier's response (shareV followed by confirmV) and produce
* the prover's key confirmation (confirmP), which is sent to the verifier.
*
* Returns BOTAN_FFI_ERROR_BAD_MAC if the verifier's key confirmation is
* wrong, typically meaning the passwords do not match.
*
* @param prover the prover object
* @param rng a random number generator
* @param peer_message the verifier's response
* @param peer_message_len length of peer_message in bytes
* @param ctx a context pointer passed to the view callback
* @param view a view callback which is invoked with the prover's key confirmation
*/
BOTAN_FFI_EXPORT(3, 13)
int botan_spake2p_prover_process_message(botan_spake2p_prover_t prover,
                                         botan_rng_t rng,
                                         const uint8_t peer_message[],
                                         size_t peer_message_len,
                                         botan_view_ctx ctx,
                                         botan_view_bin_fn view);

/**
* Return the prover's shared secret (K_shared)
*
* This may be called only after botan_spake2p_prover_process_message
* has succeeded.
*
* @param prover the prover object
* @param ctx a context pointer passed to the view callback
* @param view a view callback which is invoked with the shared secret
*/
BOTAN_FFI_EXPORT(3, 13)
int botan_spake2p_prover_shared_secret(botan_spake2p_prover_t prover, botan_view_ctx ctx, botan_view_bin_fn view);

/**
* Initialize a SPAKE2+ verifier
*
* The identities and context must be agreed upon by both parties; the
* identities must additionally match the values used when deriving the
* prover secret.
*
* @param verifier output parameter for the created verifier object
* @param params the SPAKE2+ system parameters
* @param record the serialized registration record
* @param record_len length of record in bytes
* @param prover_id the identity of the prover
* @param prover_id_len length of prover_id in bytes
* @param verifier_id the identity of the verifier
* @param verifier_id_len length of verifier_id in bytes
* @param context an application specific context string
* @param context_len length of context in bytes
*/
BOTAN_FFI_EXPORT(3, 13)
int botan_spake2p_verifier_init(botan_spake2p_verifier_t* verifier,
                                botan_spake2p_params_t params,
                                const uint8_t record[],
                                size_t record_len,
                                const uint8_t prover_id[],
                                size_t prover_id_len,
                                const uint8_t verifier_id[],
                                size_t verifier_id_len,
                                const uint8_t context[],
                                size_t context_len);

/**
* Frees all resources of a SPAKE2+ verifier
*/
BOTAN_FFI_EXPORT(3, 13)
int botan_spake2p_verifier_destroy(botan_spake2p_verifier_t verifier);

/**
* Consume the prover's key share (shareP) and produce the verifier's
* response (shareV followed by confirmV), which is sent to the prover.
*
* This can be called only once per verifier object.
*
* @param verifier the verifier object
* @param rng a random number generator
* @param peer_message the prover's key share
* @param peer_message_len length of peer_message in bytes
* @param ctx a context pointer passed to the view callback
* @param view a view callback which is invoked with the verifier's response
*/
BOTAN_FFI_EXPORT(3, 13)
int botan_spake2p_verifier_process_message(botan_spake2p_verifier_t verifier,
                                           botan_rng_t rng,
                                           const uint8_t peer_message[],
                                           size_t peer_message_len,
                                           botan_view_ctx ctx,
                                           botan_view_bin_fn view);

/**
* Check the prover's key confirmation (confirmP)
*
* Returns BOTAN_FFI_ERROR_BAD_MAC if the confirmation is wrong, meaning
* the prover does not know the password.
*
* @param verifier the verifier object
* @param confirmation the prover's key confirmation
* @param confirmation_len length of confirmation in bytes
*/
BOTAN_FFI_EXPORT(3, 13)
int botan_spake2p_verifier_verify_confirmation(botan_spake2p_verifier_t verifier,
                                               const uint8_t confirmation[],
                                               size_t confirmation_len);

/**
* Skip checking the prover's key confirmation (confirmP)
*
* This can be called after botan_spake2p_verifier_process_message, in
* place of botan_spake2p_verifier_verify_confirmation, to allow extracting
* the shared secret without having checked the prover's key confirmation.
*
* Warning: after calling this, nothing is known about the peer; only a
* prover which knows the password can compute the same shared secret, but
* no evidence of this has been received. It is intended solely for
* protocols which embed SPAKE2+ and perform the prover's key confirmation
* themselves, for example the proposed TLS PAKE extension, where the TLS
* handshake takes the place of confirmP. Anywhere else, use
* botan_spake2p_verifier_verify_confirmation.
*
* @param verifier the verifier object
*/
BOTAN_FFI_EXPORT(3, 13)
int botan_spake2p_verifier_skip_confirmation(botan_spake2p_verifier_t verifier);

/**
* Return the verifier's shared secret (K_shared)
*
* This may be called only after botan_spake2p_verifier_verify_confirmation
* has succeeded, or after botan_spake2p_verifier_skip_confirmation.
*
* @param verifier the verifier object
* @param ctx a context pointer passed to the view callback
* @param view a view callback which is invoked with the shared secret
*/
BOTAN_FFI_EXPORT(3, 13)
int botan_spake2p_verifier_shared_secret(botan_spake2p_verifier_t verifier, botan_view_ctx ctx, botan_view_bin_fn view);

/**
 * ZFEC
 */

/**
 * Encode some bytes with certain ZFEC parameters.
 *
 * @param K the number of shares needed for recovery
 * @param N the number of shares generated
 * @param input the data to FEC
 * @param size the length in bytes of input, which must be a multiple of K
 *
 * @param outputs An out parameter pointing to a fully allocated array of size
 *                [N][size / K].  For all n in range, an encoded block will be
 *                written to the memory starting at outputs[n][0].
 *
 * @return 0 on success, negative on failure
 */
BOTAN_FFI_EXPORT(3, 0)
int botan_zfec_encode(size_t K, size_t N, const uint8_t* input, size_t size, uint8_t** outputs);

/**
 * Decode some previously encoded shares using certain ZFEC parameters.
 *
 * @param K the number of shares needed for recovery
 * @param N the total number of shares
 *
 * @param indexes The index into the encoder's outputs for the corresponding
 *                element of the inputs array. Must be of length K.
 *
 * @param inputs K previously encoded shares to decode
 * @param shareSize the length in bytes of each input
 *
 * @param outputs An out parameter pointing to a fully allocated array of size
 *                [K][shareSize].  For all k in range, a decoded block will
 *                written to the memory starting at outputs[k][0].
 *
 * @return 0 on success, negative on failure
 */
BOTAN_FFI_EXPORT(3, 0)
int botan_zfec_decode(
   size_t K, size_t N, const size_t* indexes, uint8_t* const* inputs, size_t shareSize, uint8_t** outputs);

/**
* TPM2 context
*/
typedef struct botan_tpm2_ctx_struct* botan_tpm2_ctx_t;

/**
* TPM2 session
*/
typedef struct botan_tpm2_session_struct* botan_tpm2_session_t;

/**
* TPM2 crypto backend state object
*/
typedef struct botan_tpm2_crypto_backend_state_struct* botan_tpm2_crypto_backend_state_t;

struct ESYS_CONTEXT;

/**
* Checks if Botan's TSS2 crypto backend can be used in this build
* @returns 1 if the crypto backend can be enabled
*/
BOTAN_FFI_EXPORT(3, 6)
int botan_tpm2_supports_crypto_backend(void);

/**
* Initialize a TPM2 context
* @param ctx_out output TPM2 context
* @param tcti_nameconf TCTI config (may be nullptr)
* @return 0 on success
*/
BOTAN_FFI_EXPORT(3, 6) int botan_tpm2_ctx_init(botan_tpm2_ctx_t* ctx_out, const char* tcti_nameconf);

/**
* Initialize a TPM2 context
* @param ctx_out output TPM2 context
* @param tcti_name TCTI name (may be nullptr)
* @param tcti_conf TCTI config (may be nullptr)
* @return 0 on success
*/
BOTAN_FFI_EXPORT(3, 6)
int botan_tpm2_ctx_init_ex(botan_tpm2_ctx_t* ctx_out, const char* tcti_name, const char* tcti_conf);

/**
* Wrap an existing ESYS_CONTEXT for use in Botan.
* Note that destroying the created botan_tpm2_ctx_t won't
* finalize @p esys_ctx
* @param ctx_out output TPM2 context
* @param esys_ctx ESYS_CONTEXT to wrap
* @return 0 on success
*/
BOTAN_FFI_EXPORT(3, 7)
int botan_tpm2_ctx_from_esys(botan_tpm2_ctx_t* ctx_out, struct ESYS_CONTEXT* esys_ctx);

/**
* Enable Botan's TSS2 crypto backend that replaces the cryptographic functions
* required for the communication with the TPM with implementations provided
* by Botan instead of using TSS' defaults OpenSSL or mbedTLS.
* Note that the provided @p rng should not be dependent on the TPM and the
* caller must ensure that it remains usable for the lifetime of the @p ctx.
* @param ctx TPM2 context
* @param rng random number generator to be used by the crypto backend
*/
BOTAN_FFI_EXPORT(3, 6)
int botan_tpm2_ctx_enable_crypto_backend(botan_tpm2_ctx_t ctx, botan_rng_t rng);

/**
* Frees all resources of a TPM2 context
* @param ctx TPM2 context
* @return 0 on success
*/
BOTAN_FFI_EXPORT(3, 6) int botan_tpm2_ctx_destroy(botan_tpm2_ctx_t ctx);

/**
* Use this if you just need Botan's crypto backend but do not want to wrap any
* other ESYS functionality using Botan's TPM2 wrapper.
* A Crypto Backend State is created that the user needs to keep alive for as
* long as the crypto backend is used and needs to be destroyed after.
* Note that the provided @p rng should not be dependent on the TPM and the
* caller must ensure that it remains usable for the lifetime of the @p esys_ctx.
* @param cbs_out To be created Crypto Backend State
* @param esys_ctx TPM2 context
* @param rng random number generator to be used by the crypto backend
*/
BOTAN_FFI_EXPORT(3, 7)
int botan_tpm2_enable_crypto_backend(botan_tpm2_crypto_backend_state_t* cbs_out,
                                     struct ESYS_CONTEXT* esys_ctx,
                                     botan_rng_t rng);

/**
* Frees all resources of a TPM2 Crypto Callback State
* Note that this does not attempt to de-register the crypto backend,
* it just frees the resource pointed to by @p cbs. Use the ESAPI function
* ``Esys_SetCryptoCallbacks(ctx, nullptr)`` to deregister manually.
* @param cbs TPM2 Crypto Callback State
* @return 0 on success
*/
BOTAN_FFI_EXPORT(3, 7) int botan_tpm2_crypto_backend_state_destroy(botan_tpm2_crypto_backend_state_t cbs);

/**
* Initialize a random number generator object via TPM2
* @param rng_out rng object to create
* @param ctx TPM2 context
* @param s1 the first session to use (optional, may be nullptr)
* @param s2 the second session to use (optional, may be nullptr)
* @param s3 the third session to use (optional, may be nullptr)
*/
BOTAN_FFI_EXPORT(3, 6)
int botan_tpm2_rng_init(botan_rng_t* rng_out,
                        botan_tpm2_ctx_t ctx,
                        botan_tpm2_session_t s1,
                        botan_tpm2_session_t s2,
                        botan_tpm2_session_t s3);

/**
* Create an unauthenticated session for use with TPM2
* @param session_out the session object to create
* @param ctx TPM2 context
*/
BOTAN_FFI_EXPORT(3, 6)
int botan_tpm2_unauthenticated_session_init(botan_tpm2_session_t* session_out, botan_tpm2_ctx_t ctx);

/**
* Create an unauthenticated session for use with TPM2
* @param session the session object to destroy
*/
BOTAN_FFI_EXPORT(3, 6)
int botan_tpm2_session_destroy(botan_tpm2_session_t session);

/* NOLINTEND(*-macro-usage,*-misplaced-const) */

#ifdef __cplusplus
}
#endif

#endif
