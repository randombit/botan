/*
 * C API for the HQC-KEM Rust implementation (rust-hqc).
 *
 * Mirrors the `extern "C"` functions exported from src/capi.rs. The numeric
 * values below are pinned against the Rust constants by a test in that file,
 * so a change on either side that is not mirrored fails `cargo test`.
 *
 * The interface is stateless: every call takes the parameter set as a
 * discriminant byte (1, 3 or 5), and there is no handle to create or free.
 * Buffers are passed as pointer + length pairs; the required lengths for a
 * parameter set are obtained from hqc_sizes() and hqc_randomness_lengths().
 *
 * Key generation and encapsulation are derandomized: the caller passes
 * exactly the bytes the HQC specification draws from the random number
 * generator (the 32-byte master seed, which is the decapsulation key, resp.
 * the message followed by the salt), and the crate does not expand them.
 * Feeding the output of the NIST KAT DRBG therefore reproduces the reference
 * known answer tests.
 *
 * The crate contains neither a hash function nor an allocator for secrets of
 * its own. Every operation receives a hqc_callbacks_t through which the
 * caller supplies SHA3-256, SHA3-512, SHAKE256 and secure memory (see below);
 * Botan implements these with its own hash objects and secure allocator.
 *
 * All functions catch Rust panics internally and return HQC_ERR_INTERNAL
 * instead of unwinding across the language boundary.
 */

#ifndef HQC_C_API_H
#define HQC_C_API_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Parameter-set discriminants.
 *
 * The enum is for naming only. Functions take the discriminant as a plain
 * uint8_t, because the C standard does not fix an enum's underlying type and
 * the Rust side expects exactly one byte.
 */
typedef enum hqc_param_set_t {
   HQC_PARAM_SET_1 = 1, /* NIST category 1, 128-bit classical security */
   HQC_PARAM_SET_3 = 3, /* NIST category 3, 192-bit classical security */
   HQC_PARAM_SET_5 = 5  /* NIST category 5, 256-bit classical security */
} hqc_param_set_t;

/*
 * Return codes.
 *
 * As above, the enum names the values; every function returns int32_t.
 * All non-zero codes describe structural problems with the call (lengths,
 * null pointers, an unknown parameter set, unusable callbacks) and never
 * depend on key or ciphertext content.
 */
typedef enum hqc_error_t {
   HQC_OK = 0,                     /* Success. */
   HQC_ERR_BUFFER_LENGTH = -1,     /* A buffer had the wrong length for the parameter set. */
   HQC_ERR_INVALID_KEY = -2,       /* The key was not valid for the parameter set. */
   HQC_ERR_INVALID_CIPHERTEXT = -3,/* The ciphertext was not valid for the parameter set. */
   HQC_ERR_RANDOMNESS = -4,        /* The randomness source failed. */
   HQC_ERR_INTERNAL = -5,          /* An internal invariant failed, or a panic was caught. */
   HQC_ERR_BAD_PARAMETER_SET = -6, /* The parameter-set discriminant was not 1, 3 or 5. */
   HQC_ERR_NULL_POINTER = -7,      /* A required pointer was null. */
   HQC_ERR_HASH_CALLBACK = -8,     /* A hash callback returned a non-zero value. */
   HQC_ERR_BAD_CALLBACKS = -9,     /* The callback struct was null, had a null member or an unsupported version. */
   HQC_ERR_ALLOC = -10             /* The secure_alloc callback returned NULL. */
} hqc_error_t;

/*
 * Hash callbacks.
 *
 * The caller provides the hash functions HQC needs. Every callback receives
 * the `ctx` member of hqc_hash_callbacks_t as its first argument, unchanged;
 * the crate never inspects it. Callbacks return 0 on success and any non-zero
 * value on failure, which the crate reports as HQC_ERR_HASH_CALLBACK.
 *
 * Inputs are handed over as an array of `parts` that are to be hashed as if
 * concatenated. The parts may contain secret data (the message m and the
 * implicit-rejection secret sigma); the provider must neither retain the
 * pointers after returning nor leave copies of the data behind.
 *
 * SHAKE256 is used as an extendable-output function whose output is squeezed
 * incrementally. shake256_init absorbs all parts and returns an opaque state
 * in *out_xof; shake256_squeeze produces the next out_len bytes of the output
 * stream of that state; shake256_free releases it. The crate releases every
 * state it created, also on error paths, and never uses one state from two
 * threads at the same time. Callbacks may be invoked from any thread.
 */
typedef struct hqc_xof_st hqc_xof_t;

typedef struct hqc_buffer_t {
   const uint8_t* data;
   size_t len;
} hqc_buffer_t;

typedef struct hqc_hash_callbacks_t {
   /* Passed unchanged as the first argument of every callback; may be NULL. */
   void* ctx;

   /* SHA3-256 over the concatenation of the parts; out receives 32 bytes. */
   int32_t (*sha3_256)(void* ctx, const hqc_buffer_t* parts, size_t n_parts, uint8_t* out);

   /* SHA3-512 over the concatenation of the parts; out receives 64 bytes. */
   int32_t (*sha3_512)(void* ctx, const hqc_buffer_t* parts, size_t n_parts, uint8_t* out);

   /* SHAKE256: absorb the parts and return a state ready for squeezing. */
   int32_t (*shake256_init)(void* ctx, const hqc_buffer_t* parts, size_t n_parts, hqc_xof_t** out_xof);

   /* Squeeze the next out_len bytes from the state. */
   int32_t (*shake256_squeeze)(void* ctx, hqc_xof_t* xof, uint8_t* out, size_t out_len);

   /* Release a state returned by shake256_init. */
   void (*shake256_free)(void* ctx, hqc_xof_t* xof);
} hqc_hash_callbacks_t;

/*
 * Secure memory callbacks.
 *
 * The crate keeps key material and per-message secrets (seeds, the message,
 * the implicit-rejection secret, the shared secret, the secret vectors and
 * the sampler's index list) in memory obtained from the caller, so that a
 * provider such as Botan can serve them from its locked memory pool and
 * scrub them on release. As with the hash callbacks, `ctx` is passed through
 * unchanged.
 *
 * secure_alloc returns len bytes of zero-filled memory aligned for any
 * integer type up to 8 bytes, or NULL on failure (reported by the crate as
 * HQC_ERR_ALLOC). secure_free scrubs and releases memory obtained from
 * secure_alloc; len is the value that was passed to secure_alloc. The crate
 * releases every buffer it obtained, also on error paths, never hands such a
 * buffer to the caller, and does not zeroize these buffers itself: scrubbing
 * is the provider's responsibility. Non-secret data stays on the crate's own
 * heap and is never freed by the caller.
 */
typedef struct hqc_alloc_callbacks_t {
   /* Passed unchanged as the first argument of both callbacks; may be NULL. */
   void* ctx;

   void* (*secure_alloc)(void* ctx, size_t len);

   void (*secure_free)(void* ctx, void* ptr, size_t len);
} hqc_alloc_callbacks_t;

/*
 * All callbacks the crate needs, grouped in sections; `version` allows the
 * crate to reject a struct it does not understand. Version 2 added the
 * memory allocation section.
 */
#define HQC_CALLBACKS_VERSION 2

typedef struct hqc_callbacks_t {
   uint32_t version; /* Must be HQC_CALLBACKS_VERSION. */
   hqc_hash_callbacks_t hash;
   hqc_alloc_callbacks_t alloc;
} hqc_callbacks_t;

/*
 * Writes the byte sizes for `param_set`.
 *
 * Any out pointer may be NULL, in which case that size is not written. Lets
 * a caller allocate correctly without duplicating the parameter table.
 *
 * Returns HQC_OK, or HQC_ERR_BAD_PARAMETER_SET.
 */
int32_t hqc_sizes(uint8_t param_set,
                  size_t* ek_len,
                  size_t* dk_len,
                  size_t* ct_len,
                  size_t* ss_len);

/*
 * Writes the number of random bytes hqc_keypair() and hqc_encaps() consume
 * for `param_set`: 32 for key generation (the master seed), and the message
 * length (16, 24 or 32) plus the 16-byte salt for encapsulation.
 *
 * Either out pointer may be NULL, in which case that length is not written.
 *
 * Returns HQC_OK, or HQC_ERR_BAD_PARAMETER_SET.
 */
int32_t hqc_randomness_lengths(uint8_t param_set, size_t* keypair_len, size_t* encaps_len);

/*
 * Generates a keypair into `ek` (encapsulation key) and `dk` (decapsulation
 * key) from `seed`, the master seed of the specification's KeyGen.
 *
 * `seed` must be `seed_len` == 32 bytes (hqc_randomness_lengths()) from a
 * secure entropy source. It is used as is and becomes the decapsulation key,
 * so `dk` receives a copy of it. `ek_len` and `dk_len` must equal the values
 * reported by hqc_sizes() for `param_set`.
 *
 * Returns HQC_OK, or HQC_ERR_BAD_PARAMETER_SET, HQC_ERR_BAD_CALLBACKS,
 * HQC_ERR_NULL_POINTER, HQC_ERR_BUFFER_LENGTH, HQC_ERR_HASH_CALLBACK,
 * HQC_ERR_ALLOC, HQC_ERR_INTERNAL.
 */
int32_t hqc_keypair(uint8_t param_set,
                    const hqc_callbacks_t* callbacks,
                    uint8_t* ek,
                    size_t ek_len,
                    uint8_t* dk,
                    size_t dk_len,
                    const uint8_t* seed,
                    size_t seed_len);

/*
 * Derives the encapsulation key belonging to the decapsulation key `dk` into
 * `ek`.
 *
 * Key generation is deterministic in the master seed, so this repeats its
 * public half; it is how a stored 32-byte private key is loaded. Like key
 * generation it uses variable-time rejection sampling. `ek_len` must equal
 * the value reported by hqc_sizes(); a `dk` of the wrong length is reported
 * as HQC_ERR_INVALID_KEY. Output buffers must not alias the inputs.
 *
 * Returns HQC_OK, or HQC_ERR_BAD_PARAMETER_SET, HQC_ERR_BAD_CALLBACKS,
 * HQC_ERR_NULL_POINTER, HQC_ERR_BUFFER_LENGTH, HQC_ERR_INVALID_KEY,
 * HQC_ERR_HASH_CALLBACK, HQC_ERR_ALLOC, HQC_ERR_INTERNAL.
 */
int32_t hqc_public_key(uint8_t param_set,
                       const hqc_callbacks_t* callbacks,
                       uint8_t* ek,
                       size_t ek_len,
                       const uint8_t* dk,
                       size_t dk_len);

/*
 * Encapsulates to the encapsulation key `ek`, writing the ciphertext to `ct`
 * and the shared secret to `ss`.
 *
 * `randomness` is the message m followed by the salt, as the specification's
 * Encaps draws them: `randomness_len` must equal the encapsulation length
 * reported by hqc_randomness_lengths(), and the bytes must come from a secure
 * entropy source and never be reused. Output buffers must not alias the
 * inputs. All other lengths must match hqc_sizes() for `param_set`.
 *
 * Returns HQC_OK, or HQC_ERR_BAD_PARAMETER_SET, HQC_ERR_BAD_CALLBACKS,
 * HQC_ERR_NULL_POINTER, HQC_ERR_BUFFER_LENGTH, HQC_ERR_INVALID_KEY,
 * HQC_ERR_HASH_CALLBACK, HQC_ERR_ALLOC, HQC_ERR_INTERNAL.
 */
int32_t hqc_encaps(uint8_t param_set,
                   const hqc_callbacks_t* callbacks,
                   uint8_t* ct,
                   size_t ct_len,
                   uint8_t* ss,
                   size_t ss_len,
                   const uint8_t* ek,
                   size_t ek_len,
                   const uint8_t* randomness,
                   size_t randomness_len);

/*
 * Decapsulates the ciphertext `ct` with the decapsulation key `dk`, writing
 * the shared secret to `ss`.
 *
 * Never signals a decryption failure. HQC uses the Fujisaki-Okamoto transform
 * with implicit rejection: a ciphertext that does not re-encrypt yields a
 * pseudo-random shared secret derived from the rejection key. A non-zero
 * return means the inputs were structurally wrong, not that decryption
 * failed. Output buffers must not alias the inputs.
 *
 * Returns HQC_OK, or HQC_ERR_BAD_PARAMETER_SET, HQC_ERR_BAD_CALLBACKS,
 * HQC_ERR_NULL_POINTER, HQC_ERR_BUFFER_LENGTH, HQC_ERR_INVALID_CIPHERTEXT,
 * HQC_ERR_INVALID_KEY, HQC_ERR_HASH_CALLBACK, HQC_ERR_ALLOC,
 * HQC_ERR_INTERNAL.
 */
int32_t hqc_decaps(uint8_t param_set,
                   const hqc_callbacks_t* callbacks,
                   uint8_t* ss,
                   size_t ss_len,
                   const uint8_t* ct,
                   size_t ct_len,
                   const uint8_t* dk,
                   size_t dk_len);

#ifdef __cplusplus
}
#endif

#endif /* HQC_C_API_H */
