/*
* (C) 2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PK_OPERATIONS_H_
#define BOTAN_PK_OPERATIONS_H_

/**
* Ordinary applications should never need to include or use this
* header. It is exposed only for specialized applications which want
* to implement new versions of public key crypto without merging them
* as changes to the library. One actual example of such usage is an
* application which creates RSA signatures using a custom TPM library.
* Unless you're doing something like that, you don't need anything
* here. Instead use pubkey.h which wraps these types safely and
* provides a stable application-oriented API.
*
* Note: This header was accidentally pulled from the public API between
*       Botan 3.0.0 and 3.2.0, and then restored in 3.3.0. If you are
*       maintaining an application which used this header in Botan 2.x,
*       you should make sure to use Botan 3.3.0 or later when migrating.
*/

#include <botan/pk_keys.h>
#include <botan/secmem.h>
#include <span>

namespace Botan {

class RandomNumberGenerator;
class EME;
class KDF;
class EMSA;

}  // namespace Botan

namespace Botan::PK_Ops {

/**
* Public key encryption interface
*/
class BOTAN_UNSTABLE_API Encryption {
   public:
      /**
      * Encrypt a message returning the ciphertext
      */
      virtual std::vector<uint8_t> encrypt(std::span<const uint8_t> msg, RandomNumberGenerator& rng) = 0;

      /**
      * Return the maximum input size for this key
      */
      virtual size_t max_input_bits() const = 0;

      /**
      * Given the plaintext length, return an upper bound of the ciphertext
      * length for this key and padding.
      */
      virtual size_t ciphertext_length(size_t ptext_len) const = 0;

      virtual ~Encryption() = default;
};

/**
* Public key decryption interface
*/
class BOTAN_UNSTABLE_API Decryption {
   public:
      virtual secure_vector<uint8_t> decrypt(uint8_t& valid_mask, std::span<const uint8_t> ctext) = 0;

      virtual size_t plaintext_length(size_t ctext_len) const = 0;

      virtual ~Decryption() = default;
};

/**
* Public key signature verification interface
*/
class BOTAN_UNSTABLE_API Verification {
   public:
      /**
      * Add more data to the message currently being signed
      * @param input the input to be hashed/verified
      */
      virtual void update(std::span<const uint8_t> input) = 0;

      /**
      * Perform a verification operation
      * @param sig the signature to be checked with respect to the input
      */
      virtual bool is_valid_signature(std::span<const uint8_t> sig) = 0;

      /**
      * Return the hash function being used by this signer
      */
      virtual std::string hash_function() const = 0;

      virtual ~Verification() = default;
};

/**
* Public key signature creation interface
*/
class BOTAN_UNSTABLE_API Signature {
   public:
      /**
      * Add more data to the message currently being signed
      * @param input the input to be hashed/signed
      */
      virtual void update(std::span<const uint8_t> input) = 0;

      /**
      * Perform a signature operation
      * @param rng a random number generator
      */
      virtual std::vector<uint8_t> sign(RandomNumberGenerator& rng) = 0;

      /**
      * Return an upper bound on the length of the output signature
      */
      virtual size_t signature_length() const = 0;

      /**
      * Return an algorithm identifier associated with this signature scheme.
      *
      * Default implementation throws an exception
      */
      virtual AlgorithmIdentifier algorithm_identifier() const;

      /**
      * Return the hash function being used by this signer
      */
      virtual std::string hash_function() const = 0;

      virtual ~Signature() = default;
};

/**
* A generic key agreement operation (eg DH or ECDH)
*/
class BOTAN_UNSTABLE_API Key_Agreement {
   public:
      virtual secure_vector<uint8_t> agree(size_t key_len,
                                           std::span<const uint8_t> other_key,
                                           std::span<const uint8_t> salt) = 0;

      virtual size_t agreed_value_size() const = 0;

      virtual ~Key_Agreement() = default;
};

/**
* KEM (key encapsulation)
*/
class BOTAN_UNSTABLE_API KEM_Encryption {
   public:
      virtual void kem_encrypt(std::span<uint8_t> out_encapsulated_key,
                               std::span<uint8_t> out_shared_key,
                               RandomNumberGenerator& rng,
                               size_t desired_shared_key_len,
                               std::span<const uint8_t> salt) = 0;

      virtual size_t shared_key_length(size_t desired_shared_key_len) const = 0;

      virtual size_t encapsulated_key_length() const = 0;

      virtual ~KEM_Encryption() = default;
};

class BOTAN_UNSTABLE_API KEM_Decryption {
   public:
      virtual void kem_decrypt(std::span<uint8_t> out_shared_key,
                               std::span<const uint8_t> encapsulated_key,
                               size_t desired_shared_key_len,
                               std::span<const uint8_t> salt) = 0;

      virtual size_t shared_key_length(size_t desired_shared_key_len) const = 0;

      virtual size_t encapsulated_key_length() const = 0;

      virtual ~KEM_Decryption() = default;
};

}  // namespace Botan::PK_Ops

#endif
