/*
* KDF defined in NIST SP 800-56a revision 2 (Single-step key-derivation function)
*
* (C) 2017 Ribose Inc. Written by Krzysztof Kwiatkowski.
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SP800_56A_H_
#define BOTAN_SP800_56A_H_

#include <botan/hash.h>
#include <botan/kdf.h>
#include <botan/mac.h>

namespace Botan {

/**
 * NIST SP 800-56A KDF using hash function
 * @warning This KDF ignores the provided salt value
 */
class SP800_56A_Hash final : public KDF {
   public:
      std::string name() const override;

      std::unique_ptr<KDF> new_object() const override;

      /**
      * Derive a key using the SP800-56A KDF.
      *
      * The implementation hard codes the context value for the
      * expansion step to the empty string.
      *
      * @param key derived keying material K_M
      * @param key_len the desired output length in bytes
      * @param secret shared secret Z
      * @param secret_len size of Z in bytes
      * @param salt ignored
      * @param salt_len ignored
      * @param label label for the expansion step
      * @param label_len size of label in bytes
      *
      * @throws Invalid_Argument key_len > 2^32
      */
      void kdf(uint8_t key[],
               size_t key_len,
               const uint8_t secret[],
               size_t secret_len,
               const uint8_t salt[],
               size_t salt_len,
               const uint8_t label[],
               size_t label_len) const override;

      /**
      * @param hash the hash function to use as the auxiliary function
      */
      explicit SP800_56A_Hash(std::unique_ptr<HashFunction> hash) : m_hash(std::move(hash)) {}

   private:
      std::unique_ptr<HashFunction> m_hash;
};

/**
 * NIST SP 800-56A KDF using HMAC
 */
class SP800_56A_HMAC final : public KDF {
   public:
      std::string name() const override;

      std::unique_ptr<KDF> new_object() const override;

      /**
      * Derive a key using the SP800-56A KDF.
      *
      * The implementation hard codes the context value for the
      * expansion step to the empty string.
      *
      * @param key derived keying material K_M
      * @param key_len the desired output length in bytes
      * @param secret shared secret Z
      * @param secret_len size of Z in bytes
      * @param salt ignored
      * @param salt_len ignored
      * @param label label for the expansion step
      * @param label_len size of label in bytes
      *
      * @throws Invalid_Argument key_len > 2^32 or MAC is not a HMAC
      */
      void kdf(uint8_t key[],
               size_t key_len,
               const uint8_t secret[],
               size_t secret_len,
               const uint8_t salt[],
               size_t salt_len,
               const uint8_t label[],
               size_t label_len) const override;

      /**
      * @param mac the HMAC to use as the auxiliary function
      */
      explicit SP800_56A_HMAC(std::unique_ptr<MessageAuthenticationCode> mac);

   private:
      std::unique_ptr<MessageAuthenticationCode> m_mac;
};

}  // namespace Botan

#endif
