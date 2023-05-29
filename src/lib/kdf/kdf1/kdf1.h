/*
* KDF1
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_KDF1_H_
#define BOTAN_KDF1_H_

#include <botan/hash.h>
#include <botan/kdf.h>

namespace Botan {

/**
* KDF1, from IEEE 1363
*/
class KDF1 final : public KDF {
   public:
      std::string name() const override;

      std::unique_ptr<KDF> new_object() const override;

      void kdf(uint8_t key[],
               size_t key_len,
               const uint8_t secret[],
               size_t secret_len,
               const uint8_t salt[],
               size_t salt_len,
               const uint8_t label[],
               size_t label_len) const override;

      /**
      * @param hash function to use
      */
      explicit KDF1(std::unique_ptr<HashFunction> hash) : m_hash(std::move(hash)) {}

   private:
      std::unique_ptr<HashFunction> m_hash;
};

}  // namespace Botan

#endif
