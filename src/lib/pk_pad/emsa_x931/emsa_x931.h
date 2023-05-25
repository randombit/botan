/*
* X9.31 EMSA
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_EMSA_X931_H_
#define BOTAN_EMSA_X931_H_

#include <botan/hash.h>
#include <botan/internal/emsa.h>

namespace Botan {

/**
* EMSA from X9.31 (EMSA2 in IEEE 1363)
* Useful for Rabin-Williams, also sometimes used with RSA in
* odd protocols.
*/
class EMSA_X931 final : public EMSA {
   public:
      /**
      * @param hash the hash function to use
      */
      explicit EMSA_X931(std::unique_ptr<HashFunction> hash);

      std::string name() const override;

      std::string hash_function() const override { return m_hash->name(); }

   private:
      void update(const uint8_t[], size_t) override;
      std::vector<uint8_t> raw_data() override;

      std::vector<uint8_t> encoding_of(const std::vector<uint8_t>&, size_t, RandomNumberGenerator& rng) override;

      bool verify(const std::vector<uint8_t>&, const std::vector<uint8_t>&, size_t) override;

      std::vector<uint8_t> m_empty_hash;
      std::unique_ptr<HashFunction> m_hash;
      uint8_t m_hash_id;
};

}  // namespace Botan

#endif
