/*
* PSSR
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PSSR_H_
#define BOTAN_PSSR_H_

#include <botan/hash.h>
#include <botan/internal/emsa.h>
#include <optional>

namespace Botan {

/**
* PSSR (called EMSA4 in IEEE 1363 and in old versions of the library)
*/
class PSSR final : public EMSA {
   public:
      /**
      * @param hash the hash function to use
      * @param salt_size the size of the salt to use in bytes
      */
      PSSR(std::unique_ptr<HashFunction> hash, std::optional<size_t> salt_size);

      std::string name() const override;

      std::string hash_function() const override { return m_hash->name(); }

   private:
      void update(const uint8_t input[], size_t length) override;

      std::vector<uint8_t> raw_data() override;

      std::vector<uint8_t> encoding_of(const std::vector<uint8_t>& msg,
                                       size_t output_bits,
                                       RandomNumberGenerator& rng) override;

      bool verify(const std::vector<uint8_t>& coded, const std::vector<uint8_t>& raw, size_t key_bits) override;

      std::unique_ptr<HashFunction> m_hash;
      size_t m_salt_size;
      bool m_required_salt_len;
};

/**
* PSSR_Raw
* This accepts a pre-hashed buffer
*/
class PSSR_Raw final : public EMSA {
   public:
      /**
      * @param hash the hash function to use
      * @param salt_size the size of the salt to use in bytes
      */
      PSSR_Raw(std::unique_ptr<HashFunction> hash, std::optional<size_t> salt_size = std::nullopt);

      std::string hash_function() const override { return m_hash->name(); }

      std::string name() const override;

   private:
      void update(const uint8_t input[], size_t length) override;

      std::vector<uint8_t> raw_data() override;

      std::vector<uint8_t> encoding_of(const std::vector<uint8_t>& msg,
                                       size_t output_bits,
                                       RandomNumberGenerator& rng) override;

      bool verify(const std::vector<uint8_t>& coded, const std::vector<uint8_t>& raw, size_t key_bits) override;

      std::unique_ptr<HashFunction> m_hash;
      std::vector<uint8_t> m_msg;
      size_t m_salt_size;
      bool m_required_salt_len;
};

}  // namespace Botan

#endif
