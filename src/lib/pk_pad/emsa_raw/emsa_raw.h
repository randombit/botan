/*
* EMSA-Raw
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_EMSA_RAW_H_
#define BOTAN_EMSA_RAW_H_

#include <botan/internal/emsa.h>

namespace Botan {

/**
* EMSA-Raw - sign inputs directly
* Don't use this unless you know what you are doing.
*/
class EMSA_Raw final : public EMSA {
   public:
      explicit EMSA_Raw(size_t expected_hash_size = 0) : m_expected_size(expected_hash_size) {}

      std::string hash_function() const override { return "Raw"; }

      std::string name() const override;

   private:
      void update(const uint8_t[], size_t) override;
      std::vector<uint8_t> raw_data() override;

      std::vector<uint8_t> encoding_of(std::span<const uint8_t> raw,
                                       size_t key_bits,
                                       RandomNumberGenerator& rng) override;

      bool verify(std::span<const uint8_t> coded, std::span<const uint8_t> raw, size_t key_bits) override;

      const size_t m_expected_size;
      std::vector<uint8_t> m_message;
};

}  // namespace Botan

#endif
