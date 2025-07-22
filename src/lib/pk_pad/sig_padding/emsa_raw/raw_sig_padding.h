/*
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SIGN_RAW_BYTES_H_
#define BOTAN_SIGN_RAW_BYTES_H_

#include <botan/internal/sig_padding.h>
#include <string>
#include <vector>

namespace Botan {

class RandomNumberGenerator;

/**
* This class sign inputs directly with no intermediate hashing or padding.
*
* This is insecure unless used very carefully.
*/
class SignRawBytes final : public SignaturePaddingScheme {
   public:
      explicit SignRawBytes(size_t expected_hash_size = 0) : m_expected_size(expected_hash_size) {}

      std::string hash_function() const override { return "Raw"; }

      std::string name() const override;

   private:
      void update(const uint8_t input[], size_t length) override;
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
