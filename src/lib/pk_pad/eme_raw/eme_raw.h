/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_EME_RAW_H_
#define BOTAN_EME_RAW_H_

#include <botan/internal/eme.h>

namespace Botan {

class EME_Raw final : public EME {
   public:
      EME_Raw() = default;

   private:
      size_t maximum_input_size(size_t i) const override;

      size_t pad(std::span<uint8_t> output,
                 std::span<const uint8_t> input,
                 size_t key_length,
                 RandomNumberGenerator& rng) const override;

      CT::Option<size_t> unpad(std::span<uint8_t> output, std::span<const uint8_t> input) const override;
};

}  // namespace Botan

#endif
