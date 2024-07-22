/*
* EME PKCS#1 v1.5
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_EME_PKCS1_H_
#define BOTAN_EME_PKCS1_H_

#include <botan/internal/eme.h>

namespace Botan {

/**
* EME from PKCS #1 v1.5
*/
class BOTAN_FUZZER_API EME_PKCS1v15 final : public EME {
   private:
      size_t maximum_input_size(size_t) const override;

      size_t pad(std::span<uint8_t> output,
                 std::span<const uint8_t> input,
                 size_t key_length,
                 RandomNumberGenerator& rng) const override;

      CT::Option<size_t> unpad(std::span<uint8_t> output, std::span<const uint8_t> input) const override;
};

}  // namespace Botan

#endif
