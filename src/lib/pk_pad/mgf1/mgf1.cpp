/*
* (C) 1999-2007,2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/mgf1.h>

#include <botan/hash.h>
#include <botan/mem_ops.h>
#include <algorithm>

namespace Botan {

void mgf1_mask(HashFunction& hash, std::span<const uint8_t> input, std::span<uint8_t> output) {
   uint32_t counter = 0;

   std::vector<uint8_t> buffer(hash.output_length());
   while(!output.empty()) {
      hash.update(input);
      hash.update_be(counter);
      hash.final(buffer);

      const size_t xored = std::min<size_t>(buffer.size(), output.size());
      xor_buf(output.first(xored), std::span{buffer}.first(xored));
      output = output.subspan(xored);

      ++counter;
   }
}

}  // namespace Botan
