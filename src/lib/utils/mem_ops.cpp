/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/mem_ops.h>

#include <botan/internal/ct_utils.h>

namespace Botan {

uint8_t ct_compare_u8(const uint8_t x[], const uint8_t y[], size_t len) {
   return CT::is_equal(x, y, len).value();
}

bool constant_time_compare(std::span<const uint8_t> x, std::span<const uint8_t> y) {
   const auto min_size = CT::Mask<size_t>::is_lte(x.size(), y.size()).select(x.size(), y.size());
   const auto equal_size = CT::Mask<size_t>::is_equal(x.size(), y.size());
   const auto equal_content = CT::Mask<size_t>::expand(CT::is_equal(x.data(), y.data(), min_size));
   return (equal_content & equal_size).as_bool();
}

}  // namespace Botan
