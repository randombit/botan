/*
 * Helper functions to implement Keccak-derived functions from NIST SP.800-185
 * (C) 2023 Jack Lloyd
 * (C) 2023 René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/keccak_helpers.h>

#include <botan/internal/bit_ops.h>
#include <botan/internal/loadstor.h>

#include <limits>

namespace Botan {

namespace {

size_t int_encoding_size(uint64_t x) {
   BOTAN_ASSERT_NOMSG(x < std::numeric_limits<uint64_t>::max());
   return ceil_tobytes(std::max(uint8_t(1), ceil_log2(x + 1)));
}

uint8_t encode(std::span<uint8_t> out, uint64_t x) {
   const auto bytes_needed = int_encoding_size(x);
   BOTAN_ASSERT_NOMSG(out.size() >= bytes_needed);

   std::array<uint8_t, sizeof(x)> bigendian_x;
   store_be(x, bigendian_x.data());

   auto begin = bigendian_x.begin();
   std::advance(begin, sizeof(x) - bytes_needed);
   std::copy(begin, bigendian_x.end(), out.begin());

   return static_cast<uint8_t>(bytes_needed);
}

}  // namespace

std::span<const uint8_t> keccak_int_left_encode(std::span<uint8_t> out, size_t x) {
   BOTAN_ASSERT_NOMSG(!out.empty());
   out[0] = encode(out.last(out.size() - 1), x);
   return out.first(out[0] + 1 /* the length tag */);
}

std::span<const uint8_t> keccak_int_right_encode(std::span<uint8_t> out, size_t x) {
   const auto bytes_needed = encode(out, x);
   BOTAN_ASSERT_NOMSG(out.size() >= bytes_needed + size_t(1));
   out[bytes_needed] = bytes_needed;
   return out.first(bytes_needed + 1 /* the length tag */);
}

size_t keccak_int_encoding_size(size_t x) {
   return int_encoding_size(x) + 1 /* the length tag */;
}

}  // namespace Botan
