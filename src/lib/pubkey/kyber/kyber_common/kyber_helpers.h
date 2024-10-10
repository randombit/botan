/*
 * Crystals Kyber Internal Helpers
 *
 * Further changes
 * (C) 2024 Jack Lloyd
 * (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_KYBER_HELPERS_H_
#define BOTAN_KYBER_HELPERS_H_

#include <botan/internal/ct_utils.h>
#include <botan/internal/kyber_constants.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/pqcrystals_helpers.h>

namespace Botan::Kyber_Algos {

/**
 * Special load_le<> that takes 3 bytes and returns a 32-bit integer.
 */
inline uint32_t load_le3(std::span<const uint8_t, 3> in) {
   return Botan::load_le(std::array<uint8_t, 4>{in[0], in[1], in[2], 0});
}

/**
 * NIST FIPS 203, Formula 4.7 (Compress)
 */
template <size_t d>
   requires(d > 0 && d < 12)
constexpr std::make_unsigned_t<KyberConstants::T> compress(KyberConstants::T x) {
   BOTAN_DEBUG_ASSERT(x >= 0 && x < KyberConstants::Q);
   const uint32_t n = (static_cast<uint32_t>(x) << d) + KyberConstants::Q / 2;

   // This is a mitigation for a potential side channel called "KyberSlash".
   //
   // It implements the division by Q using a multiplication and a shift. Most
   // compilers would generate similar code for such a division by a constant.
   // Though, in some cases, compilers might use a variable-time int division,
   // resulting in a potential side channel.
   //
   // The constants below work for all values that appear in Kyber with the
   // greatest being 3328 * 2^11 + Q // 2 = 6,817,408 < 2**23 = 8,388,608.
   //
   //   See "Hacker's Delight" (Second Edition) by Henry S. Warren, Jr.
   //   Chapter 10-9 "Unsigned Division by Divisors >= 1"
   BOTAN_DEBUG_ASSERT(n < (1 << 23));
   static_assert(KyberConstants::Q == 3329);
   using unsigned_T = std::make_unsigned_t<KyberConstants::T>;

   constexpr uint64_t m = 2580335;
   constexpr size_t p = 33;
   constexpr unsigned_T mask = (1 << d) - 1;
   return static_cast<unsigned_T>((n * m) >> p) & mask;
};

/**
 * NIST FIPS 203, Formula 4.8 (Decompress)
 */
template <size_t d>
   requires(d > 0 && d < 12)
constexpr KyberConstants::T decompress(std::make_unsigned_t<KyberConstants::T> x) {
   BOTAN_DEBUG_ASSERT(x >= 0 && x < (1 << d));

   constexpr uint32_t offset = 1 << (d - 1);
   constexpr uint32_t mask = (1 << d) - 1;
   return static_cast<KyberConstants::T>(((static_cast<uint32_t>(x) & mask) * KyberConstants::Q + offset) >> d);
}

}  // namespace Botan::Kyber_Algos

#endif
