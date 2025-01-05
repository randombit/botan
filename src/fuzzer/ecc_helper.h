/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef ECC_HELPERS_H_
#define ECC_HELPERS_H_

#include "fuzzers.h"

#include <botan/ec_group.h>
#include <botan/hex.h>
#include <botan/numthry.h>
#include <botan/reducer.h>

namespace {

inline std::ostream& operator<<(std::ostream& o, const Botan::EC_AffinePoint& point) {
   o << Botan::hex_encode(point.serialize_uncompressed()) << "\n";
   return o;
}

inline Botan::BigInt decompress_point(bool yMod2,
                                      const Botan::BigInt& x,
                                      const Botan::BigInt& curve_p,
                                      const Botan::BigInt& curve_a,
                                      const Botan::BigInt& curve_b) {
   Botan::BigInt xpow3 = x * x * x;

   Botan::BigInt g = curve_a * x;
   g += xpow3;
   g += curve_b;
   g = g % curve_p;

   Botan::BigInt z = sqrt_modulo_prime(g, curve_p);

   if(z < 0) {
      throw Botan::Exception("Could not perform square root");
   }

   if(z.get_bit(0) != yMod2) {
      z = curve_p - z;
   }

   return z;
}

inline void check_ecc_math(const Botan::EC_Group& group, std::span<const uint8_t> in) {
   const size_t hlen = in.size() / 2;

   const auto a = Botan::EC_Scalar::from_bytes_mod_order(group, in.subspan(0, hlen));
   const auto b = Botan::EC_Scalar::from_bytes_mod_order(group, in.subspan(hlen, in.size() - hlen));
   const auto c = a + b;

   if(a.is_zero() || b.is_zero() || c.is_zero()) {
      return;
   }

   auto& rng = fuzzer_rng();
   std::vector<Botan::BigInt> ws;

   const auto P1 = Botan::EC_AffinePoint::g_mul(a, rng, ws);
   const auto Q1 = Botan::EC_AffinePoint::g_mul(b, rng, ws);
   const auto R1 = Botan::EC_AffinePoint::g_mul(c, rng, ws);

   const auto S1 = P1.add(Q1);
   const auto T1 = Q1.add(P1);

   FUZZER_ASSERT_EQUAL(S1, R1);
   FUZZER_ASSERT_EQUAL(T1, R1);

   const auto g = Botan::EC_AffinePoint::generator(group);

   const auto P2 = g.mul(a, rng, ws);
   const auto Q2 = g.mul(b, rng, ws);
   const auto R2 = g.mul(c, rng, ws);

   const auto S2 = P2.add(Q2);
   const auto T2 = Q2.add(P2);

   FUZZER_ASSERT_EQUAL(S2, R2);
   FUZZER_ASSERT_EQUAL(T2, R2);
}

}  // namespace

#endif
