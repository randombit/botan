/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef ECC_HELPERS_H_
#define ECC_HELPERS_H_

#include "fuzzers.h"

#include <botan/ec_group.h>
#include <botan/numthry.h>
#include <botan/reducer.h>

namespace {

inline std::ostream& operator<<(std::ostream& o, const Botan::EC_Point& point) {
   o << point.get_affine_x() << "," << point.get_affine_y();
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

inline void check_ecc_math(const Botan::EC_Group& group, const uint8_t in[], size_t len) {
   // These depend only on the group, which is also static
   static const Botan::EC_Point base_point = group.get_base_point();

   // This is shared across runs to reduce overhead
   static std::vector<Botan::BigInt> ws(Botan::EC_Point::WORKSPACE_SIZE);

   const size_t hlen = len / 2;
   const Botan::BigInt a = Botan::BigInt::decode(in, hlen);
   const Botan::BigInt b = Botan::BigInt::decode(in + hlen, len - hlen);
   const Botan::BigInt c = a + b;

   const Botan::EC_Point P1 = base_point * a;
   const Botan::EC_Point Q1 = base_point * b;
   const Botan::EC_Point R1 = base_point * c;

   const Botan::EC_Point S1 = P1 + Q1;
   const Botan::EC_Point T1 = Q1 + P1;

   FUZZER_ASSERT_EQUAL(S1, R1);
   FUZZER_ASSERT_EQUAL(T1, R1);

   const Botan::EC_Point P2 = group.blinded_base_point_multiply(a, fuzzer_rng(), ws);
   const Botan::EC_Point Q2 = group.blinded_base_point_multiply(b, fuzzer_rng(), ws);
   const Botan::EC_Point R2 = group.blinded_base_point_multiply(c, fuzzer_rng(), ws);
   const Botan::EC_Point S2 = P2 + Q2;
   const Botan::EC_Point T2 = Q2 + P2;

   FUZZER_ASSERT_EQUAL(S2, R2);
   FUZZER_ASSERT_EQUAL(T2, R2);

   const Botan::EC_Point P3 = group.blinded_var_point_multiply(base_point, a, fuzzer_rng(), ws);
   const Botan::EC_Point Q3 = group.blinded_var_point_multiply(base_point, b, fuzzer_rng(), ws);
   const Botan::EC_Point R3 = group.blinded_var_point_multiply(base_point, c, fuzzer_rng(), ws);
   const Botan::EC_Point S3 = P3 + Q3;
   const Botan::EC_Point T3 = Q3 + P3;

   FUZZER_ASSERT_EQUAL(S3, R3);
   FUZZER_ASSERT_EQUAL(T3, R3);

   FUZZER_ASSERT_EQUAL(S1, S2);
   FUZZER_ASSERT_EQUAL(S1, S3);

   try {
      const auto yp = decompress_point(true, a, group.get_p(), group.get_a(), group.get_b());
      const auto pt_p = group.blinded_var_point_multiply(group.point(a, yp), b, fuzzer_rng(), ws);

      const auto yn = -yp;
      const auto pt_n = group.blinded_var_point_multiply(group.point(a, yn), b, fuzzer_rng(), ws);

      FUZZER_ASSERT_EQUAL(pt_p, -pt_n);
   } catch(...) {}
}

}  // namespace

#endif
