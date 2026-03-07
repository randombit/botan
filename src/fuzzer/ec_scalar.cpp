/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include "fuzzers.h"

#include <botan/ec_group.h>
#include <botan/ec_scalar.h>
#include <array>

namespace {

void check_scalar_arith(const Botan::EC_Group& group, std::span<const uint8_t> in) {
   // Need at least 2 scalars worth of input
   const size_t scalar_bytes = group.get_order_bytes();

   if(in.size() < 2 * scalar_bytes || in.size() > 2 * 2 * scalar_bytes) {
      return;
   }

   const auto a = Botan::EC_Scalar::from_bytes_mod_order(group, in.first(in.size() / 2));
   const auto b = Botan::EC_Scalar::from_bytes_mod_order(group, in.last(in.size() / 2));

   const auto one = Botan::EC_Scalar::one(group);

   // a - a == 0
   FUZZER_ASSERT_TRUE((a - a).is_zero());

   // a + (-a) == 0
   FUZZER_ASSERT_TRUE((a + a.negate()).is_zero());

   // a * 1 == a
   FUZZER_ASSERT_TRUE((a * one) == a);

   // a + b == b + a (commutativity)
   FUZZER_ASSERT_TRUE((a + b) == (b + a));

   // a * b == b * a (commutativity)
   FUZZER_ASSERT_TRUE((a * b) == (b * a));

   if(!a.is_zero()) {
      const auto a_inv = a.invert();
      const auto a_inv_vt = a.invert_vartime();

      // invert and invert_vartime agree
      FUZZER_ASSERT_TRUE(a_inv == a_inv_vt);

      // a * a^-1 == 1
      FUZZER_ASSERT_TRUE((a * a_inv) == one);

      // (a^-1)^-1 == a
      FUZZER_ASSERT_TRUE(a_inv.invert() == a);
   }

   if(!b.is_zero()) {
      const auto b_inv = b.invert();
      const auto b_inv_vt = b.invert_vartime();

      FUZZER_ASSERT_TRUE(b_inv == b_inv_vt);
      FUZZER_ASSERT_TRUE((b * b_inv) == one);
   }

   // (a + b) * c == a*c + b*c for c = a (distributivity, reusing a as c)
   FUZZER_ASSERT_TRUE((a + b) * a == (a * a + b * a));

   // square_self: a^2 == a * a
   auto a_sq = Botan::EC_Scalar(a);
   a_sq.square_self();
   FUZZER_ASSERT_TRUE(a_sq == (a * a));

   /*
   Serialization round-trip tests

   The value of zero can be serialized but *not* deserialized
   */
   if(!a.is_zero()) {
      std::vector<uint8_t> a_bytes(scalar_bytes);
      a.serialize_to(a_bytes);
      const auto a_rt = Botan::EC_Scalar::deserialize(group, a_bytes);
      FUZZER_ASSERT_TRUE(a_rt.has_value());
      FUZZER_ASSERT_TRUE(a_rt.value() == a);
   }

   if(!b.is_zero()) {
      std::vector<uint8_t> b_bytes(scalar_bytes);
      b.serialize_to(b_bytes);
      const auto b_rt = Botan::EC_Scalar::deserialize(group, b_bytes);
      FUZZER_ASSERT_TRUE(b_rt.has_value());
      FUZZER_ASSERT_TRUE(b_rt.value() == b);
   }
}

}  // namespace

void fuzz(std::span<const uint8_t> in) {
   // First byte selects the curve
   if(in.empty()) {
      return;
   }

   const uint8_t curve_id = in[0];
   const auto data = in.subspan(1);

   static const Botan::EC_Group p192 = Botan::EC_Group::from_name("secp192r1");
   static const Botan::EC_Group p224 = Botan::EC_Group::from_name("secp224r1");
   static const Botan::EC_Group p256 = Botan::EC_Group::from_name("secp256r1");
   static const Botan::EC_Group p384 = Botan::EC_Group::from_name("secp384r1");
   static const Botan::EC_Group p521 = Botan::EC_Group::from_name("secp521r1");
   static const Botan::EC_Group bp256 = Botan::EC_Group::from_name("brainpool256r1");
   static const Botan::EC_Group bp384 = Botan::EC_Group::from_name("brainpool384r1");
   static const Botan::EC_Group bp512 = Botan::EC_Group::from_name("brainpool512r1");
   static const Botan::EC_Group k256 = Botan::EC_Group::from_name("secp256k1");
   static const Botan::EC_Group frp256 = Botan::EC_Group::from_name("frp256v1");
   static const Botan::EC_Group sm2 = Botan::EC_Group::from_name("sm2p256v1");
   static const Botan::EC_Group numsp512 = Botan::EC_Group::from_name("numsp512d1");

   constexpr size_t total_curves = 12;

   // NOLINTNEXTLINE(*-avoid-c-arrays)
   std::array<const Botan::EC_Group*, total_curves> curves{
      &p192,
      &p224,
      &p256,
      &p384,
      &p521,
      &bp256,
      &bp384,
      &bp512,
      &k256,
      &frp256,
      &sm2,
      &numsp512,
   };

   const auto& group = *curves[curve_id % total_curves];
   check_scalar_arith(group, data);
}
