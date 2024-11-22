/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_BLS12_381) && defined(BOTAN_HAS_NUMBERTHEORY)
   #include <botan/bls12_381.h>

   #include <botan/bigint.h>
   #include <botan/numthry.h>
   #include <botan/reducer.h>
   #include <botan/internal/loadstor.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_BLS12_381) && defined(BOTAN_HAS_NUMBERTHEORY)

template <typename T>
T random_test_elem(Botan::RandomNumberGenerator& rng) {
   const uint8_t choice = rng.next_byte();

   if(choice == 0) {
      return T::zero();
   } else if(choice == 1) {
      return T::one();
   } else if(choice == 2) {
      return T::one().negate();
   } else if(choice <= 32) {
      const bool flip = (rng.next_byte() % 2) == 1;
      uint32_t x = 0;
      rng.randomize(reinterpret_cast<uint8_t*>(&x), 4);
      auto s = T::from_u32(x);
      return (flip) ? s.negate() : s;
   } else {
      std::array<uint8_t, T::BYTES> buf;

      constexpr uint8_t BIT_MASK = 0xFF >> (8 - (T::BITS % 8));

      for(;;) {
         rng.randomize(buf);
         buf[0] &= BIT_MASK;

         if(auto s = T::deserialize(buf)) {
            return s.value();
         }
      }
   }
}

class BLS12_381_Scalar_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         results.push_back(scalar_serde());
         results.push_back(scalar_vs_bigint());

         return results;
      }

   private:
      Test::Result scalar_vs_bigint() const {
         Test::Result result("Scalar arithmetic");

         result.start_timer();

         Botan::BigInt p = Botan::BigInt::from_bytes(Botan::BLS12_381::Scalar::one().negate().serialize()) + 1;

         Botan::Modular_Reducer mod_p(p);

         for(size_t i = 0; i != 1024; ++i) {
            const auto x_s = random_test_elem<Botan::BLS12_381::Scalar>(rng());
            const auto y_s = random_test_elem<Botan::BLS12_381::Scalar>(rng());

            const auto x_bn = Botan::BigInt::from_bytes(x_s.serialize());
            const auto y_bn = Botan::BigInt::from_bytes(y_s.serialize());

            // Addition test:
            if(true) {
               const auto z_bn = mod_p.reduce(x_bn + y_bn);
               const auto z_s = x_s + y_s;
               result.test_eq("Addition ok", z_bn.serialize(32), z_s.serialize());
            }

            // Subtraction test:
            if(true) {
               const auto z_bn = mod_p.reduce(x_bn - y_bn);
               const auto z_s = x_s - y_s;
               result.test_eq("Subtraction ok", z_bn.serialize(32), z_s.serialize());
            }

            // Multiplication test
            if(true) {
               const auto z_bn = mod_p.reduce(x_bn * y_bn);
               const auto z_s = x_s * y_s;
               result.test_eq("Multiplication ok", z_bn.serialize(32), z_s.serialize());
            }

            // Squaring test
            if(true) {
               const auto x2_bn = mod_p.reduce(x_bn * x_bn);
               const auto x2_s = x_s.square();
               result.test_eq("Squaring ok", x2_bn.serialize(32), x2_s.serialize());

               const auto y2_bn = mod_p.reduce(y_bn * y_bn);
               const auto y2_s = y_s.square();
               result.test_eq("Squaring ok", y2_bn.serialize(32), y2_s.serialize());
            }

            // Inversion test
            if(true) {
               const auto x_s_inv = x_s.invert();
               const auto x_bn_inv = Botan::inverse_mod(x_bn, p);
               result.test_eq("Inversion ok", x_bn_inv.serialize(32), x_s_inv.serialize());

               const auto y_s_inv = y_s.invert();
               const auto y_bn_inv = Botan::inverse_mod(y_bn, p);
               result.test_eq("Inversion ok", y_bn_inv.serialize(32), y_s_inv.serialize());
            }
         }

         // Wide reduction
         for(size_t i = 0; i != 128; ++i) {
            std::array<uint8_t, 64> buf;
            rng().randomize(buf);
            auto s = Botan::BLS12_381::Scalar::from_bytes_wide(buf);
            auto bn = mod_p.reduce(Botan::BigInt::from_bytes(buf));
            result.test_eq("Scalar::from_bytes_wide", bn.serialize(32), s.serialize());
         }

         result.end_timer();

         return result;
      }

      Test::Result scalar_serde() const {
         Test::Result result("Scalar serde");

         result.start_timer();

         result.test_eq("Expected serialization of zero",
                        Botan::BLS12_381::Scalar::zero().serialize(),
                        "0000000000000000000000000000000000000000000000000000000000000000");

         result.test_eq("Expected serialization of one",
                        Botan::BLS12_381::Scalar::one().serialize(),
                        "0000000000000000000000000000000000000000000000000000000000000001");

         result.test_eq("Expected serialization of -1",
                        Botan::BLS12_381::Scalar::one().negate().serialize(),
                        "73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000000");

         result.test_eq("Expected serialization of 666",
                        Botan::BLS12_381::Scalar::from_u32(666).serialize(),
                        "000000000000000000000000000000000000000000000000000000000000029A");

         result.test_eq("Expected serialization of 0xFEDCBA98",
                        Botan::BLS12_381::Scalar::from_u32(0xFEDCBA98).serialize(),
                        "00000000000000000000000000000000000000000000000000000000FEDCBA98");

         for(size_t i = 0; i != 128; ++i) {
            std::array<uint8_t, Botan::BLS12_381::Scalar::BYTES> buf;
            rng().randomize(buf);

            if(auto s = Botan::BLS12_381::Scalar::deserialize(buf)) {
               result.test_eq("Round trip ok", s->serialize(), buf);
            } else {
               const uint64_t first64 = Botan::load_be<uint64_t>(buf.data(), 0);
               result.confirm("Expected leading 64 bits for rejected scalar", first64 >= 0x73EDA753299D7D48);
            }
         }

         result.end_timer();

         return result;
      }
};

BOTAN_REGISTER_TEST("bls12_381", "bls12_381_scalar", BLS12_381_Scalar_Tests);

class BLS12_381_FieldElement_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         results.push_back(scalar_serde());
         results.push_back(scalar_vs_bigint());

         return results;
      }

   private:
      Test::Result scalar_vs_bigint() const {
         Test::Result result("FieldElement arithmetic");

         result.start_timer();

         Botan::BigInt p = Botan::BigInt::from_bytes(Botan::BLS12_381::FieldElement::one().negate().serialize()) + 1;

         Botan::Modular_Reducer mod_p(p);

         for(size_t i = 0; i != 1024; ++i) {
            const auto x_s = random_test_elem<Botan::BLS12_381::FieldElement>(rng());
            const auto y_s = random_test_elem<Botan::BLS12_381::FieldElement>(rng());

            const auto x_bn = Botan::BigInt::from_bytes(x_s.serialize());
            const auto y_bn = Botan::BigInt::from_bytes(y_s.serialize());

            // Addition test:
            if(true) {
               const auto z_bn = mod_p.reduce(x_bn + y_bn);
               const auto z_s = x_s + y_s;
               result.test_eq("Addition ok", z_bn.serialize(48), z_s.serialize());
            }

            // Subtraction test:
            if(true) {
               const auto z_bn = mod_p.reduce(x_bn - y_bn);
               const auto z_s = x_s - y_s;
               result.test_eq("Subtraction ok", z_bn.serialize(48), z_s.serialize());
            }

            // Multiplication test
            if(true) {
               const auto z_bn = mod_p.reduce(x_bn * y_bn);
               const auto z_s = x_s * y_s;
               result.test_eq("Multiplication ok", z_bn.serialize(48), z_s.serialize());
            }

            // Squaring test
            if(true) {
               const auto x2_bn = mod_p.reduce(x_bn * x_bn);
               const auto x2_s = x_s.square();
               result.test_eq("Squaring ok", x2_bn.serialize(48), x2_s.serialize());

               const auto y2_bn = mod_p.reduce(y_bn * y_bn);
               const auto y2_s = y_s.square();
               result.test_eq("Squaring ok", y2_bn.serialize(48), y2_s.serialize());
            }

            // Inversion test
            if(true) {
               const auto x_s_inv = x_s.invert();
               const auto x_bn_inv = Botan::inverse_mod(x_bn, p);
               result.test_eq("Inversion ok", x_bn_inv.serialize(48), x_s_inv.serialize());

               const auto y_s_inv = y_s.invert();
               const auto y_bn_inv = Botan::inverse_mod(y_bn, p);
               result.test_eq("Inversion ok", y_bn_inv.serialize(48), y_s_inv.serialize());
            }
         }

         // Wide reduction
         for(size_t i = 0; i != 128; ++i) {
            std::array<uint8_t, 96> buf;
            rng().randomize(buf);
            auto s = Botan::BLS12_381::FieldElement::from_bytes_wide(buf);
            auto bn = mod_p.reduce(Botan::BigInt::from_bytes(buf));
            result.test_eq("FieldElement::from_bytes_wide", bn.serialize(48), s.serialize());
         }

         result.end_timer();

         return result;
      }

      Test::Result scalar_serde() const {
         Test::Result result("FieldElement serde");

         result.start_timer();

         result.test_eq(
            "Expected serialization of zero",
            Botan::BLS12_381::FieldElement::zero().serialize(),
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

         result.test_eq(
            "Expected serialization of one",
            Botan::BLS12_381::FieldElement::one().serialize(),
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001");

         result.test_eq(
            "Expected serialization of -1",
            Botan::BLS12_381::FieldElement::one().negate().serialize(),
            "1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAA");

         result.test_eq(
            "Expected serialization of 666",
            Botan::BLS12_381::FieldElement::from_u32(666).serialize(),
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000029A");

         result.test_eq(
            "Expected serialization of 0xFEDCBA98",
            Botan::BLS12_381::FieldElement::from_u32(0xFEDCBA98).serialize(),
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000FEDCBA98");

         for(size_t i = 0; i != 128; ++i) {
            std::array<uint8_t, Botan::BLS12_381::FieldElement::BYTES> buf;
            rng().randomize(buf);

            if(auto s = Botan::BLS12_381::FieldElement::deserialize(buf)) {
               result.test_eq("Round trip ok", s->serialize(), buf);
            } else {
               const uint64_t first64 = Botan::load_be<uint64_t>(buf.data(), 0);
               result.confirm("Expected leading 64 bits for rejected scalar", first64 >= 0x1A0111EA397FE69A);
            }
         }

         result.end_timer();

         return result;
      }
};

BOTAN_REGISTER_TEST("bls12_381", "bls12_381_fe", BLS12_381_FieldElement_Tests);

class BLS12_381_G1_Mul_Tests final : public Text_Based_Test {
   public:
      BLS12_381_G1_Mul_Tests() : Text_Based_Test("bls12_381/g1_mul.vec", "P,K,Z") {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override {
         Test::Result result("BLS12-381 G1 mul");

         const auto pt = Botan::BLS12_381::G1Affine::deserialize(vars.get_req_bin("P"));
         const auto k = Botan::BLS12_381::Scalar::deserialize(vars.get_req_bin("K"));
         const auto z = vars.get_req_bin("Z");

         result.confirm("P is accepted", pt.has_value());
         result.confirm("K is accepted", k.has_value());

         auto cz = Botan::BLS12_381::G1Projective::from_affine(pt.value()).mul(k.value());

         result.test_eq("Expected Z", cz.to_affine().serialize(), z);

         return result;
      }
};

BOTAN_REGISTER_TEST("bls12_381", "bls12_381_g1_mul", BLS12_381_G1_Mul_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
