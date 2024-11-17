/*
* (C) 2024,2025,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_BLS12_381) && defined(BOTAN_HAS_NUMBERTHEORY)
   #include <botan/bls12_381.h>

   #include <botan/bigint.h>
   #include <botan/hash.h>
   #include <botan/hex.h>
   #include <botan/numthry.h>
   #include <botan/reducer.h>
   #include <botan/rng.h>
   #include <botan/internal/bls12_381_fields.h>
   #include <botan/internal/bls12_381_tower.h>
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
      std::array<uint8_t, T::BYTES> buf{};

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
         results.push_back(scalar_hash());

         return results;
      }

   private:
      Test::Result scalar_hash() const {
         using Botan::BLS12_381::Scalar;

         Test::Result result("Scalar hash");

         result.start_timer();

         const auto msg1 = Botan::hex_decode("F00F");
         const auto msg2 = Botan::hex_decode("F00E");
         const auto dst1 = Botan::hex_decode("AABB");
         const auto dst2 = Botan::hex_decode("AABC");

         result.test_bin_eq(
            "Hashing is deterministic", Scalar::hash(msg1, dst1).serialize(), Scalar::hash(msg1, dst1).serialize());
         result.test_bin_ne(
            "Messages are separated", Scalar::hash(msg1, dst1).serialize(), Scalar::hash(msg2, dst1).serialize());
         result.test_bin_ne(
            "Domains are separated", Scalar::hash(msg1, dst1).serialize(), Scalar::hash(msg1, dst2).serialize());

         result.test_throws("Empty domain separation tag rejected", [&]() { Scalar::hash(msg1, {}); });

         result.end_timer();

         return result;
      }

      Test::Result scalar_vs_bigint() const {
         Test::Result result("Scalar arithmetic");

         result.start_timer();

         const Botan::BigInt p = Botan::BigInt::from_bytes(Botan::BLS12_381::Scalar::one().negate().serialize()) + 1;

         const auto mod_p = Botan::Modular_Reducer::for_public_modulus(p);

         for(size_t i = 0; i != 1024; ++i) {
            const auto x_s = random_test_elem<Botan::BLS12_381::Scalar>(rng());
            const auto y_s = random_test_elem<Botan::BLS12_381::Scalar>(rng());

            const auto x_bn = Botan::BigInt::from_bytes(x_s.serialize());
            const auto y_bn = Botan::BigInt::from_bytes(y_s.serialize());

            // Addition test:
            if(true) {
               const auto z_bn = mod_p.reduce(x_bn + y_bn);
               const auto z_s = x_s + y_s;
               result.test_bin_eq("Addition ok", z_bn.serialize(32), z_s.serialize());
            }

            // Subtraction test:
            if(true) {
               const auto z_bn = mod_p.reduce(x_bn - y_bn);
               const auto z_s = x_s - y_s;
               result.test_bin_eq("Subtraction ok", z_bn.serialize(32), z_s.serialize());
            }

            // Multiplication test
            if(true) {
               const auto z_bn = mod_p.reduce(x_bn * y_bn);
               const auto z_s = x_s * y_s;
               result.test_bin_eq("Multiplication ok", z_bn.serialize(32), z_s.serialize());
            }

            // Squaring test
            if(true) {
               const auto x2_bn = mod_p.reduce(x_bn * x_bn);
               const auto x2_s = x_s.square();
               result.test_bin_eq("Squaring ok", x2_bn.serialize(32), x2_s.serialize());

               const auto y2_bn = mod_p.reduce(y_bn * y_bn);
               const auto y2_s = y_s.square();
               result.test_bin_eq("Squaring ok", y2_bn.serialize(32), y2_s.serialize());
            }

            // Inversion test
            if(true) {
               const auto x_s_inv = x_s.invert();
               const auto x_bn_inv = Botan::inverse_mod(x_bn, p);
               result.test_bin_eq("Inversion ok", x_bn_inv.serialize(32), x_s_inv.serialize());

               const auto y_s_inv = y_s.invert();
               const auto y_bn_inv = Botan::inverse_mod(y_bn, p);
               result.test_bin_eq("Inversion ok", y_bn_inv.serialize(32), y_s_inv.serialize());
            }
         }

         // Wide reduction
         for(size_t i = 0; i != 128; ++i) {
            std::array<uint8_t, 64> buf{};
            rng().randomize(buf);
            auto s = Botan::BLS12_381::Scalar::from_bytes_wide(buf);
            auto bn = mod_p.reduce(Botan::BigInt::from_bytes(buf));
            result.test_bin_eq("Scalar::from_bytes_wide", bn.serialize(32), s.serialize());
         }

         result.end_timer();

         return result;
      }

      Test::Result scalar_serde() const {
         Test::Result result("Scalar serde");

         result.start_timer();

         result.test_bin_eq("Expected serialization of zero",
                            Botan::BLS12_381::Scalar::zero().serialize(),
                            "0000000000000000000000000000000000000000000000000000000000000000");

         result.test_bin_eq("Expected serialization of one",
                            Botan::BLS12_381::Scalar::one().serialize(),
                            "0000000000000000000000000000000000000000000000000000000000000001");

         result.test_bin_eq("Expected serialization of -1",
                            Botan::BLS12_381::Scalar::one().negate().serialize(),
                            "73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000000");

         result.test_bin_eq("Expected serialization of 666",
                            Botan::BLS12_381::Scalar::from_u32(666).serialize(),
                            "000000000000000000000000000000000000000000000000000000000000029A");

         result.test_bin_eq("Expected serialization of 0xFEDCBA98",
                            Botan::BLS12_381::Scalar::from_u32(0xFEDCBA98).serialize(),
                            "00000000000000000000000000000000000000000000000000000000FEDCBA98");

         for(size_t i = 0; i != 128; ++i) {
            std::array<uint8_t, Botan::BLS12_381::Scalar::BYTES> buf{};
            rng().randomize(buf);

            if(auto s = Botan::BLS12_381::Scalar::deserialize(buf)) {
               result.test_bin_eq("Round trip ok", s->serialize(), buf);
            } else {
               // A scalar is rejected only if it is >= r or is zero
               const uint64_t first64 = Botan::load_be<uint64_t>(buf.data(), 0);

               const bool exactly_zero = [&]() {
                  for(const uint8_t b : buf) {
                     if(b > 0) {
                        return true;
                     }
                  }
                  return false;
               }();

               result.test_is_true("Rejected scalar is out of range or zero",
                                   exactly_zero || first64 >= 0x73EDA753299D7D48);
            }
         }

         // The group order r itself is rejected as non-canonical
         const auto r_bytes = Botan::hex_decode("73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001");
         result.test_is_true("Scalar equal to r rejected", !Botan::BLS12_381::Scalar::deserialize(r_bytes).has_value());

         // The zero scalar is rejected as a likely mistake
         std::array<uint8_t, Botan::BLS12_381::Scalar::BYTES> zero_buf{};
         result.test_is_true("Zero scalar rejected", !Botan::BLS12_381::Scalar::deserialize(zero_buf).has_value());
         result.test_is_true(
            "Serialized zero rejected on deserialize",
            !Botan::BLS12_381::Scalar::deserialize(Botan::BLS12_381::Scalar::zero().serialize()).has_value());

         // Wrong length is rejected
         std::array<uint8_t, Botan::BLS12_381::Scalar::BYTES - 1> short_buf{};
         result.test_is_true("Wrong length rejected", !Botan::BLS12_381::Scalar::deserialize(short_buf).has_value());

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
         results.push_back(fe_sqrt());

         return results;
      }

   private:
      Test::Result fe_sqrt() const {
         Test::Result result("FieldElement sqrt");

         result.start_timer();

         for(size_t i = 0; i != 128; ++i) {
            const auto x = random_test_elem<Botan::BLS12_381::FieldElement>(rng());
            const auto x2 = x.square();

            const auto s = x2.sqrt();
            if(result.test_is_true("sqrt of a square exists", s.has_value())) {
               result.test_is_true("sqrt returns +-x", (*s == x || *s == x.negate()).as_bool());
            }

            // -1 is not a square since p == 3 (mod 4), so -x^2 has no root for x != 0
            if(!x.is_zero().as_bool()) {
               result.test_is_true("sqrt of a nonsquare fails", !x2.negate().sqrt().has_value());
            }
         }

         const auto zero_sqrt = Botan::BLS12_381::FieldElement::zero().sqrt();
         if(result.test_is_true("sqrt of zero exists", zero_sqrt.has_value())) {
            result.test_is_true("sqrt of zero is zero", zero_sqrt->is_zero().as_bool());
         }

         result.end_timer();

         return result;
      }

      Test::Result scalar_vs_bigint() const {
         Test::Result result("FieldElement arithmetic");

         result.start_timer();

         const Botan::BigInt p =
            Botan::BigInt::from_bytes(Botan::BLS12_381::FieldElement::one().negate().serialize()) + 1;

         const auto mod_p = Botan::Modular_Reducer::for_public_modulus(p);

         for(size_t i = 0; i != 1024; ++i) {
            const auto x_s = random_test_elem<Botan::BLS12_381::FieldElement>(rng());
            const auto y_s = random_test_elem<Botan::BLS12_381::FieldElement>(rng());

            const auto x_bn = Botan::BigInt::from_bytes(x_s.serialize());
            const auto y_bn = Botan::BigInt::from_bytes(y_s.serialize());

            // Addition test:
            if(true) {
               const auto z_bn = mod_p.reduce(x_bn + y_bn);
               const auto z_s = x_s + y_s;
               result.test_bin_eq("Addition ok", z_bn.serialize(48), z_s.serialize());
            }

            // Subtraction test:
            if(true) {
               const auto z_bn = mod_p.reduce(x_bn - y_bn);
               const auto z_s = x_s - y_s;
               result.test_bin_eq("Subtraction ok", z_bn.serialize(48), z_s.serialize());
            }

            // Multiplication test
            if(true) {
               const auto z_bn = mod_p.reduce(x_bn * y_bn);
               const auto z_s = x_s * y_s;
               result.test_bin_eq("Multiplication ok", z_bn.serialize(48), z_s.serialize());
            }

            // Squaring test
            if(true) {
               const auto x2_bn = mod_p.reduce(x_bn * x_bn);
               const auto x2_s = x_s.square();
               result.test_bin_eq("Squaring ok", x2_bn.serialize(48), x2_s.serialize());

               const auto y2_bn = mod_p.reduce(y_bn * y_bn);
               const auto y2_s = y_s.square();
               result.test_bin_eq("Squaring ok", y2_bn.serialize(48), y2_s.serialize());
            }

            // Inversion test
            if(true) {
               const auto x_s_inv = x_s.invert();
               const auto x_bn_inv = Botan::inverse_mod(x_bn, p);
               result.test_bin_eq("Inversion ok", x_bn_inv.serialize(48), x_s_inv.serialize());

               const auto y_s_inv = y_s.invert();
               const auto y_bn_inv = Botan::inverse_mod(y_bn, p);
               result.test_bin_eq("Inversion ok", y_bn_inv.serialize(48), y_s_inv.serialize());
            }
         }

         // Wide reduction
         for(size_t i = 0; i != 128; ++i) {
            std::array<uint8_t, 96> buf{};
            rng().randomize(buf);
            auto s = Botan::BLS12_381::FieldElement::from_bytes_wide(buf);
            auto bn = mod_p.reduce(Botan::BigInt::from_bytes(buf));
            result.test_bin_eq("FieldElement::from_bytes_wide", bn.serialize(48), s.serialize());
         }

         result.end_timer();

         return result;
      }

      Test::Result scalar_serde() const {
         Test::Result result("FieldElement serde");

         result.start_timer();

         result.test_bin_eq(
            "Expected serialization of zero",
            Botan::BLS12_381::FieldElement::zero().serialize(),
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

         result.test_bin_eq(
            "Expected serialization of one",
            Botan::BLS12_381::FieldElement::one().serialize(),
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001");

         result.test_bin_eq(
            "Expected serialization of -1",
            Botan::BLS12_381::FieldElement::one().negate().serialize(),
            "1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAA");

         result.test_bin_eq(
            "Expected serialization of 666",
            Botan::BLS12_381::FieldElement::from_u32(666).serialize(),
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000029A");

         result.test_bin_eq(
            "Expected serialization of 0xFEDCBA98",
            Botan::BLS12_381::FieldElement::from_u32(0xFEDCBA98).serialize(),
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000FEDCBA98");

         for(size_t i = 0; i != 128; ++i) {
            std::array<uint8_t, Botan::BLS12_381::FieldElement::BYTES> buf{};
            rng().randomize(buf);

            if(auto s = Botan::BLS12_381::FieldElement::deserialize(buf)) {
               result.test_bin_eq("Round trip ok", s->serialize(), buf);
            } else {
               const uint64_t first64 = Botan::load_be<uint64_t>(buf.data(), 0);
               result.test_is_true("Expected leading 64 bits for rejected element", first64 >= 0x1A0111EA397FE69A);
            }
         }

         // The field modulus p itself is rejected as non-canonical
         const auto p_bytes = Botan::hex_decode(
            "1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB");
         result.test_is_true("FieldElement equal to p rejected",
                             !Botan::BLS12_381::FieldElement::deserialize(p_bytes).has_value());

         // Wrong length is rejected
         std::array<uint8_t, Botan::BLS12_381::FieldElement::BYTES - 1> short_buf{};
         result.test_is_true("Wrong length rejected",
                             !Botan::BLS12_381::FieldElement::deserialize(short_buf).has_value());

         result.end_timer();

         return result;
      }
};

BOTAN_REGISTER_TEST("bls12_381", "bls12_381_fe", BLS12_381_FieldElement_Tests);

Botan::BLS12_381::FieldElement2 random_fp2(Botan::RandomNumberGenerator& rng) {
   const auto c0 = random_test_elem<Botan::BLS12_381::FieldElement>(rng);
   const auto c1 = random_test_elem<Botan::BLS12_381::FieldElement>(rng);
   return Botan::BLS12_381::FieldElement2(c0, c1);
}

class BLS12_381_Fp2_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         results.push_back(fp2_serde());
         results.push_back(fp2_vs_bigint());
         results.push_back(fp2_sqrt());

         return results;
      }

   private:
      Test::Result fp2_serde() const {
         using Botan::BLS12_381::FieldElement2;

         Test::Result result("Fp2 serde");

         result.start_timer();

         result.test_bin_eq(
            "Expected serialization of one",
            FieldElement2::one().serialize(),
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001");

         for(size_t i = 0; i != 64; ++i) {
            const auto x = random_fp2(rng());
            const auto x2 = FieldElement2::deserialize(x.serialize());
            if(result.test_is_true("Round trip deserializes", x2.has_value())) {
               result.test_is_true("Round trip value", (*x2 == x).as_bool());
            }
         }

         // c0 out of range (the encoding of -1 with c0 replaced by p)
         const char* p_hex =
            "1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB";
         const auto p_bytes = Botan::hex_decode(p_hex);

         std::array<uint8_t, FieldElement2::BYTES> buf{};
         std::copy(p_bytes.begin(), p_bytes.end(), buf.begin());
         result.test_is_true("Non-canonical c1 rejected", !FieldElement2::deserialize(buf).has_value());

         std::array<uint8_t, FieldElement2::BYTES> buf2{};
         std::copy(p_bytes.begin(), p_bytes.end(), buf2.begin() + FieldElement2::BYTES / 2);
         result.test_is_true("Non-canonical c0 rejected", !FieldElement2::deserialize(buf2).has_value());

         std::array<uint8_t, FieldElement2::BYTES - 1> short_buf{};
         result.test_is_true("Wrong length rejected", !FieldElement2::deserialize(short_buf).has_value());

         result.end_timer();

         return result;
      }

      Test::Result fp2_vs_bigint() const {
         using Botan::BLS12_381::FieldElement2;

         Test::Result result("Fp2 arithmetic");

         result.start_timer();

         const Botan::BigInt p =
            Botan::BigInt::from_bytes(Botan::BLS12_381::FieldElement::one().negate().serialize()) + 1;
         const auto mod_p = Botan::Modular_Reducer::for_public_modulus(p);

         auto fp2_to_bn = [](const FieldElement2& x) {
            return std::pair{Botan::BigInt::from_bytes(x.c0().serialize()),
                             Botan::BigInt::from_bytes(x.c1().serialize())};
         };

         auto bn_eq =
            [&](const char* what, const FieldElement2& x, const Botan::BigInt& c0_bn, const Botan::BigInt& c1_bn) {
               result.test_bin_eq(what, x.c0().serialize(), mod_p.reduce(c0_bn).serialize(48));
               result.test_bin_eq(what, x.c1().serialize(), mod_p.reduce(c1_bn).serialize(48));
            };

         for(size_t i = 0; i != 256; ++i) {
            const auto x = random_fp2(rng());
            const auto y = random_fp2(rng());

            const auto [x0, x1] = fp2_to_bn(x);
            const auto [y0, y1] = fp2_to_bn(y);

            bn_eq("Addition", x + y, x0 + y0, x1 + y1);
            bn_eq("Subtraction", x - y, x0 - y0, x1 - y1);
            bn_eq("Multiplication", x * y, x0 * y0 - x1 * y1, x0 * y1 + x1 * y0);
            bn_eq("Squaring", x.square(), x0 * x0 - x1 * x1, x0 * x1 + x1 * x0);
            bn_eq("Negation", x.negate(), -x0, -x1);
            bn_eq("Conjugation", x.conjugate(), x0, -x1);
            bn_eq("Nonresidue mul", x.mul_by_nonresidue(), x0 - x1, x0 + x1);

            const auto xinv = x.invert();
            result.test_is_true(
               "Inversion",
               x.is_zero().as_bool() ? xinv.is_zero().as_bool() : ((x * xinv) == FieldElement2::one()).as_bool());
         }

         result.end_timer();

         return result;
      }

      Test::Result fp2_sqrt() const {
         using Botan::BLS12_381::FieldElement2;

         Test::Result result("Fp2 sqrt");

         result.start_timer();

         for(size_t i = 0; i != 64; ++i) {
            const auto x = random_fp2(rng());
            const auto x2 = x.square();

            const auto s = x2.sqrt();
            if(result.test_is_true("sqrt of a square exists", s.has_value())) {
               result.test_is_true("sqrt returns +-x", (*s == x || *s == x.negate()).as_bool());
            }

            // (u+1) is a quadratic nonresidue in Fp2
            if(!x.is_zero().as_bool()) {
               result.test_is_true("sqrt of a nonsquare fails", !x2.mul_by_nonresidue().sqrt().has_value());
            }
         }

         const auto zero_sqrt = FieldElement2::zero().sqrt();
         if(result.test_is_true("sqrt of zero exists", zero_sqrt.has_value())) {
            result.test_is_true("sqrt of zero is zero", zero_sqrt->is_zero().as_bool());
         }

         result.end_timer();

         return result;
      }
};

BOTAN_REGISTER_TEST("bls12_381", "bls12_381_fp2", BLS12_381_Fp2_Tests);

class BLS12_381_Fp2_Arith_Tests final : public Text_Based_Test {
   public:
      BLS12_381_Fp2_Arith_Tests() : Text_Based_Test("bls12_381/fp2_arith.vec", "X,Y,A,S,M,I") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         using Botan::BLS12_381::FieldElement2;

         Test::Result result("BLS12-381 Fp2 arithmetic KAT");

         const auto x = FieldElement2::deserialize(vars.get_req_bin("X"));
         const auto y = FieldElement2::deserialize(vars.get_req_bin("Y"));

         result.test_is_true("X is accepted", x.has_value());
         result.test_is_true("Y is accepted", y.has_value());

         result.test_bin_eq("X+Y", (*x + *y).serialize(), vars.get_req_bin("A"));
         result.test_bin_eq("X-Y", (*x - *y).serialize(), vars.get_req_bin("S"));
         result.test_bin_eq("X*Y", (*x * *y).serialize(), vars.get_req_bin("M"));
         result.test_bin_eq("1/X", x->invert().serialize(), vars.get_req_bin("I"));

         return result;
      }
};

BOTAN_REGISTER_TEST("bls12_381", "bls12_381_fp2_arith", BLS12_381_Fp2_Arith_Tests);

Botan::BLS12_381::Fp6 random_fp6(Botan::RandomNumberGenerator& rng) {
   return Botan::BLS12_381::Fp6(random_fp2(rng), random_fp2(rng), random_fp2(rng));
}

Botan::BLS12_381::Fp12 random_fp12(Botan::RandomNumberGenerator& rng) {
   return Botan::BLS12_381::Fp12(random_fp6(rng), random_fp6(rng));
}

Botan::BLS12_381::Fp12 fp12_pow(const Botan::BLS12_381::Fp12& x, const Botan::BigInt& e) {
   auto r = Botan::BLS12_381::Fp12::one();
   for(size_t i = e.bits(); i > 0; --i) {
      r = r.square();
      if(e.get_bit(i - 1)) {
         r = r * x;
      }
   }
   return r;
}

std::optional<Botan::BLS12_381::Fp12> fp12_deserialize(std::span<const uint8_t> bytes) {
   using namespace Botan::BLS12_381;

   if(bytes.size() != Fp12::BYTES) {
      return {};
   }

   std::array<FieldElement, 12> coeffs;
   for(size_t i = 0; i != coeffs.size(); ++i) {
      auto fe = FieldElement::deserialize(bytes.subspan(i * FieldElement::BYTES, FieldElement::BYTES));
      if(!fe) {
         return {};
      }
      coeffs[i] = *fe;
   }

   auto fp6_at = [&](size_t base) {
      return Fp6(FieldElement2(coeffs[base], coeffs[base + 1]),
                 FieldElement2(coeffs[base + 2], coeffs[base + 3]),
                 FieldElement2(coeffs[base + 4], coeffs[base + 5]));
   };

   return Fp12(fp6_at(0), fp6_at(6));
}

class BLS12_381_Tower_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         results.push_back(fp6_ops());
         results.push_back(fp12_ops());
         results.push_back(frobenius());

         return results;
      }

   private:
      Test::Result fp6_ops() const {
         using namespace Botan::BLS12_381;

         Test::Result result("Fp6 operations");

         result.start_timer();

         result.test_is_true("one is not zero", !Fp6::one().is_zero().as_bool());
         result.test_is_true("zero is zero", Fp6::zero().is_zero().as_bool());
         result.test_is_true("inverse of zero is zero", Fp6::zero().invert().is_zero().as_bool());

         for(size_t i = 0; i != 64; ++i) {
            const auto x = random_fp6(rng());
            const auto y = random_fp6(rng());
            const auto z = random_fp6(rng());

            result.test_is_true("addition commutes", (x + y == y + x).as_bool());
            result.test_is_true("multiplication commutes", (x * y == y * x).as_bool());
            result.test_is_true("multiplication associates", ((x * y) * z == x * (y * z)).as_bool());
            result.test_is_true("distributive law", (x * (y + z) == x * y + x * z).as_bool());
            result.test_is_true("squaring matches multiplication", (x.square() == x * x).as_bool());
            result.test_is_true("negation", (x - x).is_zero().as_bool());  // NOLINT(*-redundant-expression)

            if(!x.is_zero().as_bool()) {
               result.test_is_true("x times inverse is one", (x * x.invert() == Fp6::one()).as_bool());
            }

            const auto b0 = random_fp2(rng());
            const auto b1 = random_fp2(rng());

            result.test_is_true(
               "mul_by_nonresidue matches",
               (x.mul_by_nonresidue() == x * Fp6(FieldElement2::zero(), FieldElement2::one(), FieldElement2::zero()))
                  .as_bool());
            result.test_is_true(
               "mul_by_1 matches",
               (x.mul_by_1(b1) == x * Fp6(FieldElement2::zero(), b1, FieldElement2::zero())).as_bool());
            result.test_is_true("mul_by_01 matches",
                                (x.mul_by_01(b0, b1) == x * Fp6(b0, b1, FieldElement2::zero())).as_bool());
         }

         result.end_timer();

         return result;
      }

      Test::Result fp12_ops() const {
         using namespace Botan::BLS12_381;

         Test::Result result("Fp12 operations");

         result.start_timer();

         result.test_is_true("one is not zero", !Fp12::one().is_zero().as_bool());
         result.test_is_true("inverse of zero is zero", Fp12::zero().invert().is_zero().as_bool());

         for(size_t i = 0; i != 64; ++i) {
            const auto x = random_fp12(rng());
            const auto y = random_fp12(rng());
            const auto z = random_fp12(rng());

            result.test_is_true("addition commutes", (x + y == y + x).as_bool());
            result.test_is_true("multiplication commutes", (x * y == y * x).as_bool());
            result.test_is_true("multiplication associates", ((x * y) * z == x * (y * z)).as_bool());
            result.test_is_true("distributive law", (x * (y + z) == x * y + x * z).as_bool());
            result.test_is_true("squaring matches multiplication", (x.square() == x * x).as_bool());

            if(!x.is_zero().as_bool()) {
               result.test_is_true("x times inverse is one", (x * x.invert() == Fp12::one()).as_bool());
            }

            const auto b0 = random_fp2(rng());
            const auto b1 = random_fp2(rng());
            const auto b4 = random_fp2(rng());

            const auto sparse =
               Fp12(Fp6(b0, b1, FieldElement2::zero()), Fp6(FieldElement2::zero(), b4, FieldElement2::zero()));
            result.test_is_true("mul_by_014 matches", (x.mul_by_014(b0, b1, b4) == x * sparse).as_bool());

            // An element of the cyclotomic subgroup, via the easy part of
            // the final exponentiation: g = f^((p^6-1)(p^2+1))
            if(!x.is_zero().as_bool()) {
               const auto t = x.conjugate() * x.invert();
               const auto g = t.frobenius_map().frobenius_map() * t;
               result.test_is_true("cyclotomic squaring matches", (g.cyclotomic_square() == g.square()).as_bool());
            }
         }

         result.end_timer();

         return result;
      }

      Test::Result frobenius() const {
         using namespace Botan::BLS12_381;

         Test::Result result("Fp12 Frobenius");

         result.start_timer();

         const Botan::BigInt p = Botan::BigInt::from_bytes(FieldElement::one().negate().serialize()) + 1;

         for(size_t i = 0; i != 8; ++i) {
            const auto x = random_fp12(rng());

            result.test_is_true("frobenius is x^p", (x.frobenius_map() == fp12_pow(x, p)).as_bool());

            auto frob12 = x;
            for(size_t j = 0; j != 12; ++j) {
               frob12 = frob12.frobenius_map();
            }
            result.test_is_true("frobenius^12 is the identity map", (frob12 == x).as_bool());

            auto frob6 = x;
            for(size_t j = 0; j != 6; ++j) {
               frob6 = frob6.frobenius_map();
            }
            result.test_is_true("frobenius^6 is conjugation", (frob6 == x.conjugate()).as_bool());

            const auto y = random_fp12(rng());
            result.test_is_true("frobenius is multiplicative",
                                ((x * y).frobenius_map() == x.frobenius_map() * y.frobenius_map()).as_bool());
         }

         result.end_timer();

         return result;
      }
};

BOTAN_REGISTER_TEST("bls12_381", "bls12_381_tower", BLS12_381_Tower_Tests);

class BLS12_381_Fp12_Arith_Tests final : public Text_Based_Test {
   public:
      BLS12_381_Fp12_Arith_Tests() : Text_Based_Test("bls12_381/fp12_arith.vec", "X,Y,M,I") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         using Botan::BLS12_381::Fp12;

         Test::Result result("BLS12-381 Fp12 arithmetic KAT");

         const auto x = fp12_deserialize(vars.get_req_bin("X"));
         const auto y = fp12_deserialize(vars.get_req_bin("Y"));

         result.test_is_true("X is accepted", x.has_value());
         result.test_is_true("Y is accepted", y.has_value());

         result.test_bin_eq("X*Y", (*x * *y).serialize(), vars.get_req_bin("M"));
         result.test_bin_eq("1/X", x->invert().serialize(), vars.get_req_bin("I"));

         return result;
      }
};

BOTAN_REGISTER_TEST("bls12_381", "bls12_381_fp12_arith", BLS12_381_Fp12_Arith_Tests);

class BLS12_381_G1_Mul_Tests final : public Text_Based_Test {
   public:
      BLS12_381_G1_Mul_Tests() : Text_Based_Test("bls12_381/g1_mul.vec", "P,K,Z") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("BLS12-381 G1 mul");

         const auto pt = Botan::BLS12_381::G1Affine::deserialize(vars.get_req_bin("P"));
         const auto k = Botan::BLS12_381::Scalar::deserialize(vars.get_req_bin("K"));
         const auto z = vars.get_req_bin("Z");

         result.test_is_true("P is accepted", pt.has_value());
         result.test_is_true("K is accepted", k.has_value());

         auto cz = Botan::BLS12_381::G1Projective::from_affine(pt.value()).mul(k.value());

         result.test_bin_eq("Expected Z", cz.to_affine().serialize(), z);

         return result;
      }
};

BOTAN_REGISTER_TEST("bls12_381", "bls12_381_g1_mul", BLS12_381_G1_Mul_Tests);

class BLS12_381_G1_Deser_Tests final : public Text_Based_Test {
   public:
      BLS12_381_G1_Deser_Tests() : Text_Based_Test("bls12_381/g1_deser.vec", "P") {}

      Test::Result run_one_test(const std::string& header, const VarMap& vars) override {
         Test::Result result("BLS12-381 G1 deserialization");

         const auto bytes = vars.get_req_bin("P");
         const auto pt = Botan::BLS12_381::G1Affine::deserialize(bytes);

         if(header == "Valid") {
            if(result.test_is_true("Valid encoding accepted", pt.has_value())) {
               result.test_bin_eq("Round trip", pt->serialize(), bytes);
            }
         } else {
            result.test_is_true("Invalid encoding rejected", !pt.has_value());
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("bls12_381", "bls12_381_g1_deser", BLS12_381_G1_Deser_Tests);

class BLS12_381_G1_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         results.push_back(g1_group_law());
         results.push_back(g1_mul2());
         results.push_back(g1_msm());
         results.push_back(g1_batch_affine());

         return results;
      }

   private:
      Test::Result g1_mul2() const {
         using Botan::BLS12_381::G1Projective;
         using Botan::BLS12_381::Scalar;

         Test::Result result("G1 2-ary multiplication");

         result.start_timer();

         const auto g = G1Projective::generator();

         for(size_t i = 0; i != 8; ++i) {
            const auto p = g.mul(random_test_elem<Scalar>(rng()));
            const auto q = g.mul(random_test_elem<Scalar>(rng()));
            const auto a = random_test_elem<Scalar>(rng());
            const auto b = random_test_elem<Scalar>(rng());

            const auto ref = p.mul(a).add(q.mul(b));

            result.test_bin_eq("mul2 matches mul+add",
                               G1Projective::mul2(p, a, q, b).to_affine().serialize(),
                               ref.to_affine().serialize());
            result.test_bin_eq("mul2_vartime matches mul+add",
                               G1Projective::mul2_vartime(p, a, q, b).to_affine().serialize(),
                               ref.to_affine().serialize());

            // p == q exercises the doubling case within additions
            result.test_bin_eq("mul2 with equal points",
                               G1Projective::mul2(p, a, p, b).to_affine().serialize(),
                               p.mul(a + b).to_affine().serialize());

            result.test_bin_eq("mul2 with zero scalar",
                               G1Projective::mul2(p, Scalar::zero(), q, b).to_affine().serialize(),
                               q.mul(b).to_affine().serialize());
            result.test_bin_eq("mul2_vartime with zero scalar",
                               G1Projective::mul2_vartime(p, a, q, Scalar::zero()).to_affine().serialize(),
                               p.mul(a).to_affine().serialize());

            result.test_bin_eq("mul2 with identity point",
                               G1Projective::mul2(G1Projective::identity(), a, q, b).to_affine().serialize(),
                               q.mul(b).to_affine().serialize());
         }

         result.test_is_true("mul2 of zeros is the identity",
                             G1Projective::mul2(g, Scalar::zero(), g, Scalar::zero()).is_identity());
         result.test_is_true("mul2_vartime of zeros is the identity",
                             G1Projective::mul2_vartime(g, Scalar::zero(), g, Scalar::zero()).is_identity());

         result.end_timer();

         return result;
      }

      Test::Result g1_msm() const {
         using Botan::BLS12_381::G1Affine;
         using Botan::BLS12_381::G1Projective;
         using Botan::BLS12_381::Scalar;

         Test::Result result("G1 multiscalar multiplication");

         result.start_timer();

         result.test_is_true("Empty sum is the identity", G1Projective::msm_vartime({}, {}).is_identity());

         result.test_throws("Mismatched span lengths throw", [&]() {
            const std::array<G1Affine, 1> p{G1Affine::generator()};
            G1Projective::msm_vartime(p, {});
         });

         const auto g = G1Projective::generator();

         // Sizes on both sides of the dispatch between the 2-ary chain
         // and the Pippenger bucket method
         for(const size_t n : {1, 2, 3, 15, 16, 40}) {
            std::vector<G1Affine> points;
            std::vector<Scalar> scalars;

            auto naive = G1Projective::identity();
            for(size_t i = 0; i != n; ++i) {
               // Include edge cases: the identity point and special scalars
               const auto pt = (i == 1) ? G1Affine::identity() : g.mul(random_test_elem<Scalar>(rng())).to_affine();
               const auto k = random_test_elem<Scalar>(rng());

               points.push_back(pt);
               scalars.push_back(k);
               naive = naive.add(G1Projective::from_affine(pt).mul(k));
            }

            const auto msm = G1Projective::msm_vartime(points, scalars);
            result.test_bin_eq("MSM matches naive sum for n=" + std::to_string(n),
                               msm.to_affine().serialize(),
                               naive.to_affine().serialize());
         }

         result.end_timer();

         return result;
      }

      Test::Result g1_batch_affine() const {
         using Botan::BLS12_381::G1Projective;
         using Botan::BLS12_381::Scalar;

         Test::Result result("G1 batch affine conversion");

         result.start_timer();

         result.test_sz_eq("Empty batch", G1Projective::to_affine_batch({}).size(), 0);

         const auto g = G1Projective::generator();

         // Sizes chosen to place identity elements (every third point)
         // first, last, and in the interior of the batch
         for(const size_t n : {1, 2, 3, 4, 20}) {
            std::vector<G1Projective> pts;
            pts.reserve(n);
            for(size_t i = 0; i != n; ++i) {
               if(i % 3 == 0) {
                  pts.push_back(G1Projective::identity());
               } else {
                  pts.push_back(g.mul(random_test_elem<Scalar>(rng())));
               }
            }

            const auto affine = G1Projective::to_affine_batch(pts);

            if(result.test_sz_eq("Batch size matches for n=" + std::to_string(n), affine.size(), n)) {
               for(size_t i = 0; i != n; ++i) {
                  const auto ref = pts[i].to_affine();
                  result.test_is_true("Batch identity flag matches", affine[i].is_identity() == ref.is_identity());
                  result.test_bin_eq("Batch x matches", affine[i]._x().serialize(), ref._x().serialize());
                  result.test_bin_eq("Batch y matches", affine[i]._y().serialize(), ref._y().serialize());
                  result.test_bin_eq("Batch serialization matches", affine[i].serialize(), ref.serialize());
               }
            }
         }

         result.end_timer();

         return result;
      }

      Test::Result g1_group_law() const {
         using Botan::BLS12_381::G1Affine;
         using Botan::BLS12_381::G1Projective;
         using Botan::BLS12_381::Scalar;

         Test::Result result("G1 group operations");

         result.start_timer();

         const auto g = G1Projective::generator();

         result.test_bin_eq("Affine and projective generator serialize identically",
                            g.to_affine().serialize(),
                            G1Affine::generator().serialize());

         result.test_is_true("Generator is not the identity", !g.is_identity());
         result.test_is_true("Identity is the identity", G1Projective::identity().is_identity());

         result.test_bin_eq("0*G is the identity",
                            g.mul(Scalar::zero()).to_affine().serialize(),
                            G1Projective::identity().to_affine().serialize());

         // Regression test: to_affine must canonicalize the identity, so
         // that round tripping it through from_affine yields a valid
         // (non absorbing) projective identity
         result.test_bin_eq("Identity affine round trip is not absorbing",
                            G1Projective::from_affine(g.mul(Scalar::zero()).to_affine()).add(g).to_affine().serialize(),
                            g.to_affine().serialize());

         result.test_bin_eq("1*G is G", g.mul(Scalar::one()).to_affine().serialize(), g.to_affine().serialize());

         for(size_t i = 0; i != 16; ++i) {
            const auto a = random_test_elem<Scalar>(rng());
            const auto b = random_test_elem<Scalar>(rng());

            const auto apb_g = g.mul(a + b);
            const auto ag_bg = g.mul(a).add(g.mul(b));
            result.test_bin_eq("(a+b)*G == a*G + b*G", apb_g.to_affine().serialize(), ag_bg.to_affine().serialize());

            const auto ab_g = g.mul(a * b);
            const auto b_ag = g.mul(a).mul(b);
            result.test_bin_eq("(a*b)*G == b*(a*G)", ab_g.to_affine().serialize(), b_ag.to_affine().serialize());

            const auto ag = g.mul(a);
            const auto ag_maybe = G1Affine::deserialize(ag.to_affine().serialize());
            if(result.test_is_true("Serialization of a*G accepted", ag_maybe.has_value())) {
               result.test_bin_eq("Round trip of a*G", ag_maybe->serialize(), ag.to_affine().serialize());
            }

            const auto sum = ag.add(ag.negate());
            result.test_is_true("P + -P is the identity", sum.is_identity());

            const auto mixed = ag.add_mixed(g.mul(b).to_affine());
            result.test_bin_eq(
               "Mixed and projective addition agree", mixed.to_affine().serialize(), apb_g.to_affine().serialize());

            const auto plus_identity = ag.add_mixed(G1Affine::identity());
            result.test_bin_eq(
               "Mixed addition of the identity", plus_identity.to_affine().serialize(), ag.to_affine().serialize());
         }

         result.end_timer();

         return result;
      }
};

BOTAN_REGISTER_TEST("bls12_381", "bls12_381_g1", BLS12_381_G1_Tests);

class BLS12_381_G2_Mul_Tests final : public Text_Based_Test {
   public:
      BLS12_381_G2_Mul_Tests() : Text_Based_Test("bls12_381/g2_mul.vec", "P,K,Z") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("BLS12-381 G2 mul");

         const auto pt = Botan::BLS12_381::G2Affine::deserialize(vars.get_req_bin("P"));
         const auto k = Botan::BLS12_381::Scalar::deserialize(vars.get_req_bin("K"));
         const auto z = vars.get_req_bin("Z");

         result.test_is_true("P is accepted", pt.has_value());
         result.test_is_true("K is accepted", k.has_value());

         auto cz = Botan::BLS12_381::G2Projective::from_affine(pt.value()).mul(k.value());

         result.test_bin_eq("Expected Z", cz.to_affine().serialize(), z);

         return result;
      }
};

BOTAN_REGISTER_TEST("bls12_381", "bls12_381_g2_mul", BLS12_381_G2_Mul_Tests);

class BLS12_381_G2_Deser_Tests final : public Text_Based_Test {
   public:
      BLS12_381_G2_Deser_Tests() : Text_Based_Test("bls12_381/g2_deser.vec", "P") {}

      Test::Result run_one_test(const std::string& header, const VarMap& vars) override {
         Test::Result result("BLS12-381 G2 deserialization");

         const auto bytes = vars.get_req_bin("P");
         const auto pt = Botan::BLS12_381::G2Affine::deserialize(bytes);

         if(header == "Valid") {
            if(result.test_is_true("Valid encoding accepted", pt.has_value())) {
               result.test_bin_eq("Round trip", pt->serialize(), bytes);
            }
         } else {
            result.test_is_true("Invalid encoding rejected", !pt.has_value());
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("bls12_381", "bls12_381_g2_deser", BLS12_381_G2_Deser_Tests);

class BLS12_381_G2_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         results.push_back(g2_group_law());
         results.push_back(g2_mul2());
         results.push_back(g2_msm());
         results.push_back(g2_batch_affine());

         return results;
      }

   private:
      Test::Result g2_mul2() const {
         using Botan::BLS12_381::G2Projective;
         using Botan::BLS12_381::Scalar;

         Test::Result result("G2 2-ary multiplication");

         result.start_timer();

         const auto g = G2Projective::generator();

         for(size_t i = 0; i != 4; ++i) {
            const auto p = g.mul(random_test_elem<Scalar>(rng()));
            const auto q = g.mul(random_test_elem<Scalar>(rng()));
            const auto a = random_test_elem<Scalar>(rng());
            const auto b = random_test_elem<Scalar>(rng());

            const auto ref = p.mul(a).add(q.mul(b));

            result.test_bin_eq("mul2 matches mul+add",
                               G2Projective::mul2(p, a, q, b).to_affine().serialize(),
                               ref.to_affine().serialize());
            result.test_bin_eq("mul2_vartime matches mul+add",
                               G2Projective::mul2_vartime(p, a, q, b).to_affine().serialize(),
                               ref.to_affine().serialize());

            // p == q exercises the doubling case within additions
            result.test_bin_eq("mul2 with equal points",
                               G2Projective::mul2(p, a, p, b).to_affine().serialize(),
                               p.mul(a + b).to_affine().serialize());

            result.test_bin_eq("mul2 with identity point",
                               G2Projective::mul2(G2Projective::identity(), a, q, b).to_affine().serialize(),
                               q.mul(b).to_affine().serialize());
         }

         result.test_is_true("mul2 of zeros is the identity",
                             G2Projective::mul2(g, Scalar::zero(), g, Scalar::zero()).is_identity());

         result.end_timer();

         return result;
      }

      Test::Result g2_msm() const {
         using Botan::BLS12_381::G2Affine;
         using Botan::BLS12_381::G2Projective;
         using Botan::BLS12_381::Scalar;

         Test::Result result("G2 multiscalar multiplication");

         result.start_timer();

         result.test_is_true("Empty sum is the identity", G2Projective::msm_vartime({}, {}).is_identity());

         const auto g = G2Projective::generator();

         // Sizes on both sides of the dispatch between the 2-ary chain
         // and the Pippenger bucket method
         for(const size_t n : {1, 2, 3, 15, 16}) {
            std::vector<G2Affine> points;
            std::vector<Scalar> scalars;

            auto naive = G2Projective::identity();
            for(size_t i = 0; i != n; ++i) {
               const auto pt = (i == 1) ? G2Affine::identity() : g.mul(random_test_elem<Scalar>(rng())).to_affine();
               const auto k = random_test_elem<Scalar>(rng());

               points.push_back(pt);
               scalars.push_back(k);
               naive = naive.add(G2Projective::from_affine(pt).mul(k));
            }

            const auto msm = G2Projective::msm_vartime(points, scalars);
            result.test_bin_eq("MSM matches naive sum for n=" + std::to_string(n),
                               msm.to_affine().serialize(),
                               naive.to_affine().serialize());
         }

         result.end_timer();

         return result;
      }

      Test::Result g2_batch_affine() const {
         using Botan::BLS12_381::G2Projective;
         using Botan::BLS12_381::Scalar;

         Test::Result result("G2 batch affine conversion");

         result.start_timer();

         result.test_sz_eq("Empty batch", G2Projective::to_affine_batch({}).size(), 0);

         const auto g = G2Projective::generator();

         // Sizes chosen to place identity elements (every third point)
         // first, last, and in the interior of the batch
         for(const size_t n : {1, 2, 3, 4, 20}) {
            std::vector<G2Projective> pts;
            pts.reserve(n);
            for(size_t i = 0; i != n; ++i) {
               if(i % 3 == 0) {
                  pts.push_back(G2Projective::identity());
               } else {
                  pts.push_back(g.mul(random_test_elem<Scalar>(rng())));
               }
            }

            const auto affine = G2Projective::to_affine_batch(pts);

            if(result.test_sz_eq("Batch size matches for n=" + std::to_string(n), affine.size(), n)) {
               for(size_t i = 0; i != n; ++i) {
                  const auto ref = pts[i].to_affine();
                  result.test_is_true("Batch identity flag matches", affine[i].is_identity() == ref.is_identity());
                  result.test_bin_eq("Batch x matches", affine[i]._x().serialize(), ref._x().serialize());
                  result.test_bin_eq("Batch y matches", affine[i]._y().serialize(), ref._y().serialize());
                  result.test_bin_eq("Batch serialization matches", affine[i].serialize(), ref.serialize());
               }
            }
         }

         result.end_timer();

         return result;
      }

      Test::Result g2_group_law() const {
         using Botan::BLS12_381::G2Affine;
         using Botan::BLS12_381::G2Projective;
         using Botan::BLS12_381::Scalar;

         Test::Result result("G2 group operations");

         result.start_timer();

         const auto g = G2Projective::generator();

         result.test_bin_eq("Affine and projective generator serialize identically",
                            g.to_affine().serialize(),
                            G2Affine::generator().serialize());

         result.test_is_true("Generator is not the identity", !g.is_identity());
         result.test_is_true("Identity is the identity", G2Projective::identity().is_identity());

         result.test_bin_eq("0*G is the identity",
                            g.mul(Scalar::zero()).to_affine().serialize(),
                            G2Projective::identity().to_affine().serialize());

         // Regression test: to_affine must canonicalize the identity, so
         // that round tripping it through from_affine yields a valid
         // (non absorbing) projective identity
         result.test_bin_eq("Identity affine round trip is not absorbing",
                            G2Projective::from_affine(g.mul(Scalar::zero()).to_affine()).add(g).to_affine().serialize(),
                            g.to_affine().serialize());

         result.test_bin_eq("1*G is G", g.mul(Scalar::one()).to_affine().serialize(), g.to_affine().serialize());

         for(size_t i = 0; i != 8; ++i) {
            const auto a = random_test_elem<Scalar>(rng());
            const auto b = random_test_elem<Scalar>(rng());

            const auto apb_g = g.mul(a + b);
            const auto ag_bg = g.mul(a).add(g.mul(b));
            result.test_bin_eq("(a+b)*G == a*G + b*G", apb_g.to_affine().serialize(), ag_bg.to_affine().serialize());

            const auto ab_g = g.mul(a * b);
            const auto b_ag = g.mul(a).mul(b);
            result.test_bin_eq("(a*b)*G == b*(a*G)", ab_g.to_affine().serialize(), b_ag.to_affine().serialize());

            const auto ag = g.mul(a);
            const auto ag_maybe = G2Affine::deserialize(ag.to_affine().serialize());
            if(result.test_is_true("Serialization of a*G accepted", ag_maybe.has_value())) {
               result.test_bin_eq("Round trip of a*G", ag_maybe->serialize(), ag.to_affine().serialize());
            }

            const auto sum = ag.add(ag.negate());
            result.test_is_true("P + -P is the identity", sum.is_identity());

            const auto mixed = ag.add_mixed(g.mul(b).to_affine());
            result.test_bin_eq(
               "Mixed and projective addition agree", mixed.to_affine().serialize(), apb_g.to_affine().serialize());

            const auto plus_identity = ag.add_mixed(G2Affine::identity());
            result.test_bin_eq(
               "Mixed addition of the identity", plus_identity.to_affine().serialize(), ag.to_affine().serialize());
         }

         result.end_timer();

         return result;
      }
};

BOTAN_REGISTER_TEST("bls12_381", "bls12_381_g2", BLS12_381_G2_Tests);

class BLS12_381_Pairing_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         results.push_back(pairing_properties());

         return results;
      }

   private:
      Test::Result pairing_properties() const {
         using namespace Botan::BLS12_381;

         Test::Result result("Pairing properties");

         result.start_timer();

         const auto g1 = G1Projective::generator();
         const auto g2 = G2Projective::generator();

         const auto e_g1_g2 = Gt::pairing(G1Affine::generator(), G2Affine::generator());
         result.test_is_true("Non-degeneracy", !e_g1_g2.is_identity());

         result.test_is_true("Identity in G1 absorbs",
                             Gt::pairing(G1Affine::identity(), G2Affine::generator()).is_identity());
         result.test_is_true("Identity in G2 absorbs",
                             Gt::pairing(G1Affine::generator(), G2Affine::identity()).is_identity());

         result.test_is_true("Empty product is the identity", Gt::multi_pairing({}, {}).is_identity());

         result.test_throws("Mismatched span lengths throw", [&]() {
            const std::array<G1Affine, 1> p{G1Affine::generator()};
            Gt::multi_pairing(p, {});
         });

         for(size_t i = 0; i != 4; ++i) {
            const auto a = random_test_elem<Scalar>(rng());
            const auto b = random_test_elem<Scalar>(rng());

            const auto a_g1 = g1.mul(a).to_affine();
            const auto b_g2 = g2.mul(b).to_affine();
            const auto b_g1 = g1.mul(b).to_affine();
            const auto a_g2 = g2.mul(a).to_affine();
            const auto ab_g2 = g2.mul(a * b).to_affine();

            const auto e_ab = Gt::pairing(a_g1, b_g2);
            result.test_is_true("e(aG1, bG2) == e(bG1, aG2)", e_ab == Gt::pairing(b_g1, a_g2));
            result.test_is_true("e(aG1, bG2) == e(G1, abG2)", e_ab == Gt::pairing(G1Affine::generator(), ab_g2));

            // multi_pairing({P, -P}, {Q, Q}) == identity
            const auto neg_a_g1 = g1.mul(a).negate().to_affine();
            const std::array<G1Affine, 2> ps{a_g1, neg_a_g1};
            const std::array<G2Affine, 2> qs{b_g2, b_g2};
            result.test_is_true("e(P, Q)*e(-P, Q) is the identity", Gt::multi_pairing(ps, qs).is_identity());
         }

         result.end_timer();

         return result;
      }
};

BOTAN_REGISTER_TEST("bls12_381", "bls12_381_pairing", BLS12_381_Pairing_Tests);

class BLS12_381_Pairing_KAT_Tests final : public Text_Based_Test {
   public:
      BLS12_381_Pairing_KAT_Tests() : Text_Based_Test("bls12_381/pairing.vec", "A,B,E") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         using namespace Botan::BLS12_381;

         Test::Result result("BLS12-381 pairing KAT");

         const auto a = G1Affine::deserialize(vars.get_req_bin("A"));
         const auto b = G2Affine::deserialize(vars.get_req_bin("B"));

         result.test_is_true("A is accepted", a.has_value());
         result.test_is_true("B is accepted", b.has_value());

         result.test_bin_eq("e(A, B)", Gt::pairing(*a, *b).serialize(), vars.get_req_bin("E"));

         return result;
      }
};

BOTAN_REGISTER_TEST("bls12_381", "bls12_381_pairing_kat", BLS12_381_Pairing_KAT_Tests);

class BLS12_381_Multi_Pairing_KAT_Tests final : public Text_Based_Test {
   public:
      BLS12_381_Multi_Pairing_KAT_Tests() : Text_Based_Test("bls12_381/multi_pairing.vec", "A1,B1,A2,B2,E") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         using namespace Botan::BLS12_381;

         Test::Result result("BLS12-381 multi-pairing KAT");

         const auto a1 = G1Affine::deserialize(vars.get_req_bin("A1"));
         const auto b1 = G2Affine::deserialize(vars.get_req_bin("B1"));
         const auto a2 = G1Affine::deserialize(vars.get_req_bin("A2"));
         const auto b2 = G2Affine::deserialize(vars.get_req_bin("B2"));

         result.test_is_true("Points accepted", a1.has_value() && b1.has_value() && a2.has_value() && b2.has_value());

         const std::array<G1Affine, 2> ps{*a1, *a2};
         const std::array<G2Affine, 2> qs{*b1, *b2};

         result.test_bin_eq("e(A1, B1)*e(A2, B2)", Gt::multi_pairing(ps, qs).serialize(), vars.get_req_bin("E"));

         return result;
      }
};

BOTAN_REGISTER_TEST("bls12_381", "bls12_381_multi_pairing_kat", BLS12_381_Multi_Pairing_KAT_Tests);

class BLS12_381_H2C_G1_Tests final : public Text_Based_Test {
   public:
      BLS12_381_H2C_G1_Tests() : Text_Based_Test("bls12_381/h2c_g1.vec", "Msg,Dst,PX,PY") {}

      Test::Result run_one_test(const std::string& header, const VarMap& vars) override {
         using Botan::BLS12_381::G1Projective;

         Test::Result result("BLS12-381 G1 hash to curve");

         const auto msg = vars.get_req_bin("Msg");
         const auto dst = vars.get_req_bin("Dst");

         const auto pt =
            (header == "RO") ? G1Projective::hash_to_curve_ro(msg, dst) : G1Projective::hash_to_curve_nu(msg, dst);

         const auto affine = pt.to_affine();
         result.test_bin_eq("P.x", affine._x().serialize(), vars.get_req_bin("PX"));
         result.test_bin_eq("P.y", affine._y().serialize(), vars.get_req_bin("PY"));

         // The result must be in the prime order subgroup
         const auto reparsed = Botan::BLS12_381::G1Affine::deserialize(affine.serialize());
         result.test_is_true("Output accepted by deserialize", reparsed.has_value());

         return result;
      }
};

BOTAN_REGISTER_TEST("bls12_381", "bls12_381_h2c_g1", BLS12_381_H2C_G1_Tests);

class BLS12_381_H2C_G2_Tests final : public Text_Based_Test {
   public:
      BLS12_381_H2C_G2_Tests() : Text_Based_Test("bls12_381/h2c_g2.vec", "Msg,Dst,PX0,PX1,PY0,PY1") {}

      Test::Result run_one_test(const std::string& header, const VarMap& vars) override {
         using Botan::BLS12_381::G2Projective;

         Test::Result result("BLS12-381 G2 hash to curve");

         const auto msg = vars.get_req_bin("Msg");
         const auto dst = vars.get_req_bin("Dst");

         const auto pt =
            (header == "RO") ? G2Projective::hash_to_curve_ro(msg, dst) : G2Projective::hash_to_curve_nu(msg, dst);

         const auto affine = pt.to_affine();
         result.test_bin_eq("P.x c0", affine._x().c0().serialize(), vars.get_req_bin("PX0"));
         result.test_bin_eq("P.x c1", affine._x().c1().serialize(), vars.get_req_bin("PX1"));
         result.test_bin_eq("P.y c0", affine._y().c0().serialize(), vars.get_req_bin("PY0"));
         result.test_bin_eq("P.y c1", affine._y().c1().serialize(), vars.get_req_bin("PY1"));

         // The result must be in the prime order subgroup
         const auto reparsed = Botan::BLS12_381::G2Affine::deserialize(affine.serialize());
         result.test_is_true("Output accepted by deserialize", reparsed.has_value());

         return result;
      }
};

BOTAN_REGISTER_TEST("bls12_381", "bls12_381_h2c_g2", BLS12_381_H2C_G2_Tests);

class BLS12_381_H2Scalar_Tests final : public Text_Based_Test {
   public:
      BLS12_381_H2Scalar_Tests() : Text_Based_Test("bls12_381/h2scalar.vec", "Msg,Dst,S") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("BLS12-381 hash to scalar");

         const auto msg = vars.get_req_bin("Msg");
         const auto dst = vars.get_req_bin("Dst");

         result.test_bin_eq(
            "Expected scalar", Botan::BLS12_381::Scalar::hash(msg, dst).serialize(), vars.get_req_bin("S"));

         return result;
      }
};

BOTAN_REGISTER_TEST("bls12_381", "bls12_381_h2scalar", BLS12_381_H2Scalar_Tests);

class BLS12_381_H2C_DST_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         results.push_back(dst_handling());

         return results;
      }

   private:
      Test::Result dst_handling() const {
         using namespace Botan::BLS12_381;

         Test::Result result("Hash to curve DST handling");

         result.start_timer();

         const auto msg = Botan::hex_decode("F00F");

         result.test_throws("G1 RO rejects empty DST", [&]() { G1Projective::hash_to_curve_ro(msg, {}); });
         result.test_throws("G1 NU rejects empty DST", [&]() { G1Projective::hash_to_curve_nu(msg, {}); });
         result.test_throws("G2 RO rejects empty DST", [&]() { G2Projective::hash_to_curve_ro(msg, {}); });
         result.test_throws("G2 NU rejects empty DST", [&]() { G2Projective::hash_to_curve_nu(msg, {}); });

         // A DST longer than 255 bytes must be replaced by
         // H("H2C-OVERSIZE-DST-" || dst) per RFC 9380 5.3.3
         const std::string long_dst_str(300, 'x');
         const std::vector<uint8_t> long_dst(long_dst_str.begin(), long_dst_str.end());

         auto sha256 = Botan::HashFunction::create_or_throw("SHA-256");
         sha256->update("H2C-OVERSIZE-DST-");
         sha256->update(long_dst);
         const auto hashed_dst = sha256->final_stdvec();

         result.test_bin_eq("G1 RO long DST hashed",
                            G1Projective::hash_to_curve_ro(msg, long_dst).to_affine().serialize(),
                            G1Projective::hash_to_curve_ro(msg, hashed_dst).to_affine().serialize());
         result.test_bin_eq("G2 RO long DST hashed",
                            G2Projective::hash_to_curve_ro(msg, long_dst).to_affine().serialize(),
                            G2Projective::hash_to_curve_ro(msg, hashed_dst).to_affine().serialize());
         result.test_bin_eq("G1 NU long DST hashed",
                            G1Projective::hash_to_curve_nu(msg, long_dst).to_affine().serialize(),
                            G1Projective::hash_to_curve_nu(msg, hashed_dst).to_affine().serialize());
         result.test_bin_eq("Scalar hash long DST hashed",
                            Scalar::hash(msg, long_dst).serialize(),
                            Scalar::hash(msg, hashed_dst).serialize());

         result.end_timer();

         return result;
      }
};

BOTAN_REGISTER_TEST("bls12_381", "bls12_381_h2c_dst", BLS12_381_H2C_DST_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
