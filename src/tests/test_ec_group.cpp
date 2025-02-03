/*
* (C) 2007 Falko Strenzke
*     2007 Manuel Hartl
*     2009,2015,2018,2021 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_ECC_GROUP)
   #include <botan/bigint.h>
   #include <botan/data_src.h>
   #include <botan/ec_group.h>
   #include <botan/hex.h>
   #include <botan/numthry.h>
   #include <botan/pk_keys.h>
   #include <botan/reducer.h>
   #include <botan/x509_key.h>
   #include <botan/internal/ec_inner_data.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_ECC_GROUP)

   #if defined(BOTAN_HAS_LEGACY_EC_POINT)

Botan::BigInt test_integer(Botan::RandomNumberGenerator& rng, size_t bits, const BigInt& max) {
   /*
   Produces integers with long runs of ones and zeros, for testing for
   carry handling problems.
   */
   Botan::BigInt x = 0;

   auto flip_prob = [](size_t i) -> double {
      if(i % 64 == 0) {
         return .5;
      }
      if(i % 32 == 0) {
         return .4;
      }
      if(i % 8 == 0) {
         return .05;
      }
      return .01;
   };

   bool active = (rng.next_byte() > 128) ? true : false;
   for(size_t i = 0; i != bits; ++i) {
      x <<= 1;
      x += static_cast<int>(active);

      const double prob = flip_prob(i);
      const double sample = double(rng.next_byte() % 100) / 100.0;  // biased

      if(sample < prob) {
         active = !active;
      }
   }

   if(x == 0) {
      // EC_Scalar rejects zero as an input, if we hit this case instead
      // test with a completely randomized scalar
      return BigInt::random_integer(rng, 1, max);
   }

   if(max > 0) {
      while(x >= max) {
         const size_t b = x.bits() - 1;
         BOTAN_ASSERT(x.get_bit(b) == true, "Set");
         x.clear_bit(b);
      }
   }

   return x;
}

Botan::EC_Point create_random_point(Botan::RandomNumberGenerator& rng, const Botan::EC_Group& group) {
   const Botan::BigInt& p = group.get_p();
   auto mod_p = Botan::Modular_Reducer::for_public_modulus(p);

   for(;;) {
      const Botan::BigInt x = Botan::BigInt::random_integer(rng, 1, p);
      const Botan::BigInt x3 = mod_p.multiply(x, mod_p.square(x));
      const Botan::BigInt ax = mod_p.multiply(group.get_a(), x);
      const Botan::BigInt y = mod_p.reduce(x3 + ax + group.get_b());
      const Botan::BigInt sqrt_y = Botan::sqrt_modulo_prime(y, p);

      if(sqrt_y > 1) {
         BOTAN_ASSERT_EQUAL(mod_p.square(sqrt_y), y, "Square root is correct");
         return group.point(x, sqrt_y);
      }
   }
}

class ECC_Randomized_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override;
};

std::vector<Test::Result> ECC_Randomized_Tests::run() {
   std::vector<Test::Result> results;
   for(const std::string& group_name : Botan::EC_Group::known_named_groups()) {
      Test::Result result("ECC randomized " + group_name);

      result.start_timer();

      auto group = Botan::EC_Group::from_name(group_name);

      const Botan::EC_Point pt = create_random_point(this->rng(), group);

      std::vector<Botan::BigInt> blind_ws;

      try {
         const size_t trials = (Test::run_long_tests() ? 10 : 3);
         for(size_t i = 0; i < trials; ++i) {
            const Botan::BigInt a = test_integer(rng(), group.get_order_bits(), group.get_order());
            const Botan::BigInt b = test_integer(rng(), group.get_order_bits(), group.get_order());
            const Botan::BigInt c = group.mod_order(a + b);

            const Botan::EC_Point P = pt * a;
            const Botan::EC_Point Q = pt * b;
            const Botan::EC_Point R = pt * c;

            Botan::EC_Point P1 = group.blinded_var_point_multiply(pt, a, this->rng(), blind_ws);
            Botan::EC_Point Q1 = group.blinded_var_point_multiply(pt, b, this->rng(), blind_ws);
            Botan::EC_Point R1 = group.blinded_var_point_multiply(pt, c, this->rng(), blind_ws);

            Botan::EC_Point A1 = P + Q;
            Botan::EC_Point A2 = Q + P;

            result.test_eq("p + q", A1, R);
            result.test_eq("q + p", A2, R);

            A1.force_affine();
            A2.force_affine();
            result.test_eq("p + q", A1, R);
            result.test_eq("q + p", A2, R);

            result.test_eq("p on the curve", P.on_the_curve(), true);
            result.test_eq("q on the curve", Q.on_the_curve(), true);
            result.test_eq("r on the curve", R.on_the_curve(), true);

            result.test_eq("P1", P1, P);
            result.test_eq("Q1", Q1, Q);
            result.test_eq("R1", R1, R);

            P1.force_affine();
            Q1.force_affine();
            R1.force_affine();
            result.test_eq("P1", P1, P);
            result.test_eq("Q1", Q1, Q);
            result.test_eq("R1", R1, R);
         }
      } catch(std::exception& e) {
         result.test_failure(group_name, e.what());
      }
      result.end_timer();
      results.push_back(result);
   }

   return results;
}

BOTAN_REGISTER_TEST("pubkey", "ecc_randomized", ECC_Randomized_Tests);

   #endif

class EC_Group_Tests : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         for(const std::string& group_name : Botan::EC_Group::known_named_groups()) {
            Test::Result result("EC_Group " + group_name);

            result.start_timer();

            const auto group = Botan::EC_Group::from_name(group_name);

            result.confirm("EC_Group is known", group.get_curve_oid().has_value());
            result.confirm("EC_Group is considered valid", group.verify_group(this->rng(), true));
            result.confirm("EC_Group is not considered explict encoding", !group.used_explicit_encoding());

            result.test_eq("EC_Group has correct bit size", group.get_p().bits(), group.get_p_bits());
            result.test_eq("EC_Group has byte size", group.get_p().bytes(), group.get_p_bytes());

            result.test_eq("EC_Group has cofactor == 1", group.get_cofactor(), 1);

            const Botan::OID from_order = Botan::EC_Group::EC_group_identity_from_order(group.get_order());

            result.test_eq(
               "EC_group_identity_from_order works", from_order.to_string(), group.get_curve_oid().to_string());

            result.confirm("Same group is same", group == Botan::EC_Group::from_name(group_name));

            try {
               const Botan::EC_Group copy(group.get_curve_oid(),
                                          group.get_p(),
                                          group.get_a(),
                                          group.get_b(),
                                          group.get_g_x(),
                                          group.get_g_y(),
                                          group.get_order());

               result.confirm("Same group is same even with copy", group == copy);
            } catch(Botan::Invalid_Argument&) {}

            const auto group_der_oid = group.DER_encode();
            const Botan::EC_Group group_via_oid(group_der_oid);
            result.confirm("EC_Group via OID is not considered explict encoding",
                           !group_via_oid.used_explicit_encoding());

            const auto group_der_explicit = group.DER_encode(Botan::EC_Group_Encoding::Explicit);
            const Botan::EC_Group group_via_explicit(group_der_explicit);
            result.confirm("EC_Group via explicit DER is considered explict encoding",
                           group_via_explicit.used_explicit_encoding());

            if(group.a_is_minus_3()) {
               result.test_eq("Group A equals -3", group.get_a(), group.get_p() - 3);
            } else {
               result.test_ne("Group " + group_name + " A does not equal -3", group.get_a(), group.get_p() - 3);
            }

            if(group.a_is_zero()) {
               result.test_eq("Group A is zero", group.get_a(), BigInt(0));
            } else {
               result.test_ne("Group " + group_name + " A does not equal zero", group.get_a(), BigInt(0));
            }

   #if defined(BOTAN_HAS_LEGACY_EC_POINT)
            const auto pt_mult_by_order = group.get_base_point() * group.get_order();
            result.confirm("Multiplying point by the order results in zero point", pt_mult_by_order.is_zero());

            // get a valid point
            Botan::EC_Point p = group.get_base_point() * this->rng().next_nonzero_byte();

            // get a copy
            Botan::EC_Point q = p;

            p.randomize_repr(this->rng());
            q.randomize_repr(this->rng());

            result.test_eq("affine x after copy", p.get_affine_x(), q.get_affine_x());
            result.test_eq("affine y after copy", p.get_affine_y(), q.get_affine_y());

            q.force_affine();

            result.test_eq("affine x after copy", p.get_affine_x(), q.get_affine_x());
            result.test_eq("affine y after copy", p.get_affine_y(), q.get_affine_y());

            test_ser_der(result, group);
            test_basic_math(result, group);
            test_point_swap(result, group);
            test_zeropoint(result, group);
   #endif

            result.end_timer();

            results.push_back(result);
         }

         return results;
      }

   private:
   #if defined(BOTAN_HAS_LEGACY_EC_POINT)

      void test_ser_der(Test::Result& result, const Botan::EC_Group& group) {
         // generate point
         const Botan::EC_Point pt = create_random_point(this->rng(), group);
         const Botan::EC_Point zero = group.zero_point();

         for(auto scheme : {Botan::EC_Point_Format::Uncompressed,
                            Botan::EC_Point_Format::Compressed,
                            Botan::EC_Point_Format::Hybrid}) {
            result.test_eq("encoded/decode rt works", group.OS2ECP(pt.encode(scheme)), pt);
            result.test_eq("encoded/decode rt works", group.OS2ECP(zero.encode(scheme)), zero);
         }
      }

      static void test_basic_math(Test::Result& result, const Botan::EC_Group& group) {
         const Botan::EC_Point& G = group.get_base_point();

         Botan::EC_Point p1 = G * 2;
         p1 += G;

         result.test_eq("point addition", p1, G * 3);

         p1 -= G * 2;

         result.test_eq("point subtraction", p1, G);

         // The scalar multiplication algorithm relies on this being true:
         try {
            Botan::EC_Point zero_coords = group.point(0, 0);
            result.confirm("point (0,0) is not on the curve", !zero_coords.on_the_curve());
         } catch(Botan::Exception&) {
            result.test_success("point (0,0) is rejected");
         }
      }

      void test_point_swap(Test::Result& result, const Botan::EC_Group& group) {
         Botan::EC_Point a(create_random_point(this->rng(), group));
         Botan::EC_Point b(create_random_point(this->rng(), group));
         b *= Botan::BigInt(this->rng(), 20);

         Botan::EC_Point c(a);
         Botan::EC_Point d(b);

         d.swap(c);
         result.test_eq("swap correct", a, d);
         result.test_eq("swap correct", b, c);
      }

      static void test_zeropoint(Test::Result& result, const Botan::EC_Group& group) {
         Botan::EC_Point zero = group.zero_point();

         result.test_throws("Zero point throws", "Cannot convert zero point to affine", [&]() { zero.get_affine_x(); });
         result.test_throws("Zero point throws", "Cannot convert zero point to affine", [&]() { zero.get_affine_y(); });

         const Botan::EC_Point p1 = group.get_base_point() * 2;

         result.confirm("point is on the curve", p1.on_the_curve());
         result.confirm("point is not zero", !p1.is_zero());

         Botan::EC_Point p2 = p1;
         p2 -= p1;

         result.confirm("p - q with q = p results in zero", p2.is_zero());

         const Botan::EC_Point minus_p1 = -p1;
         result.confirm("point is on the curve", minus_p1.on_the_curve());
         const Botan::EC_Point shouldBeZero = p1 + minus_p1;
         result.confirm("point is on the curve", shouldBeZero.on_the_curve());
         result.confirm("point is zero", shouldBeZero.is_zero());

         result.test_eq("minus point x", minus_p1.get_affine_x(), p1.get_affine_x());
         result.test_eq("minus point y", minus_p1.get_affine_y(), group.get_p() - p1.get_affine_y());

         result.confirm("zero point is zero", zero.is_zero());
         result.confirm("zero point is on the curve", zero.on_the_curve());
         result.test_eq("addition of zero does nothing", p1, p1 + zero);
         result.test_eq("addition of zero does nothing", p1, zero + p1);
         result.test_eq("addition of zero does nothing", p1, p1 - zero);
         result.confirm("zero times anything is the zero point", (zero * 39193).is_zero());

         for(auto scheme : {Botan::EC_Point_Format::Uncompressed,
                            Botan::EC_Point_Format::Compressed,
                            Botan::EC_Point_Format::Hybrid}) {
            const std::vector<uint8_t> v = zero.encode(scheme);
            result.test_eq("encoded/decode rt works", group.OS2ECP(v), zero);
         }
      }
   #endif
};

BOTAN_REGISTER_TEST("pubkey", "ec_group", EC_Group_Tests);

Test::Result test_decoding_with_seed() {
   Test::Result result("Decode EC_Group with seed");

   try {
      if(Botan::EC_Group::supports_named_group("secp384r1")) {
         const auto secp384r1 = Botan::EC_Group::from_name("secp384r1");
         const auto secp384r1_with_seed =
            Botan::EC_Group::from_PEM(Test::read_data_file("x509/ecc/secp384r1_seed.pem"));
         result.confirm("decoding worked", secp384r1_with_seed.initialized());
         result.test_eq("P-384 prime", secp384r1_with_seed.get_p(), secp384r1.get_p());
      }
   } catch(Botan::Exception& e) {
      result.test_failure(e.what());
   }

   return result;
}

Test::Result test_mixed_points() {
   Test::Result result("Mixed Point Arithmetic");

   if(Botan::EC_Group::supports_named_group("secp256r1") && Botan::EC_Group::supports_named_group("secp384r1")) {
      const auto secp256r1 = Botan::EC_Group::from_name("secp256r1");
      const auto secp384r1 = Botan::EC_Group::from_name("secp384r1");

   #if defined(BOTAN_HAS_LEGACY_EC_POINT)
      const Botan::EC_Point& G256 = secp256r1.get_base_point();
      const Botan::EC_Point& G384 = secp384r1.get_base_point();

      result.test_throws("Mixing points from different groups", [&] { Botan::EC_Point p = G256 + G384; });
   #endif

      const auto p1 = Botan::EC_AffinePoint::generator(secp256r1);
      const auto p2 = Botan::EC_AffinePoint::generator(secp384r1);
      result.test_throws("Mixing points from different groups", [&] { auto p3 = p1.add(p2); });
   }

   return result;
}

Test::Result test_ecc_registration() {
   Test::Result result("ECC registration");

   // numsp256d1
   const Botan::BigInt p("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43");
   const Botan::BigInt a("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF40");
   const Botan::BigInt b("0x25581");
   const Botan::BigInt order("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE43C8275EA265C6020AB20294751A825");

   const Botan::BigInt g_x("0x01");
   const Botan::BigInt g_y("0x696F1853C1E466D7FC82C96CCEEEDD6BD02C2F9375894EC10BF46306C2B56C77");

   const Botan::OID oid("1.3.6.1.4.1.25258.4.1");

   // Creating this object implicitly registers the curve for future use ...
   Botan::EC_Group reg_group(oid, p, a, b, g_x, g_y, order);

   auto group = Botan::EC_Group::from_OID(oid);

   result.test_eq("Group registration worked", group.get_p(), p);

   // TODO(Botan4) this could change to == Generic
   result.confirm("Group is not pcurve", group.engine() != Botan::EC_Group_Engine::Optimized);

   return result;
}

Test::Result test_ec_group_from_params() {
   Test::Result result("EC_Group from params");

   Botan::EC_Group::clear_registered_curve_data();

   // secp256r1
   const Botan::BigInt p("0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
   const Botan::BigInt a("0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");
   const Botan::BigInt b("0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");

   const Botan::BigInt g_x("0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
   const Botan::BigInt g_y("0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
   const Botan::BigInt order("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");

   const Botan::OID oid("1.2.840.10045.3.1.7");

   // This uses the deprecated constructor to verify we dedup even without an OID
   // This whole test can be removed once explicit curve support is removed
   Botan::EC_Group reg_group(p, a, b, g_x, g_y, order, 1);
   result.confirm("Group has correct OID", reg_group.get_curve_oid() == oid);

   return result;
}

Test::Result test_ec_group_bad_registration() {
   Test::Result result("EC_Group registering non-match");

   Botan::EC_Group::clear_registered_curve_data();

   // secp256r1 params except with a bad B param
   const Botan::BigInt p("0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
   const Botan::BigInt a("0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");
   const Botan::BigInt b("0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604C");

   const Botan::BigInt g_x("0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
   const Botan::BigInt g_y("0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
   const Botan::BigInt order("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");

   const Botan::OID oid("1.2.840.10045.3.1.7");

   try {
      Botan::EC_Group reg_group(oid, p, a, b, g_x, g_y, order);
      result.test_failure("Should have failed");
   } catch(Botan::Invalid_Argument&) {
      result.test_success("Got expected exception");
   }

   return result;
}

Test::Result test_ec_group_duplicate_orders() {
   Test::Result result("EC_Group with duplicate group order");

   Botan::EC_Group::clear_registered_curve_data();

   // secp256r1
   const Botan::BigInt p("0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
   const Botan::BigInt a("0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");
   const Botan::BigInt b("0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");

   const Botan::BigInt g_x("0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
   const Botan::BigInt g_y("0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
   const Botan::BigInt order("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");

   const Botan::OID oid("1.3.6.1.4.1.25258.100.0");  // some other random OID

   Botan::EC_Group reg_group(oid, p, a, b, g_x, g_y, order);
   result.test_success("Registration success");
   result.confirm("Group has correct OID", reg_group.get_curve_oid() == oid);

   // We can now get it by OID:
   const auto hc_group = Botan::EC_Group::from_OID(oid);
   result.confirm("Group has correct OID", hc_group.get_curve_oid() == oid);

   // Existing secp256r1 unmodified:
   const Botan::OID secp160r1("1.2.840.10045.3.1.7");
   const auto other_group = Botan::EC_Group::from_OID(secp160r1);
   result.confirm("Group has correct OID", other_group.get_curve_oid() == secp160r1);

   return result;
}

Test::Result test_ec_group_registration_with_custom_oid() {
   Test::Result result("EC_Group registration of standard group with custom OID");

   Botan::EC_Group::clear_registered_curve_data();

   const Botan::OID secp256r1_oid("1.2.840.10045.3.1.7");
   const auto secp256r1 = Botan::EC_Group::from_OID(secp256r1_oid);
   result.confirm("Group has correct OID", secp256r1.get_curve_oid() == secp256r1_oid);

   const Botan::OID custom_oid("1.3.6.1.4.1.25258.100.99");  // some other random OID

   Botan::OID::register_oid(custom_oid, "secp256r1");

   Botan::EC_Group reg_group(custom_oid,
                             secp256r1.get_p(),
                             secp256r1.get_a(),
                             secp256r1.get_b(),
                             secp256r1.get_g_x(),
                             secp256r1.get_g_y(),
                             secp256r1.get_order());

   result.test_success("Registration success");
   result.confirm("Group has correct OID", reg_group.get_curve_oid() == custom_oid);

   // We can now get it by OID:
   result.confirm("Group has correct OID", Botan::EC_Group::from_OID(custom_oid).get_curve_oid() == custom_oid);

   // In the current data model of EC_Group there is a 1:1 OID:group, so these
   // have distinct underlying data
   result.confirm("Groups have different inner data pointers", reg_group._data() != secp256r1._data());

   #if defined(BOTAN_HAS_PCURVES_SECP256R1)
   // However we should have gotten a pcurves out of the deal *and* it
   // should be the exact same shared_ptr as the official curve

   result.confirm("Group is pcurves based", reg_group.engine() == Botan::EC_Group_Engine::Optimized);

   try {
      const auto& pcurve = reg_group._data()->pcurve();
      result.confirm("Group with custom OID got the same pcurve pointer", &pcurve == &secp256r1._data()->pcurve());
   } catch(...) {
      result.test_failure("Group with custom OID did not get a pcurve pointer");
   }
   #endif

   return result;
}

class ECC_Unit_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         results.push_back(test_decoding_with_seed());
         results.push_back(test_mixed_points());

         if(Botan::EC_Group::supports_application_specific_group()) {
            results.push_back(test_ecc_registration());
            results.push_back(test_ec_group_from_params());
            results.push_back(test_ec_group_bad_registration());
            results.push_back(test_ec_group_duplicate_orders());
            results.push_back(test_ec_group_registration_with_custom_oid());
         }

         return results;
      }
};

BOTAN_REGISTER_SERIALIZED_TEST("pubkey", "ecc_unit", ECC_Unit_Tests);

class EC_PointEnc_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         auto& rng = Test::rng();

         for(const auto& group_id : Botan::EC_Group::known_named_groups()) {
            const auto group = Botan::EC_Group::from_name(group_id);

            Result result("EC_AffinePoint encoding " + group_id);

            result.start_timer();

            std::vector<Botan::BigInt> ws;

            for(size_t trial = 0; trial != 100; ++trial) {
               const auto scalar = Botan::EC_Scalar::random(group, rng);
               const auto pt = Botan::EC_AffinePoint::g_mul(scalar, rng, ws);

               const auto pt_u = pt.serialize_uncompressed();
               result.test_eq("Expected uncompressed header", static_cast<size_t>(pt_u[0]), 0x04);
               const size_t fe_bytes = (pt_u.size() - 1) / 2;
               const auto pt_c = pt.serialize_compressed();

               result.test_eq("Expected compressed size", pt_c.size(), 1 + fe_bytes);
               const uint8_t expected_c_header = (pt_u[pt_u.size() - 1] % 2 == 0) ? 0x02 : 0x03;
               result.confirm("Expected compressed header", pt_c[0] == expected_c_header);

               result.test_eq(
                  "Expected compressed x", std::span{pt_c}.subspan(1), std::span{pt_u}.subspan(1, fe_bytes));

               if(auto d_pt_u = Botan::EC_AffinePoint::deserialize(group, pt_u)) {
                  result.test_eq(
                     "Deserializing uncompressed returned correct point", d_pt_u->serialize_uncompressed(), pt_u);
               } else {
                  result.test_failure("Failed to deserialize uncompressed point");
               }

               if(auto d_pt_c = Botan::EC_AffinePoint::deserialize(group, pt_c)) {
                  result.test_eq(
                     "Deserializing compressed returned correct point", d_pt_c->serialize_uncompressed(), pt_u);
               } else {
                  result.test_failure("Failed to deserialize compressed point");
               }

               const auto neg_pt_c = [&]() {
                  auto x = pt_c;
                  x[0] ^= 0x01;
                  return x;
               }();

               if(auto d_neg_pt_c = Botan::EC_AffinePoint::deserialize(group, neg_pt_c)) {
                  result.test_eq("Deserializing compressed with inverted header returned negated point",
                                 d_neg_pt_c->serialize_uncompressed(),
                                 pt.negate().serialize_uncompressed());
               } else {
                  result.test_failure("Failed to deserialize compressed point");
               }
            }

            result.end_timer();

            results.push_back(result);
         }

         return results;
      }
};

BOTAN_REGISTER_TEST("pubkey", "ec_point_enc", EC_PointEnc_Tests);

class EC_Point_Arithmetic_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         auto& rng = Test::rng();

         std::vector<Botan::BigInt> ws;

         for(const auto& group_id : Botan::EC_Group::known_named_groups()) {
            const auto group = Botan::EC_Group::from_name(group_id);

            Result result("EC_AffinePoint arithmetic " + group_id);

            result.start_timer();

            const auto one = Botan::EC_Scalar::one(group);
            const auto zero = one - one;
            const auto g = Botan::EC_AffinePoint::generator(group);
            const auto g_bytes = g.serialize_uncompressed();

            const auto id = Botan::EC_AffinePoint::g_mul(zero, rng, ws);
            result.confirm("g*zero is point at identity", id.is_identity());

            const auto id2 = id.add(id);
            result.confirm("identity plus itself is identity", id2.is_identity());

            const auto g_one = Botan::EC_AffinePoint::g_mul(one, rng, ws);
            result.test_eq("g*one == generator", g_one.serialize_uncompressed(), g_bytes);

            const auto g_plus_id = g_one.add(id);
            result.test_eq("g + id == g", g_plus_id.serialize_uncompressed(), g_bytes);

            const auto id_plus_g = id.add(g_one);
            result.test_eq("id + g == g", id_plus_g.serialize_uncompressed(), g_bytes);

            const auto g_neg_one = Botan::EC_AffinePoint::g_mul(one.negate(), rng, ws);

            const auto id_from_g = g_one.add(g_neg_one);
            result.confirm("g - g is identity", id_from_g.is_identity());

            const auto g_two = Botan::EC_AffinePoint::g_mul(one + one, rng, ws);
            const auto g_plus_g = g_one.add(g_one);
            result.test_eq("2*g == g+g", g_two.serialize_uncompressed(), g_plus_g.serialize_uncompressed());

            result.confirm("Scalar::zero is zero", zero.is_zero());
            result.confirm("(zero+zero) is zero", (zero + zero).is_zero());
            result.confirm("(zero*zero) is zero", (zero * zero).is_zero());
            result.confirm("(zero-zero) is zero", (zero - zero).is_zero());

            const auto neg_zero = zero.negate();
            result.confirm("zero.negate() is zero", neg_zero.is_zero());

            result.confirm("(zero+nz) is zero", (zero + neg_zero).is_zero());
            result.confirm("(nz+nz) is zero", (neg_zero + neg_zero).is_zero());
            result.confirm("(nz+zero) is zero", (neg_zero + zero).is_zero());

            result.confirm("Scalar::one is not zero", !one.is_zero());
            result.confirm("(one-one) is zero", (one - one).is_zero());
            result.confirm("(one+one.negate()) is zero", (one + one.negate()).is_zero());
            result.confirm("(one.negate()+one) is zero", (one.negate() + one).is_zero());

            for(size_t i = 0; i != 16; ++i) {
               const auto pt = Botan::EC_AffinePoint::g_mul(Botan::EC_Scalar::random(group, rng), rng, ws);

               const auto a = Botan::EC_Scalar::random(group, rng);
               const auto b = Botan::EC_Scalar::random(group, rng);
               const auto c = a + b;

               const auto Pa = pt.mul(a, rng, ws);
               const auto Pb = pt.mul(b, rng, ws);
               const auto Pc = pt.mul(c, rng, ws);

               const auto Pc_bytes = Pc.serialize_uncompressed();

               const auto Pab = Pa.add(Pb);
               result.test_eq("Pa + Pb == Pc", Pab.serialize_uncompressed(), Pc_bytes);

               const auto Pba = Pb.add(Pa);
               result.test_eq("Pb + Pa == Pc", Pba.serialize_uncompressed(), Pc_bytes);
            }

            for(size_t i = 0; i != 64; ++i) {
               auto h = [&]() {
                  const auto s = [&]() {
                     if(i == 0) {
                        // Test the identity case
                        return Botan::EC_Scalar(zero);
                     } else if(i <= 32) {
                        // Test cases where the two points have a linear relation
                        std::vector<uint8_t> sbytes(group.get_order_bytes());
                        sbytes[sbytes.size() - 1] = static_cast<uint8_t>((i + 1) / 2);
                        auto si = Botan::EC_Scalar::deserialize(group, sbytes).value();
                        if(i % 2 == 0) {
                           return si;
                        } else {
                           return si.negate();
                        }
                     } else {
                        return Botan::EC_Scalar::random(group, rng);
                     }
                  }();
                  auto x = Botan::EC_AffinePoint::g_mul(s, rng, ws);
                  return x;
               }();

               const auto s1 = Botan::EC_Scalar::random(group, rng);
               const auto s2 = Botan::EC_Scalar::random(group, rng);

               const Botan::EC_Group::Mul2Table mul2_table(h);

               const auto ref = Botan::EC_AffinePoint::g_mul(s1, rng, ws).add(h.mul(s2, rng, ws));

               if(auto mul2pt = mul2_table.mul2_vartime(s1, s2)) {
                  result.test_eq("ref == mul2t", ref.serialize_uncompressed(), mul2pt->serialize_uncompressed());
               } else {
                  result.confirm("ref is identity", ref.is_identity());
               }
            }

            result.end_timer();

            results.push_back(result);
         }

         return results;
      }
};

BOTAN_REGISTER_TEST("pubkey", "ec_point_arith", EC_Point_Arithmetic_Tests);

   #if defined(BOTAN_HAS_ECDSA)

class ECC_Invalid_Key_Tests final : public Text_Based_Test {
   public:
      ECC_Invalid_Key_Tests() : Text_Based_Test("pubkey/ecc_invalid.vec", "SubjectPublicKey") {}

      bool clear_between_callbacks() const override { return false; }

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("ECC invalid keys");

         const std::string encoded = vars.get_req_str("SubjectPublicKey");
         Botan::DataSource_Memory key_data(Botan::hex_decode(encoded));

         try {
            auto key = Botan::X509::load_key(key_data);
            result.test_eq("public key fails check", key->check_key(this->rng(), false), false);
         } catch(Botan::Decoding_Error&) {
            result.test_success("Decoding invalid ECC key results in decoding error exception");
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "ecc_invalid", ECC_Invalid_Key_Tests);

   #endif

#endif

}  // namespace

}  // namespace Botan_Tests
