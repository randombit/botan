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
   #include <botan/ec_point.h>
   #include <botan/hex.h>
   #include <botan/numthry.h>
   #include <botan/pk_keys.h>
   #include <botan/reducer.h>
   #include <botan/x509_key.h>
   #include <botan/internal/curve_nistp.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_ECC_GROUP)

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
   const Botan::Modular_Reducer mod_p(p);

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
      const Botan::BigInt& group_order = group.get_order();

      std::vector<Botan::BigInt> blind_ws;

      try {
         const size_t trials = (Test::run_long_tests() ? 10 : 3);
         for(size_t i = 0; i < trials; ++i) {
            const Botan::BigInt a = Botan::BigInt::random_integer(this->rng(), 2, group_order);
            const Botan::BigInt b = Botan::BigInt::random_integer(this->rng(), 2, group_order);
            const Botan::BigInt c = a + b;

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

class NIST_Curve_Reduction_Tests final : public Test {
   public:
      typedef std::function<void(Botan::BigInt&, Botan::secure_vector<Botan::word>&)> reducer_fn;

      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         // Using lambdas here to avoid strange UbSan warning (#1370)

         results.push_back(random_redc_test(
            "P-384", Botan::prime_p384(), [](Botan::BigInt& p, Botan::secure_vector<Botan::word>& ws) -> void {
               Botan::redc_p384(p, ws);
            }));
         results.push_back(random_redc_test(
            "P-256", Botan::prime_p256(), [](Botan::BigInt& p, Botan::secure_vector<Botan::word>& ws) -> void {
               Botan::redc_p256(p, ws);
            }));
         results.push_back(random_redc_test(
            "P-224", Botan::prime_p224(), [](Botan::BigInt& p, Botan::secure_vector<Botan::word>& ws) -> void {
               Botan::redc_p224(p, ws);
            }));
         results.push_back(random_redc_test(
            "P-192", Botan::prime_p192(), [](Botan::BigInt& p, Botan::secure_vector<Botan::word>& ws) -> void {
               Botan::redc_p192(p, ws);
            }));
         results.push_back(random_redc_test(
            "P-521", Botan::prime_p521(), [](Botan::BigInt& p, Botan::secure_vector<Botan::word>& ws) -> void {
               Botan::redc_p521(p, ws);
            }));

         return results;
      }

      static Test::Result random_redc_test(const std::string& prime_name,
                                           const Botan::BigInt& p,
                                           const reducer_fn& redc_fn) {
         const Botan::BigInt p2 = p * p;
         const size_t p_bits = p.bits();

         Botan::Modular_Reducer p_redc(p);
         Botan::secure_vector<Botan::word> ws;

         auto rng = Test::new_rng("random_redc " + prime_name);

         Test::Result result("NIST " + prime_name + " reduction");
         result.start_timer();

         const size_t trials = (Test::run_long_tests() ? 128 : 16);

         for(size_t i = 0; i <= trials; ++i) {
            const Botan::BigInt x = test_integer(*rng, 2 * p_bits, p2);

            // TODO: time and report all three approaches
            const Botan::BigInt v1 = x % p;
            const Botan::BigInt v2 = p_redc.reduce(x);

            Botan::BigInt v3 = x;
            redc_fn(v3, ws);

            if(!result.test_eq("reference redc", v1, v2) || !result.test_eq("specialized redc", v2, v3)) {
               result.test_note("failing input" + Botan::hex_encode(Botan::BigInt::encode(x)));
            }
         }

         result.end_timer();

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "nist_redc", NIST_Curve_Reduction_Tests);

class EC_Group_Tests : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         for(const std::string& group_name : Botan::EC_Group::known_named_groups()) {
            Test::Result result("EC_Group " + group_name);

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

            const auto group_der_oid = group.DER_encode(Botan::EC_Group_Encoding::NamedCurve);
            const Botan::EC_Group group_via_oid(group_der_oid);
            result.confirm("EC_Group via OID is not considered explict encoding",
                           !group_via_oid.used_explicit_encoding());

            const auto group_der_explicit = group.DER_encode(Botan::EC_Group_Encoding::Explicit);
            const Botan::EC_Group group_via_explicit(group_der_explicit);
            result.confirm("EC_Group via explicit DER is considered explict encoding",
                           group_via_explicit.used_explicit_encoding());

            const auto pt_mult_by_order = group.get_base_point() * group.get_order();
            result.confirm("Multiplying point by the order results in zero point", pt_mult_by_order.is_zero());

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

            results.push_back(result);
         }

         return results;
      }

   private:
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
         Botan::EC_Point zero_coords = group.point(0, 0);
         result.confirm("point (0,0) is not on the curve", !zero_coords.on_the_curve());
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
};

BOTAN_REGISTER_TEST("pubkey", "ec_group", EC_Group_Tests);

Test::Result test_decoding_with_seed() {
   Test::Result result("ECC Unit");

   const auto secp384r1_with_seed = Botan::EC_Group::from_PEM(Test::read_data_file("x509/ecc/secp384r1_seed.pem"));

   result.confirm("decoding worked", secp384r1_with_seed.initialized());

   const auto secp384r1 = Botan::EC_Group::from_name("secp384r1");

   result.test_eq("P-384 prime", secp384r1_with_seed.get_p(), secp384r1.get_p());

   return result;
}

Test::Result test_coordinates() {
   Test::Result result("ECC Unit");

   const Botan::BigInt exp_affine_x("16984103820118642236896513183038186009872590470");
   const Botan::BigInt exp_affine_y("1373093393927139016463695321221277758035357890939");

   // precalculation
   const auto secp160r1 = Botan::EC_Group::from_name("secp160r1");
   const Botan::EC_Point& p_G = secp160r1.get_base_point();

   const Botan::EC_Point point_exp = secp160r1.point(exp_affine_x, exp_affine_y);
   result.confirm("Point is on the curve", point_exp.on_the_curve());

   const Botan::EC_Point p1 = p_G * 2;
   result.test_eq("Point affine x", p1.get_affine_x(), exp_affine_x);
   result.test_eq("Point affine y", p1.get_affine_y(), exp_affine_y);
   return result;
}

/**
Test point multiplication according to
--------
SEC 2: Test Vectors for SEC 1
Certicom Research
Working Draft
September, 1999
Version 0.3;
Section 2.1.2
--------
*/
Test::Result test_point_mult() {
   Test::Result result("ECC Unit");

   const auto secp160r1 = Botan::EC_Group::from_name("secp160r1");
   const Botan::EC_Point& p_G = secp160r1.get_base_point();

   Botan::BigInt d_U("0xaa374ffc3ce144e6b073307972cb6d57b2a4e982");
   Botan::EC_Point Q_U = d_U * p_G;

   result.test_eq("affine x", Q_U.get_affine_x(), Botan::BigInt("466448783855397898016055842232266600516272889280"));
   result.test_eq("affine y", Q_U.get_affine_y(), Botan::BigInt("1110706324081757720403272427311003102474457754220"));
   return result;
}

Test::Result test_point_negative() {
   Test::Result result("ECC Unit");

   const auto secp160r1 = Botan::EC_Group::from_name("secp160r1");
   const Botan::EC_Point& p_G = secp160r1.get_base_point();

   const Botan::EC_Point p1 = p_G * 2;

   result.test_eq("affine x", p1.get_affine_x(), Botan::BigInt("16984103820118642236896513183038186009872590470"));
   result.test_eq("affine y", p1.get_affine_y(), Botan::BigInt("1373093393927139016463695321221277758035357890939"));

   const Botan::EC_Point p1_neg = -p1;

   result.test_eq("affine x", p1_neg.get_affine_x(), p1.get_affine_x());
   result.test_eq("affine y", p1_neg.get_affine_y(), Botan::BigInt("88408243403763901739989511495005261618427168388"));
   return result;
}

Test::Result test_mult_point() {
   Test::Result result("ECC Unit");

   const auto secp160r1 = Botan::EC_Group::from_name("secp160r1");
   const Botan::EC_Point& p_G = secp160r1.get_base_point();

   const Botan::EC_Point& p0 = p_G;
   Botan::EC_Point p1 = p_G * 2;

   p1 *= p0.get_affine_x();

   const Botan::BigInt exp_mult_x(std::string("967697346845926834906555988570157345422864716250"));
   const Botan::BigInt exp_mult_y(std::string("512319768365374654866290830075237814703869061656"));
   Botan::EC_Point expected = secp160r1.point(exp_mult_x, exp_mult_y);

   result.test_eq("point mult", p1, expected);
   return result;
}

Test::Result test_mixed_points() {
   Test::Result result("ECC Unit");

   const auto secp256r1 = Botan::EC_Group::from_name("secp256r1");
   const auto secp384r1 = Botan::EC_Group::from_name("secp384r1");

   const Botan::EC_Point& G256 = secp256r1.get_base_point();
   const Botan::EC_Point& G384 = secp384r1.get_base_point();

   result.test_throws("Mixing points from different groups", [&] { Botan::EC_Point p = G256 + G384; });
   return result;
}

Test::Result test_basic_operations() {
   Test::Result result("ECC Unit");

   // precalculation
   const auto secp160r1 = Botan::EC_Group::from_name("secp160r1");
   const Botan::EC_Point& p_G = secp160r1.get_base_point();

   const Botan::EC_Point& p0 = p_G;
   const Botan::EC_Point p1 = p_G * 2;

   result.test_eq("p1 affine x", p1.get_affine_x(), Botan::BigInt("16984103820118642236896513183038186009872590470"));
   result.test_eq("p1 affine y", p1.get_affine_y(), Botan::BigInt("1373093393927139016463695321221277758035357890939"));

   const Botan::EC_Point simplePlus = p1 + p0;
   const Botan::EC_Point exp_simplePlus =
      secp160r1.point(Botan::BigInt("704859595002530890444080436569091156047721708633"),
                      Botan::BigInt("1147993098458695153857594941635310323215433166682"));

   result.test_eq("point addition", simplePlus, exp_simplePlus);

   const Botan::EC_Point simpleMinus = p1 - p0;
   result.test_eq("point subtraction", simpleMinus, p_G);

   const Botan::EC_Point simpleMult = p1 * 123456789;

   result.test_eq("point mult affine x",
                  simpleMult.get_affine_x(),
                  Botan::BigInt("43638877777452195295055270548491599621118743290"));
   result.test_eq("point mult affine y",
                  simpleMult.get_affine_y(),
                  Botan::BigInt("56841378500012376527163928510402662349220202981"));

   return result;
}

Test::Result test_enc_dec_compressed_160() {
   Test::Result result("ECC Unit");

   // Test for compressed conversion (02/03) 160bit
   const auto secp160r1 = Botan::EC_Group::from_name("secp160r1");
   const std::vector<uint8_t> G_comp = Botan::hex_decode("024A96B5688EF573284664698968C38BB913CBFC82");
   const Botan::EC_Point p = secp160r1.OS2ECP(G_comp);
   const std::vector<uint8_t> sv_result = p.encode(Botan::EC_Point_Format::Compressed);

   result.test_eq("result", sv_result, G_comp);
   return result;
}

Test::Result test_enc_dec_compressed_256() {
   Test::Result result("ECC Unit");

   const auto group = Botan::EC_Group::from_name("secp256r1");

   const std::string G_secp_comp = "036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296";
   const std::vector<uint8_t> sv_G_secp_comp = Botan::hex_decode(G_secp_comp);

   Botan::EC_Point p_G = group.OS2ECP(sv_G_secp_comp);
   std::vector<uint8_t> sv_result = p_G.encode(Botan::EC_Point_Format::Compressed);

   result.test_eq("compressed_256", sv_result, sv_G_secp_comp);
   return result;
}

Test::Result test_enc_dec_uncompressed_112() {
   Test::Result result("ECC Unit");

   // Test for uncompressed conversion (04) 112bit

   // Curve is secp112r2

   const Botan::BigInt p("0xdb7c2abf62e35e668076bead208b");
   const Botan::BigInt a("0x6127C24C05F38A0AAAF65C0EF02C");
   const Botan::BigInt b("0x51DEF1815DB5ED74FCC34C85D709");

   const Botan::BigInt g_x("0x4BA30AB5E892B4E1649DD0928643");
   const Botan::BigInt g_y("0xADCD46F5882E3747DEF36E956E97");

   const Botan::BigInt order("0x36DF0AAFD8B8D7597CA10520D04B");
   const Botan::BigInt cofactor("4");  // !

   // This uses the deprecated constructor due to making use of cofactor > 1
   const Botan::EC_Group group(p, a, b, g_x, g_y, order, cofactor);

   const std::string G_secp_uncomp = "044BA30AB5E892B4E1649DD0928643ADCD46F5882E3747DEF36E956E97";
   const std::vector<uint8_t> sv_G_secp_uncomp = Botan::hex_decode(G_secp_uncomp);

   Botan::EC_Point p_G = group.OS2ECP(sv_G_secp_uncomp);
   std::vector<uint8_t> sv_result = p_G.encode(Botan::EC_Point_Format::Uncompressed);

   result.test_eq("uncompressed_112", sv_result, sv_G_secp_uncomp);
   return result;
}

Test::Result test_enc_dec_uncompressed_521() {
   Test::Result result("ECC Unit");

   // Test for uncompressed conversion(04) with big values(521 bit)

   const std::string G_secp_uncomp =
      "0400C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2ffA8DE3348B3C1856A429BF97E7E31C2E5BD66011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650";

   const std::vector<uint8_t> sv_G_secp_uncomp = Botan::hex_decode(G_secp_uncomp);

   const auto group = Botan::EC_Group::from_name("secp521r1");

   Botan::EC_Point p_G = group.OS2ECP(sv_G_secp_uncomp);

   std::vector<uint8_t> sv_result = p_G.encode(Botan::EC_Point_Format::Uncompressed);

   result.test_eq("expected", sv_result, sv_G_secp_uncomp);
   return result;
}

Test::Result test_ecc_registration() {
   Test::Result result("ECC registration");

   // secp128r1
   const Botan::BigInt p("0xfffffffdffffffffffffffffffffffff");
   const Botan::BigInt a("0xfffffffdfffffffffffffffffffffffc");
   const Botan::BigInt b("0xe87579c11079f43dd824993c2cee5ed3");

   const Botan::BigInt g_x("0x161ff7528b899b2d0c28607ca52c5b86");
   const Botan::BigInt g_y("0xcf5ac8395bafeb13c02da292dded7a83");
   const Botan::BigInt order("0xfffffffe0000000075a30d1b9038a115");

   const Botan::OID oid("1.3.132.0.28");

   // Creating this object implicitly registers the curve for future use ...
   Botan::EC_Group reg_group(oid, p, a, b, g_x, g_y, order);

   auto group = Botan::EC_Group::from_OID(oid);

   result.test_eq("Group registration worked", group.get_p(), p);

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

class ECC_Unit_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         results.push_back(test_coordinates());
         results.push_back(test_decoding_with_seed());
         results.push_back(test_point_mult());
         results.push_back(test_point_negative());
         results.push_back(test_mult_point());
         results.push_back(test_mixed_points());
         results.push_back(test_basic_operations());
         results.push_back(test_enc_dec_compressed_160());
         results.push_back(test_enc_dec_compressed_256());
         results.push_back(test_enc_dec_uncompressed_112());
         results.push_back(test_enc_dec_uncompressed_521());
         results.push_back(test_ecc_registration());
         results.push_back(test_ec_group_from_params());
         results.push_back(test_ec_group_bad_registration());
         results.push_back(test_ec_group_duplicate_orders());

         return results;
      }
};

BOTAN_REGISTER_SERIALIZED_TEST("pubkey", "ecc_unit", ECC_Unit_Tests);

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
