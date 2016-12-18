/*
* (C) 2007 Falko Strenzke
*     2007 Manuel Hartl
*     2009,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_ECC_GROUP)
  #include <botan/bigint.h>
  #include <botan/numthry.h>
  #include <botan/curve_gfp.h>
  #include <botan/curve_nistp.h>
  #include <botan/point_gfp.h>
  #include <botan/ec_group.h>
  #include <botan/reducer.h>
  #include <botan/oids.h>
  #include <botan/hex.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_ECC_GROUP)

const std::vector<std::string> ec_groups = {
      "brainpool160r1",
      "brainpool192r1",
      "brainpool224r1",
      "brainpool256r1",
      "brainpool320r1",
      "brainpool384r1",
      "brainpool512r1",
      "gost_256A",
      "secp160k1",
      "secp160r1",
      "secp160r2",
      "secp192k1",
      "secp192r1",
      "secp224k1",
      "secp224r1",
      "secp256k1",
      "secp256r1",
      "secp384r1",
      "secp521r1",
      "x962_p192v2",
      "x962_p192v3",
      "x962_p239v1",
      "x962_p239v2",
      "x962_p239v3"
   };

Botan::BigInt test_integer(Botan::RandomNumberGenerator& rng, size_t bits, BigInt max)
   {
   /*
   Produces integers with long runs of ones and zeros, for testing for
   carry handling problems.
   */
   Botan::BigInt x = 0;

   auto flip_prob = [](size_t i) {
      if(i % 64 == 0)
         return .5;
      if(i % 32 == 0)
         return .4;
      if(i % 8 == 0)
         return .05;
      return .01;
   };

   bool active = rng.next_byte() % 2;
   for(size_t i = 0; i != bits; ++i)
      {
      x <<= 1;
      x += static_cast<int>(active);

      const double prob = flip_prob(i);
      const double sample = double(rng.next_byte() % 100) / 100.0; // biased

      if(sample < prob)
         active = !active;
      }

   if(max > 0)
      {
      while(x >= max)
         {
         const size_t b = x.bits() - 1;
         BOTAN_ASSERT(x.get_bit(b) == true, "Set");
         x.clear_bit(b);
         }
      }

   return x;
   }

Botan::PointGFp create_random_point(Botan::RandomNumberGenerator& rng,
                                    const Botan::CurveGFp& curve)
   {
   const Botan::BigInt& p = curve.get_p();

   Botan::Modular_Reducer mod_p(p);

   while(true)
      {
      const Botan::BigInt x = Botan::BigInt::random_integer(rng, 1, p);
      const Botan::BigInt x3 = mod_p.multiply(x, mod_p.square(x));
      const Botan::BigInt ax = mod_p.multiply(curve.get_a(), x);
      const Botan::BigInt y = mod_p.reduce(x3 + ax + curve.get_b());
      const Botan::BigInt sqrt_y = ressol(y, p);

      if(sqrt_y > 1)
         {
         BOTAN_ASSERT_EQUAL(mod_p.square(sqrt_y), y, "Square root is correct");
         Botan::PointGFp point(curve, x, sqrt_y);
         return point;
         }
      }
   }

class ECC_Randomized_Tests : public Test
   {
   public:
      std::vector<Test::Result> run() override;
   };

std::vector<Test::Result> ECC_Randomized_Tests::run()
   {
   std::vector<Test::Result> results;
   for(auto&& group_name : ec_groups)
      {
      Test::Result result("ECC randomized " + group_name);

      Botan::EC_Group group(group_name);

      const Botan::PointGFp& base_point = group.get_base_point();
      const Botan::BigInt& group_order = group.get_order();

      const Botan::PointGFp inf = base_point * group_order;
      result.test_eq("infinite order correct", inf.is_zero(), true);
      result.test_eq("infinity on the curve", inf.on_the_curve(), true);

      try
         {
         for(size_t i = 0; i <= Test::soak_level(); ++i)
            {
            const size_t h = 1 + (Test::rng().next_byte() % 8);
            Botan::Blinded_Point_Multiply blind(base_point, group_order, h);

            const Botan::BigInt a = Botan::BigInt::random_integer(Test::rng(), 2, group_order);
            const Botan::BigInt b = Botan::BigInt::random_integer(Test::rng(), 2, group_order);
            const Botan::BigInt c = a + b;

            const Botan::PointGFp P = base_point * a;
            const Botan::PointGFp Q = base_point * b;
            const Botan::PointGFp R = base_point * c;

            const Botan::PointGFp P1 = blind.blinded_multiply(a, Test::rng());
            const Botan::PointGFp Q1 = blind.blinded_multiply(b, Test::rng());
            const Botan::PointGFp R1 = blind.blinded_multiply(c, Test::rng());

            const Botan::PointGFp A1 = P + Q;
            const Botan::PointGFp A2 = Q + P;

            result.test_eq("p + q", A1, R);
            result.test_eq("q + p", A2, R);

            result.test_eq("p on the curve", P.on_the_curve(), true);
            result.test_eq("q on the curve", Q.on_the_curve(), true);
            result.test_eq("r on the curve", R.on_the_curve(), true);
            result.test_eq("a1 on the curve", A1.on_the_curve(), true);
            result.test_eq("a2 on the curve", A2.on_the_curve(), true);

            result.test_eq("P1", P1, P);
            result.test_eq("Q1", Q1, Q);
            result.test_eq("R1", R1, R);
            }
         }
      catch(std::exception& e)
         {
         result.test_failure(group_name, e.what());
         }
      results.push_back(result);
      }

   return results;
   }

BOTAN_REGISTER_TEST("ecc_randomized", ECC_Randomized_Tests);

class NIST_Curve_Reduction_Tests : public Test
   {
   public:
      typedef std::function<void (Botan::BigInt&, Botan::secure_vector<Botan::word>&)> reducer_fn;
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

#if defined(BOTAN_HAS_NIST_PRIME_REDUCERS_W32)
         results.push_back(random_redc_test("P-192", Botan::prime_p192(), Botan::redc_p192));
         results.push_back(random_redc_test("P-224", Botan::prime_p224(), Botan::redc_p224));
         results.push_back(random_redc_test("P-256", Botan::prime_p256(), Botan::redc_p256));
         results.push_back(random_redc_test("P-384", Botan::prime_p384(), Botan::redc_p384));
#endif
         results.push_back(random_redc_test("P-521", Botan::prime_p521(), Botan::redc_p521));
         return results;
         }

      Test::Result random_redc_test(const std::string& prime_name,
                                    const Botan::BigInt& p,
                                    reducer_fn redc_fn)
         {
         const Botan::BigInt p2 = p*p;
         const size_t p_bits = p.bits();

         Botan::Modular_Reducer p_redc(p);
         Botan::secure_vector<Botan::word> ws;

         Test::Result result("NIST " + prime_name + " reduction");

         for(size_t i = 0; i <= 10 * Test::soak_level(); ++i)
            {
            const Botan::BigInt x = test_integer(Test::rng(), 2*p_bits, p2);

            // TODO: time and report all three approaches
            const Botan::BigInt v1 = x % p;
            const Botan::BigInt v2 = p_redc.reduce(x);

            Botan::BigInt v3 = x;
            redc_fn(v3, ws);

            if(!result.test_eq("reference redc", v1, v2) ||
               !result.test_eq("specialized redc", v2, v3))
               {
               result.test_note("failing input" + Botan::hex_encode(Botan::BigInt::encode(x)));
               }
            }

         return result;
         }
   };

BOTAN_REGISTER_TEST("nist_redc", NIST_Curve_Reduction_Tests);

Test::Result test_coordinates()
   {
   Test::Result result("ECC Unit");

   const Botan::BigInt exp_affine_x("16984103820118642236896513183038186009872590470");
   const Botan::BigInt exp_affine_y("1373093393927139016463695321221277758035357890939");

   // precalculation
   const Botan::EC_Group secp160r1(Botan::OIDS::lookup("secp160r1"));
   const Botan::CurveGFp& curve = secp160r1.get_curve();
   const Botan::PointGFp& p_G = secp160r1.get_base_point();
   const Botan::PointGFp p0 = p_G;
   const Botan::PointGFp p1 = p_G * 2;
   const Botan::PointGFp point_exp(curve, exp_affine_x, exp_affine_y);
   result.confirm("Point is on the curve", point_exp.on_the_curve());

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
Test::Result test_point_transformation ()
   {
   Test::Result result("ECC Unit");

   // get a valid point
   Botan::EC_Group dom_pars(Botan::OID("1.3.132.0.8"));
   Botan::PointGFp p = dom_pars.get_base_point() * Test::rng().next_nonzero_byte();

   // get a copy
   Botan::PointGFp q = p;

   p.randomize_repr(Test::rng());
   q.randomize_repr(Test::rng());

   result.test_eq("affine x after copy", p.get_affine_x(), q.get_affine_x());
   result.test_eq("affine y after copy", p.get_affine_y(), q.get_affine_y());
   return result;
   }

Test::Result test_point_mult ()
   {
   Test::Result result("ECC Unit");

   Botan::EC_Group secp160r1(Botan::OIDS::lookup("secp160r1"));
   const Botan::PointGFp& p_G = secp160r1.get_base_point();

   Botan::BigInt d_U("0xaa374ffc3ce144e6b073307972cb6d57b2a4e982");
   Botan::PointGFp Q_U = d_U * p_G;

   result.test_eq("affine x", Q_U.get_affine_x(), Botan::BigInt("466448783855397898016055842232266600516272889280"));
   result.test_eq("affine y", Q_U.get_affine_y(), Botan::BigInt("1110706324081757720403272427311003102474457754220"));
   return result;
   }

Test::Result test_point_negative()
   {
   Test::Result result("ECC Unit");

   Botan::EC_Group secp160r1(Botan::OIDS::lookup("secp160r1"));
   const Botan::PointGFp& p_G = secp160r1.get_base_point();

   const Botan::PointGFp p1 = p_G * 2;

   result.test_eq("affine x", p1.get_affine_x(), Botan::BigInt("16984103820118642236896513183038186009872590470"));
   result.test_eq("affine y", p1.get_affine_y(), Botan::BigInt("1373093393927139016463695321221277758035357890939"));

   const Botan::PointGFp p1_neg = -p1;

   result.test_eq("affine x", p1_neg.get_affine_x(), p1.get_affine_x());
   result.test_eq("affine y", p1_neg.get_affine_y(),  Botan::BigInt("88408243403763901739989511495005261618427168388"));
   return result;
   }

Test::Result test_zeropoint()
   {
   Test::Result result("ECC Unit");

   Botan::EC_Group secp160r1(Botan::OIDS::lookup("secp160r1"));
   const Botan::CurveGFp& curve = secp160r1.get_curve();

   Botan::PointGFp p1(curve,
               Botan::BigInt("16984103820118642236896513183038186009872590470"),
               Botan::BigInt("1373093393927139016463695321221277758035357890939"));

   result.confirm("point is on the curve", p1.on_the_curve());
   p1 -= p1;

   result.confirm("p - q with q = p results in zero", p1.is_zero());
   return result;
   }

Test::Result test_zeropoint_enc_dec()
   {
   Test::Result result("ECC Unit");

   Botan::EC_Group secp160r1(Botan::OIDS::lookup("secp160r1"));
   const Botan::CurveGFp& curve = secp160r1.get_curve();

   Botan::PointGFp p(curve);
   result.confirm("zero point is zero", p.is_zero());

   std::vector<uint8_t> sv_p = unlock(EC2OSP(p, Botan::PointGFp::UNCOMPRESSED));
   result.test_eq("encoded/decode rt works", OS2ECP(sv_p, curve), p);

   sv_p = unlock(EC2OSP(p, Botan::PointGFp::COMPRESSED));
   result.test_eq("encoded/decode compressed rt works", OS2ECP(sv_p, curve), p);

   sv_p = unlock(EC2OSP(p, Botan::PointGFp::HYBRID));
   result.test_eq("encoded/decode hybrid rt works", OS2ECP(sv_p, curve), p);
   return result;
   }

Test::Result test_calc_with_zeropoint()
   {
   Test::Result result("ECC Unit");

   Botan::EC_Group secp160r1(Botan::OIDS::lookup("secp160r1"));
   const Botan::CurveGFp& curve = secp160r1.get_curve();

   Botan::PointGFp p(curve,
              Botan::BigInt("16984103820118642236896513183038186009872590470"),
              Botan::BigInt("1373093393927139016463695321221277758035357890939"));

   result.confirm("point is on the curve", p.on_the_curve());
   result.confirm("point is not zero", !p.is_zero());

   Botan::PointGFp zero(curve);
   result.confirm("zero point is zero", zero.is_zero());

   Botan::PointGFp res = p + zero;
   result.test_eq("point + 0 equals the point", p, res);

   res = p - zero;
   result.test_eq("point - 0 equals the point", p, res);

   res = zero * 32432243;
   result.confirm("point * 0 is the zero point", res.is_zero());
   return result;
   }

Test::Result test_add_point()
   {
   Test::Result result("ECC Unit");

   // precalculation
   Botan::EC_Group secp160r1(Botan::OIDS::lookup("secp160r1"));
   const Botan::CurveGFp& curve = secp160r1.get_curve();
   const Botan::PointGFp& p_G = secp160r1.get_base_point();

   Botan::PointGFp p0 = p_G;
   Botan::PointGFp p1 = p_G * 2;

   p1 += p0;

   Botan::PointGFp expected(curve,
                     Botan::BigInt("704859595002530890444080436569091156047721708633"),
                     Botan::BigInt("1147993098458695153857594941635310323215433166682"));

   result.test_eq("point addition", p1, expected);
   return result;
   }

Test::Result test_sub_point()
   {
   Test::Result result("ECC Unit");

   Botan::EC_Group secp160r1(Botan::OIDS::lookup("secp160r1"));
   const Botan::CurveGFp& curve = secp160r1.get_curve();
   const Botan::PointGFp& p_G = secp160r1.get_base_point();

   Botan::PointGFp p0 = p_G;
   Botan::PointGFp p1 = p_G * 2;

   p1 -= p0;

   Botan::PointGFp expected(curve,
                            Botan::BigInt("425826231723888350446541592701409065913635568770"),
                            Botan::BigInt("203520114162904107873991457957346892027982641970"));

   result.test_eq("point subtraction", p1, expected);
   return result;
   }

Test::Result test_mult_point()
   {
   Test::Result result("ECC Unit");

   Botan::EC_Group secp160r1(Botan::OIDS::lookup("secp160r1"));
   const Botan::CurveGFp& curve = secp160r1.get_curve();
   const Botan::PointGFp& p_G = secp160r1.get_base_point();

   Botan::PointGFp p0 = p_G;
   Botan::PointGFp p1 = p_G * 2;

   p1 *= p0.get_affine_x();

   const Botan::BigInt exp_mult_x(std::string("967697346845926834906555988570157345422864716250"));
   const Botan::BigInt exp_mult_y(std::string("512319768365374654866290830075237814703869061656"));
   Botan::PointGFp expected(curve, exp_mult_x, exp_mult_y);

   result.test_eq("point mult", p1, expected);
   return result;
   }

Test::Result test_basic_operations()
   {
   Test::Result result("ECC Unit");

   // precalculation
   Botan::EC_Group secp160r1(Botan::OIDS::lookup("secp160r1"));
   const Botan::CurveGFp& curve = secp160r1.get_curve();
   const Botan::PointGFp& p_G = secp160r1.get_base_point();

   const Botan::PointGFp p0 = p_G;
   const Botan::PointGFp p1 = p_G * 2;

   result.test_eq("p1 affine x", p1.get_affine_x(), Botan::BigInt("16984103820118642236896513183038186009872590470"));
   result.test_eq("p1 affine y", p1.get_affine_y(), Botan::BigInt("1373093393927139016463695321221277758035357890939"));

   const Botan::PointGFp simplePlus = p1 + p0;
   const Botan::PointGFp exp_simplePlus(curve,
                           Botan::BigInt("704859595002530890444080436569091156047721708633"),
                           Botan::BigInt("1147993098458695153857594941635310323215433166682"));

   result.test_eq("point addition", simplePlus, exp_simplePlus);

   const Botan::PointGFp simpleMinus = p1 - p0;
   const Botan::PointGFp exp_simpleMinus(curve,
                            Botan::BigInt("425826231723888350446541592701409065913635568770"),
                            Botan::BigInt("203520114162904107873991457957346892027982641970"));

   result.test_eq("point subtraction", simpleMinus, exp_simpleMinus);

   const Botan::PointGFp simpleMult = p1 * 123456789;

   result.test_eq("point mult affine x", simpleMult.get_affine_x(),
                  Botan::BigInt("43638877777452195295055270548491599621118743290"));
   result.test_eq("point mult affine y", simpleMult.get_affine_y(),
                  Botan::BigInt("56841378500012376527163928510402662349220202981"));

   return result;
   }

Test::Result test_enc_dec_compressed_160()
   {
   Test::Result result("ECC Unit");

   // Test for compressed conversion (02/03) 160bit
   Botan::EC_Group secp160r1(Botan::OIDS::lookup("secp160r1"));
   const Botan::CurveGFp& curve = secp160r1.get_curve();

   const std::vector<uint8_t> G_comp = Botan::hex_decode("024A96B5688EF573284664698968C38BB913CBFC82");

   const Botan::PointGFp p = Botan::OS2ECP(G_comp, curve);

   std::vector<uint8_t> sv_result = unlock(Botan::EC2OSP(p, Botan::PointGFp::COMPRESSED));

   result.test_eq("result", sv_result, G_comp);
   return result;
   }

Test::Result test_enc_dec_compressed_256()
   {
   Test::Result result("ECC Unit");

   // Test for compressed conversion (02/03) 256bit
   std::string p_secp = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
   std::string a_secp = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffFC";
   std::string b_secp = "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B";
   std::string G_secp_comp = "036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296";

   std::vector<uint8_t> sv_p_secp = Botan::hex_decode ( p_secp );
   std::vector<uint8_t> sv_a_secp = Botan::hex_decode ( a_secp );
   std::vector<uint8_t> sv_b_secp = Botan::hex_decode ( b_secp );
   std::vector<uint8_t> sv_G_secp_comp = Botan::hex_decode ( G_secp_comp );

   Botan::BigInt bi_p_secp = Botan::BigInt::decode ( sv_p_secp.data(), sv_p_secp.size() );
   Botan::BigInt bi_a_secp = Botan::BigInt::decode ( sv_a_secp.data(), sv_a_secp.size() );
   Botan::BigInt bi_b_secp = Botan::BigInt::decode ( sv_b_secp.data(), sv_b_secp.size() );

   Botan::CurveGFp curve(bi_p_secp, bi_a_secp, bi_b_secp);

   Botan::PointGFp p_G = OS2ECP ( sv_G_secp_comp, curve );
   std::vector<uint8_t> sv_result = unlock(EC2OSP(p_G, Botan::PointGFp::COMPRESSED));

   result.test_eq("compressed_256", sv_result, sv_G_secp_comp);
   return result;
   }


Test::Result test_enc_dec_uncompressed_112()
   {
   Test::Result result("ECC Unit");

   // Test for uncompressed conversion (04) 112bit

   std::string p_secp = "db7c2abf62e35e668076bead208b";
   std::string a_secp = "6127C24C05F38A0AAAF65C0EF02C";
   std::string b_secp = "51DEF1815DB5ED74FCC34C85D709";
   std::string G_secp_uncomp = "044BA30AB5E892B4E1649DD0928643ADCD46F5882E3747DEF36E956E97";

   std::vector<uint8_t> sv_p_secp = Botan::hex_decode ( p_secp );
   std::vector<uint8_t> sv_a_secp = Botan::hex_decode ( a_secp );
   std::vector<uint8_t> sv_b_secp = Botan::hex_decode ( b_secp );
   std::vector<uint8_t> sv_G_secp_uncomp = Botan::hex_decode ( G_secp_uncomp );

   Botan::BigInt bi_p_secp = Botan::BigInt::decode ( sv_p_secp.data(), sv_p_secp.size() );
   Botan::BigInt bi_a_secp = Botan::BigInt::decode ( sv_a_secp.data(), sv_a_secp.size() );
   Botan::BigInt bi_b_secp = Botan::BigInt::decode ( sv_b_secp.data(), sv_b_secp.size() );

   Botan::CurveGFp curve(bi_p_secp, bi_a_secp, bi_b_secp);

   Botan::PointGFp p_G = OS2ECP ( sv_G_secp_uncomp, curve );
   std::vector<uint8_t> sv_result = unlock(EC2OSP(p_G, Botan::PointGFp::UNCOMPRESSED));

   result.test_eq("uncompressed_112", sv_result, sv_G_secp_uncomp);
   return result;
   }

Test::Result test_enc_dec_uncompressed_521()
   {
   Test::Result result("ECC Unit");

   // Test for uncompressed conversion(04) with big values(521 bit)
   std::string p_secp = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
   std::string a_secp = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffFC";
   std::string b_secp = "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00";
   std::string G_secp_uncomp = "0400C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2ffA8DE3348B3C1856A429BF97E7E31C2E5BD66011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650";

   std::vector<uint8_t> sv_p_secp = Botan::hex_decode ( p_secp );
   std::vector<uint8_t> sv_a_secp = Botan::hex_decode ( a_secp );
   std::vector<uint8_t> sv_b_secp = Botan::hex_decode ( b_secp );
   std::vector<uint8_t> sv_G_secp_uncomp = Botan::hex_decode ( G_secp_uncomp );

   Botan::BigInt bi_p_secp = Botan::BigInt::decode ( sv_p_secp.data(), sv_p_secp.size() );
   Botan::BigInt bi_a_secp = Botan::BigInt::decode ( sv_a_secp.data(), sv_a_secp.size() );
   Botan::BigInt bi_b_secp = Botan::BigInt::decode ( sv_b_secp.data(), sv_b_secp.size() );

   Botan::CurveGFp curve(bi_p_secp, bi_a_secp, bi_b_secp);

   Botan::PointGFp p_G = Botan::OS2ECP ( sv_G_secp_uncomp, curve );

   std::vector<uint8_t> sv_result = unlock(EC2OSP(p_G, Botan::PointGFp::UNCOMPRESSED));

   result.test_eq("expected", sv_result, sv_G_secp_uncomp);
   return result;
   }

Test::Result test_enc_dec_uncompressed_521_prime_too_large()
   {
   Test::Result result("ECC Unit");

   // Test for uncompressed conversion(04) with big values(521 bit)
   std::string p_secp = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"; // length increased by "ff"
   std::string a_secp = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffFC";
   std::string b_secp = "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00";
   std::string G_secp_uncomp = "0400C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2ffA8DE3348B3C1856A429BF97E7E31C2E5BD66011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650";

   std::vector<uint8_t> sv_p_secp = Botan::hex_decode ( p_secp );
   std::vector<uint8_t> sv_a_secp = Botan::hex_decode ( a_secp );
   std::vector<uint8_t> sv_b_secp = Botan::hex_decode ( b_secp );
   std::vector<uint8_t> sv_G_secp_uncomp = Botan::hex_decode ( G_secp_uncomp );

   Botan::BigInt bi_p_secp = Botan::BigInt::decode ( sv_p_secp.data(), sv_p_secp.size() );
   Botan::BigInt bi_a_secp = Botan::BigInt::decode ( sv_a_secp.data(), sv_a_secp.size() );
   Botan::BigInt bi_b_secp = Botan::BigInt::decode ( sv_b_secp.data(), sv_b_secp.size() );

   Botan::CurveGFp secp521r1 (bi_p_secp, bi_a_secp, bi_b_secp);
   std::unique_ptr<Botan::PointGFp> p_G;

   try
      {
      p_G = std::unique_ptr<Botan::PointGFp>(new Botan::PointGFp(Botan::OS2ECP ( sv_G_secp_uncomp, secp521r1)));
      result.test_failure("point decoding with too large value accepted");
      }
   catch(std::exception&)
      {
      result.test_note("rejected invalid point");
      }

   return result;
   }

Test::Result test_gfp_store_restore()
   {
   Test::Result result("ECC Unit");

   // generate point
   Botan::EC_Group dom_pars(Botan::OID("1.3.132.0.8"));
   Botan::PointGFp p = dom_pars.get_base_point();

   std::vector<uint8_t> sv_mes = unlock(EC2OSP(p, Botan::PointGFp::COMPRESSED));
   Botan::PointGFp new_p = Botan::OS2ECP(sv_mes, dom_pars.get_curve());

   result.test_eq("original and restored points are same", p, new_p);
   return result;
   }


// maybe move this test
Test::Result test_cdc_curve_33()
   {
   Test::Result result("ECC Unit");

   std::string G_secp_uncomp = "04081523d03d4f12cd02879dea4bf6a4f3a7df26ed888f10c5b2235a1274c386a2f218300dee6ed217841164533bcdc903f07a096f9fbf4ee95bac098a111f296f5830fe5c35b3e344d5df3a2256985f64fbe6d0edcc4c61d18bef681dd399df3d0194c5a4315e012e0245ecea56365baa9e8be1f7";

   std::vector<uint8_t> sv_G_uncomp = Botan::hex_decode ( G_secp_uncomp );

   Botan::BigInt bi_p_secp = Botan::BigInt("2117607112719756483104013348936480976596328609518055062007450442679169492999007105354629105748524349829824407773719892437896937279095106809");
   Botan::BigInt bi_a_secp("0xa377dede6b523333d36c78e9b0eaa3bf48ce93041f6d4fc34014d08f6833807498deedd4290101c5866e8dfb589485d13357b9e78c2d7fbe9fe");
   Botan::BigInt bi_b_secp("0xa9acf8c8ba617777e248509bcb4717d4db346202bf9e352cd5633731dd92a51b72a4dc3b3d17c823fcc8fbda4da08f25dea89046087342595a7");

   Botan::CurveGFp curve(bi_p_secp, bi_a_secp, bi_b_secp);
   Botan::PointGFp p_G = Botan::OS2ECP ( sv_G_uncomp, curve);
   result.confirm("point is on the curve", p_G.on_the_curve());
   return result;
   }

Test::Result test_more_zeropoint()
   {
   Test::Result result("ECC Unit");

   // by Falko

   Botan::EC_Group secp160r1(Botan::OIDS::lookup("secp160r1"));
   const Botan::CurveGFp& curve = secp160r1.get_curve();

   Botan::PointGFp p1(curve,
               Botan::BigInt("16984103820118642236896513183038186009872590470"),
               Botan::BigInt("1373093393927139016463695321221277758035357890939"));

   result.confirm("point is on the curve", p1.on_the_curve());
   Botan::PointGFp minus_p1 = -p1;
   result.confirm("point is on the curve", minus_p1.on_the_curve());
   Botan::PointGFp shouldBeZero = p1 + minus_p1;
   result.confirm("point is on the curve", shouldBeZero.on_the_curve());
   result.confirm("point is zero", shouldBeZero.is_zero());

   Botan::BigInt y1 = p1.get_affine_y();
   y1 = curve.get_p() - y1;

   result.test_eq("minus point x", minus_p1.get_affine_x(), p1.get_affine_x());
   result.test_eq("minus point y", minus_p1.get_affine_y(), y1);

   Botan::PointGFp zero(curve);
   result.confirm("zero point is on the curve", zero.on_the_curve());
   result.test_eq("addition of zero does nothing", p1, p1 + zero);

   return result;
   }

Test::Result test_mult_by_order()
   {
   Test::Result result("ECC Unit");

   // generate point
   Botan::EC_Group dom_pars(Botan::OID("1.3.132.0.8"));
   Botan::PointGFp p = dom_pars.get_base_point();
   Botan::PointGFp shouldBeZero = p * dom_pars.get_order();

   result.confirm("G * order = 0", shouldBeZero.is_zero());
   return result;
   }

Test::Result test_point_swap()
   {
   Test::Result result("ECC Unit");

   Botan::EC_Group dom_pars(Botan::OID("1.3.132.0.8"));

   Botan::PointGFp a(create_random_point(Test::rng(), dom_pars.get_curve()));
   Botan::PointGFp b(create_random_point(Test::rng(), dom_pars.get_curve()));
   b *= Botan::BigInt(Test::rng(), 20);

   Botan::PointGFp c(a);
   Botan::PointGFp d(b);

   d.swap(c);
   result.test_eq("swap correct", a, d);
   result.test_eq("swap correct", b, c);

   return result;
   }

/**
* This test verifies that the side channel attack resistant multiplication function
* yields the same result as the normal (insecure) multiplication via operator*=
*/
Test::Result test_mult_sec_mass()
   {
   Test::Result result("ECC Unit");

   Botan::EC_Group dom_pars(Botan::OID("1.3.132.0.8"));
   for(int i = 0; i<50; i++)
      {
      try
         {
         Botan::PointGFp a(create_random_point(Test::rng(), dom_pars.get_curve()));
         Botan::BigInt scal(Botan::BigInt(Test::rng(), 40));
         Botan::PointGFp b = a * scal;
         Botan::PointGFp c(a);

         c *= scal;
         result.test_eq("same result", b, c);
         }
      catch(std::exception& e)
         {
         result.test_failure("mult_sec_mass", e.what());
         }
      }

   return result;
   }

Test::Result test_curve_cp_ctor()
   {
   Test::Result result("ECC Unit");

   try
      {
      Botan::EC_Group dom_pars(Botan::OID("1.3.132.0.8"));
      Botan::CurveGFp curve(dom_pars.get_curve());
      }
   catch(std::exception& e)
      {
      result.test_failure("curve_cp_ctor", e.what());
      }

   return result;
   }

class ECC_Unit_Tests : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         results.push_back(test_coordinates());
         results.push_back(test_point_transformation ());
         results.push_back(test_point_mult ());
         results.push_back(test_point_negative());
         results.push_back(test_zeropoint());
         results.push_back(test_zeropoint_enc_dec());
         results.push_back(test_calc_with_zeropoint());
         results.push_back(test_add_point());
         results.push_back(test_sub_point());
         results.push_back(test_mult_point());
         results.push_back(test_basic_operations());
         results.push_back(test_enc_dec_compressed_160());
         results.push_back(test_enc_dec_compressed_256());
         results.push_back(test_enc_dec_uncompressed_112());
         results.push_back(test_enc_dec_uncompressed_521());
         results.push_back(test_enc_dec_uncompressed_521_prime_too_large());
         results.push_back(test_gfp_store_restore());
         results.push_back(test_cdc_curve_33());
         results.push_back(test_more_zeropoint());
         results.push_back(test_mult_by_order());
         results.push_back(test_point_swap());
         results.push_back(test_mult_sec_mass());
         results.push_back(test_curve_cp_ctor());

         return results;
         }
   };

BOTAN_REGISTER_TEST("ecc_unit", ECC_Unit_Tests);

#endif

}

}
