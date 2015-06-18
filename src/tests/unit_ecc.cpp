/*
* (C) 2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#include <botan/hex.h>
#include <iostream>
#include <memory>

#if defined(BOTAN_HAS_ECC_GROUP)

#include <botan/bigint.h>
#include <botan/numthry.h>
#include <botan/curve_gfp.h>
#include <botan/point_gfp.h>
#include <botan/ec_group.h>
#include <botan/reducer.h>
#include <botan/oids.h>

using namespace Botan;

#define CHECK_MESSAGE(expr, print) try { if(!(expr)) { ++fails; std::cout << "FAILURE: " << print << std::endl; }} catch(std::exception& e) { std::cout << __FUNCTION__ << ": " << e.what() << std::endl; }
#define CHECK(expr) try { if(!(expr)) { ++fails; std::cout << "FAILURE: " << #expr << std::endl; } } catch(std::exception& e) { std::cout << __FUNCTION__ << ": " << e.what() << std::endl; }

namespace {

std::ostream& operator<<(std::ostream& out, const PointGFp& point)
   {
   out << "(" << point.get_affine_x() << " " << point.get_affine_y() << ")";
   return out;
   }

PointGFp create_random_point(RandomNumberGenerator& rng,
                             const CurveGFp& curve)
   {
   const BigInt& p = curve.get_p();

   Modular_Reducer mod_p(p);

   while(true)
      {
      const BigInt x = BigInt::random_integer(rng, 1, p);
      const BigInt x3 = mod_p.multiply(x, mod_p.square(x));
      const BigInt ax = mod_p.multiply(curve.get_a(), x);
      const BigInt y = mod_p.reduce(x3 + ax + curve.get_b());
      const BigInt sqrt_y = ressol(y, p);

      if(sqrt_y > 1)
         {
         BOTAN_ASSERT_EQUAL(mod_p.square(sqrt_y), y, "Square root is correct");
         PointGFp point(curve, x, sqrt_y);
         return point;
         }
      }
   }

size_t test_point_turn_on_sp_red_mul()
   {
   size_t fails = 0;

   // setting up expected values
   BigInt exp_Qx(std::string("466448783855397898016055842232266600516272889280"));
   BigInt exp_Qy(std::string("1110706324081757720403272427311003102474457754220"));
   BigInt exp_Qz(1);

   // performing calculation to test
   std::string p_secp = "ffffffffffffffffffffffffffffffff7fffffff";
   std::string a_secp = "ffffffffffffffffffffffffffffffff7ffffffc";
   std::string b_secp = "1c97befc54bd7a8b65acf89f81d4d4adc565fa45";
   std::string G_secp_comp = "024a96b5688ef573284664698968c38bb913cbfc82";
   std::vector<byte> sv_p_secp = hex_decode(p_secp);
   std::vector<byte> sv_a_secp = hex_decode(a_secp);
   std::vector<byte> sv_b_secp = hex_decode(b_secp);
   std::vector<byte> sv_G_secp_comp = hex_decode(G_secp_comp);
   BigInt bi_p_secp = BigInt::decode(&sv_p_secp[0], sv_p_secp.size());
   BigInt bi_a_secp = BigInt::decode(&sv_a_secp[0], sv_a_secp.size());
   BigInt bi_b_secp = BigInt::decode(&sv_b_secp[0], sv_b_secp.size());
   CurveGFp secp160r1(bi_p_secp, bi_a_secp, bi_b_secp);
   PointGFp p_G = OS2ECP(sv_G_secp_comp, secp160r1);

   BigInt d("459183204582304");

   PointGFp r1 = d * p_G;
   CHECK(r1.get_affine_x() != 0);

   PointGFp p_G2(p_G);

   PointGFp r2 = d * p_G2;
   CHECK_MESSAGE(r1 == r2, "error with point mul after extra turn on sp red mul");
   CHECK(r1.get_affine_x() != 0);

   PointGFp p_r1 = r1;
   PointGFp p_r2 = r2;

   p_r1 *= 2;
   p_r2 *= 2;
   CHECK_MESSAGE(p_r1.get_affine_x() == p_r2.get_affine_x(), "error with mult2 after extra turn on sp red mul");
   CHECK(p_r1.get_affine_x() != 0);
   CHECK(p_r2.get_affine_x() != 0);
   r1 *= 2;

   r2 *= 2;

   CHECK_MESSAGE(r1 == r2, "error with mult2 after extra turn on sp red mul");
   CHECK_MESSAGE(r1.get_affine_x() == r2.get_affine_x(), "error with mult2 after extra turn on sp red mul");
   CHECK(r1.get_affine_x() != 0);
   r1 += p_G;
   r2 += p_G2;

   CHECK_MESSAGE(r1 == r2, "error with op+= after extra turn on sp red mul");

   r1 += p_G;
   r2 += p_G2;

   CHECK_MESSAGE(r1 == r2, "error with op+= after extra turn on sp red mul for both operands");
   r1 += p_G;
   r2 += p_G2;

   CHECK_MESSAGE(r1 == r2, "error with op+= after extra turn on sp red mul for both operands");
   return fails;
   }

size_t test_coordinates()
   {
   size_t fails = 0;

   BigInt exp_affine_x(std::string("16984103820118642236896513183038186009872590470"));
   BigInt exp_affine_y(std::string("1373093393927139016463695321221277758035357890939"));

   // precalculation
   std::string p_secp = "ffffffffffffffffffffffffffffffff7fffffff";
   std::string a_secp = "ffffffffffffffffffffffffffffffff7ffffffc";
   std::string b_secp = "1c97befc54bd7a8b65acf89f81d4d4adc565fa45";
   std::string G_secp_comp = "024a96b5688ef573284664698968c38bb913cbfc82";
   std::vector<byte> sv_p_secp = hex_decode ( p_secp );
   std::vector<byte> sv_a_secp = hex_decode ( a_secp );
   std::vector<byte> sv_b_secp = hex_decode ( b_secp );
   std::vector<byte> sv_G_secp_comp = hex_decode ( G_secp_comp );

   BigInt bi_p_secp = BigInt::decode ( &sv_p_secp[0], sv_p_secp.size() );
   BigInt bi_a_secp = BigInt::decode ( &sv_a_secp[0], sv_a_secp.size() );
   BigInt bi_b_secp = BigInt::decode ( &sv_b_secp[0], sv_b_secp.size() );
   CurveGFp secp160r1 (bi_p_secp, bi_a_secp, bi_b_secp);
   PointGFp p_G = OS2ECP ( sv_G_secp_comp, secp160r1 );
   PointGFp p0 = p_G;
   PointGFp p1 = p_G * 2;
   PointGFp point_exp(secp160r1, exp_affine_x, exp_affine_y);
   if(!point_exp.on_the_curve())
      throw Internal_Error("Point not on the curve");

   CHECK_MESSAGE(p1.get_affine_x() == exp_affine_x, "p1_x = " << p1.get_affine_x() << "\n" << "exp_x = " << exp_affine_x);
   CHECK_MESSAGE(p1.get_affine_y() == exp_affine_y, "p1_y = " << p1.get_affine_y() << "\n" << "exp_y = " << exp_affine_y);
   return fails;
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

size_t test_point_transformation ()
   {
   size_t fails = 0;

   // get a vailid point
   EC_Group dom_pars(OID("1.3.132.0.8"));
   PointGFp p = dom_pars.get_base_point();

   // get a copy
   PointGFp q = p;

   CHECK_MESSAGE( p.get_affine_x() == q.get_affine_x(), "affine_x changed during copy");
   CHECK_MESSAGE( p.get_affine_y() == q.get_affine_y(), "affine_y changed during copy");
   return fails;
   }

size_t test_point_mult ()
   {
   size_t fails = 0;

   EC_Group secp160r1(OIDS::lookup("secp160r1"));

   const CurveGFp& curve = secp160r1.get_curve();

   std::string G_secp_comp = "024a96b5688ef573284664698968c38bb913cbfc82";
   std::vector<byte> sv_G_secp_comp = hex_decode(G_secp_comp);
   PointGFp p_G = OS2ECP(sv_G_secp_comp, curve);

   BigInt d_U("0xaa374ffc3ce144e6b073307972cb6d57b2a4e982");
   PointGFp Q_U = d_U * p_G;

   CHECK(Q_U.get_affine_x() == BigInt("466448783855397898016055842232266600516272889280"));
   CHECK(Q_U.get_affine_y() == BigInt("1110706324081757720403272427311003102474457754220"));
   return fails;
   }

size_t test_point_negative()
   {
   size_t fails = 0;

   // performing calculation to test
   std::string p_secp = "ffffffffffffffffffffffffffffffff7fffffff";
   std::string a_secp = "ffffffffffffffffffffffffffffffff7ffffffc";
   std::string b_secp = "1c97befc54bd7a8b65acf89f81d4d4adc565fa45";
   std::string G_secp_comp = "024a96b5688ef573284664698968c38bb913cbfc82";
   std::vector<byte> sv_p_secp = hex_decode ( p_secp );
   std::vector<byte> sv_a_secp = hex_decode ( a_secp );
   std::vector<byte> sv_b_secp = hex_decode ( b_secp );
   std::vector<byte> sv_G_secp_comp = hex_decode ( G_secp_comp );
   BigInt bi_p_secp = BigInt::decode ( &sv_p_secp[0], sv_p_secp.size() );
   BigInt bi_a_secp = BigInt::decode ( &sv_a_secp[0], sv_a_secp.size() );
   BigInt bi_b_secp = BigInt::decode ( &sv_b_secp[0], sv_b_secp.size() );
   CurveGFp secp160r1(bi_p_secp, bi_a_secp, bi_b_secp);
   PointGFp p_G = OS2ECP ( sv_G_secp_comp, secp160r1 );

   PointGFp p1 = p_G *= 2;

   CHECK(p1.get_affine_x() == BigInt("16984103820118642236896513183038186009872590470"));
   CHECK(p1.get_affine_y() == BigInt("1373093393927139016463695321221277758035357890939"));

   PointGFp p1_neg = p1.negate();

   CHECK(p1_neg.get_affine_x() == BigInt("16984103820118642236896513183038186009872590470"));
   CHECK(p1_neg.get_affine_y() == BigInt("88408243403763901739989511495005261618427168388"));
   return fails;
   }

size_t test_zeropoint()
   {
   size_t fails = 0;

   std::string G_secp_comp = "024a96b5688ef573284664698968c38bb913cbfc82";
   std::vector<byte> sv_G_secp_comp = hex_decode ( G_secp_comp );
   BigInt bi_p_secp("0xffffffffffffffffffffffffffffffff7fffffff");
   BigInt bi_a_secp("0xffffffffffffffffffffffffffffffff7ffffffc");
   BigInt bi_b_secp("0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45");
   CurveGFp secp160r1(bi_p_secp, bi_a_secp, bi_b_secp);

   PointGFp p1(secp160r1,
               BigInt("16984103820118642236896513183038186009872590470"),
               BigInt("1373093393927139016463695321221277758035357890939"));

   if(!p1.on_the_curve())
      throw Internal_Error("Point not on the curve");
   p1 -= p1;

   CHECK_MESSAGE(  p1.is_zero(), "p - q with q = p is not zero!");
   return fails;
   }

size_t test_zeropoint_enc_dec()
   {
   size_t fails = 0;

   BigInt bi_p_secp("0xffffffffffffffffffffffffffffffff7fffffff");
   BigInt bi_a_secp("0xffffffffffffffffffffffffffffffff7ffffffc");
   BigInt bi_b_secp("0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45");
   CurveGFp curve(bi_p_secp, bi_a_secp, bi_b_secp);

   PointGFp p(curve);
   CHECK_MESSAGE(  p.is_zero(), "by constructor created zeropoint is no zeropoint!");


   std::vector<byte> sv_p = unlock(EC2OSP(p, PointGFp::UNCOMPRESSED));
   PointGFp p_encdec = OS2ECP(sv_p, curve);
   CHECK_MESSAGE(  p == p_encdec, "encoded-decoded (uncompressed) point is not equal the original!");

   sv_p = unlock(EC2OSP(p, PointGFp::UNCOMPRESSED));
   p_encdec = OS2ECP(sv_p, curve);
   CHECK_MESSAGE(  p == p_encdec, "encoded-decoded (compressed) point is not equal the original!");

   sv_p = unlock(EC2OSP(p, PointGFp::HYBRID));
   p_encdec = OS2ECP(sv_p, curve);
   CHECK_MESSAGE(  p == p_encdec, "encoded-decoded (hybrid) point is not equal the original!");
   return fails;
   }

size_t test_calc_with_zeropoint()
   {
   size_t fails = 0;

   std::string G_secp_comp = "024a96b5688ef573284664698968c38bb913cbfc82";
   std::vector<byte> sv_G_secp_comp = hex_decode ( G_secp_comp );
   BigInt bi_p_secp("0xffffffffffffffffffffffffffffffff7fffffff");
   BigInt bi_a_secp("0xffffffffffffffffffffffffffffffff7ffffffc");
   BigInt bi_b_secp("0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45");
   CurveGFp curve(bi_p_secp, bi_a_secp, bi_b_secp);

   PointGFp p(curve,
              BigInt("16984103820118642236896513183038186009872590470"),
              BigInt("1373093393927139016463695321221277758035357890939"));

   if(!p.on_the_curve())
      throw Internal_Error("Point not on the curve");
   CHECK_MESSAGE(  !p.is_zero(), "created is zeropoint, shouldn't be!");

   PointGFp zero(curve);
   CHECK_MESSAGE(  zero.is_zero(), "by constructor created zeropoint is no zeropoint!");

   PointGFp res = p + zero;
   CHECK_MESSAGE(  res == p, "point + zeropoint is not equal the point");

   res = p - zero;
   CHECK_MESSAGE(  res == p, "point - zeropoint is not equal the point");

   res = zero * 32432243;
   CHECK_MESSAGE(  res.is_zero(), "zeropoint * skalar is not a zero-point!");
   return fails;
   }

size_t test_add_point()
   {
   size_t fails = 0;

   // precalculation
   std::string p_secp = "ffffffffffffffffffffffffffffffff7fffffff";
   std::string a_secp = "ffffffffffffffffffffffffffffffff7ffffffc";
   std::string b_secp = "1c97befc54bd7a8b65acf89f81d4d4adc565fa45";
   std::string G_secp_comp = "024a96b5688ef573284664698968c38bb913cbfc82";
   std::vector<byte> sv_p_secp = hex_decode ( p_secp );
   std::vector<byte> sv_a_secp = hex_decode ( a_secp );
   std::vector<byte> sv_b_secp = hex_decode ( b_secp );
   std::vector<byte> sv_G_secp_comp = hex_decode ( G_secp_comp );
   BigInt bi_p_secp = BigInt::decode ( &sv_p_secp[0], sv_p_secp.size() );
   BigInt bi_a_secp = BigInt::decode ( &sv_a_secp[0], sv_a_secp.size() );
   BigInt bi_b_secp = BigInt::decode ( &sv_b_secp[0], sv_b_secp.size() );
   CurveGFp secp160r1(bi_p_secp, bi_a_secp, bi_b_secp);
   PointGFp p_G = OS2ECP ( sv_G_secp_comp, secp160r1 );

   PointGFp p0 = p_G;
   PointGFp p1 = p_G *= 2;

   p1 += p0;

   PointGFp expected(secp160r1,
                     BigInt("704859595002530890444080436569091156047721708633"),
                     BigInt("1147993098458695153857594941635310323215433166682"));

   CHECK(p1 == expected);
   return fails;
   }

size_t test_sub_point()
   {
   size_t fails = 0;

   //Setting up expected values
   BigInt exp_sub_x(std::string("112913490230515010376958384252467223283065196552"));
   BigInt exp_sub_y(std::string("143464803917389475471159193867377888720776527730"));
   BigInt exp_sub_z(std::string("562006223742588575209908669014372619804457947208"));

   // precalculation
   std::string p_secp = "ffffffffffffffffffffffffffffffff7fffffff";
   std::string a_secp = "ffffffffffffffffffffffffffffffff7ffffffc";
   std::string b_secp = "1c97befc54bd7a8b65acf89f81d4d4adc565fa45";
   std::string G_secp_comp = "024a96b5688ef573284664698968c38bb913cbfc82";
   std::vector<byte> sv_p_secp = hex_decode ( p_secp );
   std::vector<byte> sv_a_secp = hex_decode ( a_secp );
   std::vector<byte> sv_b_secp = hex_decode ( b_secp );
   std::vector<byte> sv_G_secp_comp = hex_decode ( G_secp_comp );
   BigInt bi_p_secp = BigInt::decode ( &sv_p_secp[0], sv_p_secp.size() );
   BigInt bi_a_secp = BigInt::decode ( &sv_a_secp[0], sv_a_secp.size() );
   BigInt bi_b_secp = BigInt::decode ( &sv_b_secp[0], sv_b_secp.size() );
   CurveGFp secp160r1(bi_p_secp, bi_a_secp, bi_b_secp);
   PointGFp p_G = OS2ECP ( sv_G_secp_comp, secp160r1 );

   PointGFp p0 = p_G;
   PointGFp p1 = p_G *= 2;

   p1 -= p0;

   PointGFp expected(secp160r1,
                     BigInt("425826231723888350446541592701409065913635568770"),
                     BigInt("203520114162904107873991457957346892027982641970"));

   CHECK(p1 == expected);
   return fails;
   }

size_t test_mult_point()
   {
   size_t fails = 0;

   //Setting up expected values
   BigInt exp_mult_x(std::string("967697346845926834906555988570157345422864716250"));
   BigInt exp_mult_y(std::string("512319768365374654866290830075237814703869061656"));

   // precalculation
   std::string p_secp = "ffffffffffffffffffffffffffffffff7fffffff";
   std::string a_secp = "ffffffffffffffffffffffffffffffff7ffffffc";
   std::string b_secp = "1c97befc54bd7a8b65acf89f81d4d4adc565fa45";
   std::string G_secp_comp = "024a96b5688ef573284664698968c38bb913cbfc82";
   std::vector<byte> sv_p_secp = hex_decode ( p_secp );
   std::vector<byte> sv_a_secp = hex_decode ( a_secp );
   std::vector<byte> sv_b_secp = hex_decode ( b_secp );
   std::vector<byte> sv_G_secp_comp = hex_decode ( G_secp_comp );
   BigInt bi_p_secp = BigInt::decode ( &sv_p_secp[0], sv_p_secp.size() );
   BigInt bi_a_secp = BigInt::decode ( &sv_a_secp[0], sv_a_secp.size() );
   BigInt bi_b_secp = BigInt::decode ( &sv_b_secp[0], sv_b_secp.size() );
   CurveGFp secp160r1(bi_p_secp, bi_a_secp, bi_b_secp);
   PointGFp p_G = OS2ECP ( sv_G_secp_comp, secp160r1 );

   PointGFp p0 = p_G;
   PointGFp p1 = p_G *= 2;

   p1 *= p0.get_affine_x();

   PointGFp expected(secp160r1, exp_mult_x, exp_mult_y);

   CHECK(p1 == expected);
   return fails;
   }

size_t test_basic_operations()
   {
   size_t fails = 0;

   // precalculation
   std::string p_secp = "ffffffffffffffffffffffffffffffff7fffffff";
   std::string a_secp = "ffffffffffffffffffffffffffffffff7ffffffc";
   std::string b_secp = "1c97befc54bd7a8b65acf89f81d4d4adc565fa45";
   std::string G_secp_comp = "024a96b5688ef573284664698968c38bb913cbfc82";
   std::vector<byte> sv_p_secp = hex_decode ( p_secp );
   std::vector<byte> sv_a_secp = hex_decode ( a_secp );
   std::vector<byte> sv_b_secp = hex_decode ( b_secp );
   std::vector<byte> sv_G_secp_comp = hex_decode ( G_secp_comp );
   BigInt bi_p_secp = BigInt::decode ( &sv_p_secp[0], sv_p_secp.size() );
   BigInt bi_a_secp = BigInt::decode ( &sv_a_secp[0], sv_a_secp.size() );
   BigInt bi_b_secp = BigInt::decode ( &sv_b_secp[0], sv_b_secp.size() );
   CurveGFp secp160r1(bi_p_secp, bi_a_secp, bi_b_secp);

   PointGFp p_G = OS2ECP ( sv_G_secp_comp, secp160r1 );

   PointGFp p0 = p_G;

   PointGFp expected(secp160r1,
                     BigInt("425826231723888350446541592701409065913635568770"),
                     BigInt("203520114162904107873991457957346892027982641970"));

   CHECK(p0 == expected);

   PointGFp p1 = p_G *= 2;

   CHECK(p1.get_affine_x() == BigInt("16984103820118642236896513183038186009872590470"));
   CHECK(p1.get_affine_y() == BigInt("1373093393927139016463695321221277758035357890939"));

   PointGFp simplePlus= p1 + p0;
   PointGFp exp_simplePlus(secp160r1,
                           BigInt("704859595002530890444080436569091156047721708633"),
                           BigInt("1147993098458695153857594941635310323215433166682"));
   if(simplePlus != exp_simplePlus)
      std::cout << simplePlus << " != " << exp_simplePlus << std::endl;

   PointGFp simpleMinus= p1 - p0;
   PointGFp exp_simpleMinus(secp160r1,
                            BigInt("425826231723888350446541592701409065913635568770"),
                            BigInt("203520114162904107873991457957346892027982641970"));

   CHECK(simpleMinus == exp_simpleMinus);

   PointGFp simpleMult= p1 * 123456789;

   CHECK(simpleMult.get_affine_x() == BigInt("43638877777452195295055270548491599621118743290"));
   CHECK(simpleMult.get_affine_y() == BigInt("56841378500012376527163928510402662349220202981"));

   // check that all initial points hasn't changed
   CHECK(p1.get_affine_x() == BigInt("16984103820118642236896513183038186009872590470"));
   CHECK(p1.get_affine_y() == BigInt("1373093393927139016463695321221277758035357890939"));

   CHECK(p0.get_affine_x() == BigInt("425826231723888350446541592701409065913635568770"));
   CHECK(p0.get_affine_y() == BigInt("203520114162904107873991457957346892027982641970"));
   return fails;
   }

size_t test_enc_dec_compressed_160()
   {
   size_t fails = 0;

   // Test for compressed conversion (02/03) 160bit
   std::string p_secp = "ffffffffffffffffffffffffffffffff7fffffff";
   std::string a_secp = "ffffffffffffffffffffffffffffffff7ffffffC";
   std::string b_secp = "1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45";
   std::string G_secp_comp = "024A96B5688EF573284664698968C38BB913CBFC82";
   std::string G_order_secp_comp = "0100000000000000000001F4C8F927AED3CA752257";

   std::vector<byte> sv_p_secp = hex_decode ( p_secp );
   std::vector<byte> sv_a_secp = hex_decode ( a_secp );
   std::vector<byte> sv_b_secp = hex_decode ( b_secp );
   std::vector<byte> sv_G_secp_comp = hex_decode ( G_secp_comp );

   BigInt bi_p_secp = BigInt::decode ( &sv_p_secp[0], sv_p_secp.size() );
   BigInt bi_a_secp = BigInt::decode ( &sv_a_secp[0], sv_a_secp.size() );
   BigInt bi_b_secp = BigInt::decode ( &sv_b_secp[0], sv_b_secp.size() );

   CurveGFp secp160r1(bi_p_secp, bi_a_secp, bi_b_secp);

   PointGFp p_G = OS2ECP ( sv_G_secp_comp, secp160r1 );
   std::vector<byte> sv_result = unlock(EC2OSP(p_G, PointGFp::COMPRESSED));

   CHECK( sv_result == sv_G_secp_comp);
   return fails;
   }

size_t test_enc_dec_compressed_256()
   {
   size_t fails = 0;

   // Test for compressed conversion (02/03) 256bit
   std::string p_secp = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
   std::string a_secp = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffFC";
   std::string b_secp = "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B";
   std::string G_secp_comp = "036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296";
   std::string G_order_secp_comp = "ffffffff00000000ffffffffffffffffBCE6FAADA7179E84F3B9CAC2FC632551";

   std::vector<byte> sv_p_secp = hex_decode ( p_secp );
   std::vector<byte> sv_a_secp = hex_decode ( a_secp );
   std::vector<byte> sv_b_secp = hex_decode ( b_secp );
   std::vector<byte> sv_G_secp_comp = hex_decode ( G_secp_comp );

   BigInt bi_p_secp = BigInt::decode ( &sv_p_secp[0], sv_p_secp.size() );
   BigInt bi_a_secp = BigInt::decode ( &sv_a_secp[0], sv_a_secp.size() );
   BigInt bi_b_secp = BigInt::decode ( &sv_b_secp[0], sv_b_secp.size() );

   CurveGFp curve(bi_p_secp, bi_a_secp, bi_b_secp);

   PointGFp p_G = OS2ECP ( sv_G_secp_comp, curve );
   std::vector<byte> sv_result = unlock(EC2OSP(p_G, PointGFp::COMPRESSED));

   CHECK( sv_result == sv_G_secp_comp);
   return fails;
   }


size_t test_enc_dec_uncompressed_112()
   {
   size_t fails = 0;

   // Test for uncompressed conversion (04) 112bit

   std::string p_secp = "db7c2abf62e35e668076bead208b";
   std::string a_secp = "6127C24C05F38A0AAAF65C0EF02C";
   std::string b_secp = "51DEF1815DB5ED74FCC34C85D709";
   std::string G_secp_uncomp = "044BA30AB5E892B4E1649DD0928643ADCD46F5882E3747DEF36E956E97";
   std::string G_order_secp_uncomp = "36DF0AAFD8B8D7597CA10520D04B";

   std::vector<byte> sv_p_secp = hex_decode ( p_secp );
   std::vector<byte> sv_a_secp = hex_decode ( a_secp );
   std::vector<byte> sv_b_secp = hex_decode ( b_secp );
   std::vector<byte> sv_G_secp_uncomp = hex_decode ( G_secp_uncomp );

   BigInt bi_p_secp = BigInt::decode ( &sv_p_secp[0], sv_p_secp.size() );
   BigInt bi_a_secp = BigInt::decode ( &sv_a_secp[0], sv_a_secp.size() );
   BigInt bi_b_secp = BigInt::decode ( &sv_b_secp[0], sv_b_secp.size() );

   CurveGFp curve(bi_p_secp, bi_a_secp, bi_b_secp);

   PointGFp p_G = OS2ECP ( sv_G_secp_uncomp, curve );
   std::vector<byte> sv_result = unlock(EC2OSP(p_G, PointGFp::UNCOMPRESSED));

   CHECK( sv_result == sv_G_secp_uncomp);
   return fails;
   }

size_t test_enc_dec_uncompressed_521()
   {
   size_t fails = 0;

   // Test for uncompressed conversion(04) with big values(521 bit)
   std::string p_secp = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
   std::string a_secp = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffFC";
   std::string b_secp = "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00";
   std::string G_secp_uncomp = "0400C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2ffA8DE3348B3C1856A429BF97E7E31C2E5BD66011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650";
   std::string G_order_secp_uncomp = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409";

   std::vector<byte> sv_p_secp = hex_decode ( p_secp );
   std::vector<byte> sv_a_secp = hex_decode ( a_secp );
   std::vector<byte> sv_b_secp = hex_decode ( b_secp );
   std::vector<byte> sv_G_secp_uncomp = hex_decode ( G_secp_uncomp );

   BigInt bi_p_secp = BigInt::decode ( &sv_p_secp[0], sv_p_secp.size() );
   BigInt bi_a_secp = BigInt::decode ( &sv_a_secp[0], sv_a_secp.size() );
   BigInt bi_b_secp = BigInt::decode ( &sv_b_secp[0], sv_b_secp.size() );

   CurveGFp curve(bi_p_secp, bi_a_secp, bi_b_secp);

   PointGFp p_G = OS2ECP ( sv_G_secp_uncomp, curve );

   std::vector<byte> sv_result = unlock(EC2OSP(p_G, PointGFp::UNCOMPRESSED));
   std::string result = hex_encode(&sv_result[0], sv_result.size());
   std::string exp_result = hex_encode(&sv_G_secp_uncomp[0], sv_G_secp_uncomp.size());

   CHECK_MESSAGE(sv_result == sv_G_secp_uncomp, "calc. result = " << result << "\nexp. result = " << exp_result);
   return fails;
   }

size_t test_enc_dec_uncompressed_521_prime_too_large()
   {
   size_t fails = 0;

   // Test for uncompressed conversion(04) with big values(521 bit)
   std::string p_secp = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"; // length increased by "ff"
   std::string a_secp = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffFC";
   std::string b_secp = "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00";
   std::string G_secp_uncomp = "0400C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2ffA8DE3348B3C1856A429BF97E7E31C2E5BD66011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650";
   std::string G_order_secp_uncomp = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409";

   std::vector<byte> sv_p_secp = hex_decode ( p_secp );
   std::vector<byte> sv_a_secp = hex_decode ( a_secp );
   std::vector<byte> sv_b_secp = hex_decode ( b_secp );
   std::vector<byte> sv_G_secp_uncomp = hex_decode ( G_secp_uncomp );

   BigInt bi_p_secp = BigInt::decode ( &sv_p_secp[0], sv_p_secp.size() );
   BigInt bi_a_secp = BigInt::decode ( &sv_a_secp[0], sv_a_secp.size() );
   BigInt bi_b_secp = BigInt::decode ( &sv_b_secp[0], sv_b_secp.size() );

   CurveGFp secp521r1 (bi_p_secp, bi_a_secp, bi_b_secp);
   std::unique_ptr<PointGFp> p_G;
   bool exc = false;
   try
      {
      p_G = std::unique_ptr<PointGFp>(new PointGFp(OS2ECP ( sv_G_secp_uncomp, secp521r1)));
      if(!p_G->on_the_curve())
         throw Internal_Error("Point not on the curve");
      }
   catch (std::exception e)
      {
      exc = true;
      }

   CHECK_MESSAGE(exc, "attempt of creation of point on curve with too high prime did not throw an exception");
   return fails;
   }

size_t test_gfp_store_restore()
   {
   size_t fails = 0;

   // generate point
   //EC_Group dom_pars = global_config().get_ec_dompar("1.3.132.0.8");
   //EC_Group dom_pars("1.3.132.0.8");
   EC_Group dom_pars(OID("1.3.132.0.8"));
   PointGFp p = dom_pars.get_base_point();

   //store point (to std::string)
   std::vector<byte> sv_mes = unlock(EC2OSP(p, PointGFp::COMPRESSED));
   PointGFp new_p = OS2ECP(sv_mes, dom_pars.get_curve());

   CHECK_MESSAGE( p == new_p, "original and restored point are different!");
   return fails;
   }


// maybe move this test
size_t test_cdc_curve_33()
   {
   size_t fails = 0;

   std::string G_secp_uncomp = "04081523d03d4f12cd02879dea4bf6a4f3a7df26ed888f10c5b2235a1274c386a2f218300dee6ed217841164533bcdc903f07a096f9fbf4ee95bac098a111f296f5830fe5c35b3e344d5df3a2256985f64fbe6d0edcc4c61d18bef681dd399df3d0194c5a4315e012e0245ecea56365baa9e8be1f7";

   std::vector<byte> sv_G_uncomp = hex_decode ( G_secp_uncomp );

   BigInt bi_p_secp = BigInt("2117607112719756483104013348936480976596328609518055062007450442679169492999007105354629105748524349829824407773719892437896937279095106809");
   BigInt bi_a_secp("0xa377dede6b523333d36c78e9b0eaa3bf48ce93041f6d4fc34014d08f6833807498deedd4290101c5866e8dfb589485d13357b9e78c2d7fbe9fe");
   BigInt bi_b_secp("0xa9acf8c8ba617777e248509bcb4717d4db346202bf9e352cd5633731dd92a51b72a4dc3b3d17c823fcc8fbda4da08f25dea89046087342595a7");

   CurveGFp curve(bi_p_secp, bi_a_secp, bi_b_secp);
   PointGFp p_G = OS2ECP ( sv_G_uncomp, curve);
   bool exc = false;
   try
      {
      if(!p_G.on_the_curve())
         throw Internal_Error("Point not on the curve");
      }
   catch (std::exception)
      {
      exc = true;
      }
   CHECK(!exc);
   return fails;
   }

size_t test_more_zeropoint()
   {
   size_t fails = 0;

   // by Falko

   std::string G = "024a96b5688ef573284664698968c38bb913cbfc82";
   std::vector<byte> sv_G_secp_comp = hex_decode ( G );
   BigInt bi_p("0xffffffffffffffffffffffffffffffff7fffffff");
   BigInt bi_a("0xffffffffffffffffffffffffffffffff7ffffffc");
   BigInt bi_b("0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45");
   CurveGFp curve(bi_p, bi_a, bi_b);

   PointGFp p1(curve,
               BigInt("16984103820118642236896513183038186009872590470"),
               BigInt("1373093393927139016463695321221277758035357890939"));

   if(!p1.on_the_curve())
      throw Internal_Error("Point not on the curve");
   PointGFp minus_p1 = -p1;
   if(!minus_p1.on_the_curve())
      throw Internal_Error("Point not on the curve");
   PointGFp shouldBeZero = p1 + minus_p1;
   if(!shouldBeZero.on_the_curve())
      throw Internal_Error("Point not on the curve");

   BigInt y1 = p1.get_affine_y();
   y1 = curve.get_p() - y1;

   CHECK_MESSAGE(p1.get_affine_x() == minus_p1.get_affine_x(),
                 "problem with minus_p1 : x");
   CHECK_MESSAGE(minus_p1.get_affine_y() == y1,
                 "problem with minus_p1 : y");

   PointGFp zero(curve);
   if(!zero.on_the_curve())
      throw Internal_Error("Point not on the curve");
   CHECK_MESSAGE(p1 + zero == p1, "addition of zero modified point");

   CHECK_MESSAGE(  shouldBeZero.is_zero(), "p - q with q = p is not zero!");
   return fails;
   }

size_t test_mult_by_order()
   {
   size_t fails = 0;

   // generate point
   EC_Group dom_pars(OID("1.3.132.0.8"));
   PointGFp p = dom_pars.get_base_point();
   PointGFp shouldBeZero = p * dom_pars.get_order();

   CHECK_MESSAGE(shouldBeZero.is_zero(), "G * order != O");
   return fails;
   }

size_t test_point_swap()
   {
   size_t fails = 0;

   EC_Group dom_pars(OID("1.3.132.0.8"));

   auto& rng = test_rng();

   PointGFp a(create_random_point(rng, dom_pars.get_curve()));
   PointGFp b(create_random_point(rng, dom_pars.get_curve()));
   b *= BigInt(rng, 20);

   PointGFp c(a);
   PointGFp d(b);

   d.swap(c);
   CHECK(a == d);
   CHECK(b == c);

   return fails;
   }

/**
* This test verifies that the side channel attack resistant multiplication function
* yields the same result as the normal (insecure) multiplication via operator*=
*/
size_t test_mult_sec_mass()
   {
   size_t fails = 0;

   auto& rng = test_rng();

   EC_Group dom_pars(OID("1.3.132.0.8"));
   for(int i = 0; i<50; i++)
      {
      try
         {
         PointGFp a(create_random_point(rng, dom_pars.get_curve()));
         BigInt scal(BigInt(rng, 40));
         PointGFp b = a * scal;
         PointGFp c(a);

         c *= scal;
         CHECK(b == c);
         }
      catch(std::exception& e)
         {
         std::cout << "test_mult_sec_mass failed: " << e.what() << std::endl;
         ++fails;
         }
      }

   return fails;
   }

size_t test_curve_cp_ctor()
   {
   try
      {
      EC_Group dom_pars(OID("1.3.132.0.8"));
      CurveGFp curve(dom_pars.get_curve());
      }
   catch(...)
      {
      return 1;

      }

   return 0;
   }

size_t ecc_randomized_test()
   {
   const std::vector<std::string> groups = {
      "brainpool160r1",
      "brainpool192r1",
      "brainpool224r1",
      "brainpool256r1",
      "brainpool320r1",
      "brainpool384r1",
      "brainpool512r1",
      "gost_256A",
      "secp112r1",
      "secp112r2",
      "secp128r1",
      "secp128r2",
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

   auto& rng = test_rng();
   size_t fails = 0;
   size_t tests = 0;

   for(auto&& group_name : groups)
      {
      EC_Group group(group_name);

      const PointGFp& base_point = group.get_base_point();
      const BigInt& group_order = group.get_order();

      const PointGFp inf = base_point * group_order;
      CHECK(inf.is_zero());
      CHECK(inf.on_the_curve());

      try
         {
         for(size_t i = 0; i != 10; ++i)
            {
            ++tests;

            const BigInt a = BigInt::random_integer(rng, 2, group_order);
            const BigInt b = BigInt::random_integer(rng, 2, group_order);
            const BigInt c = a + b;

            const PointGFp P = base_point * a;
            const PointGFp Q = base_point * b;
            const PointGFp R = base_point * c;

            const PointGFp A1 = P + Q;
            const PointGFp A2 = Q + P;

            CHECK(A1 == R);
            CHECK(A2 == R);
            CHECK(P.on_the_curve());
            CHECK(Q.on_the_curve());
            CHECK(R.on_the_curve());
            CHECK(A1.on_the_curve());
            CHECK(A2.on_the_curve());
            }
         }
      catch(std::exception& e)
         {
         std::cout << "Testing " << group_name << " failed: " << e.what() << std::endl;
         ++fails;
         }
      }

   test_report("ECC Randomized", tests, fails);
   return fails;
   }
#endif

}

size_t test_ecc_unit()
   {
   size_t fails = 0;

#if defined(BOTAN_HAS_ECC_GROUP)
   fails += test_point_turn_on_sp_red_mul();
   fails += test_coordinates();
   fails += test_point_transformation ();
   fails += test_point_mult ();
   fails += test_point_negative();
   fails += test_zeropoint();
   fails += test_zeropoint_enc_dec();
   fails += test_calc_with_zeropoint();
   fails += test_add_point();
   fails += test_sub_point();
   fails += test_mult_point();
   fails += test_basic_operations();
   fails += test_enc_dec_compressed_160();
   fails += test_enc_dec_compressed_256();
   fails += test_enc_dec_uncompressed_112();
   fails += test_enc_dec_uncompressed_521();
   fails += test_enc_dec_uncompressed_521_prime_too_large();
   fails += test_gfp_store_restore();
   fails += test_cdc_curve_33();
   fails += test_more_zeropoint();
   fails += test_mult_by_order();
   fails += test_point_swap();
   fails += test_mult_sec_mass();
   fails += test_curve_cp_ctor();

   test_report("ECC", 0, fails);

   ecc_randomized_test();
#endif

   return fails;
   }
