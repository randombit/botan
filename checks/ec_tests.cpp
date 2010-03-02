/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/


#include <botan/build.h>
#include "validate.h"

#if !defined(BOTAN_HAS_ECDSA)

void do_ec_tests(RandomNumberGenerator&) { return; }

#else

#include <botan/bigint.h>
#include <botan/numthry.h>
#include <botan/curve_gfp.h>
#include <botan/point_gfp.h>
#include <botan/ecdsa.h>

using namespace Botan;

#include <iostream>
#include <assert.h>

#include "getopt.h"

#include "common.h"

#define CHECK_MESSAGE(expr, print) try { if(!(expr)) std::cout << print << "\n"; } catch(std::exception& e) { std::cout << __FUNCTION__ << ": " << e.what() << "\n"; }
#define CHECK(expr) try { if(!(expr)) std::cout << #expr << "\n"; } catch(std::exception& e) { std::cout << __FUNCTION__ << ": " << e.what() << "\n"; }

namespace {

PointGFp create_random_point(RandomNumberGenerator& rng,
                             const CurveGFp& curve)
   {
   const BigInt& p = curve.get_p();

   const Modular_Reducer& mod_p = curve.mod_p();

   while(true)
      {
      BigInt x(rng, p.bits());

      BigInt x3 = mod_p.multiply(x, mod_p.square(x));

      BigInt ax = mod_p.multiply(curve.get_a(), x);

      BigInt bx3 = mod_p.multiply(curve.get_b(), x3);

      BigInt y = mod_p.reduce(ax + bx3);

      if(ressol(y, p) > 0)
         return PointGFp(curve, x, y);
      }
   }

void test_point_turn_on_sp_red_mul()
   {
   std::cout << "." << std::flush;

   // setting up expected values
   std::string test_str("test");
   BigInt test_bi(3);
   BigInt exp_Qx(std::string("466448783855397898016055842232266600516272889280"));
   BigInt exp_Qy(std::string("1110706324081757720403272427311003102474457754220"));
   BigInt exp_Qz(1);

   // performing calculation to test
   std::string p_secp = "ffffffffffffffffffffffffffffffff7fffffff";
   std::string a_secp = "ffffffffffffffffffffffffffffffff7ffffffc";
   std::string b_secp = "1c97befc54bd7a8b65acf89f81d4d4adc565fa45";
   std::string G_secp_comp = "024a96b5688ef573284664698968c38bb913cbfc82";
   SecureVector<byte> sv_p_secp = decode_hex(p_secp);
   SecureVector<byte> sv_a_secp = decode_hex(a_secp);
   SecureVector<byte> sv_b_secp = decode_hex(b_secp);
   SecureVector<byte> sv_G_secp_comp = decode_hex(G_secp_comp);
   BigInt bi_p_secp = BigInt::decode(sv_p_secp.begin(), sv_p_secp.size());
   BigInt bi_a_secp = BigInt::decode(sv_a_secp.begin(), sv_a_secp.size());
   BigInt bi_b_secp = BigInt::decode(sv_b_secp.begin(), sv_b_secp.size());
   CurveGFp secp160r1(bi_p_secp, bi_a_secp, bi_b_secp);
   PointGFp p_G = OS2ECP(sv_G_secp_comp, secp160r1);

   BigInt d("459183204582304");

   PointGFp r1 = d * p_G;
   CHECK(r1.get_affine_x() != BigInt("0"));

   PointGFp p_G2(p_G);

   PointGFp r2 = d * p_G2;
   CHECK_MESSAGE(r1 == r2, "error with point mul after extra turn on sp red mul");
   CHECK(r1.get_affine_x() != BigInt("0"));

   PointGFp p_r1 = r1;
   PointGFp p_r2 = r2;

   p_r1 *= 2;
   p_r2 *= 2;
   CHECK_MESSAGE(p_r1.get_affine_x() == p_r2.get_affine_x(), "error with mult2 after extra turn on sp red mul");
   CHECK(p_r1.get_affine_x() != BigInt("0"));
   CHECK(p_r2.get_affine_x() != BigInt("0"));
   r1 *= 2;

   r2 *= 2;

   CHECK_MESSAGE(r1 == r2, "error with mult2 after extra turn on sp red mul");
   CHECK_MESSAGE(r1.get_affine_x() == r2.get_affine_x(), "error with mult2 after extra turn on sp red mul");
   CHECK(r1.get_affine_x() != BigInt("0"));
   r1 += p_G;
   r2 += p_G2;

   CHECK_MESSAGE(r1 == r2, "error with op+= after extra turn on sp red mul");

   r1 += p_G;
   r2 += p_G2;

   CHECK_MESSAGE(r1 == r2, "error with op+= after extra turn on sp red mul for both operands");
   r1 += p_G;
   r2 += p_G2;

   CHECK_MESSAGE(r1 == r2, "error with op+= after extra turn on sp red mul for both operands");
   }

void test_coordinates()
   {
   std::cout << "." << std::flush;

   //Setting up expected values
   BigInt exp_x(std::string("1340569834321789103897171369812910390864714275730"));
   BigInt exp_y(std::string("1270827321510686389126940426305655825361326281787"));
   BigInt exp_z(std::string("407040228325808215747982915914693784055965283940"));
   BigInt exp_affine_x(std::string("16984103820118642236896513183038186009872590470"));
   BigInt exp_affine_y(std::string("1373093393927139016463695321221277758035357890939"));

   // precalculation
   std::string p_secp = "ffffffffffffffffffffffffffffffff7fffffff";
   std::string a_secp = "ffffffffffffffffffffffffffffffff7ffffffc";
   std::string b_secp = "1c97befc54bd7a8b65acf89f81d4d4adc565fa45";
   std::string G_secp_comp = "024a96b5688ef573284664698968c38bb913cbfc82";
   SecureVector<byte> sv_p_secp = decode_hex ( p_secp );
   SecureVector<byte> sv_a_secp = decode_hex ( a_secp );
   SecureVector<byte> sv_b_secp = decode_hex ( b_secp );
   SecureVector<byte> sv_G_secp_comp = decode_hex ( G_secp_comp );

   BigInt bi_p_secp = BigInt::decode ( sv_p_secp.begin(), sv_p_secp.size() );
   BigInt bi_a_secp = BigInt::decode ( sv_a_secp.begin(), sv_a_secp.size() );
   BigInt bi_b_secp = BigInt::decode ( sv_b_secp.begin(), sv_b_secp.size() );
   CurveGFp secp160r1 (bi_p_secp, bi_a_secp, bi_b_secp);
   PointGFp p_G = OS2ECP ( sv_G_secp_comp, secp160r1 );
   PointGFp p0 = p_G;
   PointGFp p1 = p_G * 2;
   PointGFp point_exp(secp160r1, exp_affine_x, exp_affine_y);
   point_exp.check_invariants();

   if(p1.get_x() != exp_x)
      std::cout << p1.get_x() << " != " << exp_x << "\n";
   if(p1.get_y() != exp_y)
      std::cout << p1.get_y() << " != " << exp_y << "\n";
   if(p1.get_z() != exp_z)
      std::cout << p1.get_z() << " != " << exp_z << "\n";

   CHECK_MESSAGE( p1.get_affine_x() == exp_affine_x, " p1_x = " << p1.get_affine_x() << "\n" << "exp_x = " << exp_affine_x << "\n");
   CHECK_MESSAGE( p1.get_affine_y() == exp_affine_y, " p1_y = " << p1.get_affine_y() << "\n" << "exp_y = " << exp_affine_y << "\n");
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

void test_point_transformation ()
   {
   std::cout << "." << std::flush;


   // get a vailid point
   EC_Domain_Params dom_pars(OID("1.3.132.0.8"));
   PointGFp p = dom_pars.get_base_point();

   // get a copy
   PointGFp q = p;

   //turn on montg.
   CHECK_MESSAGE( p.get_x() == q.get_x(), "projective_x changed while turning on montg.!");
   CHECK_MESSAGE( p.get_y() == q.get_y(), "projective_y changed while turning on montg.!");
   CHECK_MESSAGE( p.get_z() == q.get_z(), "projective_z changed while turning on montg.!");
   CHECK_MESSAGE( p.get_affine_x() == q.get_affine_x(), "affine_x changed while turning on montg.!");
   CHECK_MESSAGE( p.get_affine_y() == q.get_affine_y(), "affine_y changed while turning on montg.!");
   }

void test_point_mult ()
   {
   std::cout << "." << std::flush;

   // setting up expected values
   std::string test_str("test");
   BigInt test_bi(3);
   BigInt exp_Qx(std::string("466448783855397898016055842232266600516272889280"));
   BigInt exp_Qy(std::string("1110706324081757720403272427311003102474457754220"));
   BigInt exp_Qz(1);

   // performing calculation to test
   std::string p_secp = "ffffffffffffffffffffffffffffffff7fffffff";
   std::string a_secp = "ffffffffffffffffffffffffffffffff7ffffffc";
   std::string b_secp = "1c97befc54bd7a8b65acf89f81d4d4adc565fa45";
   std::string G_secp_comp = "024a96b5688ef573284664698968c38bb913cbfc82";
   SecureVector<byte> sv_p_secp = decode_hex(p_secp);
   SecureVector<byte> sv_a_secp = decode_hex(a_secp);
   SecureVector<byte> sv_b_secp = decode_hex(b_secp);
   SecureVector<byte> sv_G_secp_comp = decode_hex(G_secp_comp);
   BigInt bi_p_secp = BigInt::decode(sv_p_secp.begin(), sv_p_secp.size());
   BigInt bi_a_secp = BigInt::decode(sv_a_secp.begin(), sv_a_secp.size());
   BigInt bi_b_secp = BigInt::decode(sv_b_secp.begin(), sv_b_secp.size());
   CurveGFp secp160r1(bi_p_secp, bi_a_secp, bi_b_secp);
   PointGFp p_G = OS2ECP(sv_G_secp_comp, secp160r1);

   SecureVector<byte> sv_G_dec = EC2OSP(p_G,0x01);
   std::string str_d_U = "aa374ffc3ce144e6b073307972cb6d57b2a4e982";
   SecureVector<byte> sv_d_U = decode_hex(str_d_U);
   BigInt d_U = BigInt::decode(sv_d_U.begin(), sv_d_U.size());
   PointGFp Q_U = d_U * p_G;
   CHECK( Q_U.get_x() == exp_Qx);
   CHECK( Q_U.get_y() == exp_Qy);
   CHECK( Q_U.get_z() == exp_Qz);
   }

void test_point_negative()
   {
   std::cout << "." << std::flush;

   //Setting up expected values
   BigInt exp_p1_x(std::string("1340569834321789103897171369812910390864714275730"));
   BigInt exp_p1_y(std::string("1270827321510686389126940426305655825361326281787"));
   BigInt exp_p1_neg_x(std::string("1340569834321789103897171369812910390864714275730"));
   BigInt exp_p1_neg_y(std::string("190674315820216529076744406410627194292458777540"));

   // performing calculation to test
   std::string p_secp = "ffffffffffffffffffffffffffffffff7fffffff";
   std::string a_secp = "ffffffffffffffffffffffffffffffff7ffffffc";
   std::string b_secp = "1c97befc54bd7a8b65acf89f81d4d4adc565fa45";
   std::string G_secp_comp = "024a96b5688ef573284664698968c38bb913cbfc82";
   SecureVector<byte> sv_p_secp = decode_hex ( p_secp );
   SecureVector<byte> sv_a_secp = decode_hex ( a_secp );
   SecureVector<byte> sv_b_secp = decode_hex ( b_secp );
   SecureVector<byte> sv_G_secp_comp = decode_hex ( G_secp_comp );
   BigInt bi_p_secp = BigInt::decode ( sv_p_secp.begin(), sv_p_secp.size() );
   BigInt bi_a_secp = BigInt::decode ( sv_a_secp.begin(), sv_a_secp.size() );
   BigInt bi_b_secp = BigInt::decode ( sv_b_secp.begin(), sv_b_secp.size() );
   CurveGFp secp160r1(bi_p_secp, bi_a_secp, bi_b_secp);
   PointGFp p_G = OS2ECP ( sv_G_secp_comp, secp160r1 );

   PointGFp p1 = p_G *= 2;

   CHECK( p1.get_x() == exp_p1_x);
   CHECK( p1.get_y() == exp_p1_y);
   //cout << "p1.y_proj = " << p1.get_y() << "\n";
   PointGFp p1_neg = p1.negate();
   //cout << "p1_neg.y_proj = " << p1_neg.get_y() << "\n";
   //p1.negate();
   BigInt calc_y_value = p1_neg.get_y();
   BigInt calc_z_value = p1_neg.get_z();
   CHECK( p1_neg.get_x() == exp_p1_neg_x);
   CHECK_MESSAGE(  calc_y_value == exp_p1_neg_y, "calc_y_value = " << calc_y_value << "\nexp_p1_neg_v = " << exp_p1_neg_y);
   //CHECK_MESSAGE(  calc_z_value == exp_p1_neg_y, "calc_y_value = " << calc_y_value << "\nexp_p1_neg_v = " << exp_p1_neg_y);
   }

void test_zeropoint()
   {
   std::cout << "." << std::flush;


   std::string G_secp_comp = "024a96b5688ef573284664698968c38bb913cbfc82";
   SecureVector<byte> sv_G_secp_comp = decode_hex ( G_secp_comp );
   BigInt bi_p_secp("0xffffffffffffffffffffffffffffffff7fffffff");
   BigInt bi_a_secp("0xffffffffffffffffffffffffffffffff7ffffffc");
   BigInt bi_b_secp("0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45");
   CurveGFp secp160r1(bi_p_secp, bi_a_secp, bi_b_secp);

   BigInt bi_p1_xval ("1340569834321789103897171369812910390864714275730");
   BigInt bi_p1_yval ("1270827321510686389126940426305655825361326281787");
   BigInt bi_p1_zval ("407040228325808215747982915914693784055965283940");

   PointGFp p1(secp160r1, bi_p1_xval, bi_p1_yval, bi_p1_zval);
   p1.check_invariants();
   p1 -= p1;

   CHECK_MESSAGE(  p1.is_zero(), "p - q with q = p is not zero!");
   }

void test_zeropoint_enc_dec()
   {
   std::cout << "." << std::flush;


   BigInt bi_p_secp("0xffffffffffffffffffffffffffffffff7fffffff");
   BigInt bi_a_secp("0xffffffffffffffffffffffffffffffff7ffffffc");
   BigInt bi_b_secp("0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45");
   CurveGFp curve(bi_p_secp, bi_a_secp, bi_b_secp);

   PointGFp p(curve);
   CHECK_MESSAGE(  p.is_zero(), "by constructor created zeropoint is no zeropoint!");


   SecureVector<byte> sv_p = EC2OSP(p, PointGFp::UNCOMPRESSED);
   PointGFp p_encdec = OS2ECP(sv_p, curve);
   CHECK_MESSAGE(  p == p_encdec, "encoded-decoded (uncompressed) point is not equal the original!");

   sv_p = EC2OSP(p, PointGFp::UNCOMPRESSED);
   p_encdec = OS2ECP(sv_p, curve);
   CHECK_MESSAGE(  p == p_encdec, "encoded-decoded (compressed) point is not equal the original!");

   sv_p = EC2OSP(p, PointGFp::HYBRID);
   p_encdec = OS2ECP(sv_p, curve);
   CHECK_MESSAGE(  p == p_encdec, "encoded-decoded (hybrid) point is not equal the original!");
   }

void test_calc_with_zeropoint()
   {
   std::cout << "." << std::flush;



   std::string G_secp_comp = "024a96b5688ef573284664698968c38bb913cbfc82";
   SecureVector<byte> sv_G_secp_comp = decode_hex ( G_secp_comp );
   BigInt bi_p_secp("0xffffffffffffffffffffffffffffffff7fffffff");
   BigInt bi_a_secp("0xffffffffffffffffffffffffffffffff7ffffffc");
   BigInt bi_b_secp("0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45");
   CurveGFp curve(bi_p_secp, bi_a_secp, bi_b_secp);

   BigInt bi_p1_xval ("1340569834321789103897171369812910390864714275730");
   BigInt bi_p1_yval ("1270827321510686389126940426305655825361326281787");
   BigInt bi_p1_zval ("407040228325808215747982915914693784055965283940");

   PointGFp p(curve, bi_p1_xval, bi_p1_yval, bi_p1_zval);

   p.check_invariants();
   CHECK_MESSAGE(  !p.is_zero(), "created is zeropoint, shouldn't be!");

   PointGFp zero(curve);
   CHECK_MESSAGE(  zero.is_zero(), "by constructor created zeropoint is no zeropoint!");

   PointGFp res = p + zero;
   CHECK_MESSAGE(  res == p, "point + zeropoint is not equal the point");

   res = p - zero;
   CHECK_MESSAGE(  res == p, "point - zeropoint is not equal the point");

   res = zero * 32432243;
   CHECK_MESSAGE(  res.is_zero(), "zeropoint * skalar is not a zero-point!");
   }

void test_add_point()
   {
   std::cout << "." << std::flush;

   //Setting up expected values
   BigInt exp_add_x(std::string("1435263815649099438763411093143066583800699119469"));
   BigInt exp_add_y(std::string("1300090790154238148372364036549849084558669436512"));
   BigInt exp_add_z(std::string("562006223742588575209908669014372619804457947208"));

   // precalculation
   std::string p_secp = "ffffffffffffffffffffffffffffffff7fffffff";
   std::string a_secp = "ffffffffffffffffffffffffffffffff7ffffffc";
   std::string b_secp = "1c97befc54bd7a8b65acf89f81d4d4adc565fa45";
   std::string G_secp_comp = "024a96b5688ef573284664698968c38bb913cbfc82";
   SecureVector<byte> sv_p_secp = decode_hex ( p_secp );
   SecureVector<byte> sv_a_secp = decode_hex ( a_secp );
   SecureVector<byte> sv_b_secp = decode_hex ( b_secp );
   SecureVector<byte> sv_G_secp_comp = decode_hex ( G_secp_comp );
   BigInt bi_p_secp = BigInt::decode ( sv_p_secp.begin(), sv_p_secp.size() );
   BigInt bi_a_secp = BigInt::decode ( sv_a_secp.begin(), sv_a_secp.size() );
   BigInt bi_b_secp = BigInt::decode ( sv_b_secp.begin(), sv_b_secp.size() );
   CurveGFp secp160r1(bi_p_secp, bi_a_secp, bi_b_secp);
   PointGFp p_G = OS2ECP ( sv_G_secp_comp, secp160r1 );

   PointGFp p0 = p_G;
   PointGFp p1 = p_G *= 2;

   PointGFp expected(secp160r1, exp_add_x, exp_add_y, exp_add_z);

   p1 += p0;
   CHECK(p1 == expected);
   }

void test_sub_point()
   {
   std::cout << "." << std::flush;

   //Setting up expected values
   BigInt exp_sub_x(std::string("112913490230515010376958384252467223283065196552"));
   BigInt exp_sub_y(std::string("143464803917389475471159193867377888720776527730"));
   BigInt exp_sub_z(std::string("562006223742588575209908669014372619804457947208"));

   // precalculation
   std::string p_secp = "ffffffffffffffffffffffffffffffff7fffffff";
   std::string a_secp = "ffffffffffffffffffffffffffffffff7ffffffc";
   std::string b_secp = "1c97befc54bd7a8b65acf89f81d4d4adc565fa45";
   std::string G_secp_comp = "024a96b5688ef573284664698968c38bb913cbfc82";
   SecureVector<byte> sv_p_secp = decode_hex ( p_secp );
   SecureVector<byte> sv_a_secp = decode_hex ( a_secp );
   SecureVector<byte> sv_b_secp = decode_hex ( b_secp );
   SecureVector<byte> sv_G_secp_comp = decode_hex ( G_secp_comp );
   BigInt bi_p_secp = BigInt::decode ( sv_p_secp.begin(), sv_p_secp.size() );
   BigInt bi_a_secp = BigInt::decode ( sv_a_secp.begin(), sv_a_secp.size() );
   BigInt bi_b_secp = BigInt::decode ( sv_b_secp.begin(), sv_b_secp.size() );
   CurveGFp secp160r1(bi_p_secp, bi_a_secp, bi_b_secp);
   PointGFp p_G = OS2ECP ( sv_G_secp_comp, secp160r1 );

   PointGFp p0 = p_G;
   PointGFp p1 = p_G *= 2;

   p1 -= p0;

   PointGFp expected(secp160r1, exp_sub_x, exp_sub_y, exp_sub_z);
   CHECK(p1 == expected);
   }

void test_mult_point()
   {
   std::cout << "." << std::flush;

   //Setting up expected values
   BigInt exp_mult_x(std::string("967697346845926834906555988570157345422864716250"));
   BigInt exp_mult_y(std::string("512319768365374654866290830075237814703869061656"));

   // precalculation
   std::string p_secp = "ffffffffffffffffffffffffffffffff7fffffff";
   std::string a_secp = "ffffffffffffffffffffffffffffffff7ffffffc";
   std::string b_secp = "1c97befc54bd7a8b65acf89f81d4d4adc565fa45";
   std::string G_secp_comp = "024a96b5688ef573284664698968c38bb913cbfc82";
   SecureVector<byte> sv_p_secp = decode_hex ( p_secp );
   SecureVector<byte> sv_a_secp = decode_hex ( a_secp );
   SecureVector<byte> sv_b_secp = decode_hex ( b_secp );
   SecureVector<byte> sv_G_secp_comp = decode_hex ( G_secp_comp );
   BigInt bi_p_secp = BigInt::decode ( sv_p_secp.begin(), sv_p_secp.size() );
   BigInt bi_a_secp = BigInt::decode ( sv_a_secp.begin(), sv_a_secp.size() );
   BigInt bi_b_secp = BigInt::decode ( sv_b_secp.begin(), sv_b_secp.size() );
   CurveGFp secp160r1(bi_p_secp, bi_a_secp, bi_b_secp);
   PointGFp p_G = OS2ECP ( sv_G_secp_comp, secp160r1 );

   PointGFp p0 = p_G;
   PointGFp p1 = p_G *= 2;

   p1 *= p0.get_x();

   PointGFp expected(secp160r1, exp_mult_x, exp_mult_y);

   CHECK(p1 == expected);
   }

void test_basic_operations()
   {
   std::cout << "." << std::flush;


   // set up expected values
   BigInt exp_p1_x(std::string("1340569834321789103897171369812910390864714275730"));
   BigInt exp_p1_y(std::string("1270827321510686389126940426305655825361326281787"));
   BigInt exp_p1_z(std::string("407040228325808215747982915914693784055965283940"));

   BigInt exp_p0_x(std::string("425826231723888350446541592701409065913635568770"));
   BigInt exp_p0_y(std::string("203520114162904107873991457957346892027982641970"));
   BigInt exp_p0_z(std::string("1"));

   BigInt exp_plus_x(std::string("1435263815649099438763411093143066583800699119469"));
   BigInt exp_plus_y(std::string("1300090790154238148372364036549849084558669436512"));
   BigInt exp_plus_z(std::string("562006223742588575209908669014372619804457947208"));

   BigInt exp_minus_x(std::string("112913490230515010376958384252467223283065196552"));
   BigInt exp_minus_y(std::string("143464803917389475471159193867377888720776527730"));
   BigInt exp_minus_z(std::string("562006223742588575209908669014372619804457947208"));

   BigInt exp_mult_x(std::string("43638877777452195295055270548491599621118743290"));
   BigInt exp_mult_y(std::string("56841378500012376527163928510402662349220202981"));
   BigInt exp_mult_z(std::string("1"));

   // precalculation
   std::string p_secp = "ffffffffffffffffffffffffffffffff7fffffff";
   std::string a_secp = "ffffffffffffffffffffffffffffffff7ffffffc";
   std::string b_secp = "1c97befc54bd7a8b65acf89f81d4d4adc565fa45";
   std::string G_secp_comp = "024a96b5688ef573284664698968c38bb913cbfc82";
   SecureVector<byte> sv_p_secp = decode_hex ( p_secp );
   SecureVector<byte> sv_a_secp = decode_hex ( a_secp );
   SecureVector<byte> sv_b_secp = decode_hex ( b_secp );
   SecureVector<byte> sv_G_secp_comp = decode_hex ( G_secp_comp );
   BigInt bi_p_secp = BigInt::decode ( sv_p_secp.begin(), sv_p_secp.size() );
   BigInt bi_a_secp = BigInt::decode ( sv_a_secp.begin(), sv_a_secp.size() );
   BigInt bi_b_secp = BigInt::decode ( sv_b_secp.begin(), sv_b_secp.size() );
   CurveGFp secp160r1(bi_p_secp, bi_a_secp, bi_b_secp);

   PointGFp p_G = OS2ECP ( sv_G_secp_comp, secp160r1 );

   PointGFp p0 = p_G;
   PointGFp p1 = p_G *= 2;

   // check that all points have correct values
   CHECK( p1.get_x() == exp_p1_x);
   CHECK( p1.get_y() == exp_p1_y);
   CHECK( p1.get_z() == exp_p1_z);

   PointGFp expected(secp160r1, exp_p0_x, exp_p0_y, exp_p0_z);
   CHECK(p0 == expected);

   PointGFp simplePlus= p1 + p0;
   PointGFp exp_simplePlus(secp160r1, exp_plus_x, exp_plus_y, exp_plus_z);
   CHECK(simplePlus == exp_simplePlus);

   PointGFp simpleMinus= p1 - p0;
   PointGFp exp_simpleMinus(secp160r1, exp_minus_x, exp_minus_y, exp_minus_z);
   CHECK(simpleMinus == exp_simpleMinus);

   PointGFp simpleMult= p1 * 123456789;
   CHECK( simpleMult.get_x() == exp_mult_x);
   CHECK( simpleMult.get_y() == exp_mult_y);
   CHECK( simpleMult.get_z() == exp_mult_z);

   // check that all initial points hasn't changed
   CHECK( p1.get_x() == exp_p1_x);
   CHECK( p1.get_y() == exp_p1_y);
   CHECK( p1.get_z() == exp_p1_z);

   CHECK( p0.get_x() == exp_p0_x);
   CHECK( p0.get_y() == exp_p0_y);
   CHECK( p0.get_z() == exp_p0_z);
   }

void test_enc_dec_compressed_160()
   {
   std::cout << "." << std::flush;


   // Test for compressed conversion (02/03) 160bit
   std::string p_secp = "ffffffffffffffffffffffffffffffff7fffffff";
   std::string a_secp = "ffffffffffffffffffffffffffffffff7ffffffC";
   std::string b_secp = "1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45";
   std::string G_secp_comp = "024A96B5688EF573284664698968C38BB913CBFC82";
   std::string G_order_secp_comp = "0100000000000000000001F4C8F927AED3CA752257";

   SecureVector<byte> sv_p_secp = decode_hex ( p_secp );
   SecureVector<byte> sv_a_secp = decode_hex ( a_secp );
   SecureVector<byte> sv_b_secp = decode_hex ( b_secp );
   SecureVector<byte> sv_G_secp_comp = decode_hex ( G_secp_comp );

   BigInt bi_p_secp = BigInt::decode ( sv_p_secp.begin(), sv_p_secp.size() );
   BigInt bi_a_secp = BigInt::decode ( sv_a_secp.begin(), sv_a_secp.size() );
   BigInt bi_b_secp = BigInt::decode ( sv_b_secp.begin(), sv_b_secp.size() );

   CurveGFp secp160r1(bi_p_secp, bi_a_secp, bi_b_secp);

   PointGFp p_G = OS2ECP ( sv_G_secp_comp, secp160r1 );
   SecureVector<byte> sv_result = EC2OSP(p_G, PointGFp::COMPRESSED);

   CHECK( sv_result == sv_G_secp_comp);
   }

void test_enc_dec_compressed_256()
   {
   std::cout << "." << std::flush;


   // Test for compressed conversion (02/03) 256bit
   std::string p_secp = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
   std::string a_secp = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffFC";
   std::string b_secp = "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B";
   std::string G_secp_comp = "036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296";
   std::string G_order_secp_comp = "ffffffff00000000ffffffffffffffffBCE6FAADA7179E84F3B9CAC2FC632551";

   SecureVector<byte> sv_p_secp = decode_hex ( p_secp );
   SecureVector<byte> sv_a_secp = decode_hex ( a_secp );
   SecureVector<byte> sv_b_secp = decode_hex ( b_secp );
   SecureVector<byte> sv_G_secp_comp = decode_hex ( G_secp_comp );

   BigInt bi_p_secp = BigInt::decode ( sv_p_secp.begin(), sv_p_secp.size() );
   BigInt bi_a_secp = BigInt::decode ( sv_a_secp.begin(), sv_a_secp.size() );
   BigInt bi_b_secp = BigInt::decode ( sv_b_secp.begin(), sv_b_secp.size() );

   CurveGFp secp160r1(bi_p_secp, bi_a_secp, bi_b_secp);

   PointGFp p_G = OS2ECP ( sv_G_secp_comp, secp160r1 );
   SecureVector<byte> sv_result = EC2OSP(p_G, PointGFp::COMPRESSED);

   CHECK( sv_result == sv_G_secp_comp);
   }


void test_enc_dec_uncompressed_112()
   {
   std::cout << "." << std::flush;


   // Test for uncompressed conversion (04) 112bit

   std::string p_secp = "db7c2abf62e35e668076bead208b";
   std::string a_secp = "6127C24C05F38A0AAAF65C0EF02C";
   std::string b_secp = "51DEF1815DB5ED74FCC34C85D709";
   std::string G_secp_uncomp = "044BA30AB5E892B4E1649DD0928643ADCD46F5882E3747DEF36E956E97";
   std::string G_order_secp_uncomp = "36DF0AAFD8B8D7597CA10520D04B";

   SecureVector<byte> sv_p_secp = decode_hex ( p_secp );
   SecureVector<byte> sv_a_secp = decode_hex ( a_secp );
   SecureVector<byte> sv_b_secp = decode_hex ( b_secp );
   SecureVector<byte> sv_G_secp_uncomp = decode_hex ( G_secp_uncomp );

   BigInt bi_p_secp = BigInt::decode ( sv_p_secp.begin(), sv_p_secp.size() );
   BigInt bi_a_secp = BigInt::decode ( sv_a_secp.begin(), sv_a_secp.size() );
   BigInt bi_b_secp = BigInt::decode ( sv_b_secp.begin(), sv_b_secp.size() );

   CurveGFp secp160r1(bi_p_secp, bi_a_secp, bi_b_secp);

   PointGFp p_G = OS2ECP ( sv_G_secp_uncomp, secp160r1 );
   SecureVector<byte> sv_result = EC2OSP(p_G, PointGFp::UNCOMPRESSED);

   CHECK( sv_result == sv_G_secp_uncomp);
   }

void test_enc_dec_uncompressed_521()
   {
   std::cout << "." << std::flush;


   // Test for uncompressed conversion(04) with big values(521 bit)
   std::string p_secp = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
   std::string a_secp = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffFC";
   std::string b_secp = "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00";
   std::string G_secp_uncomp = "0400C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2ffA8DE3348B3C1856A429BF97E7E31C2E5BD66011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650";
   std::string G_order_secp_uncomp = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409";

   SecureVector<byte> sv_p_secp = decode_hex ( p_secp );
   SecureVector<byte> sv_a_secp = decode_hex ( a_secp );
   SecureVector<byte> sv_b_secp = decode_hex ( b_secp );
   SecureVector<byte> sv_G_secp_uncomp = decode_hex ( G_secp_uncomp );

   BigInt bi_p_secp = BigInt::decode ( sv_p_secp.begin(), sv_p_secp.size() );
   BigInt bi_a_secp = BigInt::decode ( sv_a_secp.begin(), sv_a_secp.size() );
   BigInt bi_b_secp = BigInt::decode ( sv_b_secp.begin(), sv_b_secp.size() );

   CurveGFp secp160r1(bi_p_secp, bi_a_secp, bi_b_secp);

   PointGFp p_G = OS2ECP ( sv_G_secp_uncomp, secp160r1 );

   SecureVector<byte> sv_result = EC2OSP(p_G, PointGFp::UNCOMPRESSED);
   std::string result = hex_encode(sv_result.begin(), sv_result.size());
   std::string exp_result = hex_encode(sv_G_secp_uncomp.begin(), sv_G_secp_uncomp.size());

   CHECK_MESSAGE( sv_result == sv_G_secp_uncomp, "\ncalc. result = " << result << "\nexp. result = " << exp_result << "\n");
   }

void test_enc_dec_uncompressed_521_prime_too_large()
   {
   std::cout << "." << std::flush;


   // Test for uncompressed conversion(04) with big values(521 bit)
   std::string p_secp = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"; // length increased by "ff"
   std::string a_secp = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffFC";
   std::string b_secp = "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00";
   std::string G_secp_uncomp = "0400C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2ffA8DE3348B3C1856A429BF97E7E31C2E5BD66011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650";
   std::string G_order_secp_uncomp = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409";

   SecureVector<byte> sv_p_secp = decode_hex ( p_secp );
   SecureVector<byte> sv_a_secp = decode_hex ( a_secp );
   SecureVector<byte> sv_b_secp = decode_hex ( b_secp );
   SecureVector<byte> sv_G_secp_uncomp = decode_hex ( G_secp_uncomp );

   BigInt bi_p_secp = BigInt::decode ( sv_p_secp.begin(), sv_p_secp.size() );
   BigInt bi_a_secp = BigInt::decode ( sv_a_secp.begin(), sv_a_secp.size() );
   BigInt bi_b_secp = BigInt::decode ( sv_b_secp.begin(), sv_b_secp.size() );

   CurveGFp secp521r1 (bi_p_secp, bi_a_secp, bi_b_secp);
   std::auto_ptr<PointGFp> p_G;
   bool exc = false;
   try
      {
      p_G = std::auto_ptr<PointGFp>(new PointGFp(OS2ECP ( sv_G_secp_uncomp, secp521r1)));
      p_G->check_invariants();
      }
   catch (std::exception e)
      {
      exc = true;
      }

   CHECK_MESSAGE(exc, "attempt of creation of point on curve with too high prime did not throw an exception");
   //SecureVector<byte> sv_result = EC2OSP(p_G, PointGFp::UNCOMPRESSED);
   //string result = hex_encode(sv_result.begin(), sv_result.size());
   //string exp_result = hex_encode(sv_G_secp_uncomp.begin(), sv_G_secp_uncomp.size());

   //CHECK_MESSAGE( sv_result == sv_G_secp_uncomp, "\ncalc. result = " << result << "\nexp. result = " << exp_result << "\n");
   }

void test_gfp_store_restore()
   {
   std::cout << "." << std::flush;

   // generate point
   //EC_Domain_Params dom_pars = global_config().get_ec_dompar("1.3.132.0.8");
   //EC_Domain_Params dom_pars("1.3.132.0.8");
   EC_Domain_Params dom_pars(OID("1.3.132.0.8"));
   PointGFp p = dom_pars.get_base_point();

   //store point (to std::string)
   SecureVector<byte> sv_mes = EC2OSP(p, PointGFp::COMPRESSED);
   std::string storrage = hex_encode(sv_mes, sv_mes.size());

   // restore point (from std::string)
   SecureVector<byte> sv_new_point = decode_hex(storrage);
   PointGFp new_p = OS2ECP(sv_new_point, dom_pars.get_curve());

   CHECK_MESSAGE( p == new_p, "original and restored point are different!");
   }


// maybe move this test
void test_cdc_curve_33()
   {
   std::cout << "." << std::flush;

   std::string G_secp_uncomp = "04081523d03d4f12cd02879dea4bf6a4f3a7df26ed888f10c5b2235a1274c386a2f218300dee6ed217841164533bcdc903f07a096f9fbf4ee95bac098a111f296f5830fe5c35b3e344d5df3a2256985f64fbe6d0edcc4c61d18bef681dd399df3d0194c5a4315e012e0245ecea56365baa9e8be1f7";

   SecureVector<byte> sv_G_uncomp = decode_hex ( G_secp_uncomp );

   BigInt bi_p_secp = BigInt("2117607112719756483104013348936480976596328609518055062007450442679169492999007105354629105748524349829824407773719892437896937279095106809");
   BigInt bi_a_secp("0xa377dede6b523333d36c78e9b0eaa3bf48ce93041f6d4fc34014d08f6833807498deedd4290101c5866e8dfb589485d13357b9e78c2d7fbe9fe");
   BigInt bi_b_secp("0xa9acf8c8ba617777e248509bcb4717d4db346202bf9e352cd5633731dd92a51b72a4dc3b3d17c823fcc8fbda4da08f25dea89046087342595a7");

   CurveGFp curve(bi_p_secp, bi_a_secp, bi_b_secp);
   PointGFp p_G = OS2ECP ( sv_G_uncomp, curve);
   bool exc = false;
   try
      {
      p_G.check_invariants();
      }
   catch (std::exception& e)
      {
      exc = true;
      }
   CHECK(!exc);
   }

void test_more_zeropoint()
   {
   std::cout << "." << std::flush;
   // by Falko

   std::string G = "024a96b5688ef573284664698968c38bb913cbfc82";
   SecureVector<byte> sv_G_secp_comp = decode_hex ( G );
   BigInt bi_p("0xffffffffffffffffffffffffffffffff7fffffff");
   BigInt bi_a("0xffffffffffffffffffffffffffffffff7ffffffc");
   BigInt bi_b("0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45");
   CurveGFp curve(bi_p, bi_a, bi_b);

   BigInt bi_p1_xval ("1340569834321789103897171369812910390864714275730");
   BigInt bi_p1_yval ("1270827321510686389126940426305655825361326281787");
   BigInt bi_p1_zval ("407040228325808215747982915914693784055965283940");

   PointGFp p1(curve, bi_p1_xval, bi_p1_yval, bi_p1_zval);

   p1.check_invariants();
   PointGFp minus_p1 = -p1;
   minus_p1.check_invariants();
   PointGFp shouldBeZero = p1 + minus_p1;
   shouldBeZero.check_invariants();

   BigInt y1 = p1.get_affine_y();
   y1 = curve.get_p() - y1;

   CHECK_MESSAGE(p1.get_affine_x() == minus_p1.get_affine_x(),
                 "problem with minus_p1 : x");
   CHECK_MESSAGE(minus_p1.get_affine_y() == y1,
                 "problem with minus_p1 : y");

   PointGFp zero(curve);
   zero.check_invariants();
   CHECK_MESSAGE(p1 + zero == p1, "addition of zero modified point");

   CHECK_MESSAGE(  shouldBeZero.is_zero(), "p - q with q = p is not zero!");
   }

void test_mult_by_order()
   {
   std::cout << "." << std::flush;

   // generate point
   EC_Domain_Params dom_pars(OID("1.3.132.0.8"));
   PointGFp p = dom_pars.get_base_point();
   PointGFp shouldBeZero = p * dom_pars.get_order();

   CHECK_MESSAGE(shouldBeZero.is_zero(), "G * order != O");
   }

void test_point_swap(RandomNumberGenerator& rng)
   {
   std::cout << "." << std::flush;

   EC_Domain_Params dom_pars(OID("1.3.132.0.8"));

   PointGFp a(create_random_point(rng, dom_pars.get_curve()));
   PointGFp b(create_random_point(rng, dom_pars.get_curve()));
   b *= BigInt(20);

   PointGFp c(a);
   PointGFp d(b);

   d.swap(c);
   CHECK(a == d);
   CHECK(b == c);
   }

/**
* This test verifies that the side channel attack resistant multiplication function
* yields the same result as the normal (insecure) multiplication via operator*=
*/
void test_mult_sec_mass(RandomNumberGenerator& rng)
   {

   EC_Domain_Params dom_pars(OID("1.3.132.0.8"));
   for(int i = 0; i<50; i++)
      {
      std::cout << "." << std::flush;
      std::cout.flush();
      PointGFp a(create_random_point(rng, dom_pars.get_curve()));
      BigInt scal(BigInt(rng, 40));
      PointGFp b = a * scal;
      PointGFp c(a);

      c *= scal;
      CHECK(b == c);
      }
   }

void test_curve_cp_ctor()
   {
   std::cout << "." << std::flush;

   EC_Domain_Params dom_pars(OID("1.3.132.0.8"));
   CurveGFp curve(dom_pars.get_curve());
   }

/**
* The following test checks assignment operator and copy ctor for ec keys
*/
void test_ec_key_cp_and_assignment(RandomNumberGenerator& rng)
   {
   std::cout << "." << std::flush;


   std::string g_secp("024a96b5688ef573284664698968c38bb913cbfc82");
   SecureVector<byte> sv_g_secp = decode_hex ( g_secp);
   BigInt bi_p_secp("0xffffffffffffffffffffffffffffffff7fffffff");
   BigInt bi_a_secp("0xffffffffffffffffffffffffffffffff7ffffffc");
   BigInt bi_b_secp("0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45");
   BigInt order = BigInt("0x0100000000000000000001f4c8f927aed3ca752257");
   CurveGFp curve(bi_p_secp, bi_a_secp, bi_b_secp);

   BigInt cofactor = BigInt(1);
   PointGFp p_G = OS2ECP ( sv_g_secp, curve );

   EC_Domain_Params dom_pars = EC_Domain_Params(curve, p_G, order, cofactor);
   ECDSA_PrivateKey my_priv_key(rng, dom_pars);

   std::string str_message = ("12345678901234567890abcdef12");
   SecureVector<byte> sv_message = decode_hex(str_message);

   // sign with the original key
   SecureVector<byte> signature = my_priv_key.sign(sv_message.begin(), sv_message.size(), rng);
   bool ver_success = my_priv_key.verify(sv_message.begin(), sv_message.size(), signature.begin(), signature.size());
   CHECK_MESSAGE(ver_success, "generated signature could not be verified positively");

   // make a copy and sign
   ECDSA_PrivateKey cp_key(my_priv_key);
   SecureVector<byte> cp_sig = cp_key.sign(sv_message.begin(), sv_message.size(), rng);

   // now cross verify...
   CHECK(my_priv_key.verify(sv_message.begin(), sv_message.size(), cp_sig.begin(), cp_sig.size()));
   CHECK(cp_key.verify(sv_message.begin(), sv_message.size(), signature.begin(), signature.size()));

   // make an copy assignment and verify
   ECDSA_PrivateKey ass_key = my_priv_key;
   SecureVector<byte> ass_sig = ass_key.sign(sv_message.begin(), sv_message.size(), rng);

   // now cross verify...
   CHECK(my_priv_key.verify(sv_message.begin(), sv_message.size(), ass_sig.begin(), ass_sig.size()));
   CHECK(ass_key.verify(sv_message.begin(), sv_message.size(), signature.begin(), signature.size()));
   }

void test_ec_key_cast(RandomNumberGenerator& rng)
   {
   std::cout << "." << std::flush;

   std::string g_secp("024a96b5688ef573284664698968c38bb913cbfc82");
   SecureVector<byte> sv_g_secp = decode_hex ( g_secp);
   BigInt bi_p_secp("0xffffffffffffffffffffffffffffffff7fffffff");
   BigInt bi_a_secp("0xffffffffffffffffffffffffffffffff7ffffffc");
   BigInt bi_b_secp("0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45");
   BigInt order = BigInt("0x0100000000000000000001f4c8f927aed3ca752257");
   CurveGFp curve(bi_p_secp, bi_a_secp, bi_b_secp);
   BigInt cofactor = BigInt(1);
   PointGFp p_G = OS2ECP ( sv_g_secp, curve );

   EC_Domain_Params dom_pars = EC_Domain_Params(curve, p_G, order, cofactor);
   ECDSA_PrivateKey my_priv_key(rng, dom_pars);
   ECDSA_PublicKey my_ecdsa_pub_key = my_priv_key;

   Public_Key* my_pubkey = static_cast<Public_Key*>(&my_ecdsa_pub_key);
   ECDSA_PublicKey* ec_cast_back = dynamic_cast<ECDSA_PublicKey*>(my_pubkey);

   std::string str_message = ("12345678901234567890abcdef12");
   SecureVector<byte> sv_message = decode_hex(str_message);

   // sign with the original key
   SecureVector<byte> signature = my_priv_key.sign(sv_message.begin(), sv_message.size(), rng);

   bool ver_success = ec_cast_back->verify(sv_message.begin(), sv_message.size(), signature.begin(), signature.size());
   CHECK_MESSAGE(ver_success, "generated signature could not be verified positively");
   }

}

void do_ec_tests(RandomNumberGenerator& rng)
   {
   std::cout << "Testing ECC: " << std::flush;

   test_point_turn_on_sp_red_mul();
   test_coordinates();
   test_point_transformation ();
   test_point_mult ();
   test_point_negative();
   test_zeropoint();
   test_zeropoint_enc_dec();
   test_calc_with_zeropoint();
   test_add_point();
   test_sub_point();
   test_mult_point();
   test_basic_operations();
   test_enc_dec_compressed_160();
   test_enc_dec_compressed_256();
   test_enc_dec_uncompressed_112();
   test_enc_dec_uncompressed_521();
   test_enc_dec_uncompressed_521_prime_too_large();
   test_gfp_store_restore();
   test_cdc_curve_33();
   test_more_zeropoint();
   test_mult_by_order();
   test_point_swap(rng);
   test_mult_sec_mass(rng);
   test_curve_cp_ctor();
   test_ec_key_cp_and_assignment(rng);
   test_ec_key_cast(rng);

   std::cout << std::endl;
   }

#endif

