
#include <botan/build.h>
#include "validate.h"

#if !defined(BOTAN_HAS_ECDSA)

void do_ec_tests(RandomNumberGenerator&) { return; }

#else

#include <botan/bigint.h>
#include <botan/numthry.h>
#include <botan/mp_types.h>
#include <botan/curve_gfp.h>
#include <botan/point_gfp.h>
#include <botan/gfp_element.h>
#include <botan/ecdsa.h>

using namespace Botan;

#include <iostream>
#include <assert.h>

#include "getopt.h"

#include "common.h"

#define CHECK_MESSAGE(expr, print) try { if(!(expr)) std::cout << print << "\n"; } catch(std::exception& e) { std::cout << __FUNCTION__ << ": " << e.what() << "\n"; }
#define CHECK(expr) try { if(!(expr)) std::cout << #expr << "\n"; } catch(std::exception& e) { std::cout << __FUNCTION__ << ": " << e.what() << "\n"; }

namespace {

void test_point_turn_on_sp_red_mul_simple()
   {
   std::cout << "." << std::flush;

   // setting up expected values
   EC_Domain_Params dom_pars(get_EC_Dom_Pars_by_oid("1.3.36.3.3.2.8.1.1.5"));
   PointGFp p(dom_pars.get_base_point());
   p.turn_on_sp_red_mul();
   CHECK(p.get_affine_x().get_value() != BigInt(0));
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
   CurveGFp secp160r1(GFpElement(bi_p_secp,bi_a_secp), GFpElement(bi_p_secp, bi_b_secp), bi_p_secp);
   PointGFp p_G = OS2ECP(sv_G_secp_comp, secp160r1);

   BigInt d("459183204582304");

   PointGFp r1 = d * p_G;
   CHECK(r1.get_affine_x().get_value() != BigInt("0"));

   PointGFp p_G2(p_G);

   p_G2.turn_on_sp_red_mul();

   PointGFp r2 = d * p_G2;
   CHECK_MESSAGE(r1 == r2, "error with point mul after extra turn on sp red mul");
   CHECK(r1.get_affine_x().get_value() != BigInt("0"));

   std::tr1::shared_ptr<PointGFp> p_r1(new PointGFp(r1));
   std::tr1::shared_ptr<PointGFp> p_r2(new PointGFp(r2));

   p_r1->mult2_in_place(); // wird für Fehler nicht gebraucht
   p_r2->turn_on_sp_red_mul();    // 1. t_o() macht nur p_r2 kaputt
   p_r2->turn_on_sp_red_mul();  // 2. t_o() macht auch p_r1 kaputt!!!
   p_r2->mult2_in_place(); // wird für Fehler nicht gebraucht
   CHECK_MESSAGE(p_r1->get_affine_x() == p_r2->get_affine_x(), "error with mult2 after extra turn on sp red mul");
   CHECK(p_r1->get_affine_x().get_value() != BigInt("0"));
   CHECK(p_r2->get_affine_x().get_value() != BigInt("0"));
   r1.mult2_in_place();

   r2.turn_on_sp_red_mul();
   r2.turn_on_sp_red_mul();
   r2.mult2_in_place();

   CHECK_MESSAGE(r1 == r2, "error with mult2 after extra turn on sp red mul");
   CHECK_MESSAGE(r1.get_affine_x() == r2.get_affine_x(), "error with mult2 after extra turn on sp red mul");
   CHECK(r1.get_affine_x().get_value() != BigInt("0"));
   //std::cout << "r1 x = " << r1.get_affine_x() << endl;
   r1 += p_G;
   r2 += p_G2;

   CHECK_MESSAGE(r1 == r2, "error with op+= after extra turn on sp red mul");

   p_G2.turn_on_sp_red_mul();

   r1 += p_G;
   r2 += p_G2;

   CHECK_MESSAGE(r1 == r2, "error with op+= after extra turn on sp red mul for both operands");
   p_G2.turn_on_sp_red_mul();
   r1.turn_on_sp_red_mul();
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
   CurveGFp secp160r1 ( GFpElement ( bi_p_secp,bi_a_secp ), GFpElement ( bi_p_secp, bi_b_secp ), bi_p_secp );
   PointGFp p_G = OS2ECP ( sv_G_secp_comp, secp160r1 );
   PointGFp p0 = p_G;
   PointGFp p1 = p_G.mult2_in_place();
   PointGFp point_exp(secp160r1, GFpElement(bi_p_secp, exp_affine_x), GFpElement(bi_p_secp, exp_affine_y));
   try
      {
      point_exp.check_invariants();
      }
   catch (Illegal_Point e)
      {
      assert(false);
      }

   // testarea
   CHECK( p1.get_jac_proj_x().get_value() == exp_x);
   CHECK( p1.get_jac_proj_y().get_value() == exp_y);
   CHECK( p1.get_jac_proj_z().get_value() == exp_z);
   CHECK_MESSAGE( p1.get_affine_x().get_value() == exp_affine_x, " p1_x = " << p1.get_affine_x().get_value() << "\n" << "exp_x = " << exp_affine_x << "\n");
   CHECK_MESSAGE( p1.get_affine_y().get_value() == exp_affine_y, " p1_y = " << p1.get_affine_y().get_value() << "\n" << "exp_y = " << exp_affine_y << "\n");
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
   EC_Domain_Params dom_pars(get_EC_Dom_Pars_by_oid("1.3.132.0.8"));
   PointGFp p = dom_pars.get_base_point();

   // get a copy
   PointGFp q = p;

   //turn on montg.
   p.turn_on_sp_red_mul();
   CHECK_MESSAGE( p.get_jac_proj_x().get_value() == q.get_jac_proj_x().get_value(), "projective_x changed while turning on montg.!");
   CHECK_MESSAGE( p.get_jac_proj_y().get_value() == q.get_jac_proj_y().get_value(), "projective_y changed while turning on montg.!");
   CHECK_MESSAGE( p.get_jac_proj_z().get_value() == q.get_jac_proj_z().get_value(), "projective_z changed while turning on montg.!");
   CHECK_MESSAGE( p.get_affine_x().get_value() == q.get_affine_x().get_value(), "affine_x changed while turning on montg.!");
   CHECK_MESSAGE( p.get_affine_y().get_value() == q.get_affine_y().get_value(), "affine_y changed while turning on montg.!");
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
   CurveGFp secp160r1(GFpElement(bi_p_secp,bi_a_secp), GFpElement(bi_p_secp, bi_b_secp), bi_p_secp);
   PointGFp p_G = OS2ECP(sv_G_secp_comp, secp160r1);

   SecureVector<byte> sv_G_dec = EC2OSP(p_G,0x01);
   std::string str_d_U = "aa374ffc3ce144e6b073307972cb6d57b2a4e982";
   SecureVector<byte> sv_d_U = decode_hex(str_d_U);
   BigInt d_U = BigInt::decode(sv_d_U.begin(), sv_d_U.size());
   PointGFp Q_U = d_U * p_G;
   CHECK( Q_U.get_jac_proj_x().get_value() == exp_Qx);
   CHECK( Q_U.get_jac_proj_y().get_value() == exp_Qy);
   CHECK( Q_U.get_jac_proj_z().get_value() == exp_Qz);
   }

#if 0
void test_montgm_calc_R ()
   {
   // this tests isnt´t correct anymore. the determination of R has changed
   // to be 0 mod word_range.

   // setting up (expected) values
   BigInt prime_modulus(101);
   u64bit n = prime_modulus.bits();
   BigInt exp_R(128);
   // function under test
   BigInt calc_R = montgm_calc_r_oddmod(prime_modulus);
   CHECK_MESSAGE(exp_R == calc_R, "exp_R = " << exp_R << ", calc_R = " << calc_R << ", n = " << n << "\n");

   }
#endif

#if 0
void test_naive_montg_mult ()
   {
   std::cout << "." << std::flush;

   BigInt a_bar(1);
   BigInt b_bar(2);
   BigInt m(11);
   BigInt m_dash(13);
   BigInt r(5);
   //BigInt test_res = montg_mult(a_bar, b_bar, m, m_dash, r);
   //cout << "test_res = " << test_res << "\n";
   GFpElement a_norm_mult(11, 3);
   GFpElement b_norm_mult(11, 5);
   GFpElement c_norm_mult = a_norm_mult * b_norm_mult;
   //cout << "c_norm_mult = " << c_norm_mult << "\n";
   GFpElement a_mm(11, 3, true);
   GFpElement b_mm(11, 5, true);
   GFpElement c_mm = a_mm * b_mm;
   //cout << "c_mm = " << c_mm << "\n";
   CHECK_MESSAGE(c_norm_mult == c_mm, "c_norm_mult = " << c_norm_mult << "\n" << "c_mm = " << c_mm << "\n");
   }
#endif

#if 0

void test_trf_mres ()
   {
   // this tests isnt´t correct anymore. the determination of R has changed
   // to be 0 mod word_range.

   //
   BigInt modulus(11);
   BigInt r = montgm_calc_r_oddmod(modulus);
   //cout << "r = " << r << "\n";
   BigInt r_inv = inverse_mod(r, modulus);
   //cout << "r_inv = " << r_inv << "\n";
   // see C43:
   BigInt exp_m_dash(13);
   BigInt calc_m_dash = montgm_calc_m_dash(r, modulus, r_inv);
   CHECK_MESSAGE(exp_m_dash == calc_m_dash, "exp_m_dash = " << exp_m_dash << "\n" << "calc_m_dash = " << calc_m_dash << "\n");
   BigInt ord_res(7);
   BigInt exp_m_res(2); // see C43
   BigInt calc_m_res = montg_trf_to_mres(ord_res, r, modulus);
   CHECK_MESSAGE(calc_m_res == exp_m_res, "calc_m_res = " << calc_m_res << "\nexp_m_res = " << exp_m_res);
   BigInt calc_ord_res_back = montg_trf_to_ordres(calc_m_res,modulus, r_inv);
   CHECK_MESSAGE(ord_res == calc_ord_res_back, "ord_res = " << ord_res << "\ncalc_ord_res_back = " << calc_ord_res_back << "\n");
   }
#endif

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
   CurveGFp secp160r1 ( GFpElement ( bi_p_secp,bi_a_secp ), GFpElement ( bi_p_secp, bi_b_secp ), bi_p_secp );
   PointGFp p_G = OS2ECP ( sv_G_secp_comp, secp160r1 );

   PointGFp p1 = p_G.mult2_in_place();

   CHECK( p1.get_jac_proj_x().get_value() == exp_p1_x);
   CHECK( p1.get_jac_proj_y().get_value() == exp_p1_y);
   //cout << "p1.y_proj = " << p1.get_jac_proj_y() << "\n";
   PointGFp p1_neg = p1.negate();
   //cout << "p1_neg.y_proj = " << p1_neg.get_jac_proj_y() << "\n";
   //p1.negate();
   BigInt calc_y_value = p1_neg.get_jac_proj_y().get_value();
   BigInt calc_z_value = p1_neg.get_jac_proj_z().get_value();
   CHECK( p1_neg.get_jac_proj_x().get_value() == exp_p1_neg_x);
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
   CurveGFp secp160r1 ( GFpElement ( bi_p_secp,bi_a_secp ), GFpElement ( bi_p_secp, bi_b_secp ), bi_p_secp );

   BigInt bi_p1_xval ("1340569834321789103897171369812910390864714275730");
   BigInt bi_p1_yval ("1270827321510686389126940426305655825361326281787");
   BigInt bi_p1_zval ("407040228325808215747982915914693784055965283940");

   GFpElement elem_p1_x(bi_p_secp, bi_p1_xval);
   GFpElement elem_p1_y(bi_p_secp, bi_p1_yval);
   GFpElement elem_p1_z(bi_p_secp, bi_p1_zval);


   PointGFp p1(secp160r1,elem_p1_x, elem_p1_y, elem_p1_z);

   p1.check_invariants();
   p1 -= p1;
   //	cout << "p1 x " << p1.get_jac_proj_x().get_value() << "\n";
   //	cout << "p1 y " << p1.get_jac_proj_y().get_value() << "\n";
   //	cout << "p1 z " << p1.get_jac_proj_z().get_value() << "\n";

   CHECK_MESSAGE(  p1.is_zero(), "p - q with q = p is not zero!");
   }

void test_zeropoint_enc_dec()
   {
   std::cout << "." << std::flush;


   BigInt bi_p_secp("0xffffffffffffffffffffffffffffffff7fffffff");
   BigInt bi_a_secp("0xffffffffffffffffffffffffffffffff7ffffffc");
   BigInt bi_b_secp("0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45");
   CurveGFp curve ( GFpElement ( bi_p_secp,bi_a_secp ), GFpElement ( bi_p_secp, bi_b_secp ), bi_p_secp );

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
   CurveGFp curve ( GFpElement ( bi_p_secp,bi_a_secp ), GFpElement ( bi_p_secp, bi_b_secp ), bi_p_secp );

   BigInt bi_p1_xval ("1340569834321789103897171369812910390864714275730");
   BigInt bi_p1_yval ("1270827321510686389126940426305655825361326281787");
   BigInt bi_p1_zval ("407040228325808215747982915914693784055965283940");

   GFpElement elem_p1_x(bi_p_secp, bi_p1_xval);
   GFpElement elem_p1_y(bi_p_secp, bi_p1_yval);
   GFpElement elem_p1_z(bi_p_secp, bi_p1_zval);

   PointGFp p(curve,elem_p1_x, elem_p1_y, elem_p1_z);

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
   CurveGFp secp160r1 ( GFpElement ( bi_p_secp,bi_a_secp ), GFpElement ( bi_p_secp, bi_b_secp ), bi_p_secp );
   PointGFp p_G = OS2ECP ( sv_G_secp_comp, secp160r1 );

   PointGFp p0 = p_G;
   PointGFp p1 = p_G.mult2_in_place();

   PointGFp expected ( secp160r1, GFpElement(bi_p_secp, BigInt(exp_add_x)),
                       GFpElement(bi_p_secp, BigInt(exp_add_y)), GFpElement(bi_p_secp, BigInt(exp_add_z)));

   p1 += p0;
   CHECK(p1 == expected);
#if 0
   CHECK( p1.get_jac_proj_x().get_value() == exp_add_x);
   CHECK( p1.get_jac_proj_y().get_value() == exp_add_y);
   CHECK( p1.get_jac_proj_z().get_value() == exp_add_z);
#endif
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
   CurveGFp secp160r1 ( GFpElement ( bi_p_secp,bi_a_secp ), GFpElement ( bi_p_secp, bi_b_secp ), bi_p_secp );
   PointGFp p_G = OS2ECP ( sv_G_secp_comp, secp160r1 );

   PointGFp p0 = p_G;
   PointGFp p1 = p_G.mult2_in_place();

   p1 -= p0;
   PointGFp expected ( secp160r1, GFpElement(bi_p_secp, BigInt(exp_sub_x)),
                       GFpElement(bi_p_secp, BigInt(exp_sub_y)), GFpElement(bi_p_secp, BigInt(exp_sub_z)));
   CHECK(p1 == expected);

#if 0
   CHECK( p1.get_jac_proj_x().get_value() == exp_sub_x);
   CHECK( p1.get_jac_proj_y().get_value() == exp_sub_y);
   CHECK( p1.get_jac_proj_z().get_value() == exp_sub_z);
#endif
   }

void test_mult_point()
   {
   std::cout << "." << std::flush;

   //Setting up expected values
   BigInt exp_mult_x(std::string("967697346845926834906555988570157345422864716250"));
   BigInt exp_mult_y(std::string("512319768365374654866290830075237814703869061656"));
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
   CurveGFp secp160r1 ( GFpElement ( bi_p_secp,bi_a_secp ), GFpElement ( bi_p_secp, bi_b_secp ), bi_p_secp );
   PointGFp p_G = OS2ECP ( sv_G_secp_comp, secp160r1 );

   PointGFp p0 = p_G;
   PointGFp p1 = p_G.mult2_in_place();

   p1 *= p0.get_jac_proj_x().get_value();

   PointGFp expected ( secp160r1, GFpElement(bi_p_secp, BigInt(exp_mult_x)),
                       GFpElement(bi_p_secp, BigInt(exp_mult_y)), GFpElement(bi_p_secp, BigInt(exp_mult_z)));
   CHECK(p1 == expected);

#if 0
   CHECK( p1.get_jac_proj_x().get_value() == exp_mult_x);
   CHECK( p1.get_jac_proj_y().get_value() == exp_mult_y);
   CHECK( p1.get_jac_proj_z().get_value() == exp_mult_z);
#endif
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
   CurveGFp secp160r1 ( GFpElement ( bi_p_secp,bi_a_secp ), GFpElement ( bi_p_secp, bi_b_secp ), bi_p_secp );
   PointGFp p_G = OS2ECP ( sv_G_secp_comp, secp160r1 );

   PointGFp p0 = p_G;
   PointGFp p1 = p_G.mult2_in_place();

   // check that all points have correct values
   CHECK( p1.get_jac_proj_x().get_value() == exp_p1_x);
   CHECK( p1.get_jac_proj_y().get_value() == exp_p1_y);
   CHECK( p1.get_jac_proj_z().get_value() == exp_p1_z);

   PointGFp expected ( secp160r1, GFpElement(bi_p_secp, exp_p0_x),
                       GFpElement(bi_p_secp, exp_p0_y), GFpElement(bi_p_secp, exp_p0_z));
   CHECK(p0 == expected);
#if 0
   CHECK( p0.get_jac_proj_x().get_value() == exp_p0_x);
   CHECK( p0.get_jac_proj_y().get_value() == exp_p0_y);
   CHECK( p0.get_jac_proj_z().get_value() == exp_p0_z);
#endif

   PointGFp simplePlus= p1 + p0;
   PointGFp exp_simplePlus ( secp160r1, GFpElement(bi_p_secp, exp_plus_x),
                             GFpElement(bi_p_secp, exp_plus_y), GFpElement(bi_p_secp, exp_plus_z));
   CHECK(simplePlus == exp_simplePlus);
#if 0
   CHECK( simplePlus.get_jac_proj_x().get_value() == exp_plus_x);
   CHECK( simplePlus.get_jac_proj_y().get_value() == exp_plus_y);
   CHECK( simplePlus.get_jac_proj_z().get_value() == exp_plus_z);
#endif

   PointGFp simpleMinus= p1 - p0;
   PointGFp exp_simpleMinus ( secp160r1, GFpElement(bi_p_secp, exp_minus_x),
                              GFpElement(bi_p_secp, exp_minus_y), GFpElement(bi_p_secp, exp_minus_z));
   CHECK(simpleMinus == exp_simpleMinus);
#if 0
   CHECK( simpleMinus.get_jac_proj_x().get_value() == exp_minus_x);
   CHECK( simpleMinus.get_jac_proj_y().get_value() == exp_minus_y);
   CHECK( simpleMinus.get_jac_proj_z().get_value() == exp_minus_z);
#endif

   PointGFp simpleMult= p1 * 123456789;
   CHECK( simpleMult.get_jac_proj_x().get_value() == exp_mult_x);
   CHECK( simpleMult.get_jac_proj_y().get_value() == exp_mult_y);
   CHECK( simpleMult.get_jac_proj_z().get_value() == exp_mult_z);

   // check that all initial points hasn't changed
   CHECK( p1.get_jac_proj_x().get_value() == exp_p1_x);
   CHECK( p1.get_jac_proj_y().get_value() == exp_p1_y);
   CHECK( p1.get_jac_proj_z().get_value() == exp_p1_z);

   CHECK( p0.get_jac_proj_x().get_value() == exp_p0_x);
   CHECK( p0.get_jac_proj_y().get_value() == exp_p0_y);
   CHECK( p0.get_jac_proj_z().get_value() == exp_p0_z);
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

   CurveGFp secp160r1 ( GFpElement ( bi_p_secp,bi_a_secp ), GFpElement ( bi_p_secp, bi_b_secp ), bi_p_secp );

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

   CurveGFp secp160r1 ( GFpElement ( bi_p_secp,bi_a_secp ), GFpElement ( bi_p_secp, bi_b_secp ), bi_p_secp );

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

   CurveGFp secp160r1 ( GFpElement ( bi_p_secp,bi_a_secp ), GFpElement ( bi_p_secp, bi_b_secp ), bi_p_secp );

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

   CurveGFp secp160r1 ( GFpElement ( bi_p_secp,bi_a_secp ), GFpElement ( bi_p_secp, bi_b_secp ), bi_p_secp );

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

   CurveGFp secp521r1 ( GFpElement ( bi_p_secp,bi_a_secp ), GFpElement ( bi_p_secp, bi_b_secp ), bi_p_secp );
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
#if 0
   cout << "mX == " << p_G.get_jac_proj_x() << endl;
   std::cout << "mY == " << p_G.get_jac_proj_y() << endl;
   std::cout << "mZ == " << p_G.get_jac_proj_x() << endl;
#endif
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
   EC_Domain_Params dom_pars(get_EC_Dom_Pars_by_oid("1.3.132.0.8"));
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

   CurveGFp curve( GFpElement ( bi_p_secp,bi_a_secp ), GFpElement ( bi_p_secp, bi_b_secp ), bi_p_secp );
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
   CurveGFp curve( GFpElement ( bi_p,bi_a ), GFpElement ( bi_p, bi_b ), bi_p );

   BigInt bi_p1_xval ("1340569834321789103897171369812910390864714275730");
   BigInt bi_p1_yval ("1270827321510686389126940426305655825361326281787");
   BigInt bi_p1_zval ("407040228325808215747982915914693784055965283940");

   GFpElement elem_p1_x(bi_p, bi_p1_xval);
   GFpElement elem_p1_y(bi_p, bi_p1_yval);
   GFpElement elem_p1_z(bi_p, bi_p1_zval);

   PointGFp p1(curve,elem_p1_x, elem_p1_y, elem_p1_z);

   p1.check_invariants();
   PointGFp minus_p1 = -p1;
   minus_p1.check_invariants();
   PointGFp shouldBeZero = p1 + minus_p1;
   shouldBeZero.check_invariants();
   GFpElement x1 = p1.get_affine_x();
   GFpElement y1 = p1.get_affine_y();

   GFpElement shouldBeY2 = -y1;

   CHECK_MESSAGE(minus_p1.get_affine_x() == x1, "problem with minus_p1 : x");
   CHECK_MESSAGE(minus_p1.get_affine_y() == shouldBeY2, "problem with minus_p1 : y");

   PointGFp zero(curve);
   zero.check_invariants();
   CHECK_MESSAGE(p1 + zero == p1, "addition of zero modified point");

#if 0
   std::cout << "sbz x " << shouldBeZero.get_jac_proj_x().get_value() << "\n";
   std::cout << "sbz y " << shouldBeZero.get_jac_proj_y().get_value() << "\n";
   std::cout << "sbz z " << shouldBeZero.get_jac_proj_z().get_value() << "\n";
#endif

   CHECK_MESSAGE(  shouldBeZero.is_zero(), "p - q with q = p is not zero!");
   }

void test_mult_by_order()
   {
   std::cout << "." << std::flush;
   //    std::cout << "starting test_mult_by_order..." << endl;



   // generate point
   //EC_Domain_Params dom_pars = global_config().get_ec_dompar("1.3.132.0.8");
   //EC_Domain_Params dom_pars("1.3.132.0.8");
   EC_Domain_Params dom_pars = get_EC_Dom_Pars_by_oid("1.3.132.0.8");
   PointGFp p = dom_pars.get_base_point();
   PointGFp shouldBeZero = p * dom_pars.get_order();
#if 0
   cout << "sbz x " << shouldBeZero.get_jac_proj_x().get_value() << "\n";
   std::cout << "sbz y " << shouldBeZero.get_jac_proj_y().get_value() << "\n";
   std::cout << "sbz z " << shouldBeZero.get_jac_proj_z().get_value() << "\n";
#endif
   CHECK_MESSAGE(shouldBeZero.is_zero(), "G * order != O");
   }

void test_gfp_curve_precomp_mres()
   {
   std::cout << "." << std::flush;


   //EC_Domain_Params parA("1.2.840.10045.3.1.1");
   EC_Domain_Params parA(get_EC_Dom_Pars_by_oid("1.2.840.10045.3.1.1"));
   CurveGFp curve1 = parA.get_curve();
   CurveGFp curve2 = parA.get_curve();
   BigInt p = curve1.get_p();
   GFpElement x(p, BigInt("2304042084023"));
   GFpElement a1_or = curve1.get_a();
   CHECK(!a1_or.is_trf_to_mres());

   GFpElement b1_mr = curve1.get_mres_b();
   CHECK(b1_mr.is_trf_to_mres());

   GFpElement a2_mr = curve2.get_mres_a();
   CHECK(a2_mr.is_trf_to_mres());

   GFpElement b2_or = curve2.get_b();
   CHECK(!b2_or.is_trf_to_mres());

   GFpElement prodA = a1_or*b1_mr;
   GFpElement prodB = a2_mr*b2_or;
   CHECK(prodA == prodB);

   CHECK(a1_or * x == a2_mr * x);
   CHECK(x* a1_or == a1_or * x);
   CHECK(x* a1_or == x * a2_mr);
   CHECK(x* a1_or == a2_mr * x);

   CHECK(a1_or + a2_mr == a2_mr + a1_or);
   CHECK(a1_or + b1_mr == a2_mr + b1_mr);
   CHECK(a1_or + x == a2_mr + x);
   }

#if 0
void test_point_worksp()
   {

   EC_Domain_Params dom_pars(get_EC_Dom_Pars_by_oid("1.3.132.0.8"));
   std::tr1::shared_ptr<std::vector<GFpElement> > worksp1;
   assert(worksp1.get() == 0);
      {
      PointGFp p = dom_pars.get_base_point();
      worksp1 = p.get_worksp_gfp();
      }
      PointGFp p2 = dom_pars.get_base_point();
      p2.set_worksp_gfp(worksp1);
      PointGFp p3 = p2*6;
      PointGFp p4 = dom_pars.get_base_point();
      p4 *= 6;
      CHECK_MESSAGE(p4 == p3,"points are not equal" );
      p2 *= 10;
      for(int i=0; i<3; i++)
         {

         PointGFp p5 = dom_pars.get_base_point();
         p5.set_worksp_gfp(worksp1);
         p5 *= 10;
         CHECK(p5 == p2);
         }
   }
#endif

void test_point_swap(RandomNumberGenerator& rng)
   {
   std::cout << "." << std::flush;

   EC_Domain_Params dom_pars(get_EC_Dom_Pars_by_oid("1.3.132.0.8"));

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
void test_mult_sec()
   {
   std::cout << "." << std::flush;

   EC_Domain_Params dom_pars(get_EC_Dom_Pars_by_oid("1.3.132.0.8"));
   PointGFp a(dom_pars.get_base_point());
   BigInt scal("123413545342234");
   PointGFp b = a * scal;
   PointGFp c(a);
   c.mult_this_secure(scal, dom_pars.get_order(), dom_pars.get_order()-1);
   PointGFp d(a);
   d.mult_this_secure(scal, BigInt(0), dom_pars.get_order()-1);
   CHECK(b == c);
   CHECK(c == d);
   }

/**
* This test verifies that the side channel attack resistant multiplication function
* yields the same result as the normal (insecure) multiplication via operator*=
*/
void test_mult_sec_mass(RandomNumberGenerator& rng)
   {

   EC_Domain_Params dom_pars(get_EC_Dom_Pars_by_oid("1.3.132.0.8"));
   for(int i = 0; i<50; i++)
      {
      std::cout << "." << std::flush;
      std::cout.flush();
      PointGFp a(create_random_point(rng, dom_pars.get_curve()));
      BigInt scal(BigInt(rng, 40));
      PointGFp b = a * scal;
      PointGFp c(a);
      c.mult_this_secure(scal, dom_pars.get_order()*dom_pars.get_cofactor(), dom_pars.get_order()-1);
      //PointGFp d(a);
      //d.mult_this_secure(scal, BigInt(0), dom_pars.get_order()-1);
      CHECK(b == c);
      //CHECK(c == d);
      }
   }

/**
* The following test verifies that PointGFps copy-ctor and assignment operator
* produce non-sharing Objects
*/
void test_point_ctors_ass_unshared()
   {
   std::cout << "." << std::flush;

   EC_Domain_Params dom_pars(get_EC_Dom_Pars_by_oid("1.3.132.0.8"));
   PointGFp p = dom_pars.get_base_point();
   PointGFp ind_cpy(p);

   // doesn´t work this way, because getters of point return an independent copy!
   CHECK(p.get_jac_proj_x().get_ptr_mod().get() != ind_cpy.get_jac_proj_x().get_ptr_mod().get());
   //CHECK(p.get_x().get_ptr_r().get() != ind_cpy.get_x().get_ptr_r().get());

   PointGFp ind_ass(p);
   ind_ass = p;
   CHECK(p.get_jac_proj_x().get_ptr_mod().get() != ind_ass.get_jac_proj_x().get_ptr_mod().get());
   //CHECK(p.get_x().get_ptr_r().get() != ind_ass.get_x().get_ptr_r().get());
   }

void test_curve_cp_ctor()
   {
   std::cout << "." << std::flush;

   EC_Domain_Params dom_pars(get_EC_Dom_Pars_by_oid("1.3.132.0.8"));
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
   CurveGFp curve(GFpElement(bi_p_secp,bi_a_secp), GFpElement(bi_p_secp, bi_b_secp), bi_p_secp);
   BigInt cofactor = BigInt(1);
   PointGFp p_G = OS2ECP ( sv_g_secp, curve );

   EC_Domain_Params dom_pars = EC_Domain_Params(curve, p_G, order, cofactor);
   ECDSA_PrivateKey my_priv_key(rng, dom_pars);

   std::string str_message = ("12345678901234567890abcdef12");
   SecureVector<byte> sv_message = decode_hex(str_message);

   // sign with the original key
   SecureVector<byte> signature = my_priv_key.sign(sv_message.begin(), sv_message.size(), rng);
   //cout << "signature = " << hex_encode(signature.begin(), signature.size()) << "\n";
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
   CurveGFp curve(GFpElement(bi_p_secp,bi_a_secp), GFpElement(bi_p_secp, bi_b_secp), bi_p_secp);
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
   //cout << "signature = " << hex_encode(signature.begin(), signature.size()) << "\n";
   bool ver_success = ec_cast_back->verify(sv_message.begin(), sv_message.size(), signature.begin(), signature.size());
   CHECK_MESSAGE(ver_success, "generated signature could not be verified positively");
   }

}

void do_ec_tests(RandomNumberGenerator& rng)
   {
   std::cout << "Testing ECC: " << std::flush;

   test_point_turn_on_sp_red_mul_simple();
   test_point_turn_on_sp_red_mul();
   test_coordinates();
   test_point_transformation ();
   test_point_mult ();
   //test_montgm_calc_R ();
   //test_naive_montg_mult ();
   //test_trf_mres ();
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
   test_gfp_curve_precomp_mres();
   //test_point_worksp();
   test_point_swap(rng);
   test_mult_sec();
   test_mult_sec_mass(rng);
   test_point_ctors_ass_unshared();
   test_curve_cp_ctor();
   test_ec_key_cp_and_assignment(rng);
   test_ec_key_cast(rng);

   std::cout << std::endl;
   }

#endif

