/******************************************************
* gfp_element tests                                   *
*                                                     *
* (C) 2007 Patrick Sona                               *
*                                                     *
*          Falko Strenzke                             *
*          strenzke@flexsecure.de                     *
******************************************************/

#include <botan/bigint.h>
#include <botan/numthry.h>
#include <botan/gfp_element.h>
#include <botan/gfp_modulus.h>
#include <botan/curve_gfp.h>
#include <botan/ec_dompar.h>

#include <iostream>

using namespace Botan;
using namespace std;

#define BOOST_AUTO_TEST_CASE(name) void name()
#define BOOST_CHECK_MESSAGE(expr, print) if(!(expr)) std::cout << print << "\n";
#define BOOST_CHECK(expr) if(!(expr)) std::cout << #expr << "\n";

BOOST_AUTO_TEST_CASE(test_turn_on_sp_red_mul)
   {
   cout << "." << flush;

   GFpElement a1(23,15);
   GFpElement b1(23,18);

   GFpElement c1 = a1*b1;

   GFpElement a2(23,15);
   GFpElement b2(23,18);

   a2.turn_on_sp_red_mul();
   a2.turn_on_sp_red_mul();
   b2.turn_on_sp_red_mul();
   b2.turn_on_sp_red_mul();

   GFpElement c2 = a2*b2;

   if(c1 == c2)
      std::cout << "test_turn_on_sp_red_mul - c1 == c2\n";

   //BOOST_CHECK_MESSAGE(c1 == c2, "error with multiple call to turn on spec red mul, should be " << c1 <<"\n, was " << c2);
   }

BOOST_AUTO_TEST_CASE(test_bi_div_even)
   {
   cout << "." << flush;

   string str_large("1552518092300708935148979488462502555256886017116696611139052038026050952686323255099158638440248181850494907312621195144895406865083132424709500362534691373159016049946612882688577088900506460909202178541447303914546699487373976586");
   BigInt to_div(str_large);
   BigInt half = to_div/2;
   BigInt should_be_to_div = half*2;
   BOOST_CHECK_MESSAGE(should_be_to_div == to_div, "error in division/multiplication of large BigInt");

   // also testing /=...
   BigInt before_div = to_div;
   to_div /= 2;
   BigInt should_be_before(to_div*2);
   BOOST_CHECK_MESSAGE(should_be_before == before_div, "error in division/multiplication of large BigInt");
   }

BOOST_AUTO_TEST_CASE(test_bi_div_odd)
   {
   cout << "." << flush;

   string str_large("1552518092300708935148979488462502555256886017116696611139052038026050952686323255099158638440248181850494907312621195144895406865083132424709500362534691373159016049946612882688577088900506460909202178541447303914546699487373976585");
   BigInt to_div(str_large);
   BigInt half = to_div/2;
   BigInt should_be_to_div = half*2;
   BigInt diff = should_be_to_div-to_div;
   BOOST_CHECK_MESSAGE((diff <= 1) && (diff >= BigInt("-1")), "error in division/multiplication (/) of large BigInt, differnce = " << diff);

   // also testing /=...
   BigInt before_div = to_div;
   to_div /= 2;
   BigInt should_be_before(to_div*2);
   BigInt diff2(should_be_before - before_div);
   BOOST_CHECK_MESSAGE((diff2 <= 1) && (diff2 >= BigInt("-1")), "error in division/multiplication (/=) of large BigInt, difference = " << diff2);
   }

BOOST_AUTO_TEST_CASE(test_deep_montgm)
   {
   cout << "." << flush;

   //string s_prime = "5334243285367";
   string s_prime = "5";
   BigInt bi_prime(s_prime);
   //string s_value_a = "3333333333334";
   string s_value_a = "4";
   BigInt bi_value_a(s_value_a);
   //string s_value_b = "4444444444444";
   string s_value_b = "3";
   BigInt bi_value_b(s_value_b);

   GFpElement gfp_a_trf(bi_prime, bi_value_a, true);
   GFpElement gfp_a_ntrf(bi_prime, bi_value_a, false);
   GFpElement gfp_b_trf(bi_prime, bi_value_b, true);
   GFpElement gfp_b_ntrf(bi_prime, bi_value_b, false);

   //BOOST_CHECK(!gfp_b_trf.is_trf_to_mres());
   gfp_b_trf.get_mres();
   gfp_a_trf.get_mres();

   GFpElement c_trf(gfp_a_trf * gfp_b_trf);
   GFpElement c_ntrf(gfp_a_ntrf * gfp_b_ntrf);

   BOOST_CHECK_MESSAGE(c_trf.get_value() == c_ntrf.get_value(), "\nc_trf.value = " << c_trf.get_value() << "\nc_ntrf.value = " << c_ntrf.get_value());
   }

BOOST_AUTO_TEST_CASE(test_gfp_div_small_numbers)
   {
   cout << "." << flush;

   string s_prime = "5";
   BigInt bi_prime(s_prime);
   string s_value_a = "2";
   BigInt bi_value_a(s_value_a);
   string s_value_b = "3";
   BigInt bi_value_b(s_value_b);

   GFpElement gfp_a(bi_prime, bi_value_a, true);
   GFpElement gfp_b(bi_prime, bi_value_b, true);
   GFpElement gfp_c(bi_prime, bi_value_b, false);

   BOOST_CHECK(!gfp_a.is_trf_to_mres());
   //convert to montgomery
   gfp_b.get_mres();
   BOOST_CHECK(gfp_b.is_trf_to_mres());
   BOOST_CHECK(!gfp_c.is_trf_to_mres());

   GFpElement res_div_m = gfp_a / gfp_b;
   BOOST_CHECK(res_div_m.is_trf_to_mres());

   GFpElement res_div_n = gfp_a / gfp_c;
   BOOST_CHECK(!res_div_n.is_trf_to_mres());

   BOOST_CHECK_MESSAGE(res_div_n.get_value() == res_div_m.get_value(), "transformed result is not equal to untransformed result");
   BOOST_CHECK_MESSAGE(gfp_a.get_value() == s_value_a, "GFpElement has changed while division operation");
   BOOST_CHECK_MESSAGE(gfp_b.get_value() == s_value_b, "GFpElement has changed while division operation");
   GFpElement inverse_b = inverse(gfp_b);
   GFpElement res_div_alternative = gfp_a * inverse_b;
   BOOST_CHECK_MESSAGE(res_div_m == res_div_alternative, "a/b is not as equal to a * b^-1");
   //cout << "Div-result transformed:" << res_div_m.get_value() << endl;
   //cout << "Div-result untransformed:" << res_div_n.get_value() << endl;
   //cout << "Div-Alternative: " << res_div_alternative.get_value() << endl;
   }

BOOST_AUTO_TEST_CASE(test_gfp_basics)
   {
   cout << "." << flush;

   string s_prime = "5334243285367";
   BigInt bi_prime(s_prime);
   string s_value_a = "3333333333333";
   BigInt bi_value_a(s_value_a);

   GFpElement gfp_a(bi_prime, bi_value_a, true);
   BOOST_CHECK(gfp_a.get_p() == s_prime);
   BOOST_CHECK(gfp_a.get_value() == s_value_a);
   BOOST_CHECK(!gfp_a.is_trf_to_mres());
   gfp_a.get_mres();
   BOOST_CHECK(gfp_a.is_trf_to_mres());
   }

BOOST_AUTO_TEST_CASE(test_gfp_addSubNegate)
   {
   cout << "." << flush;

   string s_prime = "5334243285367";
   BigInt bi_prime(s_prime);
   string s_value_a = "3333333333333";
   BigInt bi_value_a(s_value_a);

   GFpElement gfp_a(bi_prime, bi_value_a, true);
   GFpElement gfp_b(bi_prime, bi_value_a, true);

   gfp_b.negate();
   GFpElement zero = gfp_a + gfp_b;
   BigInt bi_zero("0");
   BOOST_CHECK(zero.get_value() == bi_zero);
   BOOST_CHECK(gfp_a.get_value() == bi_value_a);
   }

BOOST_AUTO_TEST_CASE(test_gfp_mult)
   {
   cout << "." << flush;

   string s_prime = "5334243285367";
   BigInt bi_prime(s_prime);
   string s_value_a = "3333333333333";
   BigInt bi_value_a(s_value_a);
   string s_value_b = "4444444444444";
   BigInt bi_value_b(s_value_b);

   GFpElement gfp_a(bi_prime, bi_value_a, true);
   GFpElement gfp_b(bi_prime, bi_value_b, true);
   GFpElement gfp_c(bi_prime, bi_value_b, false);

   BOOST_CHECK(!gfp_a.is_trf_to_mres());
   //convert to montgomery
   gfp_b.get_mres();
   BOOST_CHECK(gfp_b.is_trf_to_mres());
   BOOST_CHECK(!gfp_c.is_trf_to_mres());

   GFpElement res_mult_m = gfp_a * gfp_b;
   BOOST_CHECK(res_mult_m.is_trf_to_mres());

   GFpElement res_mult_n = gfp_a * gfp_c;
   BOOST_CHECK(!res_mult_n.is_trf_to_mres());

   BOOST_CHECK(res_mult_n.get_value() == res_mult_m.get_value());
   }

BOOST_AUTO_TEST_CASE(test_gfp_div)
   {
   cout << "." << flush;

   string s_prime = "5334243285367";
   BigInt bi_prime(s_prime);
   string s_value_a = "3333333333333";
   BigInt bi_value_a(s_value_a);
   string s_value_b = "4444444444444";
   BigInt bi_value_b(s_value_b);

   GFpElement gfp_a(bi_prime, bi_value_a, true);
   GFpElement gfp_b(bi_prime, bi_value_b, true);
   GFpElement gfp_c(bi_prime, bi_value_b, false);

   BOOST_CHECK(!gfp_a.is_trf_to_mres());
   //convert to montgomery
   gfp_b.get_mres();
   BOOST_CHECK(gfp_b.is_trf_to_mres());
   BOOST_CHECK(!gfp_c.is_trf_to_mres());

   GFpElement res_div_m = gfp_a / gfp_b;
   BOOST_CHECK(res_div_m.is_trf_to_mres());

   GFpElement res_div_n = gfp_a / gfp_c;
   BOOST_CHECK(!res_div_n.is_trf_to_mres());

   BOOST_CHECK_MESSAGE(res_div_n.get_value() == res_div_m.get_value(), "transformed result is not equal to untransformed result");
   BOOST_CHECK_MESSAGE(gfp_a.get_value() == s_value_a, "GFpElement has changed while division operation");
   BOOST_CHECK_MESSAGE(gfp_b.get_value() == s_value_b, "GFpElement has changed while division operation");
   GFpElement inverse_b = inverse(gfp_b);
   GFpElement res_div_alternative = gfp_a * inverse_b;
   BOOST_CHECK_MESSAGE(res_div_m == res_div_alternative, "a/b is not as equal to a * b^-1");
   //cout << "Div-result transformed:" << res_div_m.get_value() << endl;
   //cout << "Div-result untransformed:" << res_div_n.get_value() << endl;
   //cout << "Div-Alternative: " << res_div_alternative.get_value() << endl;
   }

BOOST_AUTO_TEST_CASE(test_gfp_add)
   {
   cout << "." << flush;

   string s_prime = "5334243285367";
   BigInt bi_prime(s_prime);
   string s_value_a = "3333333333333";
   BigInt bi_value_a(s_value_a);
   string s_value_b = "4444444444444";
   BigInt bi_value_b(s_value_b);

   GFpElement gfp_a(bi_prime, bi_value_a, true);
   GFpElement gfp_b(bi_prime, bi_value_b, true);
   GFpElement gfp_c(bi_prime, bi_value_b, true);

   BOOST_CHECK(!gfp_a.is_trf_to_mres());
   //convert to montgomery
   gfp_b.get_mres();
   BOOST_CHECK(gfp_b.is_trf_to_mres());
   BOOST_CHECK(!gfp_c.is_trf_to_mres());

   GFpElement res_add_m = gfp_a + gfp_b;
   BOOST_CHECK(res_add_m.is_trf_to_mres());

   GFpElement res_add_n = gfp_a + gfp_c;
   //  commented out by patrick, behavior is clear:
   //	rhs might be transformed, lhs never
   //  for now, this behavior is only intern, doesn't matter for programm function
   //  BOOST_CHECK_MESSAGE(res_add_n.is_trf_to_mres(), "!! Falko: NO FAIL, wrong test, please repair"); // clear: rhs might be transformed, lhs never

   BOOST_CHECK(res_add_n.get_value() == res_add_m.get_value());
   }

BOOST_AUTO_TEST_CASE(test_gfp_sub)
   {
   cout << "." << flush;

   string s_prime = "5334243285367";
   BigInt bi_prime(s_prime);
   string s_value_a = "3333333333333";
   BigInt bi_value_a(s_value_a);
   string s_value_b = "4444444444444";
   BigInt bi_value_b(s_value_b);

   GFpElement gfp_a(bi_prime, bi_value_a, true);
   GFpElement gfp_b(bi_prime, bi_value_b, true);
   GFpElement gfp_c(bi_prime, bi_value_b, true);

   BOOST_CHECK(!gfp_a.is_trf_to_mres());
   //convert to montgomery
   gfp_b.get_mres();
   BOOST_CHECK(gfp_b.is_trf_to_mres());
   BOOST_CHECK(!gfp_c.is_trf_to_mres());

   GFpElement res_sub_m = gfp_b - gfp_a;
   BOOST_CHECK(res_sub_m.is_trf_to_mres());
   BOOST_CHECK(gfp_a.is_trf_to_mres()); // added by Falko

   GFpElement res_sub_n = gfp_c - gfp_a;

   //  commented out by psona, behavior is clear:
   //	rhs might be transformed, lhs never
   //  for now, this behavior is only intern, doesn't matter for programm function
   //	BOOST_CHECK_MESSAGE(!res_sub_n.is_trf_to_mres(), "!! Falko: NO FAIL, wrong test, please repair"); // falsche
   // Erwartung: a wurde durch die operation oben auch
   // ins m-residue transformiert, daher passiert das hier auch mit
   // c, und das Ergebnis ist es auch

   BOOST_CHECK(res_sub_n.get_value() == res_sub_m.get_value());
   }

BOOST_AUTO_TEST_CASE(test_more_gfp_div)
   {
   cout << "." << flush;

   string s_prime = "5334243285367";
   BigInt bi_prime(s_prime);
   string s_value_a = "3333333333333";
   BigInt bi_value_a(s_value_a);
   string s_value_b = "4444444444444";
   BigInt bi_value_b(s_value_b);

   GFpElement gfp_a(bi_prime, bi_value_a, true);
   GFpElement gfp_b_trf(bi_prime, bi_value_b, true);
   GFpElement gfp_b_ntrf(bi_prime, bi_value_b, false);

   BOOST_CHECK(!gfp_b_trf.is_trf_to_mres());
   gfp_b_trf.get_mres();
   BOOST_CHECK(gfp_b_trf.is_trf_to_mres());

   BOOST_CHECK(!gfp_a.is_trf_to_mres());

   bool exc_ntrf = false;
   try
      {
      gfp_b_ntrf.get_mres();
      }
   catch(Botan::Illegal_Transformation e)
      {
      exc_ntrf = true;
      }
   BOOST_CHECK(exc_ntrf);

   BOOST_CHECK(!gfp_b_ntrf.is_trf_to_mres());

   BOOST_CHECK_MESSAGE(gfp_b_trf == gfp_b_ntrf, "b is not equal to itself (trf)");

   GFpElement b_trf_inv(gfp_b_trf);
   b_trf_inv.inverse_in_place();
   GFpElement b_ntrf_inv(gfp_b_ntrf);
   b_ntrf_inv.inverse_in_place();
   BOOST_CHECK_MESSAGE(b_trf_inv == b_ntrf_inv, "b inverted is not equal to itself (trf)");

   BOOST_CHECK(gfp_b_trf/gfp_b_ntrf == GFpElement(bi_prime, 1));
   BOOST_CHECK(gfp_b_trf/gfp_b_trf == GFpElement(bi_prime, 1));
   BOOST_CHECK(gfp_b_ntrf/gfp_b_ntrf == GFpElement(bi_prime, 1));
   GFpElement rhs(gfp_a/gfp_b_trf);
   GFpElement lhs(gfp_a/gfp_b_ntrf);
   BOOST_CHECK_MESSAGE(lhs == rhs, "\nrhs(trf) = " << rhs.get_value() << "\nlhs(n_trf) = " << lhs.get_value());
   }

BOOST_AUTO_TEST_CASE(test_gfp_mult_u32bit)
   {
   cout << "." << flush;

   /*
   Botan::EC_Domain_Params parA(Botan::get_EC_Dom_Pars_by_oid("1.2.840.10045.3.1.1"));
   CurveGFp curve = parA.get_curve();
   //CurveGFp curve2 = parA.get_curve();
   BigInt p = curve.get_p();
   GFpElement a = curve.get_a();
   GFpElement a_mr = curve.get_mres_a();
   Botan::u32bit u_x = 134234;
   BigInt b_x(u_x);
   GFpElement g_x(p, b_x);
   BOOST_CHECK(a*u_x == a*g_x);
   BOOST_CHECK(a*u_x == u_x*a);
   BOOST_CHECK(a*g_x == g_x*a);
   BOOST_CHECK(a_mr*u_x == a*g_x);
   BOOST_CHECK(u_x*a_mr == a*g_x);
   */
   }

/**
* This tests verifies the functionality of sharing pointers for modulus dependent values
*/
BOOST_AUTO_TEST_CASE(test_gfp_shared_vals)
   {
   cout << "." << flush;

   BigInt p("5334243285367");
   GFpElement a(p, BigInt("234090"));
   GFpElement shcpy_a(1,0);
   shcpy_a.share_assign(a);
   std::tr1::shared_ptr<GFpModulus> ptr1 = a.get_ptr_mod();
   std::tr1::shared_ptr<GFpModulus> ptr2 = shcpy_a.get_ptr_mod();
   BOOST_CHECK_MESSAGE(ptr1.get() == ptr2.get(), "shared pointers for moduli aren´t equal");

   GFpElement b(1,0);
   b = a; // create a non shared copy
   std::tr1::shared_ptr<GFpModulus> ptr_b_p = b.get_ptr_mod();
   BOOST_CHECK_MESSAGE(ptr1.get() != ptr_b_p.get(), "non shared pointers for moduli are equal");

   a.turn_on_sp_red_mul();
   GFpElement c1 = a * shcpy_a;
   GFpElement c2 = a * a;
   GFpElement c3 = shcpy_a * shcpy_a;
   GFpElement c4 = shcpy_a * a;
   shcpy_a.turn_on_sp_red_mul();
   GFpElement c5 = shcpy_a * shcpy_a;

   BOOST_CHECK(c1 == c2);
   BOOST_CHECK(c2 == c3);
   BOOST_CHECK(c3 == c4);
   BOOST_CHECK(c4 == c5);

   swap(a,shcpy_a);
   std::tr1::shared_ptr<GFpModulus> ptr3 = a.get_ptr_mod();
   std::tr1::shared_ptr<GFpModulus> ptr4 = shcpy_a.get_ptr_mod();
   BOOST_CHECK_MESSAGE(ptr3.get() == ptr4.get(), "shared pointers for moduli aren´t equal after swap");
   BOOST_CHECK(ptr1.get() == ptr4.get());
   BOOST_CHECK(ptr2.get() == ptr3.get());

   swap(a,b);
   std::tr1::shared_ptr<GFpModulus> ptr_a = a.get_ptr_mod();
   std::tr1::shared_ptr<GFpModulus> ptr_b = shcpy_a.get_ptr_mod();
   BOOST_CHECK(ptr_a.get() == ptr_b_p.get());
   BOOST_CHECK(ptr_b.get() == ptr3.get());
   }

/**
* The following test checks the behaviour of GFpElements assignment operator, which
* has quite complex behaviour with respect to sharing groups and precomputed values
* (with respect to montgomery mult.)
*/
BOOST_AUTO_TEST_CASE(test_gfpel_ass_op)
   {
   cout << "." << flush;


   // test different moduli
   GFpElement a(23,4);
   GFpElement b(11,6);

   GFpElement b2(11,6);

   a = b;
   BOOST_CHECK(a==b2);
   BOOST_CHECK(a.get_value() == b2.get_value());
   BOOST_CHECK(a.get_p() == b2.get_p());
   BOOST_CHECK(a.get_ptr_mod().get() != b.get_ptr_mod().get()); // sharing groups
   // may not be fused!

   // also test some share_assign()...
   a.share_assign(b);
   BOOST_CHECK(a==b2);
   BOOST_CHECK(a.get_value() == b2.get_value());
   BOOST_CHECK(a.get_p() == b2.get_p());
   BOOST_CHECK(a.get_ptr_mod().get() == b.get_ptr_mod().get()); // sharing groups
   // shall be fused!
   //---------------------------

   // test assignment within sharing group
   // with montg.mult.
   GFpElement c(5,2);
   GFpElement d(5,2);
   d.share_assign(c);
   BOOST_CHECK(d.get_ptr_mod().get() == c.get_ptr_mod().get());
   BOOST_CHECK(d.get_ptr_mod()->get_p() == c.get_ptr_mod()->get_p());
   BOOST_CHECK(c.get_ptr_mod()->get_r().is_zero());
   c.turn_on_sp_red_mul();
   BOOST_CHECK(d.get_ptr_mod().get() == c.get_ptr_mod().get());
   BOOST_CHECK(d.get_ptr_mod()->get_p() == c.get_ptr_mod()->get_p());
   BOOST_CHECK(!c.get_ptr_mod()->get_p().is_zero());
   GFpElement f(11,5);
   d = f;
   BOOST_CHECK(f.get_ptr_mod().get() != c.get_ptr_mod().get());

   GFpElement e = c*c;
   GFpElement g = d*d;
   GFpElement h = f*f;
   BOOST_CHECK(h == g);

   GFpElement c2(5,2);
   GFpElement d2(5,2);
   d2.share_assign(c2);
   GFpElement f2(11,5);
   d2 = f2;
   c2.turn_on_sp_red_mul();
   BOOST_CHECK(d2.get_ptr_mod().get() != c2.get_ptr_mod().get()); // the sharing group was left
   BOOST_CHECK(d2.get_ptr_mod()->get_r() == f2.get_ptr_mod()->get_r());
   BOOST_CHECK(c2.get_p() == 5); // c2´s shared values weren´t modified because
   // the sharing group with d2 was separated by
   // the assignment "d2 = f2"

   d2.turn_on_sp_red_mul();
   BOOST_CHECK(d2.get_ptr_mod()->get_p() != c2.get_ptr_mod()->get_p());
   GFpElement e2 = c2*c2;
   GFpElement g2 = d2*d2;
   GFpElement h2 = f2*f2;
   BOOST_CHECK(h2 == g2);

   GFpElement c3(5,2);
   GFpElement d3(5,2);
   d3.share_assign(c3);
   GFpElement f3(11,2);
   d3 = f3;
   GFpElement e3 = c3*c3;
   GFpElement g3 = d3*d3;

   BOOST_CHECK(e == e2);
   BOOST_CHECK(g == g2);

   BOOST_CHECK(e == e3);
   BOOST_CHECK(g == g2);
   }

BOOST_AUTO_TEST_CASE(test_gfp_swap)
   {
   cout << "." << flush;


   BigInt p("173");
   GFpElement a(p, BigInt("2342"));
   GFpElement b(p, BigInt("423420"));

   GFpModulus* a_mod = a.get_ptr_mod().get();
   GFpModulus* b_mod = b.get_ptr_mod().get();

   //GFpModulus* a_d = a.get_ptr_mod()->get_p_dash();
   //GFpModulus* b_d = b.get_ptr_mod()->get_p_dash();

   swap(a,b);
   BOOST_CHECK_MESSAGE(b.get_value() == 2342%173, "actual value of b was: " << b.get_value() );
   BOOST_CHECK_MESSAGE(a.get_value() == 423420%173, "actual value of a was: " << a.get_value() );

   BOOST_CHECK(a_mod == b.get_ptr_mod().get());
   BOOST_CHECK(b_mod == a.get_ptr_mod().get());
   //BOOST_CHECK(a_d == b.get_ptr_mod()->get_p_dash());
   //BOOST_CHECK(b_d == a.get_ptr_p_dash()->get_p_dash());

   GFpElement c(p, BigInt("2342329"));
   GFpElement d(1,1);
   d.share_assign(c);
   d += d;
   c.swap(d);
   BOOST_CHECK(d.get_value() == 2342329%173);
   BOOST_CHECK(c.get_value() == (d*2).get_value());
   }

BOOST_AUTO_TEST_CASE(test_inv_in_place)
   {
   cout << "." << flush;


   BigInt mod(173);
   GFpElement a1(mod, 288);
   a1.turn_on_sp_red_mul();
   a1.get_mres(); // enforce the conversion

   GFpElement a1_inv(a1);
   a1_inv.inverse_in_place();

   GFpElement a2(mod, 288);
   GFpElement a2_inv(a2);
   a2_inv.inverse_in_place();

   /*cout << "a1_inv = " << a1_inv << endl;
   cout << "a2_inv = " << a2_inv << endl;*/
   BOOST_CHECK_MESSAGE(a1_inv == a2_inv, "error with inverting tranformed GFpElement");

   BOOST_CHECK(a1_inv.inverse_in_place() == a1);
   BOOST_CHECK(a2_inv.inverse_in_place() == a2);
   }

BOOST_AUTO_TEST_CASE(test_op_eq)
   {
   cout << "." << flush;

   BigInt mod(173);
   GFpElement a1(mod, 299);
   a1.turn_on_sp_red_mul();
   a1.get_mres(); // enforce the conversion
   GFpElement a2(mod, 288);
   BOOST_CHECK_MESSAGE(a1 != a2, "error with GFpElement comparison");
   }

BOOST_AUTO_TEST_CASE(test_rand_int)
   {
   std::auto_ptr<RandomNumberGenerator> rng(RandomNumberGenerator::make_rng());

   for(int i=0; i< 100; i++)
      {
      cout << "." << flush;
      BigInt x = BigInt::random_integer(*rng, 1,3);
      //cout << "x = " << x << "\n";  // only 1,2 are put out
      BOOST_CHECK(x == 1 || x==2);
      }
   }

BOOST_AUTO_TEST_CASE(test_bi_bit_access)
   {
   cout << "." << flush;

   BigInt a(323);
   BOOST_CHECK(a.get_bit(1) == 1);
   BOOST_CHECK(a.get_bit(1000) == 0);
   }

BOOST_AUTO_TEST_CASE(test_sec_mod_mul)
   {
#if 0
   //cout << "starting test_sec_mod_mul" << endl;

   //mod_mul_secure(BigInt const& a, BigInt const& b, BigInt const& m)

   BigInt m("5334243285367");
   BigInt a("3333333333333");
   BigInt b("4444444444444");
   for(int i = 0; i<10; i++)
      {
      cout << "." << flush;
      BigInt c1 = a * b;
      c1 %= m;
      BigInt c2 = mod_mul_secure(a, b, m);
      BOOST_CHECK_MESSAGE(c1 == c2, "should be " << c1 << ", was " << c2);
      }
   //cout << "ending test_sec_mod_mul" << endl;
#endif
   }

/*BOOST_AUTO_TEST_CASE(test_sec_bi_mul)
{

//mod_mul_secure(BigInt const& a, BigInt const& b, BigInt const& m)

BigInt m("5334243285367");
BigInt a("3333333333333");
BigInt b("4444444444444");
for(int i = 0; i<10; i++)
{
cout << "." << flush;
BigInt c1 = a * b;
//c1 %= m;
BigInt c2(a);
c2.mult_this_secure(b, m);
BOOST_CHECK_MESSAGE(c1 == c2, "should be " << c1 << ", was " << c2);
}


}*/

int main()
   {
   test_turn_on_sp_red_mul();
   test_bi_div_even();
   test_bi_div_odd();
   test_deep_montgm();
   test_gfp_div_small_numbers();
   test_gfp_basics();
   test_gfp_addSubNegate();
   test_gfp_mult();
   test_gfp_div();
   test_gfp_add();
   test_gfp_sub();
   test_more_gfp_div();
   test_gfp_mult_u32bit();
   test_gfp_shared_vals();
   test_gfpel_ass_op();
   test_gfp_swap();
   test_inv_in_place();
   test_op_eq();
   test_rand_int();
   test_bi_bit_access();
   test_sec_mod_mul();

   std::cout << "\ndone\n";
   }
