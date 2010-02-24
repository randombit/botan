/******************************************************
* gfp_element tests                                   *
*                                                     *
* (C) 2007 Patrick Sona                               *
*                                                     *
*          Falko Strenzke                             *
*          strenzke@flexsecure.de                     *
* (C) 2008 Jack Lloyd                                 *
******************************************************/

#include "validate.h"

#if defined(BOTAN_HAS_BIGINT_GFP)

#include <botan/bigint.h>
#include <botan/numthry.h>
#include <botan/gfp_element.h>
#include <botan/curve_gfp.h>
#include <botan/ec_dompar.h>

#include <iostream>

using namespace Botan;

#define CHECK_MESSAGE(expr, print) if(!(expr)) { std::cout << print << "\n"; pass = false; }
#define CHECK(expr) if(!(expr)) { std::cout << #expr << "\n"; pass = false; }

namespace {

bool test_turn_on_sp_red_mul()
   {
   std::cout << "." << std::flush;

   bool pass = true;

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

   if(c1 != c2)
      {
      std::cout << "test_turn_on_sp_red_mul: ";
      std::cout << "c1 = " << c1 << " != ";
      std::cout << "c2 = " << c2 << "\n";
      return false; // test failed
      }

   return pass; // pass
   }

bool test_bi_div_even()
   {
   std::cout << "." << std::flush;

   bool pass = true;

   std::string str_large("1552518092300708935148979488462502555256886017116696611139052038026050952686323255099158638440248181850494907312621195144895406865083132424709500362534691373159016049946612882688577088900506460909202178541447303914546699487373976586");
   BigInt to_div(str_large);
   BigInt half = to_div/2;
   BigInt should_be_to_div = half*2;
   CHECK_MESSAGE(should_be_to_div == to_div, "error in division/multiplication of large BigInt");

   // also testing /=...
   BigInt before_div = to_div;
   to_div /= 2;
   BigInt should_be_before(to_div*2);
   CHECK_MESSAGE(should_be_before == before_div, "error in division/multiplication of large BigInt");

   return pass;
   }

bool test_bi_div_odd()
   {
   std::cout << '.' << std::flush;

   bool pass = true;

   std::string str_large("1552518092300708935148979488462502555256886017116696611139052038026050952686323255099158638440248181850494907312621195144895406865083132424709500362534691373159016049946612882688577088900506460909202178541447303914546699487373976585");
   BigInt to_div(str_large);
   BigInt half = to_div/2;
   BigInt should_be_to_div = half*2;
   BigInt diff = should_be_to_div-to_div;
   CHECK_MESSAGE((diff <= 1) && (diff >= BigInt("-1")), "error in division/multiplication (/) of large BigInt, differnce = " << diff);

   // also testing /=...
   BigInt before_div = to_div;
   to_div /= 2;
   BigInt should_be_before(to_div*2);
   BigInt diff2(should_be_before - before_div);
   CHECK_MESSAGE((diff2 <= 1) && (diff2 >= BigInt("-1")), "error in division/multiplication (/=) of large BigInt, difference = " << diff2);

   return pass;
   }

bool test_deep_montgm()
   {
   std::cout << '.' << std::flush;

   bool pass = true;

   std::string s_prime = "5334243285367";
   //std::string s_prime = "5";
   BigInt bi_prime(s_prime);
   std::string s_value_a = "3333333333334";
   //std::string s_value_a = "4";
   BigInt bi_value_a(s_value_a);
   std::string s_value_b = "4444444444444";
   //std::string s_value_b = "3";
   BigInt bi_value_b(s_value_b);

   GFpElement gfp_a_trf(bi_prime, bi_value_a, true);
   GFpElement gfp_a_ntrf(bi_prime, bi_value_a, false);
   GFpElement gfp_b_trf(bi_prime, bi_value_b, true);
   GFpElement gfp_b_ntrf(bi_prime, bi_value_b, false);

   //CHECK(!gfp_b_trf.is_trf_to_mres());
   gfp_b_trf.get_mres();
   gfp_a_trf.get_mres();

   GFpElement c_trf(gfp_a_trf * gfp_b_trf);
   GFpElement c_ntrf(gfp_a_ntrf * gfp_b_ntrf);

   if(c_trf != c_ntrf)
      {
      std::cout << "test_deep_montgm - " << c_trf << " != " << c_ntrf << "\n";
      }
   return pass; // pass
   }

bool test_gfp_div_small_numbers()
   {
   std::cout << '.' << std::flush;

   bool pass = true;

   std::string s_prime = "13";
   BigInt bi_prime(s_prime);
   std::string s_value_a = "2";
   BigInt bi_value_a(s_value_a);
   std::string s_value_b = "3";
   BigInt bi_value_b(s_value_b);

   GFpElement gfp_a(bi_prime, bi_value_a, true);
   GFpElement gfp_b(bi_prime, bi_value_b, true);
   GFpElement gfp_c(bi_prime, bi_value_b, false);

   CHECK(!gfp_a.is_trf_to_mres());
   //convert to montgomery
   gfp_b.get_mres();
   CHECK(gfp_b.is_trf_to_mres());
   CHECK(!gfp_c.is_trf_to_mres());

   GFpElement res_div_m = gfp_a / gfp_b;
   CHECK(res_div_m.is_trf_to_mres());

   GFpElement res_div_n = gfp_a / gfp_c;
   CHECK(!res_div_n.is_trf_to_mres());

   CHECK_MESSAGE(res_div_n.get_value() == res_div_m.get_value(), "transformed result is not equal to untransformed result");
   CHECK_MESSAGE(gfp_a.get_value() == s_value_a, "GFpElement has changed while division operation");
   CHECK_MESSAGE(gfp_b.get_value() == s_value_b, "GFpElement has changed while division operation");
   GFpElement inverse_b = inverse(gfp_b);
   GFpElement res_div_alternative = gfp_a * inverse_b;

   if(res_div_m != res_div_alternative)
      {
      std::cout << "test_gfp_div_small_numbers - a/b != a*b^-1 where\n"
                << "a = " << gfp_a << "\n"
                << "b = " << gfp_b << "\n"
                << "b^-1 = " << inverse_b << "\n"
                << "a*b^-1 = " << res_div_alternative << "\n"
                << "a/b = " << res_div_n << "\n";
      pass = false;
      }

   CHECK_MESSAGE(res_div_m == res_div_alternative, "a/b is not as equal to a * b^-1");
   //cout << "Div-result transformed:" << res_div_m.get_value() << endl;
   //cout << "Div-result untransformed:" << res_div_n.get_value() << endl;
   //cout << "Div-Alternative: " << res_div_alternative.get_value() << endl;
   return pass;
   }

bool test_gfp_basics()
   {
   std::cout << '.' << std::flush;

   bool pass = true;

   std::string s_prime = "5334243285367";
   BigInt bi_prime(s_prime);
   std::string s_value_a = "3333333333333";
   BigInt bi_value_a(s_value_a);

   GFpElement gfp_a(bi_prime, bi_value_a, true);
   CHECK(gfp_a.get_p() == s_prime);
   CHECK(gfp_a.get_value() == s_value_a);
   CHECK(!gfp_a.is_trf_to_mres());
   gfp_a.get_mres();
   CHECK(gfp_a.is_trf_to_mres());
   return pass;
   }

bool test_gfp_addSubNegate()
   {
   std::cout << '.' << std::flush;

   bool pass = true;

   std::string s_prime = "5334243285367";
   BigInt bi_prime(s_prime);
   std::string s_value_a = "3333333333333";
   BigInt bi_value_a(s_value_a);

   GFpElement gfp_a(bi_prime, bi_value_a, true);
   GFpElement gfp_b(bi_prime, bi_value_a, true);

   gfp_b.negate();
   GFpElement zero = gfp_a + gfp_b;
   BigInt bi_zero("0");
   CHECK(zero.get_value() == bi_zero);
   CHECK(gfp_a.get_value() == bi_value_a);
   return pass;
   }

bool test_gfp_mult()
   {
   std::cout << '.' << std::flush;

   bool pass = true;

   std::string s_prime = "5334243285367";
   BigInt bi_prime(s_prime);
   std::string s_value_a = "3333333333333";
   BigInt bi_value_a(s_value_a);
   std::string s_value_b = "4444444444444";
   BigInt bi_value_b(s_value_b);

   GFpElement gfp_a(bi_prime, bi_value_a, true);
   GFpElement gfp_b(bi_prime, bi_value_b, true);
   GFpElement gfp_c(bi_prime, bi_value_b, false);

   CHECK(!gfp_a.is_trf_to_mres());
   //convert to montgomery
   gfp_b.get_mres();
   CHECK(gfp_b.is_trf_to_mres());
   CHECK(!gfp_c.is_trf_to_mres());

   GFpElement res_mult_m = gfp_a * gfp_b;
   CHECK(res_mult_m.is_trf_to_mres());

   GFpElement res_mult_n = gfp_a * gfp_c;
   CHECK(!res_mult_n.is_trf_to_mres());

   if(res_mult_n != res_mult_m)
      std::cout << gfp_a << " * " << gfp_b << " =? "
                << "n = " << res_mult_n << " != m = " << res_mult_m << "\n";
   return pass;
   }

bool test_gfp_div()
   {
   std::cout << '.' << std::flush;

   bool pass = true;

   std::string s_prime = "5334243285367";
   BigInt bi_prime(s_prime);
   std::string s_value_a = "3333333333333";
   BigInt bi_value_a(s_value_a);
   std::string s_value_b = "4444444444444";
   BigInt bi_value_b(s_value_b);

   GFpElement gfp_a(bi_prime, bi_value_a, true);
   GFpElement gfp_b(bi_prime, bi_value_b, true);
   GFpElement gfp_c(bi_prime, bi_value_b, false);

   CHECK(!gfp_a.is_trf_to_mres());
   //convert to montgomery
   gfp_b.get_mres();
   CHECK(gfp_b.is_trf_to_mres());
   CHECK(!gfp_c.is_trf_to_mres());

   GFpElement res_div_m = gfp_a / gfp_b;
   CHECK(res_div_m.is_trf_to_mres());

   GFpElement res_div_n = gfp_a / gfp_c;
   CHECK(!res_div_n.is_trf_to_mres());

   CHECK_MESSAGE(res_div_n.get_value() == res_div_m.get_value(), "transformed result is not equal to untransformed result");
   CHECK_MESSAGE(gfp_a.get_value() == s_value_a, "GFpElement has changed while division operation");
   CHECK_MESSAGE(gfp_b.get_value() == s_value_b, "GFpElement has changed while division operation");
   GFpElement inverse_b = inverse(gfp_b);
   GFpElement res_div_alternative = gfp_a * inverse_b;
   CHECK_MESSAGE(res_div_m == res_div_alternative, "a/b is not as equal to a * b^-1");
   //cout << "Div-result transformed:" << res_div_m.get_value() << endl;
   //cout << "Div-result untransformed:" << res_div_n.get_value() << endl;
   //cout << "Div-Alternative: " << res_div_alternative.get_value() << endl;
   return pass;
   }

bool test_gfp_add()
   {
   std::cout << '.' << std::flush;

   bool pass = true;

   std::string s_prime = "5334243285367";
   BigInt bi_prime(s_prime);
   std::string s_value_a = "3333333333333";
   BigInt bi_value_a(s_value_a);
   std::string s_value_b = "4444444444444";
   BigInt bi_value_b(s_value_b);

   GFpElement gfp_a(bi_prime, bi_value_a, true);
   GFpElement gfp_b(bi_prime, bi_value_b, true);
   GFpElement gfp_c(bi_prime, bi_value_b, true);

   CHECK(!gfp_a.is_trf_to_mres());
   //convert to montgomery
   gfp_b.get_mres();
   CHECK(gfp_b.is_trf_to_mres());
   CHECK(!gfp_c.is_trf_to_mres());

   GFpElement res_add_m = gfp_a + gfp_b;
   CHECK(res_add_m.is_trf_to_mres());

   GFpElement res_add_n = gfp_a + gfp_c;
   //  commented out by patrick, behavior is clear:
   //	rhs might be transformed, lhs never
   //  for now, this behavior is only intern, doesn't matter for programm function
   //  CHECK_MESSAGE(res_add_n.is_trf_to_mres(), "!! Falko: NO FAIL, wrong test, please repair"); // clear: rhs might be transformed, lhs never

   CHECK(res_add_n.get_value() == res_add_m.get_value());
   return pass;
   }

bool test_gfp_sub()
   {
   std::cout << '.' << std::flush;

   bool pass = true;

   std::string s_prime = "5334243285367";
   BigInt bi_prime(s_prime);
   std::string s_value_a = "3333333333333";
   BigInt bi_value_a(s_value_a);
   std::string s_value_b = "4444444444444";
   BigInt bi_value_b(s_value_b);

   GFpElement gfp_a(bi_prime, bi_value_a, true);
   GFpElement gfp_b(bi_prime, bi_value_b, true);
   GFpElement gfp_c(bi_prime, bi_value_b, true);

   CHECK(!gfp_a.is_trf_to_mres());
   //convert to montgomery
   gfp_b.get_mres();
   CHECK(gfp_b.is_trf_to_mres());
   CHECK(!gfp_c.is_trf_to_mres());

   GFpElement res_sub_m = gfp_b - gfp_a;
   CHECK(res_sub_m.is_trf_to_mres());
   CHECK(gfp_a.is_trf_to_mres()); // added by Falko

   GFpElement res_sub_n = gfp_c - gfp_a;

   //  commented out by psona, behavior is clear:
   //	rhs might be transformed, lhs never
   //  for now, this behavior is only intern, doesn't matter for programm function
   //	CHECK_MESSAGE(!res_sub_n.is_trf_to_mres(), "!! Falko: NO FAIL, wrong test, please repair"); // falsche
   // Erwartung: a wurde durch die operation oben auch
   // ins m-residue transformiert, daher passiert das hier auch mit
   // c, und das Ergebnis ist es auch

   CHECK(res_sub_n.get_value() == res_sub_m.get_value());
   return pass;
   }

bool test_more_gfp_div()
   {
   std::cout << '.' << std::flush;

   bool pass = true;

   std::string s_prime = "5334243285367";
   BigInt bi_prime(s_prime);
   std::string s_value_a = "3333333333333";
   BigInt bi_value_a(s_value_a);
   std::string s_value_b = "4444444444444";
   BigInt bi_value_b(s_value_b);

   GFpElement gfp_a(bi_prime, bi_value_a, true);
   GFpElement gfp_b_trf(bi_prime, bi_value_b, true);
   GFpElement gfp_b_ntrf(bi_prime, bi_value_b, false);

   CHECK(!gfp_b_trf.is_trf_to_mres());
   gfp_b_trf.get_mres();
   CHECK(gfp_b_trf.is_trf_to_mres());

   CHECK(!gfp_a.is_trf_to_mres());

   bool exc_ntrf = false;
   try
      {
      gfp_b_ntrf.get_mres();
      }
   catch(Botan::Illegal_Transformation e)
      {
      exc_ntrf = true;
      }
   CHECK(exc_ntrf);

   CHECK(!gfp_b_ntrf.is_trf_to_mres());

   CHECK_MESSAGE(gfp_b_trf == gfp_b_ntrf, "b is not equal to itself (trf)");

   GFpElement b_trf_inv(gfp_b_trf);
   b_trf_inv.inverse_in_place();
   GFpElement b_ntrf_inv(gfp_b_ntrf);
   b_ntrf_inv.inverse_in_place();
   CHECK_MESSAGE(b_trf_inv == b_ntrf_inv, "b inverted is not equal to itself (trf)");

   CHECK(gfp_b_trf/gfp_b_ntrf == GFpElement(bi_prime, 1));
   CHECK(gfp_b_trf/gfp_b_trf == GFpElement(bi_prime, 1));
   CHECK(gfp_b_ntrf/gfp_b_ntrf == GFpElement(bi_prime, 1));
   GFpElement rhs(gfp_a/gfp_b_trf);
   GFpElement lhs(gfp_a/gfp_b_ntrf);

   if(lhs != rhs)
      {
      std::cout << "test_more_gfp_div - " << lhs << " != " << rhs << "\n";
      pass = false;
      }

   return pass;
   }

bool test_gfp_mult_u32bit()
   {
   std::cout << '.' << std::flush;

   bool pass = true;

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
   CHECK(a*u_x == a*g_x);
   CHECK(a*u_x == u_x*a);
   CHECK(a*g_x == g_x*a);
   CHECK(a_mr*u_x == a*g_x);
   CHECK(u_x*a_mr == a*g_x);
   */
   return pass;
   }

bool test_gfp_swap()
   {
   std::cout << '.' << std::flush;

   bool pass = true;

   BigInt p("173");
   GFpElement a(p, BigInt("2342"));
   GFpElement b(p, BigInt("423420"));

   swap(a,b);
   CHECK_MESSAGE(b.get_value() == 2342%173, "actual value of b was: " << b.get_value() );
   CHECK_MESSAGE(a.get_value() == 423420%173, "actual value of a was: " << a.get_value() );

   GFpElement c(p, BigInt("2342329"));
   GFpElement d(1,1);
   d = c;
   d += d;
   c.swap(d);
   CHECK(d.get_value() == 2342329%173);
   CHECK(c.get_value() == (d*2).get_value());
   return pass;
   }

bool test_inv_in_place()
   {
   std::cout << '.' << std::flush;

   bool pass = true;

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
   CHECK_MESSAGE(a1_inv == a2_inv, "error with inverting tranformed GFpElement");

   CHECK(a1_inv.inverse_in_place() == a1);
   CHECK(a2_inv.inverse_in_place() == a2);
   return pass;
   }

bool test_op_eq()
   {
   std::cout << '.' << std::flush;

   bool pass = true;

   BigInt mod(173);
   GFpElement a1(mod, 299);
   a1.turn_on_sp_red_mul();
   a1.get_mres(); // enforce the conversion
   GFpElement a2(mod, 288);
   CHECK_MESSAGE(a1 != a2, "error with GFpElement comparison");
   return pass;
   }

bool test_rand_int(RandomNumberGenerator& rng)
   {
   bool pass = true;

   for(int i=0; i< 100; i++)
      {
      std::cout << '.' << std::flush;
      BigInt x = BigInt::random_integer(rng, 1,3);
      //cout << "x = " << x << "\n";  // only 1,2 are put out
      CHECK(x == 1 || x==2);
      }

   return pass;
   }

bool test_bi_bit_access()
   {
   std::cout << '.' << std::flush;

   bool pass = true;

   BigInt a(323);
   CHECK(a.get_bit(1) == 1);
   CHECK(a.get_bit(1000) == 0);
   return pass;
   }

#if 0
bool test_sec_mod_mul()
   {
   //cout << "starting test_sec_mod_mul" << endl;

   bool pass = true;

   //mod_mul_secure(BigInt const& a, BigInt const& b, BigInt const& m)

   BigInt m("5334243285367");
   BigInt a("3333333333333");
   BigInt b("4444444444444");
   for(int i = 0; i<10; i++)
      {
      std::cout << '.' << std::flush;
      BigInt c1 = a * b;
      c1 %= m;
      BigInt c2 = mod_mul_secure(a, b, m);
      CHECK_MESSAGE(c1 == c2, "should be " << c1 << ", was " << c2);
      }
   //cout << "ending test_sec_mod_mul" << endl;
   return pass;
   }
#endif

#if 0
bool test_sec_bi_mul()
   {
   //mod_mul_secure(BigInt const& a, BigInt const& b, BigInt const& m)

   bool pass = true;

   BigInt m("5334243285367");
   BigInt a("3333333333333");
   BigInt b("4444444444444");
   for(int i = 0; i<10; i++)
      {
      std::cout << '.' << std::flush;
      BigInt c1 = a * b;
      //c1 %= m;
      BigInt c2(a);
      c2.mult_this_secure(b, m);
      CHECK_MESSAGE(c1 == c2, "should be " << c1 << ", was " << c2);
      }

   return pass;
   }
#endif

}

u32bit do_gfpmath_tests(Botan::RandomNumberGenerator& rng)
   {
   std::cout << "Testing GF(p) math " << std::flush;

   u32bit failed = 0;

   failed += !test_turn_on_sp_red_mul();
   failed += !test_bi_div_even();
   failed += !test_bi_div_odd();
   failed += !test_deep_montgm();
   failed += !test_gfp_div_small_numbers();
   failed += !test_gfp_basics();
   failed += !test_gfp_addSubNegate();
   failed += !test_gfp_mult();
   failed += !test_gfp_div();
   failed += !test_gfp_add();
   failed += !test_gfp_sub();
   failed += !test_more_gfp_div();
   failed += !test_gfp_mult_u32bit();
   failed += !test_gfp_swap();
   failed += !test_inv_in_place();
   failed += !test_op_eq();
   failed += !test_rand_int(rng);
   failed += !test_bi_bit_access();
   //failed += !test_sec_mod_mul();
   //failed += !test_sec_bi_mul();

#if 0
   if(failed == 0)
      std::cout << " OK";
   else
      std::cout << ' ' << failed << " failed";
#endif

   std::cout << std::endl;

   return failed;
   }
#else
u32bit do_gfpmath_tests(Botan::RandomNumberGenerator&) { return 0; }
#endif
