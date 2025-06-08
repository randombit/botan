/*
* (C) 2014,2015,2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_ECC_GROUP)
   #include <botan/bigint.h>
   #include <botan/ec_group.h>
   #include <botan/internal/fmt.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_ECC_GROUP)

class ECC_Basepoint_Mul_Tests final : public Text_Based_Test {
   public:
      ECC_Basepoint_Mul_Tests() : Text_Based_Test("pubkey/ecc_base_point_mul.vec", "k,P") {}

      bool skip_this_test(const std::string& group_id, const VarMap&) override {
         return !Botan::EC_Group::supports_named_group(group_id);
      }

      Test::Result run_one_test(const std::string& group_id, const VarMap& vars) override {
         Test::Result result("ECC base point multiply " + group_id);

         const auto k_bytes = vars.get_req_bin("k");
         const auto P_bytes = vars.get_req_bin("P");

         const auto group = Botan::EC_Group::from_name(group_id);

         const Botan::BigInt k(k_bytes);

   #if defined(BOTAN_HAS_LEGACY_EC_POINT)
         const auto pt = group.OS2ECP(P_bytes);
         const Botan::EC_Point p1 = group.get_base_point() * k;
         result.test_eq("EC_Point Montgomery ladder", p1.encode(Botan::EC_Point_Format::Uncompressed), P_bytes);
   #endif

         const auto scalar = Botan::EC_Scalar::from_bigint(group, k);
         const auto apg = Botan::EC_AffinePoint::g_mul(scalar, this->rng());
         result.test_eq("AffinePoint::g_mul", apg.serialize_uncompressed(), P_bytes);

         const auto ag = Botan::EC_AffinePoint::generator(group);
         const auto ap = ag.mul(scalar, this->rng());
         result.test_eq("AffinePoint::mul", ap.serialize_uncompressed(), P_bytes);

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "ecc_basemul", ECC_Basepoint_Mul_Tests);

class ECC_Varpoint_Mul_Tests final : public Text_Based_Test {
   public:
      ECC_Varpoint_Mul_Tests() : Text_Based_Test("pubkey/ecc_var_point_mul.vec", "P,k,Z") {}

      bool skip_this_test(const std::string& group_id, const VarMap&) override {
         return !Botan::EC_Group::supports_named_group(group_id);
      }

      Test::Result run_one_test(const std::string& group_id, const VarMap& vars) override {
         Test::Result result("ECC var point multiply " + group_id);

         const auto p = vars.get_req_bin("P");
         const Botan::BigInt k = vars.get_req_bn("k");
         const auto z = vars.get_req_bin("Z");

         const auto group = Botan::EC_Group::from_name(group_id);

   #if defined(BOTAN_HAS_LEGACY_EC_POINT)
         const Botan::EC_Point p1 = group.OS2ECP(p) * k;
         result.test_eq("EC_Point Montgomery ladder", p1.encode(Botan::EC_Point::Compressed), z);
   #endif

         const auto s_k = Botan::EC_Scalar::from_bigint(group, k);
         const auto apt = Botan::EC_AffinePoint::deserialize(group, p).value();
         const auto apt_k = apt.mul(s_k, this->rng());
         result.test_eq("p * k (AffinePoint)", apt_k.serialize_compressed(), z);

         const auto apt_k_neg = apt.negate().mul(s_k.negate(), this->rng());
         result.test_eq("-p * -k (AffinePoint)", apt_k_neg.serialize_compressed(), z);

         const auto neg_apt_neg_k = apt.mul(s_k.negate(), this->rng()).negate();
         result.test_eq("-(p * -k) (AffinePoint)", neg_apt_neg_k.serialize_compressed(), z);

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "ecc_varmul", ECC_Varpoint_Mul_Tests);

class ECC_Mul2_Tests final : public Text_Based_Test {
   public:
      ECC_Mul2_Tests() : Text_Based_Test("pubkey/ecc_var_point_mul2.vec", "P,x,Q,y,Z") {}

      bool skip_this_test(const std::string& group_id, const VarMap&) override {
         return !Botan::EC_Group::supports_named_group(group_id);
      }

      Test::Result run_one_test(const std::string& group_id, const VarMap& vars) override {
         Test::Result result("ECC mul2 " + group_id);

         const auto Z_bytes = vars.get_req_bin("Z");

         const auto check_px_qy = [&](const char* what,
                                      const Botan::EC_AffinePoint& p,
                                      const Botan::EC_Scalar& x,
                                      const Botan::EC_AffinePoint& q,
                                      const Botan::EC_Scalar& y,
                                      bool with_final_negation = false) {
            if(const auto z = Botan::EC_AffinePoint::mul_px_qy(p, x, q, y, rng())) {
               if(with_final_negation) {
                  result.test_eq(what, z->negate().serialize_compressed(), Z_bytes);
               } else {
                  result.test_eq(what, z->serialize_compressed(), Z_bytes);
               }
            } else {
               result.test_failure("EC_AffinePoint::mul_px_qy failed to produce a result");
            }

            // Now check the same using naive multiply and add:
            auto z = p.mul(x, rng()).add(q.mul(y, rng()));
            if(with_final_negation) {
               z = z.negate();
            }
            result.test_eq("p*x + q*y naive", z.serialize_compressed(), Z_bytes);
         };

         const auto group = Botan::EC_Group::from_name(group_id);

         const auto p = Botan::EC_AffinePoint::deserialize(group, vars.get_req_bin("P")).value();
         const auto q = Botan::EC_AffinePoint::deserialize(group, vars.get_req_bin("Q")).value();
         const auto x = Botan::EC_Scalar::from_bigint(group, vars.get_req_bn("x"));
         const auto y = Botan::EC_Scalar::from_bigint(group, vars.get_req_bn("y"));

         const auto np = p.negate();
         const auto nq = q.negate();
         const auto nx = x.negate();
         const auto ny = y.negate();

         check_px_qy("p*x + q*y", p, x, q, y);
         check_px_qy("-p*-x + -q*-y", np, nx, nq, ny);
         check_px_qy("-(p*-x + q*-y)", p, nx, q, ny, true);
         check_px_qy("-(-p*x + -q*y)", np, x, nq, y, true);

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "ecc_mul2", ECC_Mul2_Tests);

class ECC_Mul2_Inf_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         for(const auto& group_id : Botan::EC_Group::known_named_groups()) {
            Test::Result result("ECC mul2 inf " + group_id);

            const auto check_px_qy = [&](const char* what,
                                         const Botan::EC_AffinePoint& p,
                                         const Botan::EC_Scalar& x,
                                         const Botan::EC_AffinePoint& q,
                                         const Botan::EC_Scalar& y) {
               if(const auto z = Botan::EC_AffinePoint::mul_px_qy(p, x, q, y, rng())) {
                  result.test_failure(Botan::fmt("EC_AffinePoint::mul_px_qy {} unexpectedly produced a result", what));
               } else {
                  result.test_success(Botan::fmt("EC_AffinePoint::mul_px_qy {} returned nullopt as expected", what));
               }
            };

            const auto group = Botan::EC_Group::from_name(group_id);

            const auto g = Botan::EC_AffinePoint::generator(group);

            // Choose some other random point z
            const auto z = g.mul(Botan::EC_Scalar::random(group, rng()), rng());

            const auto r = Botan::EC_Scalar::random(group, rng());
            const auto neg_r = r.negate();
            const auto neg_r2 = neg_r + neg_r;

            const auto zero = r - r;
            result.confirm("Computed EC_Scalar is zero", zero.is_zero());

            const auto g2 = g.add(g);

            const auto id = Botan::EC_AffinePoint::identity(group);

            check_px_qy("0*g + r*id", g, zero, id, r);
            check_px_qy("0*id + r*id", id, zero, id, r);
            check_px_qy("0*g + 0*z", g, zero, z, zero);
            check_px_qy("r*g + -r*g", g, r, g, neg_r);
            check_px_qy("-r*g + r*g", g, neg_r, g, r);
            check_px_qy("r*g + r*-g", g, r, g.negate(), r);
            check_px_qy("r*g2 + -r2*g", g2, r, g, neg_r2);

            results.push_back(result);
         }

         return results;
      }
};

BOTAN_REGISTER_TEST("pubkey", "ecc_mul2_inf", ECC_Mul2_Inf_Tests);

class ECC_Point_Addition_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         for(const auto& group_id : Botan::EC_Group::known_named_groups()) {
            Test::Result result("ECC addition " + group_id);

            const auto group = Botan::EC_Group::from_name(group_id);

            const auto g = Botan::EC_AffinePoint::generator(group);
            result.test_eq("g is not the identity element", g.is_identity(), false);

            // Choose some other random point z
            const auto z = g.mul(Botan::EC_Scalar::random(group, rng()), rng());
            result.test_eq("z is not the identity element", z.is_identity(), false);

            const auto id = Botan::EC_AffinePoint::identity(group);
            result.test_eq("id is the identity element", id.is_identity(), true);

            const auto g_bytes = g.serialize_uncompressed();

            auto check_expr_is_g = [&](const char* msg, const Botan::EC_AffinePoint& pt) {
               result.test_eq(Botan::fmt("{} is g", msg), pt.serialize_uncompressed(), g_bytes);
            };

            const auto nz = z.negate();

            check_expr_is_g("g + id", g.add(id));
            check_expr_is_g("id + g", id.add(g));
            check_expr_is_g("g + id", g.add(id));
            check_expr_is_g("g + -id", g.add(id.negate()));
            check_expr_is_g("g + g + -g", g.add(g).add(g.negate()));
            check_expr_is_g("-id + g", id.negate().add(g));
            check_expr_is_g("z + g - z", z.add(g).add(nz));
            check_expr_is_g("z - z + g", z.add(nz).add(g));
            check_expr_is_g("z + z + g - z - z", z.add(z).add(g).add(nz).add(nz));
            check_expr_is_g("z + id + g + z - z - z", z.add(id).add(g).add(z).add(nz).add(nz));

            results.push_back(result);
         }

         return results;
      }
};

BOTAN_REGISTER_TEST("pubkey", "ecc_pt_addition", ECC_Point_Addition_Tests);

class ECC_Scalar_Arithmetic_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         auto& rng = Test::rng();

         for(const auto& group_id : Botan::EC_Group::known_named_groups()) {
            const auto group = Botan::EC_Group::from_name(group_id);

            Test::Result result("ECC scalar arithmetic " + group_id);
            test_scalar_arith(result, group, rng);
            results.push_back(result);
         }
         return results;
      }

   private:
      void test_scalar_arith(Test::Result& result,
                             const Botan::EC_Group& group,
                             Botan::RandomNumberGenerator& rng) const {
         const auto one = Botan::EC_Scalar::one(group);
         const auto zero = one - one;
         const auto two = one + one;

         const size_t order_bytes = group.get_order_bytes();

         const auto ser_zero = std::vector<uint8_t>(order_bytes);

         const auto ser_one = [=]() {
            auto b = ser_zero;
            BOTAN_ASSERT_NOMSG(b.size() > 1);
            b[b.size() - 1] = 1;
            return b;
         }();

         result.test_eq("Serialization of zero is expected value", zero.serialize(), ser_zero);
         result.test_eq("Serialization of one is expected value", one.serialize(), ser_one);

         result.test_eq("Zero is zero", zero.is_zero(), true);
         result.test_eq("Negation of zero is zero", zero.negate().is_zero(), true);
         result.test_eq("One is not zero", one.is_zero(), false);

         // Zero inverse is not mathematically correct, but works out for our purposes
         result.test_eq("Inverse of zero is zero", zero.invert().serialize(), ser_zero);
         result.test_eq("Inverse of one is one", one.invert().serialize(), ser_one);

         result.test_eq("Inverse (vt) of zero is zero", zero.invert_vartime().serialize(), ser_zero);
         result.test_eq("Inverse (vt) of one is one", one.invert_vartime().serialize(), ser_one);

         constexpr size_t test_iter = 128;

         for(size_t i = 0; i != test_iter; ++i) {
            const auto r = Botan::EC_Scalar::random(group, rng);

            // Negation and addition are inverses
            result.test_eq("r + -r == 0", (r + r.negate()).serialize(), ser_zero);

            // Serialization and deserialization are inverses
            const auto r_bytes = r.serialize();
            result.test_eq("Deserialization of r round trips",
                           Botan::EC_Scalar::deserialize(group, r_bytes).value().serialize(),
                           r_bytes);

            // Multiplication and inversion are inverses
            const auto r2 = r * r;
            const auto r_inv = r.invert();
            result.test_eq("r * r^-1 = 1", (r * r_inv).serialize(), ser_one);

            const auto r_inv_vt = r.invert_vartime();
            result.confirm("CT and variable time inversions produced same result", r_inv == r_inv_vt);
         }

         for(size_t i = 0; i != test_iter; ++i) {
            const auto a = Botan::EC_Scalar::random(group, rng);
            const auto b = Botan::EC_Scalar::random(group, rng);

            const auto ab = a * b;
            const auto a_inv = a.invert();
            const auto b_inv = b.invert();

            result.test_eq("a * b / b = a", (ab * b_inv).serialize(), a.serialize());
            result.test_eq("a * b / a = b", (ab * a_inv).serialize(), b.serialize());

            auto a_plus_b = a + b;
            result.test_eq("(a + b) - b == a", (a_plus_b - b).serialize(), a.serialize());
            result.test_eq("(a + b) - a == b", (a_plus_b - a).serialize(), b.serialize());
            result.test_eq("b - (a + b) == -a", (b - a_plus_b).serialize(), a.negate().serialize());
            result.test_eq("a - (a + b) == -b", (a - a_plus_b).serialize(), b.negate().serialize());
         }

         for(size_t i = 0; i != test_iter; ++i) {
            const auto a = Botan::EC_Scalar::random(group, rng);
            const auto b = Botan::EC_Scalar::random(group, rng);
            const auto c = Botan::EC_Scalar::random(group, rng);

            const auto ab_c = (a + b) * c;
            const auto ac_bc = a * c + b * c;

            result.test_eq("(a + b)*c == a * c + b * c", ab_c.serialize(), ac_bc.serialize());
         }

         for(size_t i = 0; i != test_iter; ++i) {
            const auto a = Botan::EC_Scalar::random(group, rng);
            const auto b = Botan::EC_Scalar::random(group, rng);
            const auto c = a * b;

            const auto c_bn = (a.to_bigint() * b.to_bigint());
            result.test_eq("matches BigInt", c.serialize(), (c_bn % group.get_order()).serialize(order_bytes));

            const auto c_wide_bytes = c_bn.serialize();
            result.test_lte("Expected size", c_wide_bytes.size(), 2 * order_bytes);

            const auto z = Botan::EC_Scalar::from_bytes_mod_order(group, c_wide_bytes);

            result.test_eq("from_bytes_mod_order", c.serialize(), z.serialize());
         }

         for(size_t i = 0; i != test_iter; ++i) {
            std::vector<uint8_t> r(2 * group.get_order_bytes());

            rng.randomize(r);

            const auto ref = Botan::BigInt::from_bytes(r) % group.get_order();

            const auto scalar = Botan::EC_Scalar::from_bytes_mod_order(group, r);

            result.test_eq("from_bytes_mod_order (random)", scalar.serialize(), ref.serialize(group.get_order_bytes()));
         }

         result.end_timer();
      }
};

BOTAN_REGISTER_TEST("pubkey", "ecc_scalar_arith", ECC_Scalar_Arithmetic_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
