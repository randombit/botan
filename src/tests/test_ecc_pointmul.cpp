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

      Test::Result run_one_test(const std::string& group_id, const VarMap& vars) override {
         Test::Result result("ECC base point multiply " + group_id);

         const auto k_bytes = vars.get_req_bin("k");
         const auto P_bytes = vars.get_req_bin("P");

         const auto group = Botan::EC_Group::from_name(group_id);

         const Botan::BigInt k(k_bytes);
         std::vector<Botan::BigInt> ws;

   #if defined(BOTAN_HAS_LEGACY_EC_POINT)
         const auto pt = group.OS2ECP(P_bytes);

         const Botan::EC_Point& base_point = group.get_base_point();

         const Botan::EC_Point p1 = base_point * k;
         result.test_eq("mul with *", p1, pt);

         const Botan::EC_Point p2 = group.blinded_base_point_multiply(k, this->rng(), ws);
         result.test_eq("blinded_base_point_multiply", p2, pt);

         const Botan::EC_Point p3 = group.blinded_var_point_multiply(base_point, k, this->rng(), ws);
         result.test_eq("blinded_var_point_multiply", p3, pt);
   #endif

         const auto scalar = Botan::EC_Scalar::from_bigint(group, k);
         const auto apg = Botan::EC_AffinePoint::g_mul(scalar, this->rng(), ws);
         result.test_eq("AffinePoint::g_mul", apg.serialize_uncompressed(), P_bytes);

         const auto ag = Botan::EC_AffinePoint::generator(group);
         const auto ap = ag.mul(scalar, this->rng(), ws);
         result.test_eq("AffinePoint::mul", ap.serialize_uncompressed(), P_bytes);

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "ecc_basemul", ECC_Basepoint_Mul_Tests);

class ECC_Varpoint_Mul_Tests final : public Text_Based_Test {
   public:
      ECC_Varpoint_Mul_Tests() : Text_Based_Test("pubkey/ecc_var_point_mul.vec", "P,k,Z") {}

      Test::Result run_one_test(const std::string& group_id, const VarMap& vars) override {
         Test::Result result("ECC var point multiply " + group_id);

         const auto p = vars.get_req_bin("P");
         const Botan::BigInt k = vars.get_req_bn("k");
         const auto z = vars.get_req_bin("Z");

         const auto group = Botan::EC_Group::from_name(group_id);

         std::vector<Botan::BigInt> ws;

   #if defined(BOTAN_HAS_LEGACY_EC_POINT)
         const Botan::EC_Point pt = group.OS2ECP(p);

         result.confirm("Input point is on the curve", pt.on_the_curve());

         const Botan::EC_Point p1 = pt * k;
         result.test_eq("p * k", p1.encode(Botan::EC_Point::Compressed), z);

         result.confirm("Output point is on the curve", p1.on_the_curve());

         const Botan::EC_Point p2 = group.blinded_var_point_multiply(pt, k, this->rng(), ws);
         result.test_eq("p * k (blinded)", p2.encode(Botan::EC_Point::Compressed), z);
   #endif

         const auto s_k = Botan::EC_Scalar::from_bigint(group, k);
         const auto apt = Botan::EC_AffinePoint::deserialize(group, p).value();
         const auto apt_k = apt.mul(s_k, this->rng(), ws);
         result.test_eq("p * k (AffinePoint)", apt_k.serialize_compressed(), z);

         const auto apt_k_neg = apt.negate().mul(s_k.negate(), this->rng(), ws);
         result.test_eq("-p * -k (AffinePoint)", apt_k_neg.serialize_compressed(), z);

         const auto neg_apt_neg_k = apt.mul(s_k.negate(), this->rng(), ws).negate();
         result.test_eq("-(p * -k) (AffinePoint)", neg_apt_neg_k.serialize_compressed(), z);

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "ecc_varmul", ECC_Varpoint_Mul_Tests);

class ECC_Mul2_Tests final : public Text_Based_Test {
   public:
      ECC_Mul2_Tests() : Text_Based_Test("pubkey/ecc_var_point_mul2.vec", "P,x,Q,y,Z") {}

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
            std::vector<BigInt> ws;
            auto z = p.mul(x, rng(), ws).add(q.mul(y, rng(), ws));
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
            std::vector<Botan::BigInt> ws;
            const auto z = g.mul(Botan::EC_Scalar::random(group, rng()), rng(), ws);

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

class ECC_Addition_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         for(const auto& group_id : Botan::EC_Group::known_named_groups()) {
            Test::Result result("ECC addition " + group_id);

            const auto group = Botan::EC_Group::from_name(group_id);

            const auto g = Botan::EC_AffinePoint::generator(group);
            result.test_eq("g is not the identity element", g.is_identity(), false);

            // Choose some other random point z
            std::vector<Botan::BigInt> ws;
            const auto z = g.mul(Botan::EC_Scalar::random(group, rng()), rng(), ws);
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

BOTAN_REGISTER_TEST("pubkey", "ecc_addition", ECC_Addition_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
