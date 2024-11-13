/*
* (C) 2014,2015,2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_BIGINT)
   #include <botan/bigint.h>
#endif

#if defined(BOTAN_HAS_ECC_GROUP)
   #include <botan/ec_group.h>
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
         const auto pt = group.OS2ECP(P_bytes);

         const Botan::EC_Point& base_point = group.get_base_point();

         const Botan::EC_Point p1 = base_point * k;
         result.test_eq("mul with *", p1, pt);

         std::vector<Botan::BigInt> ws;
         const Botan::EC_Point p2 = group.blinded_base_point_multiply(k, this->rng(), ws);
         result.test_eq("blinded_base_point_multiply", p2, pt);

         const Botan::EC_Point p3 = group.blinded_var_point_multiply(base_point, k, this->rng(), ws);
         result.test_eq("blinded_var_point_multiply", p3, pt);

         const auto scalar = Botan::EC_Scalar::from_bigint(group, k);
         const auto apg = Botan::EC_AffinePoint::g_mul(scalar, this->rng(), ws);
         result.test_eq("AffinePoint::g_mul", apg.serialize_uncompressed(), P_bytes);

         const auto ag = Botan::EC_AffinePoint(group, base_point);
         const auto ap = ag.mul(scalar, this->rng(), ws);
         result.test_eq("AffinePoint::mul", ap.to_legacy_point(), pt);

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

         const Botan::EC_Point pt = group.OS2ECP(p);

         result.confirm("Input point is on the curve", pt.on_the_curve());

         const Botan::EC_Point p1 = pt * k;
         result.test_eq("p * k", p1.encode(Botan::EC_Point::Compressed), z);

         result.confirm("Output point is on the curve", p1.on_the_curve());

         std::vector<Botan::BigInt> ws;
         const Botan::EC_Point p2 = group.blinded_var_point_multiply(pt, k, this->rng(), ws);
         result.test_eq("p * k (blinded)", p2.encode(Botan::EC_Point::Compressed), z);

         const auto apt = Botan::EC_AffinePoint::deserialize(group, p).value();
         const auto apt_k = apt.mul(Botan::EC_Scalar::from_bigint(group, k), this->rng(), ws);
         result.test_eq("p * k (AffinePoint)", apt_k.serialize_compressed(), z);

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "ecc_varmul", ECC_Varpoint_Mul_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
