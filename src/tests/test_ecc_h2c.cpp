/*
* (C) 2019,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_EC_HASH_TO_CURVE)
   #include <botan/ec_group.h>
   #include <botan/internal/ec_h2c.h>
   #include <botan/internal/xmd.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_EC_HASH_TO_CURVE)

class ECC_H2C_XMD_Tests final : public Text_Based_Test {
   public:
      ECC_H2C_XMD_Tests() : Text_Based_Test("pubkey/ec_h2c_xmd.vec", "Domain,Input,Output") {}

      bool clear_between_callbacks() const override { return false; }

      Test::Result run_one_test(const std::string& hash, const VarMap& vars) override {
         Test::Result result("ECC hash to curve XMD " + hash);

         const std::string domain = vars.get_req_str("Domain");
         const std::string input = vars.get_req_str("Input");
         const std::vector<uint8_t> expected = vars.get_req_bin("Output");

         std::vector<uint8_t> output(expected.size());
         Botan::expand_message_xmd(hash, output, input, domain);

         result.test_eq("XMD output", output, expected);
         return result;
      }
};

BOTAN_REGISTER_TEST("ec_h2c", "ec_h2c_xmd", ECC_H2C_XMD_Tests);

class ECC_H2C_Tests final : public Text_Based_Test {
   public:
      ECC_H2C_Tests() : Text_Based_Test("pubkey/ec_h2c.vec", "Group,Hash,Domain,Input,PointX,PointY") {}

      bool clear_between_callbacks() const override { return false; }

      Test::Result run_one_test(const std::string& method, const VarMap& vars) override {
         const std::string group_id = vars.get_req_str("Group");

         Test::Result result("ECC hash to curve " + method + " " + group_id);

         const std::string hash = vars.get_req_str("Hash");
         const std::string domain = vars.get_req_str("Domain");
         const std::vector<uint8_t> input = vars.get_req_bin("Input");
         const BigInt exp_point_x = vars.get_req_bn("PointX");
         const BigInt exp_point_y = vars.get_req_bn("PointY");
         const bool random_oracle = method.find("-RO") != std::string::npos;

         const auto group = Botan::EC_Group::from_name(group_id);

         const auto point = group.hash_to_curve(hash, input.data(), input.size(), domain, random_oracle);

         result.confirm("Generated point is on the curve", point.on_the_curve());

         result.test_eq("Affine X", point.get_affine_x(), exp_point_x);
         result.test_eq("Affine Y", point.get_affine_y(), exp_point_y);

         return result;
      }
};

BOTAN_REGISTER_TEST("ec_h2c", "ec_h2c_kat", ECC_H2C_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
