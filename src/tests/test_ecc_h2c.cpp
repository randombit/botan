/*
* (C) 2019,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_EC_HASH_TO_CURVE)
   #include <botan/ec_group.h>
#endif

#if defined(BOTAN_HAS_XMD)
   #include <botan/internal/xmd.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_XMD)

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

#endif

#if defined(BOTAN_HAS_EC_HASH_TO_CURVE)

class ECC_H2C_Tests final : public Text_Based_Test {
   public:
      ECC_H2C_Tests() : Text_Based_Test("pubkey/ec_h2c.vec", "Group,Hash,Domain,Input,Point") {}

      bool clear_between_callbacks() const override { return false; }

      bool skip_this_test(const std::string&, const VarMap& vars) override {
         return !Botan::EC_Group::supports_named_group(vars.get_req_str("Group"));
      }

      Test::Result run_one_test(const std::string& method, const VarMap& vars) override {
         const std::string group_id = vars.get_req_str("Group");

         Test::Result result("ECC hash to curve " + method + " " + group_id);

         const std::string hash_fn = vars.get_req_str("Hash");
         const std::string domain_str = vars.get_req_str("Domain");
         const std::vector<uint8_t> input = vars.get_req_bin("Input");
         const std::vector<uint8_t> expected_point = vars.get_req_bin("Point");
         const bool random_oracle = method.find("-RO") != std::string::npos;

         auto domain = std::span{reinterpret_cast<const uint8_t*>(domain_str.data()), domain_str.size()};

         const auto group = Botan::EC_Group::from_name(group_id);

         try {
            std::vector<uint8_t> pt;
            if(random_oracle) {
               pt = Botan::EC_AffinePoint::hash_to_curve_ro(group, hash_fn, input, domain).serialize_uncompressed();
            } else {
               pt = Botan::EC_AffinePoint::hash_to_curve_nu(group, hash_fn, input, domain).serialize_uncompressed();
            }

            result.test_eq("Generated point serialization", pt, expected_point);
         } catch(Botan::Not_Implemented&) {
            result.test_note("Skipping due to not implemented");
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("ec_h2c", "ec_h2c_kat", ECC_H2C_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
