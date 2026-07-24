/*
* (C) 2019,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_ECC_GROUP)
   #include <botan/ec_group.h>
   #include <botan/internal/fmt.h>
#endif

#if defined(BOTAN_HAS_XMD)
   #include <botan/hash.h>
   #include <botan/internal/mem_utils.h>
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

         auto hash_fn = Botan::HashFunction::create_or_throw(hash);

         std::vector<uint8_t> output(expected.size());
         Botan::expand_message_xmd(*hash_fn, output, Botan::as_span_of_bytes(input), Botan::as_span_of_bytes(domain));

         result.test_bin_eq("XMD output", output, expected);
         return result;
      }
};

BOTAN_REGISTER_TEST("ec_h2c", "ec_h2c_xmd", ECC_H2C_XMD_Tests);

#endif

#if defined(BOTAN_HAS_XMD) && defined(BOTAN_HAS_ECC_GROUP)

class ECC_H2S_Tests final : public Text_Based_Test {
   public:
      ECC_H2S_Tests() : Text_Based_Test("pubkey/ec_h2s.vec", "Hash,Domain,Input,Output") {}

      bool clear_between_callbacks() const override { return false; }

      bool skip_this_test(const std::string& group_id, const VarMap& /*vars*/) override {
         return !Botan::EC_Group::supports_named_group(group_id);
      }

      Test::Result run_one_test(const std::string& group_id, const VarMap& vars) override {
         Test::Result result("ECC hash to scalar " + group_id);

         const std::string hash_fn = vars.get_req_str("Hash");
         const std::string domain_str = vars.get_req_str("Domain");
         const std::string input_str = vars.get_req_str("Input");
         const std::vector<uint8_t> expected_value = vars.get_req_bin("Output");

         auto input = std::span{reinterpret_cast<const uint8_t*>(input_str.data()), input_str.size()};
         auto domain = std::span{reinterpret_cast<const uint8_t*>(domain_str.data()), domain_str.size()};

         const auto group = Botan::EC_Group::from_name(group_id);

         try {
            auto scalar = Botan::EC_Scalar::hash(group, hash_fn, input, domain).serialize();
            result.test_bin_eq("output", scalar, expected_value);
         } catch(Botan::Not_Implemented&) {
            result.test_note("Skipping due to not implemented");
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("ec_h2c", "ec_h2s_kat", ECC_H2S_Tests);

class ECC_H2C_Hash_Check_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("ECC hash to curve hash strength checks");

         reject(result, "secp256r1", "SHA-1");
         reject(result, "secp256r1", "MD5");
         reject(result, "secp384r1", "SHA-256");
         reject(result, "secp521r1", "SHA-384");
         reject(result, "brainpool512r1", "SHA-384");

         accept(result, "secp224r1", "SHA-224");
         accept(result, "secp256r1", "SHA-256");
         accept(result, "secp384r1", "SHA-384");
         accept(result, "secp521r1", "SHA-512");

         return {result};
      }

   private:
      static bool can_test(const std::string& group_id, const std::string& hash_fn) {
         return Botan::EC_Group::supports_named_group(group_id) && Botan::HashFunction::create(hash_fn) != nullptr;
      }

      static void reject(Test::Result& result, const std::string& group_id, const std::string& hash_fn) {
         if(!can_test(group_id, hash_fn)) {
            return;
         }

         const auto group = Botan::EC_Group::from_name(group_id);
         const std::string domain = "QUUX-V01-CS02";
         const std::vector<uint8_t> input(13);

         result.test_is_false("hash_to_curve_supported rejects " + hash_fn + " with " + group_id,
                              group.hash_to_curve_supported(hash_fn));

         result.test_throws<Botan::Invalid_Argument>("EC_Scalar::hash rejects " + hash_fn + " with " + group_id, [&]() {
            Botan::EC_Scalar::hash(group, hash_fn, input, Botan::as_span_of_bytes(domain));
         });

         try {
            Botan::EC_AffinePoint::hash_to_curve_ro(group, hash_fn, input, Botan::as_span_of_bytes(domain));
            result.test_failure("hash_to_curve_ro accepted " + hash_fn + " with " + group_id);
         } catch(Botan::Invalid_Argument&) {
            result.test_success("hash_to_curve_ro rejects " + hash_fn + " with " + group_id);
         } catch(Botan::Not_Implemented&) {
            result.test_note("Skipping due to not implemented");
         }
      }

      static void accept(Test::Result& result, const std::string& group_id, const std::string& hash_fn) {
         if(!can_test(group_id, hash_fn)) {
            return;
         }

         const auto group = Botan::EC_Group::from_name(group_id);
         const std::string domain = "QUUX-V01-CS02";
         const std::vector<uint8_t> input(13);

         result.test_no_throw("EC_Scalar::hash accepts " + hash_fn + " with " + group_id, [&]() {
            Botan::EC_Scalar::hash(group, hash_fn, input, Botan::as_span_of_bytes(domain));
         });
      }
};

BOTAN_REGISTER_TEST("ec_h2c", "ec_h2c_hash_checks", ECC_H2C_Hash_Check_Tests);

#endif

#if defined(BOTAN_HAS_EC_HASH_TO_CURVE)

class ECC_H2C_Tests final : public Text_Based_Test {
   public:
      ECC_H2C_Tests() : Text_Based_Test("pubkey/ec_h2c.vec", "Group,Hash,Domain,Input,Point") {}

      bool clear_between_callbacks() const override { return false; }

      bool skip_this_test(const std::string& /*header*/, const VarMap& vars) override {
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

            result.test_bin_eq("Generated point serialization", pt, expected_point);
            result.test_is_true("hash_to_curve_supported", group.hash_to_curve_supported(hash_fn));
         } catch(Botan::Not_Implemented&) {
            result.test_is_false("hash_to_curve_supported", group.hash_to_curve_supported(hash_fn));
            result.test_note("Skipping due to not implemented");
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("ec_h2c", "ec_h2c_kat", ECC_H2C_Tests);

class ECC_H2C_Supported_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("EC_Group::hash_to_curve_supported");

         const std::vector<uint8_t> input{1, 2, 3};
         const std::string domain_sep = "hash_to_curve_supported test";

         const std::vector<std::string> hash_fns{
            "SHA-1", "SHA-256", "SHA-384", "SHA-512", "SHAKE-128(256)", "NotARealHash"};

         for(const auto& group_name : Botan::EC_Group::known_named_groups()) {
            const auto group = Botan::EC_Group::from_name(group_name);

            for(const auto& hash_fn : hash_fns) {
               const bool supported = group.hash_to_curve_supported(hash_fn);

               bool ro_worked = false;
               try {
                  Botan::EC_AffinePoint::hash_to_curve_ro(group, hash_fn, input, domain_sep);
                  ro_worked = true;
               } catch(Botan::Exception&) {}

               bool nu_worked = false;
               try {
                  Botan::EC_AffinePoint::hash_to_curve_nu(group, hash_fn, input, domain_sep);
                  nu_worked = true;
               } catch(Botan::Exception&) {}

               result.test_is_true(Botan::fmt("{}/{} prediction matches behavior", group_name, hash_fn),
                                   supported == ro_worked && supported == nu_worked);
            }
         }

         return {result};
      }
};

BOTAN_REGISTER_TEST("ec_h2c", "ec_h2c_supported", ECC_H2C_Supported_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
