/*
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*     2023,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_ASN1)
   #include <botan/asn1_obj.h>
   #include <botan/ber_dec.h>
   #include <botan/der_enc.h>
   #include <botan/oids.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_ASN1)

Test::Result test_OID_to_string() {
   /*
   See #2730 and #2237

   Certain locales format integers with thousands seperators.  This
   caused a subtle bug which caused OID comparisons to fail because
   OID::to_string(), which used ostringstream, introduced a thousands
   seperator when the OID component had a value >= 1000. But this
   only failed in certain locales (pt_BR was reported).

   Nominally C++ requires std::to_string to also be locale-respecting.
   But, libc++, libstdc++, and MSVC's STL library all implement
   std::to_string in a way that ignores locales, because adding locale
   support means std::to_string will be both slow and a serialization
   point. So as a stopgap we assume this behavior from std::to_string.

   Here we test the original issue of #2237 to verify it works. If
   the compiler implements std::to_string in a way that respects locale,
   *and* this test is run in a locale that uses thousands seperators,
   then it will fail. Which is much better than a very subtle failure.
   However if it ever does fail then we must replace nearly every
   call to std::to_string with something else that ignores locale.
   */

   Botan::OID oid{1, 2, 1000, 1001, 1002000};

   Test::Result result("OID::to_string");

   result.test_eq("OID::to_string behaves as we expect", oid.to_string(), "1.2.1000.1001.1002000");

   return result;
}

Test::Result test_oid_registration() {
   Test::Result result("OID add");

   const std::string name = "botan-test-oid1";
   const Botan::OID oid("1.3.6.1.4.1.25258.1000.1");

   result.test_eq("named OID not found", Botan::OID::from_name(name).has_value(), false);

   Botan::OID::register_oid(oid, name);

   result.test_eq("named OID found", Botan::OID::from_name(name).has_value(), true);

   result.test_eq("name of OID matches expected", oid.to_formatted_string(), name);

   return result;
}

Test::Result test_add_and_lookup() {
   Test::Result result("OID add with redundant entries");

   const std::string name = "botan-test-oid2";
   const std::string name2 = "botan-test-oid2.2";
   const Botan::OID oid("1.3.6.1.4.1.25258.1001.1");
   const Botan::OID oid2("1.3.6.1.4.1.25258.1001.2");

   result.test_eq("named OID not found", Botan::OID::from_name(name).has_value(), false);

   Botan::OID::register_oid(oid, name);

   result.confirm("named OID found", Botan::OID::from_name(name).value_or(Botan::OID()) == oid);
   result.test_eq("name of OID matches expected", oid.to_formatted_string(), name);

   // completely redundant, nothing happens:
   Botan::OID::register_oid(oid, name);

   /*
   register a second OID to the same name; this is allowed but
   the name will still map back to the original OID
   */
   Botan::OID::register_oid(oid2, name);

   // name->oid map is unchanged:
   result.confirm("named OID found after second insert", Botan::OID::from_name(name).value_or(Botan::OID()) == oid);
   result.test_eq("name of OID matches expected", oid.to_formatted_string(), name);
   // now second OID maps back to the string as expected:
   result.test_eq("name of OID matches expected", oid2.to_formatted_string(), name);

   try {
      Botan::OID::register_oid(oid2, name2);
      result.test_failure("Registration of second name to the same OID was accepted");
   } catch(Botan::Invalid_State&) {
      result.test_success("Registration of second name to the same OID fails");
   }

   return result;
}

class OID_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         std::vector<std::function<Test::Result()>> fns = {
            test_OID_to_string,
            test_oid_registration,
            test_add_and_lookup,
         };

         for(size_t i = 0; i != fns.size(); ++i) {
            try {
               results.emplace_back(fns[i]());
            } catch(const std::exception& e) {
               results.emplace_back(Test::Result::Failure("OID tests " + std::to_string(i), e.what()));
            }
         }

         return results;
      }
};

BOTAN_REGISTER_TEST("asn1", "oid", OID_Tests);

class OID_Encoding_Tests : public Text_Based_Test {
   public:
      OID_Encoding_Tests() : Text_Based_Test("asn1_oid.vec", "OID,DER") {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override {
         const auto oid_str = vars.get_req_str("OID");
         const auto expected_der = vars.get_req_bin("DER");

         Test::Result result("OID DER encode/decode");

         const Botan::OID oid(oid_str);

         try {
            std::vector<uint8_t> der;
            Botan::DER_Encoder enc(der);
            enc.encode(oid);
            result.test_eq("Encoding correct", der, expected_der);
         } catch(std::exception& e) {
            result.test_failure("Encoding OID failed", e.what());
         }

         try {
            Botan::BER_Decoder dec(expected_der);
            Botan::OID dec_oid;
            dec.decode(dec_oid);
            dec.verify_end();
            result.test_eq("Decoding OID correct", dec_oid.to_string(), oid_str);
         } catch(std::exception& e) {
            result.test_failure("Decoding OID failed", e.what());
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("asn1", "oid_enc", OID_Encoding_Tests);

class OID_Invalid_Encoding_Tests : public Text_Based_Test {
   public:
      OID_Invalid_Encoding_Tests() : Text_Based_Test("asn1_oid_invalid.vec", "DER") {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override {
         const auto test_der = vars.get_req_bin("DER");

         Test::Result result("OID DER decode invalid");

         try {
            Botan::BER_Decoder dec(test_der);
            Botan::OID oid;
            dec.decode(oid);
            dec.verify_end();
            result.test_failure("Accepted invalid OID encoding", oid.to_string());
         } catch(Botan::Decoding_Error&) {
            result.test_success("Rejected invalid OID with Decoding_Error");
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("asn1", "oid_dec_invalid", OID_Invalid_Encoding_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
