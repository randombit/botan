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
   #include <set>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_ASN1)

Test::Result test_OID_to_string() {
   /*
   See #2730 and #2237

   Certain locales format integers with thousands separators.  This
   caused a subtle bug which caused OID comparisons to fail because
   OID::to_string(), which used ostringstream, introduced a thousands
   separator when the OID component had a value >= 1000. But this
   only failed in certain locales (pt_BR was reported).

   Nominally C++ requires std::to_string to also be locale-respecting.
   But, libc++, libstdc++, and MSVC's STL library all implement
   std::to_string in a way that ignores locales, because adding locale
   support means std::to_string will be both slow and a serialization
   point. So as a stopgap we assume this behavior from std::to_string.

   Here we test the original issue of #2237 to verify it works. If
   the compiler implements std::to_string in a way that respects locale,
   *and* this test is run in a locale that uses thousands separators,
   then it will fail. Which is much better than a very subtle failure.
   However if it ever does fail then we must replace nearly every
   call to std::to_string with something else that ignores locale.
   */

   const Botan::OID oid{1, 2, 1000, 1001, 1002000};

   Test::Result result("OID::to_string");

   result.test_str_eq("OID::to_string behaves as we expect", oid.to_string(), "1.2.1000.1001.1002000");
   result.test_str_eq(
      "OID::to_formatted_string falls back to dotted decimal", oid.to_formatted_string(), oid.to_string());

   return result;
}

Test::Result test_oid_registration() {
   Test::Result result("OID add");

   const std::string name = "botan-test-oid1";
   const Botan::OID oid("1.3.6.1.4.1.25258.1000.1");

   result.test_is_false("named OID not found", Botan::OID::from_name(name).has_value());

   Botan::OID::register_oid(oid, name);

   result.test_is_true("named OID found", Botan::OID::from_name(name).has_value());

   result.test_opt_str_eq("name of OID matches expected", oid.registered_name(), name);

   return result;
}

Test::Result test_add_and_lookup() {
   Test::Result result("OID add with redundant entries");

   const std::string name = "botan-test-oid2";
   const std::string name2 = "botan-test-oid2.2";
   const Botan::OID oid("1.3.6.1.4.1.25258.1001.1");
   const Botan::OID oid2("1.3.6.1.4.1.25258.1001.2");

   result.test_is_false("named OID not found", Botan::OID::from_name(name).has_value());

   Botan::OID::register_oid(oid, name);

   result.test_is_true("named OID found", Botan::OID::from_name(name).value_or(Botan::OID()) == oid);
   result.test_opt_str_eq("name of OID matches expected", oid.registered_name(), name);

   // completely redundant, nothing happens:
   Botan::OID::register_oid(oid, name);

   /*
   register a second OID to the same name; this is allowed but
   the name will still map back to the original OID
   */
   Botan::OID::register_oid(oid2, name);

   // name->oid map is unchanged:
   result.test_is_true("named OID found after second insert",
                       Botan::OID::from_name(name).value_or(Botan::OID()) == oid);
   result.test_opt_str_eq("name of OID matches expected", oid.registered_name(), name);
   // now second OID maps back to the string as expected:
   result.test_opt_str_eq("name of OID matches expected", oid2.registered_name(), name);

   try {
      Botan::OID::register_oid(oid2, name2);
      result.test_failure("Registration of second name to the same OID was accepted");
   } catch(Botan::Invalid_State&) {
      result.test_success("Registration of second name to the same OID fails");
   }

   const Botan::OID oid3("1.3.6.1.4.1.25258.1001.3");
   result.test_throws<Botan::Invalid_Argument>("Registration of an empty name is rejected",
                                               [&]() { Botan::OID::register_oid(oid3, ""); });
   result.test_is_false("OID with rejected empty name remains unregistered", oid3.registered_oid());

   return result;
}

Test::Result test_oid_large_arcs() {
   Test::Result result("OID large arcs");

   // GH #4020: a UUID embedded as an arc under 2.25 (ITU-T X.667)
   const std::string uuid_oid_str = "2.25.329800735698586629295641978511506172918";
   const Botan::OID uuid_oid(uuid_oid_str);

   result.test_str_eq("to_string round trips", uuid_oid.to_string(), uuid_oid_str);
   result.test_str_eq("to_formatted_string falls back to dotted decimal", uuid_oid.to_formatted_string(), uuid_oid_str);
   result.test_is_false("OID is not registered", uuid_oid.registered_oid());
   result.test_bin_eq("DER contents", uuid_oid.der_contents(), "6983F09DA7EBCFDEE0C7A1A7B2C0948CC8F9D776");
   result.test_bin_eq("BER encoding", uuid_oid.BER_encode(), "06146983F09DA7EBCFDEE0C7A1A7B2C0948CC8F9D776");

   const auto from_der = Botan::OID::from_der_contents(uuid_oid.der_contents());
   result.test_is_true("from_der_contents round trips", from_der == uuid_oid);
   result.test_is_true("Hash codes of equal OIDs agree", from_der.hash_code() == uuid_oid.hash_code());
   result.test_is_false("Equal OIDs are not ordered", uuid_oid < from_der || from_der < uuid_oid);

   result.test_is_false("matches rejects a prefix", uuid_oid.matches({2, 25}));
   result.test_is_false("matches rejects an unrelated OID", uuid_oid.matches({2, 25, 1}));

   const Botan::OID sha256_rsa("1.2.840.113549.1.1.11");
   result.test_is_true("matches accepts an exact match", sha256_rsa.matches({1, 2, 840, 113549, 1, 1, 11}));
   result.test_is_false("matches rejects a prefix of the OID", sha256_rsa.matches({1, 2, 840, 113549, 1, 1}));
   result.test_is_false("matches rejects an extension of the OID",
                        sha256_rsa.matches({1, 2, 840, 113549, 1, 1, 11, 1}));

   // The second arc is unbounded under root 2
   const std::string big_second_str = "2.18446744073709551616";
   const Botan::OID big_second(big_second_str);
   result.test_str_eq("Large second arc round trips", big_second.to_string(), big_second_str);
   result.test_bin_eq("Large second arc encoding", big_second.der_contents(), "82808080808080808050");

   // OIDs with large arcs can be registered and looked up
   const std::string name = "botan-test-uuid-oid";
   Botan::OID::register_oid(uuid_oid, name);
   result.test_opt_str_eq("Registered name is found", uuid_oid.registered_name(), name);
   result.test_is_true("Lookup by name returns the OID", Botan::OID::from_string(name) == uuid_oid);
   result.test_is_true("Lookup by dotted string returns the OID", Botan::OID::from_string(uuid_oid_str) == uuid_oid);

   // The static table resolves in both directions
   result.test_str_eq(
      "Static table lookup by name", Botan::OID::from_string("RSA").to_string(), "1.2.840.113549.1.1.1");
   result.test_opt_str_eq("Static table lookup by OID", Botan::OID("1.2.840.113549.1.1.1").registered_name(), "RSA");

   const std::vector<uint32_t> sha256_rsa_arcs{1, 2, 840, 113549, 1, 1, 11};
   result.test_is_true("Construction from a span of arcs", Botan::OID(sha256_rsa_arcs) == sha256_rsa);

   // The ordering is consistent, so OIDs with large arcs work in ordered containers
   const std::set<Botan::OID> oids = {uuid_oid, big_second, sha256_rsa, Botan::OID("2.5.29.32")};
   result.test_sz_eq("Set contains all OIDs", oids.size(), 4);
   result.test_is_true("Set lookup of OID with large arc", oids.contains(Botan::OID(uuid_oid_str)));
   result.test_is_true("Set lookup of registered OID", oids.contains(Botan::OID("2.5.29.32")));

   return result;
}

Test::Result test_oid_invalid() {
   Test::Result result("OID invalid inputs");

   const std::vector<std::string> invalid_strings = {
      "",
      // Leading zeros are not permitted
      "01.2",
      "1.02",
      "1.2.03",
      "1.2.00",
      "1.2.0018446744073709551616",
      "1",
      "3.1",
      "1.40",
      "0.40.1",
      "1.18446744073709551616",
      "1.2.x",
      "1..2",
      "1.2.",
      ".1.2",
      "1.2.3.-4",
      "1.2.3 ",
      "1.2.18446744073709551616x",
      // Arcs of 2^133 or more
      "1.2.10889035741470030830827987437816582766592",
      "2.10889035741470030830827987437816582766512",
      "1.2.100000000000000000000000000000000000000000",
   };

   for(const auto& str : invalid_strings) {
      result.test_throws<Botan::Invalid_Argument>("Rejects '" + str + "'", [&]() { const Botan::OID oid(str); });
   }

   result.test_str_eq("A single zero is a valid arc", Botan::OID("0.0.0").to_string(), "0.0.0");
   result.test_throws<Botan::Lookup_Error>("from_string rejects leading zeros",
                                           []() { Botan::OID::from_string("1.2.03"); });
   result.test_is_true("Default constructed OID is empty", Botan::OID().empty());

   // Encodings over 128 bytes are rejected
   std::string long_oid = "1.2";
   for(size_t i = 0; i != 127; ++i) {
      long_oid += ".1";
   }
   result.test_sz_eq("128 byte encoding is accepted", Botan::OID(long_oid).der_contents().size(), 128);
   long_oid += ".1";
   result.test_throws<Botan::Invalid_Argument>("129 byte encoding is rejected",
                                               [&]() { const Botan::OID oid(long_oid); });

   // The largest arc accepted is 2^133 - 1, slightly over the largest UUID
   const std::string max_arc = "1.2.10889035741470030830827987437816582766591";
   result.test_str_eq("Largest arc is accepted", Botan::OID(max_arc).to_string(), max_arc);

   // Oversized inputs are rejected before any expensive conversion
   const std::string huge_arc = "1.2." + std::string(1000000, '9');
   result.test_throws<Botan::Invalid_Argument>("Rejects a million digit arc",
                                               [&]() { const Botan::OID oid(huge_arc); });

   std::string many_arcs = "1.2";
   for(size_t i = 0; i != 100000; ++i) {
      many_arcs += ".1";
   }
   result.test_throws<Botan::Invalid_Argument>("Rejects a hundred thousand arcs",
                                               [&]() { const Botan::OID oid(many_arcs); });

   const std::vector<uint32_t> many_int_arcs(100000, 1);
   result.test_throws<Botan::Invalid_Argument>("Rejects a hundred thousand integer arcs",
                                               [&]() { const Botan::OID oid(many_int_arcs); });

   result.test_throws<Botan::Invalid_Argument>("Rejects a single arc", []() { const Botan::OID oid{1}; });
   result.test_throws<Botan::Invalid_Argument>("Rejects root over 2", []() { const Botan::OID oid{3, 1}; });
   result.test_throws<Botan::Invalid_Argument>("Rejects second arc over 39 under root 1", []() {
      const Botan::OID oid{1, 40};
   });
   result.test_str_eq(
      "Accepts second arc over 39 under root 2", Botan::OID({2, 4294967295}).to_string(), "2.4294967295");

   result.test_throws<Botan::Decoding_Error>("Rejects empty encoding",
                                             []() { Botan::OID::from_der_contents(std::span<const uint8_t>()); });
   const std::vector<uint8_t> truncated = {0x2A, 0x81};
   result.test_throws<Botan::Decoding_Error>("Rejects truncated encoding",
                                             [&]() { Botan::OID::from_der_contents(truncated); });
   const std::vector<uint8_t> non_minimal = {0x2A, 0x80, 0x01};
   result.test_throws<Botan::Decoding_Error>("Rejects non-minimal encoding",
                                             [&]() { Botan::OID::from_der_contents(non_minimal); });
   // 1.2.<2^133>
   std::vector<uint8_t> large_arc(21, 0x80);
   large_arc.front() = 0x2A;
   large_arc[1] = 0x81;
   large_arc.back() = 0x00;
   result.test_throws<Botan::Decoding_Error>("Rejects arc over 133 bits",
                                             [&]() { Botan::OID::from_der_contents(large_arc); });
   const std::vector<uint8_t> too_long(129, 0x01);
   result.test_throws<Botan::Decoding_Error>("Rejects encoding over 128 bytes",
                                             [&]() { Botan::OID::from_der_contents(too_long); });

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
            test_oid_large_arcs,
            test_oid_invalid,
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

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         const auto oid_str = vars.get_req_str("OID");
         const auto expected_der = vars.get_req_bin("DER");

         Test::Result result("OID DER encode/decode");

         const Botan::OID oid(oid_str);

         try {
            std::vector<uint8_t> der;
            Botan::DER_Encoder enc(der);
            enc.encode(oid);
            result.test_bin_eq("Encoding correct", der, expected_der);
         } catch(std::exception& e) {
            result.test_failure("Encoding OID failed", e.what());
         }

         try {
            Botan::BER_Decoder dec(expected_der, Botan::BER_Decoder::Limits::DER());
            Botan::OID dec_oid;
            dec.decode(dec_oid);
            dec.verify_end();
            result.test_str_eq("Decoding OID correct", dec_oid.to_string(), oid_str);
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

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
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
