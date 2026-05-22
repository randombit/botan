/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   #include <botan/ber_dec.h>
   #include <botan/pkix_types.h>
   #include <sstream>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_X509_CERTIFICATES)
class X509_DN_Comparisons_Tests final : public Text_Based_Test {
   public:
      X509_DN_Comparisons_Tests() : Text_Based_Test("x509_dn.vec", "DN1,DN2") {}

      Test::Result run_one_test(const std::string& type, const VarMap& vars) override {
         const std::vector<uint8_t> dn_bits1 = vars.get_req_bin("DN1");
         const std::vector<uint8_t> dn_bits2 = vars.get_req_bin("DN2");

         const bool dn_same = (type == "Equal");

         Test::Result result("X509_DN comparisons");
         try {
            Botan::X509_DN dn1;
            Botan::BER_Decoder bd1(dn_bits1);
            dn1.decode_from(bd1);

            Botan::X509_DN dn2;
            Botan::BER_Decoder bd2(dn_bits2);
            dn2.decode_from(bd2);

            const bool compared_same = (dn1 == dn2);
            result.test_bool_eq("Comparison matches expected", dn_same, compared_same);

            const bool lt1 = (dn1 < dn2);
            const bool lt2 = (dn2 < dn1);

            if(dn_same) {
               result.test_is_false("same means neither is less than", lt1);
               result.test_is_false("same means neither is less than", lt2);
            } else {
               result.test_is_true("different means one is less than", lt1 || lt2);
               result.test_is_false("different means only one is less than", lt1 && lt2);
            }
         } catch(Botan::Exception& e) {
            result.test_failure(e.what());
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("x509", "x509_dn_cmp", X509_DN_Comparisons_Tests);

class X509_DN_String_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;
         results.push_back(test_single_ava_round_trip());
         results.push_back(test_multi_ava_rdn_emits_plus());
         results.push_back(test_multi_ava_rdn_round_trip());
         results.push_back(test_parse_multi_ava_rdn());
         results.push_back(test_mixed_single_and_multi_ava_round_trip());
         results.push_back(test_quoted_plus_in_value_not_split());
         return results;
      }

   private:
      static Botan::X509_DN parse(std::string_view s) {
         Botan::X509_DN dn;
         std::istringstream iss{std::string(s)};
         iss >> dn;
         return dn;
      }

      static std::string format(const Botan::X509_DN& dn) {
         std::ostringstream oss;
         oss << dn;
         return oss.str();
      }

      static Test::Result test_single_ava_round_trip() {
         Test::Result result("X509_DN string round-trip (single-AVA RDNs)");
         Botan::X509_DN dn;
         dn.add_attribute("X520.CommonName", "Alice");
         dn.add_attribute("X520.Organization", "Example");

         const std::string s = format(dn);
         result.test_str_eq("expected serialization", s, R"(CN="Alice",O="Example")");

         const Botan::X509_DN parsed = parse(s);
         result.test_sz_eq("two RDNs", parsed.count(), size_t(2));
         result.test_is_true("parses back to equal DN", parsed == dn);
         return result;
      }

      static Test::Result test_multi_ava_rdn_emits_plus() {
         Test::Result result("X509_DN string output uses '+' within RDN");
         Botan::X509_DN dn;
         dn.add_rdn({{Botan::OID::from_string("X520.CommonName"), Botan::ASN1_String("Alice")},
                     {Botan::OID::from_string("X520.Organization"), Botan::ASN1_String("Example")}});

         const std::string s = format(dn);
         result.test_str_eq("multi-AVA RDN uses '+' separator", s, R"(CN="Alice"+O="Example")");
         return result;
      }

      static Test::Result test_multi_ava_rdn_round_trip() {
         Test::Result result("X509_DN string round-trip (multi-AVA RDN)");
         Botan::X509_DN dn;
         dn.add_rdn({{Botan::OID::from_string("X520.CommonName"), Botan::ASN1_String("Alice")},
                     {Botan::OID::from_string("X520.Organization"), Botan::ASN1_String("Example")}});

         const std::string s = format(dn);
         const Botan::X509_DN parsed = parse(s);

         result.test_sz_eq("one RDN", parsed.count(), size_t(1));
         result.test_sz_eq("two AVAs in RDN", parsed.rdns().at(0).size(), size_t(2));
         result.test_is_true("parses back to equal DN", parsed == dn);
         result.test_str_eq("re-emits identical string", format(parsed), s);
         return result;
      }

      static Test::Result test_parse_multi_ava_rdn() {
         Test::Result result("X509_DN parses '+'-separated AVAs into one RDN");
         const Botan::X509_DN parsed = parse(R"(CN="Alice"+O="Example")");
         result.test_sz_eq("one RDN", parsed.count(), size_t(1));
         result.test_sz_eq("two AVAs in that RDN", parsed.rdns().at(0).size(), size_t(2));

         // ',' continues to act as the RDN separator.
         const Botan::X509_DN comma = parse(R"(CN="Alice",O="Example")");
         result.test_sz_eq("',' yields two RDNs", comma.count(), size_t(2));
         result.test_sz_eq("each RDN has one AVA", comma.rdns().at(0).size(), size_t(1));
         result.test_is_false("two distinct groupings", parsed == comma);
         return result;
      }

      static Test::Result test_mixed_single_and_multi_ava_round_trip() {
         Test::Result result("X509_DN string round-trip (mixed RDNs)");
         Botan::X509_DN dn;
         dn.add_attribute("X520.Country", "US");
         dn.add_rdn({{Botan::OID::from_string("X520.CommonName"), Botan::ASN1_String("Alice")},
                     {Botan::OID::from_string("X520.Organization"), Botan::ASN1_String("Example")}});
         dn.add_attribute("X520.OrganizationalUnit", "Eng");

         const std::string s = format(dn);
         result.test_str_eq("mixed RDN format", s, R"(C="US",CN="Alice"+O="Example",OU="Eng")");

         const Botan::X509_DN parsed = parse(s);
         result.test_sz_eq("three RDNs", parsed.count(), size_t(3));
         result.test_sz_eq("first is single AVA", parsed.rdns().at(0).size(), size_t(1));
         result.test_sz_eq("second is multi-AVA", parsed.rdns().at(1).size(), size_t(2));
         result.test_sz_eq("third is single AVA", parsed.rdns().at(2).size(), size_t(1));
         result.test_is_true("round-trips equal", parsed == dn);
         return result;
      }

      static Test::Result test_quoted_plus_in_value_not_split() {
         Test::Result result("X509_DN parser treats '+' inside quotes as data");
         const Botan::X509_DN parsed = parse(R"(CN="A+B")");
         result.test_sz_eq("one RDN", parsed.count(), size_t(1));
         result.test_sz_eq("one AVA", parsed.rdns().at(0).size(), size_t(1));
         result.test_str_eq("value preserved", parsed.get_first_attribute("CN"), "A+B");
         return result;
      }
};

BOTAN_REGISTER_TEST("x509", "x509_dn_string", X509_DN_String_Tests);
#endif

}  // namespace

}  // namespace Botan_Tests
