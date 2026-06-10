/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   #include <botan/ber_dec.h>
   #include <botan/hex.h>
   #include <botan/pkix_types.h>
   #include <botan/internal/charset.h>
   #include <algorithm>
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

class X509_DN_Valid_String_Tests final : public Text_Based_Test {
   public:
      X509_DN_Valid_String_Tests() : Text_Based_Test("x509/x509_dn_valid.vec", "Input,DER", "Output") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("X509_DN valid string encoding");

         const std::string input = vars.get_req_str("Input");
         const std::vector<uint8_t> expected_der = vars.get_req_bin("DER");
         const std::string expected_print = vars.get_opt_str("Output", input);

         const auto parsed = Botan::X509_DN::parse(input);
         if(!result.test_is_true("X509_DN::parse accepts valid input", parsed.has_value())) {
            return result;
         }

         // The parsed DN must encode to exactly the expected bytes ...
         result.test_bin_eq("DER encoding", parsed->DER_encode(), expected_der);

         // ... and that DER must decode back to an equal DN
         Botan::X509_DN decoded;
         Botan::BER_Decoder ber(expected_der);
         decoded.decode_from(ber);
         ber.verify_end();
         result.test_is_true("DER decodes to equal DN", *parsed == decoded);

         // to_string reproduces the input exactly, unless it's not canonical
         result.test_str_eq("string formatting", parsed->to_string(), expected_print);

         // to_string of the parsed DN and the decoded-from-DER DN should be the same
         result.test_str_eq("string formatting", parsed->to_string(), decoded.to_string());

         return result;
      }
};

BOTAN_REGISTER_TEST("x509", "x509_dn_valid", X509_DN_Valid_String_Tests);

class X509_DN_Invalid_String_Tests final : public Text_Based_Test {
   public:
      X509_DN_Invalid_String_Tests() : Text_Based_Test("x509/x509_dn_invalid.vec", "Input") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("X509_DN invalid string rejection");

         const std::string input = vars.get_req_str("Input");

         result.test_is_false("parse rejects malformed input", Botan::X509_DN::parse(input).has_value());

         // Stream extraction must signal the same failure via the failbit
         std::istringstream iss(input);
         Botan::X509_DN dn;
         iss >> dn;
         result.test_is_true("stream extraction sets failbit", iss.fail());

         return result;
      }
};

BOTAN_REGISTER_TEST("x509", "x509_dn_invalid", X509_DN_Invalid_String_Tests);

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
         results.push_back(test_parse_rejects_trailing_separator_with_whitespace());
         results.push_back(test_decode_failure_leaves_dn_unchanged());
         results.push_back(test_value_escaping_round_trips());
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

      static Test::Result test_parse_rejects_trailing_separator_with_whitespace() {
         Test::Result result("X509_DN parser rejects trailing separators");

         // The test vector harness strips trailing whitespace from the input, so
         // the whitespace-after-separator forms are checked here directly.
         for(const auto* input : {"CN=A,   ", "CN=A+   ", "CN=A, \t"}) {
            result.test_is_false(std::string("rejects '") + input + "'", Botan::X509_DN::parse(input).has_value());
         }

         // A separator with a following AVA is still accepted
         result.test_is_true("accepts CN=A, O=B", Botan::X509_DN::parse("CN=A, O=B").has_value());
         return result;
      }

      static Test::Result test_decode_failure_leaves_dn_unchanged() {
         Test::Result result("X509_DN decode failure leaves DN unchanged");

         Botan::X509_DN dn;
         dn.add_attribute("X520.CommonName", "Original");
         const Botan::X509_DN original = dn;

         const auto invalid_dn = Botan::hex_decode("3010310C300A06035504030C034261643100");
         result.test_throws("invalid empty RDN rejected", [&] {
            Botan::BER_Decoder bd(invalid_dn);
            dn.decode_from(bd);
         });

         result.test_str_eq("string form unchanged", format(dn), format(original));
         result.test_is_true("DN comparison unchanged", dn == original);
         return result;
      }

      static Test::Result test_value_escaping_round_trips() {
         Test::Result result("X509_DN value escaping and round-trip");

         auto has_raw_control_byte = [](std::string_view s) -> bool {
            return std::any_of(s.begin(), s.end(), [](char c) { return Botan::is_ascii_control_char(c); });
         };

         auto check_cn = [&](const std::string& label, std::string_view value) -> std::string {
            // Render a DN with CN=value and check the invariants that hold for any
            // value: the rendering has no raw C0/DEL control byte, and it parses back
            // to the exact value and re-renders identically. Returns the rendering.
            Botan::X509_DN dn;
            dn.add_attribute("X520.CommonName", value);
            const std::string s = format(dn);

            result.test_is_false(label + ": no raw control byte", has_raw_control_byte(s));
            const Botan::X509_DN parsed = parse(s);
            result.test_str_eq(label + ": value preserved", parsed.get_first_attribute("CN"), value);
            result.test_str_eq(label + ": re-emits identically", format(parsed), s);
            return s;
         };

         const std::string all_ascii = []() {
            std::string s;
            for(uint8_t b = 0x01; b <= 0x7F; ++b) {
               s.push_back(static_cast<char>(b));
            }
            return s;
         }();

         const std::vector<std::pair<std::string, std::string>> cases = {
            {"embedded newline", "This\nThat"},
            {"terminal escape", "ACME\x1b[2J\x1b[31mTRUSTED"},
            {"all ASCII bytes", all_ascii},
            {"embedded NUL", std::string("a\0b", 3)},
         };
         for(const auto& [label, value] : cases) {
            check_cn(label, value);
         }

         // Normal UTF-8 is unmodified
         const std::string utf8 = check_cn("printable UTF-8", "Fräulein");
         result.test_is_true("UTF-8 not escaped", utf8.find('\\') == std::string::npos);

         return result;
      }
};

BOTAN_REGISTER_TEST("x509", "x509_dn_string", X509_DN_String_Tests);
#endif

}  // namespace

}  // namespace Botan_Tests
