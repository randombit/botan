/*
* (C) 2015,2016 Kai Michaelis
*     2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   #include <botan/ber_dec.h>
   #include <botan/data_src.h>
   #include <botan/pkix_types.h>
   #include <botan/x509cert.h>
   #include <botan/x509path.h>
   #include <botan/internal/calendar.h>
   #include <botan/internal/x509_utils.h>
   #include <algorithm>
   #include <fstream>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_X509_CERTIFICATES) && defined(BOTAN_HAS_ECDSA) && defined(BOTAN_HAS_SHA2_32) && \
   defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

class Name_Constraint_Validation_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         /*
         * Each test is a single PEM file containing the chain leaf-first (leaf,
         * intermediates...), the trust anchor is shared as root.pem, and expected.txt
         * maps test-name to the Path_Validation_Result::result_string() output.
         */
         const std::string base = "x509/name_constraints/";
         const auto expected = read_manifest(Test::data_file(base + "expected.txt"));

         const Botan::X509_Certificate trust_anchor(Test::data_file(base + "root.pem"));

         const auto when = Botan::calendar_point(2027, 1, 1, 0, 0, 0).to_std_timepoint();

         const Botan::Path_Validation_Restrictions restrictions(false, 128);

         for(const auto& [name, expected_result] : expected) {
            Test::Result result("Name constraints test " + name);

            Botan::Certificate_Store_In_Memory store;
            store.add_certificate(trust_anchor);

            const auto chain = load_chain(Test::data_file(base + name + ".pem"));
            if(chain.empty()) {
               result.test_failure("No certs found in " + name + ".pem");
               results.emplace_back(std::move(result));
               continue;
            }

            const std::string hostname;

            const auto pv =
               Botan::x509_path_validate(chain, restrictions, store, hostname, Botan::Usage_Type::UNSPECIFIED, when);

            result.test_str_eq("validation result", pv.result_string(), expected_result);
            results.emplace_back(std::move(result));
         }

         return results;
      }

   private:
      // Read all certificates from a PEM bundle in file order (leaf first).
      static std::vector<Botan::X509_Certificate> load_chain(const std::string& filename) {
         Botan::DataSource_Stream in(filename);
         std::vector<Botan::X509_Certificate> certs;
         while(!in.end_of_data()) {
            try {
               certs.emplace_back(in);
            } catch(const Botan::Decoding_Error&) {
               break;
            }
         }
         return certs;
      }

      // Parse `<chain-name>:<result>` lines; ignore blanks and `#` comments.
      static std::vector<std::pair<std::string, std::string>> read_manifest(const std::string& path) {
         std::vector<std::pair<std::string, std::string>> out;
         std::ifstream in(path);
         std::string line;
         while(std::getline(in, line)) {
            if(line.empty() || line.front() == '#') {
               continue;
            }
            const auto colon = line.find(':');
            if(colon == std::string::npos) {
               continue;
            }
            out.emplace_back(line.substr(0, colon), line.substr(colon + 1));
         }
         return out;
      }
};

BOTAN_REGISTER_TEST("x509", "x509_name_constraints", Name_Constraint_Validation_Tests);

/*
* Validate that GeneralName iPAddress decoding rejects masks that are not a
* contiguous CIDR prefix. Drives the decoder with hand-rolled BER for a
* single [7] IMPLICIT OCTET STRING carrying {net || mask}.
*/
class Name_Constraint_IP_Mask_Tests final : public Text_Based_Test {
   public:
      Name_Constraint_IP_Mask_Tests() : Text_Based_Test("x509/general_name_ip.vec", "Address,Netmask") {}

      Test::Result run_one_test(const std::string& header, const VarMap& vars) override {
         Test::Result result("GeneralName iPAddress mask validation");

         const auto address = vars.get_req_bin("Address");
         const auto netmask = vars.get_req_bin("Netmask");

         const auto der = encode_address(address, netmask);

         Botan::BER_Decoder decoder(der, Botan::BER_Decoder::Limits::DER());
         Botan::GeneralName gn;

         if(header == "Valid") {
            try {
               gn.decode_from(decoder);
               result.test_success("Accepted valid GeneralName IP encoding");
            } catch(Botan::Decoding_Error&) {
               result.test_failure("Rejected valid GeneralName IP encoding");
            }
         } else {
            try {
               gn.decode_from(decoder);
               result.test_failure("Accepted invalid GeneralName IP encoding");
            } catch(Botan::Decoding_Error&) {
               result.test_success("Rejected invalid GeneralName IP encoding");
            }
         }

         return result;
      }

   private:
      static std::vector<uint8_t> encode_address(std::span<const uint8_t> address, std::span<const uint8_t> netmask) {
         std::vector<uint8_t> der;
         // [7] IMPLICIT OCTET STRING, primitive, context-specific.
         der.push_back(0x87);
         // Short for length is sufficient here
         der.push_back(static_cast<uint8_t>(address.size() + netmask.size()));
         der.insert(der.end(), address.begin(), address.end());
         der.insert(der.end(), netmask.begin(), netmask.end());
         return der;
      }
};

BOTAN_REGISTER_TEST("x509", "x509_name_constraint_ip_mask", Name_Constraint_IP_Mask_Tests);

/*
* Strict validation at the constraint-factory boundary: malformed
* inputs throw, valid inputs are canonicalized (lowercase host,
* preserve email local-part case).
*/
class Name_Constraint_Factory_Validation_Tests final : public Test {
   private:
      using FactoryFn = Botan::GeneralName (*)(std::string_view);

      static void check_valid(Test::Result& result,
                              const std::string& label,
                              FactoryFn make,
                              std::string_view input,
                              std::string_view expected_name) {
         try {
            const auto gn = make(input);
            result.test_str_eq(label + " canonical: " + std::string(input), gn.name(), expected_name);
         } catch(const std::exception& e) {
            result.test_failure(label + " rejected valid '" + std::string(input) + "': " + e.what());
         }
      }

      static void check_invalid(Test::Result& result,
                                const std::string& label,
                                FactoryFn make,
                                std::string_view input) {
         try {
            (void)make(input);
            result.test_failure(label + " accepted invalid '" + std::string(input) + "'");
         } catch(const Botan::Invalid_Argument&) {
            result.test_success(label + " rejected '" + std::string(input) + "'");
         }
      }

      static Test::Result test_dns() {
         Test::Result result("X509v3 Name Constraints: DNS factory validation");
         const auto m = &Botan::GeneralName::dns;
         check_valid(result, "DNS", m, "example.com", "example.com");
         check_valid(result, "DNS", m, "EXAMPLE.com", "example.com");
         check_valid(result, "DNS", m, "host", "host");
         check_valid(result, "DNS", m, ".example.com", ".example.com");

         const auto rejected = {"",
                                ".",
                                "..example.com",
                                "example..com",
                                "example.com.",
                                "*.example.com",
                                "host name",
                                " example.com",
                                "example.com ",
                                "_acme-challenge.example.com"};

         for(const auto& bad : rejected) {
            check_invalid(result, "DNS", m, bad);
         }
         return result;
      }

      static Test::Result test_uri() {
         Test::Result result("X509v3 Name Constraints: URI factory validation");
         const auto m = &Botan::GeneralName::uri;
         check_valid(result, "URI", m, "example.com", "example.com");
         check_valid(result, "URI", m, ".example.com", ".example.com");
         check_valid(result, "URI", m, "EXAMPLE.com", "example.com");
         // RFC 5280 4.2.1.10: "The constraint MUST be specified as a
         // fully qualified domain name". Single-label hosts and full
         // URIs are not constraint-shaped; both are rejected.
         for(const auto& bad : {"",
                                ".",
                                "localhost",
                                ".localhost",
                                "https://example.com",
                                "https://example.com/path",
                                "example.com:443",
                                "*.example.com",
                                "example.com.",
                                "..example.com"}) {
            check_invalid(result, "URI", m, bad);
         }
         return result;
      }

      static Test::Result test_uri_san_value() {
         Test::Result result("X509v3 Name Constraints: URI SAN value factory validation");
         const auto m = &Botan::GeneralName::_uri_san_value;
         check_valid(result, "URI SAN", m, "https://example.com", "https://example.com");
         check_valid(result, "URI SAN", m, "https://example.com/path?q=1#frag", "https://example.com/path?q=1#frag");
         check_valid(result, "URI SAN", m, "HTTPS://Example.COM/", "HTTPS://Example.COM/");
         check_valid(result, "URI SAN", m, "https://localhost/", "https://localhost/");
         // Inputs URI::parse rejects (RFC 3986 syntax violations,
         // constraint-shape values that aren't URIs).
         for(const auto& bad : {"",
                                "example.com",
                                ".example.com",
                                "not a uri",
                                "://no.scheme/",
                                "https://example.com/has space",
                                "https://user@bad@example.com/",
                                "https://example.com/%G0"}) {
            check_invalid(result, "URI SAN", m, bad);
         }
         return result;
      }

      static Test::Result test_dns_san_value() {
         Test::Result result("X509v3 Name Constraints: DNS SAN value factory validation");
         const auto m = &Botan::GeneralName::_dns_san_value;

         check_valid(result, "DNS SAN", m, "example.com", "example.com");
         check_valid(result, "DNS SAN", m, "EXAMPLE.com", "example.com");
         check_valid(result, "DNS SAN", m, "*.example.com", "*.example.com");
         check_valid(result, "DNS SAN", m, "foo*.example.com", "foo*.example.com");
         check_valid(result, "DNS SAN", m, "*bar.example.com", "*bar.example.com");

         for(const auto& bad : {"", ".", "..example.com", "*.*.example.com", "foo.*.example.com", "host name"}) {
            check_invalid(result, "DNS SAN", m, bad);
         }
         return result;
      }

      static Test::Result test_email() {
         Test::Result result("X509v3 Name Constraints: email factory validation");
         const auto m = &Botan::GeneralName::email;
         // Mailbox form: local-part case-preserved, host lowercased (RFC 5280 7.5).
         check_valid(result, "Email", m, "Alice@Example.COM", "Alice@example.com");
         check_valid(result, "Email", m, "user@example.com", "user@example.com");
         // Host form: bare DNS name.
         check_valid(result, "Email", m, "example.com", "example.com");
         // Subtree form: leading dot is preserved.
         check_valid(result, "Email", m, ".example.com", ".example.com");
         for(const auto& bad : {"",
                                "@example.com",
                                "user@",
                                "a@b@c",
                                ".",
                                "user@example..com",
                                "user@.example.com",
                                "user@*.example.com"}) {
            check_invalid(result, "Email", m, bad);
         }
         return result;
      }

   public:
      std::vector<Test::Result> run() override {
         return {test_dns(), test_uri(), test_email(), test_uri_san_value(), test_dns_san_value()};
      }
};

BOTAN_REGISTER_TEST("x509", "x509_name_constraint_factory_validation", Name_Constraint_Factory_Validation_Tests);

class Wildcard_Excluded_Subtree_Containment_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("X509v3 Name Constraints: wildcard SAN vs excluded DNS subtree");

         struct Case {
               std::string pattern;     // SAN wildcard
               std::string constraint;  // excluded DNS constraint value
               bool expect_intersect;
         };

         const std::vector<Case> cases = {
            // SAN of *.com can expand to evil.com.
            {"*.com", "evil.com", true},
            // Leading-dot subtree: *.com can expand to <anything>.com.
            {"*.com", ".com", true},
            // Wildcard whose tail equals the constraint: every expansion
            // is in the subtree.
            {"*.example.com", "example.com", true},
            {"*.example.com", ".example.com", true},
            // Wildcard with extra labels under the constraint: every
            // expansion is in the subtree.
            {"*.foo.example.com", "example.com", true},
            // Partial wildcards in the leftmost label that absorb the
            // missing labels of the constraint base.
            {"foo*.example.com", "example.com", true},
            {"*bar.example.com", "example.com", true},
            // Non-overlapping suffixes: no expansion in subtree.
            {"*.example.com", "evil.com", false},
            {"*.example.com", ".other.com", false},
            // Wildcard tail shorter than constraint, and leftover prefix
            // contains a dot - can't be produced by a single-label wildcard.
            {"*.com", "evil.example.com", false},
            // Single-label wildcards only match single-label hosts.
            {"*", "evil.com", false},
            {"*", "com", true},
            {"foo*", "foobar", true},
            // Leading-dot subtree excludes the apex; single-label wildcard
            // can't reach into it.
            {"*", ".com", false},
         };

         for(const auto& c : cases) {
            const bool got = Botan::wildcard_intersects_excluded_dns_subtree(c.pattern, c.constraint);
            result.test_bool_eq(c.pattern + " vs " + c.constraint, got, c.expect_intersect);
         }

         return {result};
      }
};

BOTAN_REGISTER_TEST("x509",
                    "x509_name_constraint_wildcard_excluded_containment",
                    Wildcard_Excluded_Subtree_Containment_Tests);

class SmtpUTF8Mailbox_Constraint_Match_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("X509v3 Name Constraints: rfc822Name matches SmtpUTF8Mailbox");

         // RFC 9598 Section 6: rfc822Name constraints extend to SmtpUTF8Mailbox
         // SAN entries. The constraint's local-part (if any) is
         // ignored; comparison is on the domain part.

         const auto host_constraint = Botan::GeneralName::email("example.com");
         const auto subtree_constraint = Botan::GeneralName::email(".example.com");
         const auto mailbox_constraint = Botan::GeneralName::email("alice@example.com");

         const auto mailbox = [](std::string_view s) { return Botan::SmtpUtf8Mailbox::from_string(s).value(); };

         // Host constraint: domain must match exactly.
         result.test_is_true("host constraint matches identical domain",
                             host_constraint.matches_email(mailbox("user@example.com")));
         result.test_is_false("host constraint rejects subdomain",
                              host_constraint.matches_email(mailbox("user@sub.example.com")));
         result.test_is_false("host constraint rejects unrelated domain",
                              host_constraint.matches_email(mailbox("user@evil.com")));

         // Subtree constraint (leading dot): proper subdomains match,
         // base does not.
         result.test_is_true("subtree constraint matches subdomain",
                             subtree_constraint.matches_email(mailbox("user@sub.example.com")));
         result.test_is_false("subtree constraint rejects apex",
                              subtree_constraint.matches_email(mailbox("user@example.com")));
         result.test_is_false("subtree constraint rejects unrelated domain",
                              subtree_constraint.matches_email(mailbox("user@evil.com")));

         // RFC 9549 deprecates mailbox-form rfc822Name constraints for
         // SmtpUTF8Mailbox matching: such constraints must not match.
         result.test_is_false("mailbox constraint does not apply to SmtpUTF8Mailbox",
                              mailbox_constraint.matches_email(mailbox("alice@example.com")));

         // The reviewer's bypass: a CA permitted to ".example.com" issues
         // a leaf with SmtpUTF8Mailbox "alice@evil.com". Before the fix
         // this would slip through; after, the matcher correctly reports
         // no match, and is_excluded/is_permitted will reject the chain.
         result.test_is_false("bypass closed: ASCII evil.com against .example.com",
                              subtree_constraint.matches_email(mailbox("alice@evil.com")));
         result.test_is_false("bypass closed: UTF-8 local part doesn't change the answer",
                              subtree_constraint.matches_email(mailbox("\xCE\xB4\xCE\xBF\xCE\xBA\xCE\xB9@evil.com")));

         // Non-email constraints don't match regardless of mailbox.
         const auto dns_constraint = Botan::GeneralName::dns("example.com");
         result.test_is_false("DNS constraint doesn't match SmtpUTF8Mailbox",
                              dns_constraint.matches_email(mailbox("user@example.com")));

         // SmtpUtf8Mailbox::from_string rejects the malformed shapes
         // we previously had to guard against in the matcher.
         for(const auto& bad : {"",
                                "no-at-sign.example.com",
                                "@example.com",
                                "alice@",
                                "a@b@c",
                                "alice@.example.com",
                                "alice@example..com",
                                "alice..bob@example.com",
                                ".alice@example.com",
                                // RFC 9598 Section 3: non-ASCII domain labels
                                // MUST be in A-label form on the wire.
                                // Raw UTF-8 in the domain is rejected.
                                "alice@\xD0\xBF\xD1\x80\xD0\xB8\xD0\xBC\xD0\xB5\xD1\x80.\xD1\x80\xD1\x84",
                                // Invalid UTF-8 anywhere in the input.
                                "alice@\xC0\xC0.com"}) {
            result.test_is_false("SmtpUtf8Mailbox rejects malformed: " + std::string(bad),
                                 Botan::SmtpUtf8Mailbox::from_string(bad).has_value());
         }

         // ASCII and UTF-8-local-part mailboxes both parse.
         result.test_is_true("ASCII mailbox parses",
                             Botan::SmtpUtf8Mailbox::from_string("alice@example.com").has_value());
         result.test_is_true(
            "UTF-8 local part parses",
            Botan::SmtpUtf8Mailbox::from_string("\xCE\xB4\xCE\xBF\xCE\xBA\xCE\xB9@example.com").has_value());
         // A-label encoded IDN domain parses (RFC 9598 Section 3 mandates this
         // form for any label containing non-ASCII characters).
         result.test_is_true("A-label IDN domain parses",
                             Botan::SmtpUtf8Mailbox::from_string("alice@xn--e1afmkfd.xn--p1ai").has_value());

         return {result};
      }
};

BOTAN_REGISTER_TEST("x509", "x509_name_constraint_smtp_utf8_match", SmtpUTF8Mailbox_Constraint_Match_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
