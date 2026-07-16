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
   #include <botan/der_enc.h>
   #include <botan/hex.h>
   #include <botan/pkix_types.h>
   #include <botan/x509_ext.h>
   #include <botan/x509cert.h>
   #include <botan/x509path.h>
   #include <botan/internal/calendar.h>
   #include <botan/internal/x509_utils.h>
   #include <algorithm>
   #include <fstream>
   #include <set>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_X509_CERTIFICATES) && defined(BOTAN_HAS_ECDSA) && defined(BOTAN_HAS_SHA2_32) && \
   defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

// Read all certificates from a PEM bundle in file order (leaf first).
std::vector<Botan::X509_Certificate> load_chain(const std::string& filename) {
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

// (type, name) pairs for order-preserving comparison of subtree lists
std::vector<std::pair<Botan::GeneralName::NameType, std::string>> describe(
   const std::vector<Botan::GeneralSubtree>& subtrees) {
   std::vector<std::pair<Botan::GeneralName::NameType, std::string>> out;
   out.reserve(subtrees.size());
   for(const auto& subtree : subtrees) {
      out.emplace_back(subtree.base().type_code(), subtree.base().name());
   }
   return out;
}

// Parse `<chain-name>:<result>` lines; ignore blanks and `#` comments.
std::vector<std::pair<std::string, std::string>> read_manifest(const std::string& path) {
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
               result.test_str_eq("validation result", "Certificate failed to decode", expected_result);
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
         check_valid(result, "URI SAN", m, "mailto:root@example.com", "mailto:root@example.com");
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

class Name_Constraint_Encoding_Tests final : public Test {
   private:
      static std::vector<uint8_t> der_encode_name(const Botan::GeneralName& gn) {
         std::vector<uint8_t> der;
         Botan::DER_Encoder enc(der);
         enc.encode(gn);
         return der;
      }

      static Test::Result test_general_name_golden_bytes() {
         Test::Result result("X509v3 Name Constraints: GeneralName encoding");

         result.test_bin_eq(
            "dNSName host", der_encode_name(Botan::GeneralName::dns("example.com")), "820B6578616D706C652E636F6D");
         result.test_bin_eq("dNSName subtree",
                            der_encode_name(Botan::GeneralName::dns(".example.com")),
                            "820C2E6578616D706C652E636F6D");
         result.test_bin_eq("rfc822Name mailbox",
                            der_encode_name(Botan::GeneralName::email("alice@example.com")),
                            "8111616C696365406578616D706C652E636F6D");
         result.test_bin_eq("uniformResourceIdentifier host",
                            der_encode_name(Botan::GeneralName::uri("host.example.com")),
                            "8610686F73742E6578616D706C652E636F6D");
         result.test_bin_eq(
            "iPAddress IPv4 subnet",
            der_encode_name(Botan::GeneralName::ipv4_address(Botan::IPv4Subnet::from_string("10.0.0.0/8").value())),
            "87080A000000FF000000");
         result.test_bin_eq(
            "iPAddress IPv4 host",
            der_encode_name(Botan::GeneralName::ipv4_address(Botan::IPv4Address::from_string("192.0.2.1").value())),
            "8708C0000201FFFFFFFF");
         result.test_bin_eq(
            "iPAddress IPv6 subnet",
            der_encode_name(Botan::GeneralName::ipv6_address(Botan::IPv6Subnet::from_string("2001:db8::/32").value())),
            "872020010DB8000000000000000000000000FFFFFFFF000000000000000000000000");

         Botan::X509_DN dn;
         dn.add_attribute("X520.Country", "US");
         result.test_bin_eq("directoryName",
                            der_encode_name(Botan::GeneralName::directory_name(dn)),
                            "A40F300D310B3009060355040613025553");

         return result;
      }

      static Test::Result test_extension_golden_bytes() {
         Test::Result result("X509v3 Name Constraints: extension encoding");

         std::vector<Botan::GeneralSubtree> permitted;
         permitted.emplace_back(Botan::GeneralName::dns("example.com"));
         std::vector<Botan::GeneralSubtree> excluded;
         excluded.emplace_back(Botan::GeneralName::dns("evil.example.com"));

         Botan::Extensions exts;
         exts.add(std::make_unique<Botan::Cert_Extension::Name_Constraints>(
                     Botan::NameConstraints(std::move(permitted), std::move(excluded))),
                  true);

         result.test_bin_eq("NameConstraints extension body",
                            exts.get_extension_bits(Botan::Cert_Extension::Name_Constraints::static_oid()),
                            "3027A00F300D820B6578616D706C652E636F6DA11430128210"
                            "6576696C2E6578616D706C652E636F6D");
         return result;
      }

      static Test::Result test_roundtrip() {
         Test::Result result("X509v3 Name Constraints: encode/decode round trip");

         Botan::X509_DN dn;
         dn.add_attribute("X520.Country", "US");
         dn.add_attribute("X520.Organization", "Example Corp");

         std::vector<Botan::GeneralSubtree> permitted;
         permitted.emplace_back(Botan::GeneralName::dns("example.com"));
         permitted.emplace_back(Botan::GeneralName::dns(".sub.example.com"));
         permitted.emplace_back(Botan::GeneralName::email("alice@example.com"));
         permitted.emplace_back(Botan::GeneralName::email(".mail.example.com"));
         permitted.emplace_back(Botan::GeneralName::uri("host.example.com"));
         permitted.emplace_back(Botan::GeneralName::ipv4_address(Botan::IPv4Subnet::from_string("10.0.0.0/8").value()));
         permitted.emplace_back(
            Botan::GeneralName::ipv6_address(Botan::IPv6Subnet::from_string("2001:db8::/32").value()));
         permitted.emplace_back(Botan::GeneralName::directory_name(dn));

         std::vector<Botan::GeneralSubtree> excluded;
         excluded.emplace_back(Botan::GeneralName::dns("evil.example.com"));
         excluded.emplace_back(Botan::GeneralName::ipv4_address(Botan::IPv4Address::from_string("192.0.2.1").value()));
         excluded.emplace_back(Botan::GeneralName::ipv6_address(Botan::IPv6Address::from_string("::1").value()));

         const auto expected_permitted = describe(permitted);
         const auto expected_excluded = describe(excluded);

         Botan::Extensions exts;
         exts.add(std::make_unique<Botan::Cert_Extension::Name_Constraints>(
                     Botan::NameConstraints(std::move(permitted), std::move(excluded))),
                  true);

         const auto oid = Botan::Cert_Extension::Name_Constraints::static_oid();
         const auto first_encoding = exts.get_extension_bits(oid);

         std::vector<uint8_t> wire;
         // Extensions::encode_into skips the outer SEQUENCE
         Botan::DER_Encoder(wire).start_sequence().encode(exts).end_cons();
         Botan::Extensions parsed;
         Botan::BER_Decoder dec(wire);
         parsed.decode_from(dec, Botan::Extension_Context::Certificate);

         const auto* nc = parsed.get_extension_object_as<Botan::Cert_Extension::Name_Constraints>();
         if(!result.test_not_null("NameConstraints decoded as typed extension", nc)) {
            return result;
         }

         const auto& decoded = nc->get_name_constraints();
         result.test_is_true("permitted subtrees survive round trip",
                             describe(decoded.permitted()) == expected_permitted);
         result.test_is_true("excluded subtrees survive round trip", describe(decoded.excluded()) == expected_excluded);

         Botan::Extensions reencoded;
         reencoded.add(nc->copy(), true);
         result.test_bin_eq("re-encoding is byte identical", reencoded.get_extension_bits(oid), first_encoding);

         return result;
      }

      static Test::Result test_empty_encode_rejected() {
         Test::Result result("X509v3 Name Constraints: encoder rejects empty NameConstraints");
         Botan::Extensions exts;
         result.test_throws("Extensions::add throws on empty NameConstraints",
                            [&] { exts.add(std::make_unique<Botan::Cert_Extension::Name_Constraints>(), true); });
         return result;
      }

      static Test::Result test_othername_encode_rejected() {
         Test::Result result("X509v3 Name Constraints: encoder rejects otherName constraint");

         // otherName [0]: type-id 1.2.3.4 with a [0] UTF8String "abc" value.
         // Decoding retains only the type tag, so re-encoding must refuse.
         const auto der = Botan::hex_decode("A00C06032A0304A0050C03616263");
         Botan::BER_Decoder dec(der, Botan::BER_Decoder::Limits::DER());
         Botan::GeneralName gn;
         gn.decode_from(dec);
         if(!result.test_is_true("decoded as otherName", gn.type_code() == Botan::GeneralName::NameType::Other)) {
            return result;
         }

         std::vector<Botan::GeneralSubtree> permitted;
         permitted.emplace_back(gn);
         Botan::Extensions exts;
         result.test_throws("Extensions::add throws on otherName constraint", [&] {
            exts.add(std::make_unique<Botan::Cert_Extension::Name_Constraints>(
                        Botan::NameConstraints(std::move(permitted), {})),
                     true);
         });
         return result;
      }

   public:
      std::vector<Test::Result> run() override {
         return {test_general_name_golden_bytes(),
                 test_extension_golden_bytes(),
                 test_roundtrip(),
                 test_empty_encode_rejected(),
                 test_othername_encode_rejected()};
      }
};

BOTAN_REGISTER_TEST("x509", "x509_name_constraint_encoding", Name_Constraint_Encoding_Tests);

/*
* Re-encode every NameConstraints extension in the validation corpus and
* require byte-identical output. Constraint forms whose decode does not
* retain a value (otherName, unrecognized tags) must instead be rejected
* at encode time.
*/
class Name_Constraint_Corpus_Reencode_Tests final : public Test {
   private:
      static bool has_unencodable_name(const std::vector<Botan::GeneralSubtree>& subtrees) {
         return std::any_of(subtrees.begin(), subtrees.end(), [](const Botan::GeneralSubtree& subtree) {
            const auto type = subtree.base().type_code();
            return type == Botan::GeneralName::NameType::Other || type == Botan::GeneralName::NameType::Unknown;
         });
      }

      // Decode a NameConstraints extension body via the Extensions wire form.
      // `parsed` must outlive the returned pointer.
      static const Botan::Cert_Extension::Name_Constraints* decode_nc_body(Botan::Extensions& parsed,
                                                                           const std::vector<uint8_t>& body) {
         std::vector<uint8_t> wire;
         Botan::DER_Encoder enc(wire);
         enc.start_sequence()
            .start_sequence()
            .encode(Botan::Cert_Extension::Name_Constraints::static_oid())
            .encode(true)
            .encode(body, Botan::ASN1_Type::OctetString)
            .end_cons()
            .end_cons();
         Botan::BER_Decoder dec(wire);
         parsed.decode_from(dec, Botan::Extension_Context::Certificate);
         return parsed.get_extension_object_as<Botan::Cert_Extension::Name_Constraints>();
      }

   public:
      std::vector<Test::Result> run() override {
         Test::Result result("X509v3 Name Constraints: corpus re-encode");

         /*
         * These chains deliberately carry constraint encodings that decoding
         * canonicalizes (uppercase IA5 hosts, host bits set inside a CIDR mask,
         * an explicitly encoded DEFAULT minimum). Re-encoding produces the
         * canonical form, so for them require semantic equality and encoding
         * stability rather than byte identity.
         */
         const std::set<std::string> canonicalized_by_decode = {
            "dns-case-insensitive-valid",
            "ia5-locale-independent-case-valid",
            "ipv4-name-constraint-non-canonical-cidr-valid",
            "name-constraints-explicit-minimum-zero-valid",
            "uri-host-case-insensitive-valid",
            "wildcard-excluded-case-insensitive-invalid",
         };

         const std::string base = "x509/name_constraints/";
         std::vector<std::string> files{"root"};
         for(const auto& entry : read_manifest(Test::data_file(base + "expected.txt"))) {
            files.push_back(entry.first);
         }

         const auto oid = Botan::Cert_Extension::Name_Constraints::static_oid();
         size_t reencoded_count = 0;

         for(const auto& file : files) {
            for(const auto& cert : load_chain(Test::data_file(base + file + ".pem"))) {
               const auto& exts = cert.v3_extensions();
               const auto* nc = exts.get_extension_object_as<Botan::Cert_Extension::Name_Constraints>();
               if(nc == nullptr) {
                  continue;
               }

               const auto original = exts.get_extension_bits(oid);
               const bool critical = exts.critical_extension_set(oid);

               try {
                  Botan::Extensions fresh;
                  fresh.add(nc->copy(), critical);
                  const auto reencoded = fresh.get_extension_bits(oid);
                  reencoded_count += 1;

                  if(canonicalized_by_decode.contains(file)) {
                     Botan::Extensions parsed;
                     const auto* nc2 = decode_nc_body(parsed, reencoded);
                     if(!result.test_not_null(file + " canonical re-encoding decodes", nc2)) {
                        continue;
                     }
                     const auto& before = nc->get_name_constraints();
                     const auto& after = nc2->get_name_constraints();
                     result.test_is_true(file + " canonical re-encoding is semantically equal",
                                         describe(after.permitted()) == describe(before.permitted()) &&
                                            describe(after.excluded()) == describe(before.excluded()));

                     Botan::Extensions again;
                     again.add(nc2->copy(), critical);
                     result.test_bin_eq(
                        file + " canonical re-encoding is stable", again.get_extension_bits(oid), reencoded);
                  } else {
                     result.test_bin_eq(file + " re-encodes byte identical", reencoded, original);
                  }
               } catch(const Botan::Encoding_Error&) {
                  const auto& decoded = nc->get_name_constraints();
                  result.test_is_true(
                     file + " encode rejected only for otherName/unknown constraint",
                     has_unencodable_name(decoded.permitted()) || has_unencodable_name(decoded.excluded()));
               }
            }
         }

         result.test_sz_gte("corpus provided name constraint extensions", reencoded_count, 100);

         return {result};
      }
};

BOTAN_REGISTER_TEST("x509", "x509_name_constraint_corpus_reencode", Name_Constraint_Corpus_Reencode_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
